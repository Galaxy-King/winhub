"""Calendar schedules, durable occurrences and authenticated task result summaries.

Approved scripts run only on agents. Wrappers preserve the process exit code in a
bounded result trailer; no script output is evaluated by the server.
"""
import base64
import calendar
import json
import math
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.exc import IntegrityError

from core.database import db, AgentTask, ScheduledTask, ScheduleRun, User

LOCK = threading.RLock()
ACTIVE = ('Pending', 'PickedUp', 'Running')
OPEN_RUNS = ('Claimed', 'WaitingForAgent', 'Running', 'Queued', 'ResultUnknown')
DEFAULT_POLICY = dict(delivery_seconds=3600, execution_seconds=1800, result_grace_seconds=120,
                      missed='run_once', overlap='skip', retries=0, retry_delay_seconds=300,
                      success_codes=[0], warning_codes=[], verification_codes=[21], capture_exit=True)


def integer(value, low, high, label):
    if isinstance(value, bool):
        raise ValueError(label + ' must be a number')
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ValueError(label + ' must be a number') from None
    if str(result) != str(value).strip() or not low <= result <= high:
        raise ValueError(f'{label} must be between {low} and {high}')
    return result


def normalize_policy(raw):
    if not isinstance(raw, dict):
        raise ValueError('Execution policy must be an object')
    policy = dict(DEFAULT_POLICY)
    for key, bounds in dict(delivery_seconds=(60, 604800), execution_seconds=(60, 86400),
                            retries=(0, 10), retry_delay_seconds=(60, 86400)).items():
        policy[key] = integer(raw.get(key, policy[key]), *bounds, key)
    for key, choices in dict(missed=('skip', 'run_once'), overlap=('skip', 'queue_one')).items():
        policy[key] = raw.get(key, policy[key])
        if policy[key] not in choices:
            raise ValueError('Unsupported ' + key + ' policy')
    for key in ('success_codes', 'warning_codes', 'verification_codes'):
        values = raw.get(key, policy[key])
        if not isinstance(values, list) or len(values) > 32:
            raise ValueError(key + ' must contain up to 32 integer codes')
        policy[key] = list(dict.fromkeys(integer(v, -2147483648, 2147483647, key) for v in values))
    if not policy['success_codes']:
        raise ValueError('Specify at least one successful exit code')
    sets = [set(policy[k]) for k in ('success_codes', 'warning_codes', 'verification_codes')]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i)):
        raise ValueError('Success, warning and verification codes must not overlap')
    return policy


def policy_for(task):
    if task.execution_policy:
        return json.loads(task.execution_policy)
    # Legacy jobs retain process-status semantics until explicitly edited.
    return dict(DEFAULT_POLICY, capture_exit=False, overlap='parallel',
                execution_seconds=(task.timeout_minutes or 30) * 60)


def normalize_spec(raw):
    if not isinstance(raw, dict):
        raise ValueError('Schedule must be an object')
    kind = raw.get('kind')
    if kind not in ('once', 'daily', 'weekly', 'monthly', 'interval', 'cron'):
        raise ValueError('Choose a supported recurrence')
    zone = str(raw.get('timezone') or 'Europe/Kyiv')
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError('Unknown timezone') from None
    spec = dict(kind=kind, timezone=zone)
    if kind == 'cron':
        expression = str(raw.get('cron') or '').strip()
        if len(expression) > 100:
            raise ValueError('Cron expression is too long')
        try:
            CronTrigger.from_crontab(expression, timezone=ZoneInfo(zone))
        except (ValueError, TypeError):
            raise ValueError('Invalid five-field cron expression') from None
        spec['cron'] = expression
    else:
        try:
            start = datetime.fromisoformat(str(raw.get('start') or ''))
            if start.tzinfo is not None:
                raise ValueError()
        except ValueError:
            raise ValueError('Start must be a local date and time') from None
        spec['start'] = start.replace(second=0, microsecond=0).isoformat(timespec='minutes')
        if kind in ('daily', 'weekly', 'monthly', 'interval'):
            spec['every'] = integer(raw.get('every', 1), 1, 365, 'Repeat interval')
        if kind == 'weekly':
            days = raw.get('weekdays', [])
            if not isinstance(days, list) or not 1 <= len(days) <= 7:
                raise ValueError('Select one or more weekdays')
            spec['weekdays'] = sorted(set(integer(v, 0, 6, 'Weekday') for v in days))
        if kind == 'monthly':
            spec['mode'] = raw.get('mode', 'day')
            if spec['mode'] == 'day':
                spec['day'] = integer(raw.get('day', 1), 1, 31, 'Day of month')
            elif spec['mode'] == 'last_day':
                pass
            elif spec['mode'] == 'weekday':
                spec['ordinal'] = integer(raw.get('ordinal', 1), -1, 4, 'Week ordinal')
                if spec['ordinal'] == 0:
                    raise ValueError('Choose first through fourth or last weekday')
                spec['weekday'] = integer(raw.get('weekday', 0), 0, 6, 'Weekday')
            else:
                raise ValueError('Unknown monthly mode')
        if kind == 'interval':
            spec['unit'] = raw.get('unit', 'hours')
            if spec['unit'] not in ('minutes', 'hours', 'days'):
                raise ValueError('Choose minutes, hours or days')
    if raw.get('end'):
        try:
            end = datetime.fromisoformat(str(raw['end']))
            if end.tzinfo or ('start' in spec and end < datetime.fromisoformat(spec['start'])):
                raise ValueError()
        except ValueError:
            raise ValueError('End must be a local date/time after start') from None
        spec['end'] = end.isoformat(timespec='minutes')
    return spec


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def next_fire(spec, after):
    """Strictly after UTC instant; calendar days skip DST gaps, folds run once."""
    zone, after = ZoneInfo(spec['timezone']), utc(after)
    end = datetime.fromisoformat(spec['end']).replace(tzinfo=zone).astimezone(timezone.utc) if spec.get('end') else None
    if spec['kind'] == 'cron':
        trigger = CronTrigger.from_crontab(spec['cron'], timezone=zone)
        result = trigger.get_next_fire_time(None, after + timedelta(microseconds=1))
        candidate = result.astimezone(timezone.utc) if result else None
    else:
        start = datetime.fromisoformat(spec['start'])
        aware_start = start.replace(tzinfo=zone)
        if spec['kind'] == 'once':
            candidate = aware_start.astimezone(timezone.utc)
            if candidate.astimezone(zone).replace(tzinfo=None) != start:
                return None
        elif spec['kind'] == 'interval':
            seconds = spec['every'] * {'minutes': 60, 'hours': 3600, 'days': 86400}[spec['unit']]
            start_utc = aware_start.astimezone(timezone.utc)
            count = max(0, math.floor((after - start_utc).total_seconds() / seconds) + 1)
            candidate = start_utc + timedelta(seconds=count * seconds)
        else:
            day = max(start.date(), after.astimezone(zone).date())
            candidate = None
            for offset in range(366 * 32):
                date = day + timedelta(days=offset)
                if end and date > end.astimezone(zone).date():
                    break
                delta = (date - start.date()).days
                if spec['kind'] == 'daily':
                    matches = delta % spec['every'] == 0
                elif spec['kind'] == 'weekly':
                    anchor = start.date() - timedelta(days=start.weekday())
                    matches = ((date - anchor).days // 7) % spec['every'] == 0 and date.weekday() in spec['weekdays']
                else:
                    month_delta = (date.year - start.year) * 12 + date.month - start.month
                    matches = month_delta % spec['every'] == 0
                    last = calendar.monthrange(date.year, date.month)[1]
                    if spec['mode'] == 'day':
                        matches &= date.day == spec['day']
                    elif spec['mode'] == 'last_day':
                        matches &= date.day == last
                    else:
                        ordinal = spec['ordinal']
                        matches &= date.weekday() == spec['weekday'] and ((last - date.day < 7) if ordinal == -1 else ((date.day - 1) // 7 + 1 == ordinal))
                if not matches:
                    continue
                local = datetime.combine(date, start.time()).replace(tzinfo=zone, fold=0)
                instant = local.astimezone(timezone.utc)
                if instant.astimezone(zone).replace(tzinfo=None) != local.replace(tzinfo=None):
                    continue
                if instant > after and local.replace(tzinfo=None) >= start:
                    candidate = instant
                    break
    if not candidate or candidate <= after or (end and candidate > end):
        return None
    return candidate.replace(tzinfo=None)


def spec_for(task):
    if task.schedule_spec:
        return json.loads(task.schedule_spec)
    if task.cron_expr.startswith('DATE:'):
        return dict(kind='once', timezone='Europe/Kyiv', start=task.cron_expr[5:].strip().replace(' ', 'T'))
    return dict(kind='cron', timezone='Europe/Kyiv', cron=task.cron_expr)


def preview(spec, after=None, count=5):
    at, values = after or datetime.utcnow(), []
    for _ in range(count):
        at = next_fire(spec, at)
        if at is None:
            break
        values.append(at.isoformat() + 'Z')
    return values


def script_payload(payload, os_type):
    contract = payload.get('__schedule_contract')
    if not contract or not isinstance(payload.get('script'), str):
        return payload
    script = payload['script']
    if str(os_type).lower() == 'windows':
        script = "$ErrorActionPreference = 'Stop'\n" + script
    encoded = base64.b64encode(script.encode('utf-8')).decode('ascii')
    marker = 'WINHUB_RESULT_V1:' + contract['nonce'] + ':'
    if str(os_type).lower() == 'windows':
        wrapper = r'''$ErrorActionPreference = 'Stop'
$p = Join-Path $PSScriptRoot ('schedule_' + [guid]::NewGuid().ToString('N') + '.ps1')
$code = 1
try {
    [IO.File]::WriteAllText($p, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CODE__')), [Text.UTF8Encoding]::new($true))
    $ErrorActionPreference = 'Continue'
    & "$PSHOME\powershell.exe" -NoProfile -NonInteractive -File $p 2>&1 | ForEach-Object { Write-Output $_.ToString() }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
} catch { Write-Output $_.Exception.Message; $code = 1 }
finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
Write-Output ('__MARKER__' + $code)
exit 0
'''
    else:
        wrapper = '''#!/bin/bash
p=$(mktemp) || exit 1
trap 'rm -f -- "$p"' EXIT
printf '%s' '__CODE__' | base64 -d > "$p" || exit 1
bash "$p" 2>&1
code=$?
printf '\\n__MARKER__%s\\n' "$code"
exit 0
'''
    return dict(payload, script=wrapper.replace('__CODE__', encoded).replace('__MARKER__', marker))


def receive_result(task, agent_status, log):
    if not task.schedule_run_id:
        return log
    run = db.session.get(ScheduleRun, task.schedule_run_id)
    if not run:
        return log
    policy = json.loads(run.policy_snapshot)
    payload = json.loads(task.payload or '{}')
    contract = payload.get('__schedule_contract')
    if contract:
        pattern = r'(?:^|\n)WINHUB_RESULT_V1:' + re.escape(contract['nonce']) + r':(-?\d{1,11})\s*$'
        match = re.search(pattern, log)
        if match and agent_status == 'Success' and -2147483648 <= int(match[1]) <= 2147483647:
            task.exit_code = code = int(match[1])
            task.outcome = ('Success' if code in policy['success_codes'] else 'Warning' if code in policy['warning_codes']
                            else 'VerificationFailed' if code in policy['verification_codes'] else 'ScriptFailed')
            task.status = 'Success' if task.outcome in ('Success', 'Warning') else 'Error'
            return log[:match.start()].rstrip() + '\nProcess exit code: ' + str(code)
        task.outcome = 'ResultUnknown'
        task.status = 'Error'
    else:
        task.outcome = 'Success' if agent_status == 'Success' else 'Cancelled' if agent_status == 'Cancelled' else 'ExecutionFailed'
    return log


def refresh_run(run):
    tasks = AgentTask.query.filter_by(schedule_run_id=run.id).all()
    if not tasks:
        return
    for task in tasks:
        if task.status == 'Cancelled' and task.picked_up_at and not task.outcome:
            # Cancelling a server record cannot prove a remote process stopped.
            task.outcome = 'ResultUnknown'
    pending = [t for t in tasks if t.status in ACTIVE]
    if any(t.outcome == 'ResultUnknown' for t in tasks):
        run.status, run.finished_at = 'ResultUnknown', None
    elif pending:
        run.status = 'Running' if any(t.picked_up_at for t in pending) else 'WaitingForAgent'
        run.finished_at = None
    else:
        outcomes = [t.outcome or ('Success' if t.status == 'Success' else 'Cancelled' if t.status == 'Cancelled' else 'ExecutionFailed') for t in tasks]
        unique = set(outcomes)
        run.status = (outcomes[0] if len(unique) == 1 else 'PartialFailure' if unique - {'Success', 'Warning'} else 'Warning')
        if 'ResultUnknown' in unique:
            run.status = 'ResultUnknown'
        run.finished_at = max((t.finished_at or datetime.utcnow()) for t in tasks)
    run.job_id = tasks[0].job_id
    run.message = f'{sum(t.status == "Success" for t in tasks)}/{len(tasks)} completed successfully'
    schedule = db.session.get(ScheduledTask, run.schedule_id) if run.schedule_id else None
    latest = ScheduleRun.query.filter_by(schedule_id=run.schedule_id).order_by(ScheduleRun.created_at.desc(), ScheduleRun.id.desc()).first() if schedule else None
    if schedule and latest and latest.id == run.id:
        schedule.last_status = run.status


def run_schedule(schedule_id, dispatch, *, manual_run=False, actor_user_id=None, actor_name=None,
                 launch_reason=None, due_at=None, queued_run_id=None):
    """Claim before dispatch. A crash leaves a visible unknown run, never an automatic duplicate."""
    now = datetime.utcnow()
    with LOCK:
        schedule = ScheduledTask.query.filter_by(id=schedule_id).populate_existing().with_for_update().first()
        if not schedule or ((not manual_run or queued_run_id) and not schedule.is_active):
            return dict(success=False, message='Schedule is missing or disabled')
        if due_at is not None and schedule.next_run_at != due_at:
            return dict(success=False, message='Schedule changed or occurrence already advanced')
        policy = policy_for(schedule)
        if queued_run_id:
            run = ScheduleRun.query.filter_by(id=queued_run_id, schedule_id=schedule_id).populate_existing().with_for_update().first()
            if not run or run.status != 'Queued':
                return dict(success=False, message='Queued occurrence is unavailable')
            busy = ScheduleRun.query.filter(ScheduleRun.schedule_id == schedule_id, ScheduleRun.id != run.id,
                ScheduleRun.status.in_(('Claimed', 'WaitingForAgent', 'Running', 'ResultUnknown'))).first()
            if busy:
                db.session.commit()
                return dict(success=True, run_id=run.id, state='Queued')
            spec = spec_for(schedule)
            if spec.get('end') and datetime.fromisoformat(spec['end']).replace(tzinfo=ZoneInfo(spec['timezone'])).astimezone(timezone.utc) < utc(now):
                run.status, run.finished_at, run.message = 'Expired', now, 'Schedule end date passed before dispatch'
                db.session.commit()
                return dict(success=True, run_id=run.id, state='Expired')
            run.status = 'Claimed'
            if spec['kind'] == 'once':
                schedule.is_active = False
        else:
            planned = due_at or (now if manual_run else schedule.next_run_at or now)
            key = str(uuid.uuid4()) if manual_run else planned.isoformat()
            if ScheduleRun.query.filter_by(schedule_id=schedule_id, occurrence_key=key).first():
                return dict(success=False, message='Occurrence already claimed')
            run = ScheduleRun(schedule_id=schedule_id, occurrence_key=key, name=schedule.name,
                              category=schedule.category or 'Scheduled', source='manual' if manual_run else 'scheduler',
                              scheduled_at=planned, status='Claimed', policy_snapshot=json.dumps(policy),
                              actor_user_id=actor_user_id, actor_name=actor_name or schedule.created_by, launch_reason=launch_reason or schedule.launch_reason)
            db.session.add(run)
        others = ScheduleRun.query.filter(ScheduleRun.schedule_id == schedule_id, ScheduleRun.status.in_(OPEN_RUNS),
                                         ScheduleRun.id != run.id).all()
        # A new run's Python default UUID is assigned only on flush.
        others = [r for r in others if r is not run]
        if others and policy['overlap'] != 'parallel' and not queued_run_id:
            if policy['overlap'] == 'queue_one' and not any(r.status == 'Queued' for r in others):
                run.status, run.message = 'Queued', 'Waiting for the preceding run to finish'
            else:
                run.status, run.message, run.finished_at = 'Skipped', 'Previous execution is still active or unresolved', now
        if not manual_run and not queued_run_id:
            schedule.next_run_at = next_fire(spec_for(schedule), now)
            if schedule.next_run_at is None and run.status != 'Queued':
                schedule.is_active = False
        schedule.last_run, schedule.last_status = now, run.status
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return dict(success=False, message='Occurrence already claimed')
        if run.status in ('Queued', 'Skipped'):
            return dict(success=True, run_id=run.id, state=run.status)
        # Do not dispatch a disabled once schedule again; this occurrence is already claimed.
        result = dispatch(schedule_id, manual_run=manual_run, actor_user_id=actor_user_id,
                          actor_name=actor_name, launch_reason=launch_reason, run_record=run)
        if result.get('success'):
            refresh_run(run)
        else:
            run.status, run.finished_at, run.message = 'DispatchFailed', datetime.utcnow(), str(result.get('message') or 'Dispatch failed')[:1000]
            if schedule.execution_policy:
                schedule.last_status = run.status
        db.session.commit()
        return dict(result, run_id=run.id)


def maintain(now=None):
    """Serialize with pickup/result row locks. Never retry a task accepted by an agent."""
    now = now or datetime.utcnow()
    tasks = AgentTask.query.filter(AgentTask.schedule_run_id.isnot(None), AgentTask.status.in_(ACTIVE)).with_for_update(skip_locked=True).limit(1000).all()
    for task in tasks:
        run = db.session.get(ScheduleRun, task.schedule_run_id)
        if not run:
            continue
        policy = json.loads(run.policy_snapshot)
        if task.status == 'Pending' and task.delivery_deadline and now > task.delivery_deadline:
            if task.retry_count < policy['retries']:
                task.retry_count += 1
                task.retry_after = now + timedelta(seconds=policy['retry_delay_seconds'])
                task.delivery_deadline = now + timedelta(seconds=policy['delivery_seconds'] + policy['retry_delay_seconds'])
                task.result_log = 'Delivery retry: same task, never received by agent'
            else:
                task.status, task.outcome, task.finished_at = 'Error', 'DeliveryExpired', now
                task.result_log = 'Delivery window expired. Agent did not receive this task; script was not started.'
        elif task.picked_up_at and task.result_deadline and now > task.result_deadline:
            task.status, task.outcome, task.finished_at = 'Error', 'ResultUnknown', now
            task.result_log = 'No final result after execution budget and return grace. Check the endpoint; execution may still be running. No automatic retry.'
    for run in ScheduleRun.query.filter(ScheduleRun.status.in_(OPEN_RUNS)).limit(1000).all():
        refresh_run(run)
        if run.status == 'Claimed' and run.created_at < now - timedelta(minutes=5):
            run.status, run.message = 'ResultUnknown', 'Dispatch interrupted. Check task history before resolving manually.'
    db.session.commit()


def tick(app, dispatch):
    with app.app_context(), LOCK:
        maintain()
        now = datetime.utcnow()
        due = ScheduledTask.query.filter_by(is_active=True).filter(ScheduledTask.next_run_at <= now).order_by(ScheduledTask.next_run_at).limit(100).all()
        ids = [(s.id, s.next_run_at) for s in due]
        db.session.commit()
        for schedule_id, planned in ids:
            s = ScheduledTask.query.filter_by(id=schedule_id).populate_existing().with_for_update().first()
            if not s or not s.is_active or s.next_run_at != planned:
                continue
            if policy_for(s)['missed'] == 'skip' and now - planned > timedelta(minutes=5):
                # Record one coalesced missed occurrence, without dispatching a script.
                run = ScheduleRun(schedule_id=s.id, occurrence_key=planned.isoformat(), name=s.name, category=s.category,
                                  source='scheduler', scheduled_at=planned, status='Missed', finished_at=now,
                                  policy_snapshot=json.dumps(policy_for(s)), message='Missed while scheduler was unavailable')
                db.session.add(run)
                s.next_run_at = next_fire(spec_for(s), now)
                s.is_active = bool(s.next_run_at)
                s.last_run, s.last_status = now, 'Missed'
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
            else:
                run_schedule(schedule_id, dispatch, due_at=planned)
        queued = [(r.id, r.schedule_id, r.source, r.actor_user_id, r.actor_name, r.launch_reason)
                  for r in ScheduleRun.query.filter_by(status='Queued').order_by(ScheduleRun.created_at).limit(100).all()]
        db.session.commit()
        for run_id, schedule_id, source, actor_id, actor_name, reason in queued:
            if schedule_id:
                run_schedule(schedule_id, dispatch, manual_run=source == 'manual', actor_user_id=actor_id,
                             actor_name=actor_name, launch_reason=reason, queued_run_id=run_id)
