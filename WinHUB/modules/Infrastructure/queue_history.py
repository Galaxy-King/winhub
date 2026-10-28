"""Scoped queue archives and bounded cleanup of completed task history."""
import hashlib
import json
import re
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import Response, current_app, jsonify, request, session
from sqlalchemy import func, or_

from core.database import db, AgentTask, HistorySearchToken, ScheduleRun, SoftwareStep
from core.scheduling import OPEN_RUNS, integer
from core.sensitive_data import mask_sensitive_text, mask_sensitive_object

ZONE = ZoneInfo('Europe/Kyiv')
MAX_TASKS = 10000
MAX_BYTES = 100 * 1024 * 1024
BATCH_SIZE = 5000


def iso(value):
    return value.isoformat() + 'Z' if value else None


def scoped_tasks():
    from .routes import infra_allowed_host_ids, is_interactive_superadmin
    query = AgentTask.query
    if not is_interactive_superadmin():
        allowed = infra_allowed_host_ids(session.get('user_id'), 'view_queue')
        query = query.filter(or_(AgentTask.endpoint_id.in_(allowed), AgentTask.endpoint_id_snapshot.in_(allowed)))
    return query


def date_range(raw):
    dates = []
    for key in ('date_from', 'date_to'):
        value = raw.get(key, '')
        if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            raise ValueError('Choose both dates in YYYY-MM-DD format')
        dates.append(datetime.strptime(value, '%Y-%m-%d'))
    start, last = dates
    if last < start:
        raise ValueError('The end date must not precede the start date')
    end = last + timedelta(days=1)
    return (start.replace(tzinfo=ZONE).astimezone(timezone.utc).replace(tzinfo=None),
            end.replace(tzinfo=ZONE).astimezone(timezone.utc).replace(tzinfo=None))


def eligible_tasks(cutoff):
    protected_runs = db.session.query(ScheduleRun.id).filter(ScheduleRun.status.in_(OPEN_RUNS))
    protected_software = db.session.query(SoftwareStep.task_id).filter(
        SoftwareStep.task_id.isnot(None), SoftwareStep.status.in_(['Active', 'Queued']))
    active_jobs = db.session.query(AgentTask.job_id).filter(AgentTask.job_id.isnot(None),
        or_(~func.coalesce(AgentTask.status, 'Pending').in_(['Success', 'Error', 'Cancelled']), AgentTask.outcome == 'ResultUnknown'))
    return AgentTask.query.filter(AgentTask.created_at < cutoff,
        AgentTask.status.in_(['Success', 'Error', 'Cancelled']),
        or_(AgentTask.finished_at.is_(None), AgentTask.finished_at < cutoff),
        or_(AgentTask.outcome.is_(None), AgentTask.outcome != 'ResultUnknown'),
        ~AgentTask.id.in_(protected_software),
        or_(AgentTask.job_id.is_(None), ~AgentTask.job_id.in_(active_jobs)),
        or_(AgentTask.schedule_run_id.is_(None), ~AgentTask.schedule_run_id.in_(protected_runs)))


def cleanup_history():
    from .routes import write_infra_audit
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict):
            raise ValueError('Expected a JSON object')
        days = integer(data.get('days'), 1, 3650, 'Days')
        cutoff = datetime.utcnow() - timedelta(days=days)
        if data.get('cutoff'):
            if not isinstance(data['cutoff'], str):
                raise ValueError('Invalid cutoff')
            anchored = datetime.fromisoformat(data['cutoff'].replace('Z', '+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
            if abs((cutoff - anchored).total_seconds()) > 1800:
                raise ValueError('Cleanup preview expired; preview again')
            cutoff = anchored
    except (TypeError, ValueError, OverflowError):
        return jsonify(success=False, message='Enter whole days between 1 and 3650; refresh an expired preview'), 400
    query = eligible_tasks(cutoff)
    if data.get('preview') is True:
        return jsonify(success=True, eligible=query.count(), cutoff=iso(cutoff), days=days, batch_size=BATCH_SIZE)
    rows = query.with_entities(AgentTask.id).order_by(AgentTask.created_at, AgentTask.id).with_for_update(skip_locked=True).limit(BATCH_SIZE).all()
    ids = [row[0] for row in rows]
    if ids:
        HistorySearchToken.query.filter(HistorySearchToken.entity_type == 'task',
            HistorySearchToken.entity_id.in_(ids)).delete(synchronize_session=False)
        AgentTask.query.filter(AgentTask.id.in_(ids)).delete(synchronize_session=False)
    write_infra_audit('Cleanup Scoped Task History', 'task', 'bulk', dict(days=days, cutoff=iso(cutoff), deleted=len(ids)))
    db.session.commit()
    remaining = eligible_tasks(cutoff).count()
    return jsonify(success=True, deleted=len(ids), remaining=remaining, has_more=remaining > 0, cutoff=iso(cutoff))


def archive_component(value):
    # Folder names are opaque IDs, never hostnames, titles or paths supplied by agents.
    text = str(value or 'unknown')
    if re.fullmatch(r'[A-Za-z0-9_-]{1,100}', text):
        return text
    return 'id-' + hashlib.sha256(text.encode('utf-8')).hexdigest()


def masked_json(value):
    def scrub(item):
        if isinstance(item, dict):
            return {key: scrub(value) for key, value in item.items()}
        if isinstance(item, list):
            return [scrub(value) for value in item]
        return mask_sensitive_text(item) if isinstance(item, str) else item
    return json.dumps(scrub(mask_sensitive_object(value)), ensure_ascii=False, indent=2)


def register(bp):
    @bp.route('/api/infrastructure/tasks/history-range')
    def queue_history_range():
        from .routes import require_permission
        denied = require_permission('view_queue')
        if denied:
            return denied
        oldest, newest, count = scoped_tasks().with_entities(
            func.min(AgentTask.created_at), func.max(AgentTask.created_at), func.count(AgentTask.id)).one()
        return jsonify(success=True, oldest=iso(oldest), newest=iso(newest), tasks=count, timezone=ZONE.key)

    @bp.route('/api/infrastructure/tasks/export', methods=['POST'])
    def queue_history_export():
        from .routes import require_permission, is_interactive_superadmin, write_infra_audit
        denied = require_permission('view_queue')
        if denied:
            return denied
        if session.get('api_key_auth'):
            return jsonify(success=False, message='Use an interactive session to export task history'), 403
        raw = request.get_json(silent=True)
        try:
            if not isinstance(raw, dict):
                raise ValueError('Expected a JSON object')
            start, end = date_range(raw)
        except (ValueError, TypeError, OverflowError) as exc:
            return jsonify(success=False, message=str(exc)), 400
        query = scoped_tasks().filter(AgentTask.created_at >= start, AgentTask.created_at < end)
        count = query.count()
        if not count:
            return jsonify(success=False, message='No task records exist in this date range'), 404
        if count > MAX_TASKS:
            return jsonify(success=False, message=f'This range exceeds {MAX_TASKS} tasks. Export smaller date ranges.'), 413
        spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode='w+b')
        total_bytes, actual = 0, 0
        payload_allowed = is_interactive_superadmin()
        try:
            with zipfile.ZipFile(spool, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                def write(name, value):
                    nonlocal total_bytes
                    content = value.encode('utf-8')
                    total_bytes += len(content)
                    if total_bytes > MAX_BYTES:
                        raise ValueError('Archive exceeds 100 MiB of source data. Export smaller date ranges.')
                    archive.writestr(name, content)
                for task in query.order_by(AgentTask.created_at, AgentTask.id).yield_per(25):
                    actual += 1
                    if actual > MAX_TASKS:
                        raise ValueError('The range changed and exceeds the task limit. Export a smaller range.')
                    local_date = task.created_at.replace(tzinfo=timezone.utc).astimezone(ZONE).date().isoformat()
                    folder = f'{local_date}/jobs/{archive_component(task.job_id)}/hosts/{archive_component(task.endpoint_id_snapshot or task.endpoint_id)}/{archive_component(task.id)}'
                    metadata = dict(id=task.id, job_id=task.job_id, endpoint_id=task.endpoint_id_snapshot or task.endpoint_id,
                        hostname=task.endpoint_hostname_snapshot, display_name=task.endpoint_name_snapshot,
                        title=task.title, source=task.source_type, action=task.action_type, created_by=task.created_by,
                        launch_reason=task.launch_reason, status=task.status, outcome=task.outcome, exit_code=task.exit_code,
                        created_at=iso(task.created_at), received_at=iso(task.picked_up_at), finished_at=iso(task.finished_at),
                        schedule_run_id=task.schedule_run_id, retry_count=task.retry_count)
                    write(folder + '/task.json', masked_json(metadata))
                    write(folder + '/result.log', mask_sensitive_text(task.result_log or ''))
                    if payload_allowed:
                        try:
                            payload = json.loads(task.payload or '{}')
                        except ValueError:
                            payload = {'raw': task.payload or ''}
                        write(folder + '/input.json', masked_json(payload))
                write('manifest.json', json.dumps(dict(format='winhub-task-history-v1', exported_at=iso(datetime.utcnow()),
                    date_from=raw['date_from'], date_to=raw['date_to'], timezone=ZONE.key, tasks=actual,
                    input_included=payload_allowed, masking='Known sensitive fields/patterns are masked; review before sharing.'), indent=2))
                write('README.txt', 'Task history export. Date folders and selected dates use Europe/Kyiv; JSON timestamps use UTC.\n'
                    'Each task has task.json and result.log. Interactive superadmins also receive masked input.json.\n'
                    'This is a read-only snapshot; active task results may change. No installers or server backups are included.\n'
                    'Known secret fields/patterns are masked. This is not a guarantee that all sensitive data was detected.\n')
            write_infra_audit('Export Task History', 'task', 'bulk', dict(date_from=raw['date_from'], date_to=raw['date_to'], tasks=actual))
            db.session.commit()
            spool.seek(0)
            def chunks():
                try:
                    while block := spool.read(65536):
                        yield block
                finally:
                    spool.close()
            response = Response(chunks(), mimetype='application/zip')
            response.headers['Content-Disposition'] = f'attachment; filename="winhub-tasks-{raw["date_from"]}-to-{raw["date_to"]}.zip"'
            response.headers['Content-Length'] = str(spool.seek(0, 2))
            spool.seek(0)
            response.headers['Cache-Control'] = 'no-store'
            response.call_on_close(spool.close)
            return response
        except ValueError as exc:
            spool.close()
            return jsonify(success=False, message=str(exc)), 413
        except Exception:
            spool.close()
            db.session.rollback()
            current_app.logger.exception('Task archive export failed')
            return jsonify(success=False, message='Export failed. Check server logs.'), 500
