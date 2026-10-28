"""Interactive scheduler preview, scoped run history and explicit unknown resolution."""
import json
from datetime import datetime

from flask import jsonify, request, session
from sqlalchemy import or_
from core.database import db, ScheduleRun, AgentTask, ScheduledTask
from core.scheduling import normalize_spec, preview, refresh_run
from core.sdk import WinHubCore
from core.task_reason import validate_launch_reason


def register(bp):
    def access():
        from .routes import require_permission
        denied = require_permission('manage_scheduler')
        if denied:
            return denied
        if session.get('api_key_auth'):
            return jsonify(success=False, message='An interactive Scheduler session is required'), 403

    @bp.route('/api/infrastructure/schedule/summary')
    def scheduler_summary():
        denied = access()
        if denied:
            return denied
        from .routes import current_user, infra_allowed_host_ids
        user = current_user()
        allowed = set(infra_allowed_host_ids(user.id, 'run_tasks')) if not user.is_admin else None
        rows = []
        for schedule in ScheduledTask.query.order_by(ScheduledTask.name).limit(2000).all():
            if allowed is not None:
                if schedule.target_type == 'host' and schedule.target_id not in allowed:
                    continue
                if schedule.target_type == 'group':
                    from core.group_access import group_action_allowed
                    if not group_action_allowed(user, schedule.target_id, 'run_tasks'):
                        continue
            rows.append(dict(id=schedule.id, status=schedule.last_status or 'NeverRun',
                             last_run=schedule.last_run.isoformat() + 'Z' if schedule.last_run else None,
                             next_run=schedule.next_run_at.isoformat() + 'Z' if schedule.next_run_at else None))
        return jsonify(success=True, schedules=rows)

    @bp.route('/api/infrastructure/schedule/preview', methods=['POST'])
    def scheduler_preview():
        denied = access()
        if denied:
            return denied
        try:
            raw = request.get_json(silent=True)
            spec = normalize_spec(raw.get('recurrence') if isinstance(raw, dict) else None)
            return jsonify(success=True, recurrence=spec, dates=preview(spec))
        except (ValueError, TypeError) as exc:
            return jsonify(success=False, message=str(exc)), 400

    @bp.route('/api/infrastructure/schedule/history')
    def scheduler_history():
        denied = access()
        if denied:
            return denied
        from .routes import current_user, mask_sensitive_text
        user = current_user()
        try:
            page = max(1, min(10000, int(request.args.get('page', 1))))
        except ValueError:
            return jsonify(success=False, message='Invalid page'), 400
        query = ScheduleRun.query
        allowed = None if user.is_admin else WinHubCore.authorized_target_ids(user.id, [h.id for h in WinHubCore.get_allowed_hosts(user.id, 'run_tasks')])
        if not user.is_admin:
            # Metadata-only failed runs are visible to their owner; host rows remain scoped.
            query = query.filter(or_(ScheduleRun.actor_user_id == user.id, ScheduleRun.actor_name == user.username))
        for field in ('status', 'category', 'schedule_id', 'source'):
            value = request.args.get(field, '').strip()
            if value:
                query = query.filter(getattr(ScheduleRun, field) == value[:150])
        text = request.args.get('q', '').strip()[:150]
        if text:
            query = query.filter(ScheduleRun.name.ilike('%' + text + '%'))
        host_id = request.args.get('host', '').strip()[:100]
        if host_id:
            query = query.filter(ScheduleRun.id.in_(db.session.query(AgentTask.schedule_run_id).filter(
                AgentTask.endpoint_id_snapshot == host_id)))
        for key, column in (('from', ScheduleRun.created_at), ('to', ScheduleRun.created_at)):
            if request.args.get(key):
                try:
                    date = datetime.strptime(request.args[key], '%Y-%m-%d')
                except ValueError:
                    return jsonify(success=False, message='Use YYYY-MM-DD dates'), 400
                if key == 'from':
                    query = query.filter(column >= date)
                else:
                    from datetime import timedelta
                    query = query.filter(column < date + timedelta(days=1))
        total = query.count()
        runs = query.order_by(ScheduleRun.created_at.desc(), ScheduleRun.id.desc()).offset((page - 1) * 25).limit(25).all()
        result = []
        for run in runs:
            tasks_query = AgentTask.query.filter_by(schedule_run_id=run.id)
            if host_id:
                tasks_query = tasks_query.filter(AgentTask.endpoint_id_snapshot == host_id)
            if allowed is not None:
                tasks_query = tasks_query.filter(AgentTask.endpoint_id_snapshot.in_(allowed))
            tasks = tasks_query.order_by(AgentTask.endpoint_hostname_snapshot, AgentTask.id).limit(101).all()
            iso = lambda value: value.isoformat() + 'Z' if value else None
            result.append(dict(id=run.id, schedule_id=run.schedule_id, name=run.name, category=run.category,
                source=run.source, status=run.status, message=mask_sensitive_text(run.message or ''),
                scheduled_at=iso(run.scheduled_at), created_at=iso(run.created_at), finished_at=iso(run.finished_at),
                resolve_allowed=bool(user.is_admin and run.status == 'ResultUnknown'),
                tasks_truncated=len(tasks) > 100, tasks=[dict(id=t.id, host=t.endpoint_id_snapshot,
                    name=t.endpoint_name_snapshot or t.endpoint_hostname_snapshot or t.endpoint_id_snapshot,
                    status=t.outcome or ('Running' if t.picked_up_at and t.status in ('PickedUp', 'Running') else 'WaitingForAgent' if t.status == 'Pending' else t.status),
                    exit_code=t.exit_code, retries=t.retry_count, created_at=iso(t.created_at),
                    received_at=iso(t.picked_up_at), finished_at=iso(t.finished_at),
                    duration_seconds=int((t.finished_at - t.picked_up_at).total_seconds()) if t.finished_at and t.picked_up_at else None,
                    ) for t in tasks[:100]]))
        return jsonify(success=True, runs=result, page=page, total=total, has_more=page * 25 < total)

    @bp.route('/api/infrastructure/schedule/history/<run_id>/resolve', methods=['POST'])
    def scheduler_resolve(run_id):
        from .routes import require_interactive_superadmin, write_infra_audit
        denied = require_interactive_superadmin()
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        try:
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object')
            reason = validate_launch_reason(data.get('launch_reason'))
        except ValueError as exc:
            return jsonify(success=False, message=str(exc)), 400
        if data.get('execution_stopped') is not True:
            return jsonify(success=False, message='Check the endpoint and confirm all execution has stopped'), 400
        run = ScheduleRun.query.filter_by(id=run_id).with_for_update().first()
        if not run or run.status != 'ResultUnknown':
            return jsonify(success=False, message='This run does not need manual resolution'), 409
        for task in AgentTask.query.filter_by(schedule_run_id=run.id).with_for_update().all():
            if task.outcome == 'ResultUnknown' or task.status in ('Pending', 'PickedUp', 'Running'):
                task.status, task.outcome, task.finished_at = 'Error', 'ResolvedManually', datetime.utcnow()
        run.status, run.finished_at, run.message = 'ResolvedManually', datetime.utcnow(), 'Execution stopped, confirmed by operator: ' + reason
        latest = ScheduleRun.query.filter_by(schedule_id=run.schedule_id).order_by(ScheduleRun.created_at.desc()).first() if run.schedule_id else None
        if latest and latest.id == run.id:
            schedule = db.session.get(ScheduledTask, run.schedule_id)
            if schedule:
                schedule.last_status = run.status
        write_infra_audit('Schedule Run Resolved', 'schedule_run', run.id, {'launch_reason': reason})
        db.session.commit()
        return jsonify(success=True)
