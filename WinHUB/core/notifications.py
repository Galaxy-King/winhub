"""Transaction-backed notifications. No network I/O in domain transactions."""
import hashlib
import json
import logging
import threading
import uuid
from datetime import datetime, timedelta
from urllib.parse import quote

from flask import Blueprint, abort, jsonify, request, session, render_template
from sqlalchemy import event, inspect, select
from sqlalchemy.orm import Session, defer

from core.database import (db, User, Endpoint, AgentTask, TaskTemplate, SoftwarePackage,
    SoftwareDeployment, SoftwareStep, ScheduleRun, AggregatedJob, AgentUpdateRollout, NewsletterCampaign,
    EndpointIdentityConflict, ReportDelivery, AiReportRequest, AuditLog, EncryptedText)
from core.notification_models import NotificationSignal, Notification, NotificationPreference, PushSubscription, PushDelivery
from core.permissions import has_permission
from core.group_access import allowed_host_ids_for_action

bp = Blueprint('notifications', __name__)
log = logging.getLogger(__name__)
CATEGORIES = ('approvals', 'tasks', 'software', 'scheduler', 'reports', 'fleet', 'newsletter', 'system')
TERMINAL = {'Success', 'Error', 'Cancelled', 'ResultUnknown', 'Timeout', 'Expired'}
WATCH = {Endpoint: ('host', ('approval_status', 'identity_warning')),
    TaskTemplate: ('template', ('is_approved', 'approved_content_hash', 'payload')),
    SoftwarePackage: ('package', ('record',)), AgentTask: ('task', ('status', 'outcome')),
    SoftwareDeployment: ('deployment', ('status',)), ScheduleRun: ('schedule', ('status',)),
    AggregatedJob: ('report', ('status',)), AgentUpdateRollout: ('fleet', ('status',)),
    NewsletterCampaign: ('newsletter', ('status',))}
WATCH.update({EndpointIdentityConflict: ('identity', ('status',)), ReportDelivery: ('delivery', ('status',)),
              AiReportRequest: ('ai_report', ('status',)), AuditLog: ('system', ('status',))})
MODELS = {v[0]: k for k, v in WATCH.items()}


def _collect(orm, *_):
    changed = orm.info.setdefault('notification_changes', [])
    for obj in set(orm.new) | set(orm.dirty):
        spec = WATCH.get(type(obj))
        if spec and (obj in orm.new or any(inspect(obj).attrs[name].history.has_changes() for name in spec[1])):
            changed.append((obj, spec[0]))


def _store_signals(orm, *_):
    # SQL INSERT shares the domain transaction; rollback removes both.
    for obj, kind in orm.info.pop('notification_changes', []):
        if obj in orm.deleted or not obj.id:
            continue
        state = str(getattr(obj, 'status', '') or getattr(obj, 'approval_status', '') or '')
        if kind == 'task' and state not in TERMINAL:
            continue
        if kind == 'system' and (obj.module != 'System' or state not in ('Error', 'Critical')):
            continue
        orm.connection().execute(NotificationSignal.__table__.insert().values(
            id=str(uuid.uuid4()), kind=kind, source_id=str(obj.id), state=state[:100], created_at=datetime.utcnow()))


def install_listeners():
    if not event.contains(Session, 'before_flush', _collect):
        event.listen(Session, 'before_flush', _collect)
        event.listen(Session, 'after_flush_postexec', _store_signals)
        event.listen(Session, 'do_orm_execute', _bulk_task_update)
        if not event.contains(Session, 'after_rollback', _clear_changes):
            event.listen(Session, 'after_rollback', _clear_changes)


def _clear_changes(orm):
    orm.info.pop('notification_changes', None)


def _bulk_task_update(state):
    """Bulk cancellation/finalization bypasses ORM flush listeners."""
    if not state.is_update or not state.bind_mapper or state.bind_mapper.class_ is not AgentTask:
        return
    values = getattr(state.statement, '_values', {}) or {}
    new_status = next((getattr(value, 'value', None) for key, value in values.items()
                       if getattr(key, 'key', key) == 'status'), None)
    if new_status not in TERMINAL:
        return
    state.session.flush()
    connection = state.session.connection()
    ids = connection.execute(select(AgentTask.id).where(*state.statement._where_criteria), state.parameters or {}).scalars().all()
    result = state.invoke_statement()
    if ids:
        connection.execute(NotificationSignal.__table__.insert(), [dict(id=str(uuid.uuid4()), kind='task',
            source_id=task_id, state=new_status, created_at=datetime.utcnow()) for task_id in ids])
    return result


def settings(user_id):
    row = db.session.get(NotificationPreference, user_id)
    value = dict(toasts=True, push_categories=list(CATEGORIES), errors_only=False,
                 quiet_start=None, quiet_end=None)
    value.update(json.loads(row.settings if row else '{}'))
    return value


def lightweight(model):
    # Inboxes must not decrypt task scripts, credentials and result logs on every poll.
    return db.session.query(model).options(*(defer(getattr(model, c.name)) for c in model.__table__.columns
        if isinstance(c.type, EncryptedText) and not (model is SoftwarePackage and c.name == 'record')))


def source(row):
    if row.kind == 'job':
        return lightweight(AgentTask).filter_by(job_id=row.source_id).all()
    model = MODELS.get(row.kind)
    return lightweight(model).filter_by(id=row.source_id).first() if model else None


def permitted(user, row, obj=None):
    if not user or not user.is_active:
        return False
    if row.event_key.startswith('watch:'):
        parts = row.event_key.split(':', 2)
        if not user.is_admin or len(parts) != 3:
            return False
        if row.category not in settings(user.id).get('watch_users', {}).get(parts[1], []):
            return False
    obj = source(row) if obj is None else obj
    if not obj:
        return False
    if row.category == 'approvals':
        return bool(user.is_admin)
    if row.category == 'system':
        return bool(user.is_admin)
    if row.kind == 'template':
        return has_permission(user, 'Infrastructure', 'manage_templates') and (user.is_admin or obj.created_by == user.username)
    action = {'tasks': 'view_queue', 'software': 'manage_software', 'scheduler': 'manage_scheduler',
              'reports': 'view_reports', 'fleet': 'manage_hosts'}.get(row.category)
    if row.category == 'newsletter':
        return has_permission(user, 'Newsletter', 'view_newsletter') and (user.is_admin or obj.user_id == user.id)
    if row.kind == 'package':
        return has_permission(user, 'Infrastructure', 'manage_software')
    if not action or not has_permission(user, 'Infrastructure', action):
        return False
    targets = []
    if row.kind == 'job':
        targets = [t.endpoint_id for t in obj]
    elif row.kind == 'deployment':
        targets = [s.endpoint_id for s in SoftwareStep.query.filter_by(deployment_id=obj.id)]
    elif row.kind == 'fleet':
        targets = json.loads(obj.target_ids or '[]')
    elif row.kind in ('schedule', 'report', 'delivery', 'ai_report'):
        job_id = obj.job_id if row.kind in ('schedule', 'ai_report') else obj.report_id if row.kind == 'delivery' else obj.id
        targets = [t.endpoint_id for t in AgentTask.query.filter_by(job_id=job_id)]
    if user.is_admin:
        return True
    if row.kind in ('job', 'deployment', 'report', 'fleet') and not targets:
        return False
    return not targets or (None not in targets and set(targets).issubset(allowed_host_ids_for_action(user, action)))


def descriptor(signal):
    obj = source(signal)
    if not obj:
        return None
    kind, source_id = signal.kind, signal.source_id
    state = getattr(obj, 'status', '')
    owner = getattr(obj, 'actor_user_id', None) or getattr(obj, 'user_id', None)
    if not owner:
        author = getattr(obj, 'created_by', None)
        owner_row = User.query.filter_by(username=author).first() if author else None
        owner = owner_row.id if owner_row else None
    category, severity, title, revision, admin = kind, 'info', '', state, False
    if kind == 'host':
        if obj.approval_status != 'Pending' and not obj.identity_warning:
            return None
        category, severity, admin = 'approvals', 'warning', True
        title = ('Host requires identity review: ' if obj.identity_warning else 'Host awaiting approval: ') + str(obj.display_name or obj.hostname or obj.id)
        revision = obj.identity_warning or 'Pending'
    elif kind == 'identity':
        if state != 'Open':
            return None
        category, severity, admin, title = 'approvals', 'warning', True, 'Agent identity conflict requires review'
    elif kind == 'system':
        if obj.module != 'System' or state not in ('Error', 'Critical'):
            return None
        category, severity, admin, title = 'system', 'error', True, 'System operation requires attention'
    elif kind == 'template':
        from core.template_security import template_approval_valid, current_template_hash
        if template_approval_valid(obj):
            category, severity, title = 'tasks', 'success', 'Template approved: ' + obj.name
            revision = 'approved:' + current_template_hash(obj)
        else:
            category, severity, admin, title = 'approvals', 'warning', True, 'Template awaiting approval: ' + obj.name
            revision = current_template_hash(obj)
    elif kind == 'package':
        from core.software import recipe_hash
        data = json.loads(obj.record)
        actor = User.query.filter_by(username=data.get('created_by') or data.get('updated_by')).first()
        owner = actor.id if actor else None
        if data.get('kind') != 'installer' and data.get('approved_hash') != recipe_hash(data):
            category, severity, admin, title = 'approvals', 'warning', True, 'Software recipe awaiting approval: ' + str(data.get('name', 'Software'))
            revision = recipe_hash(data)
        elif data.get('kind') != 'installer' and data.get('approved_hash') == recipe_hash(data):
            category, severity, title, revision = 'software', 'success', 'Software recipe approved', 'approved:' + recipe_hash(data)
        elif data.get('preparation') in ('Ready', 'Failed'):
            category = 'software'
            severity = 'success' if data['preparation'] == 'Ready' else 'error'
            title = 'Installer ready' if severity == 'success' else 'Installer preparation failed'
            revision = str(data.get('preparation_id', '')) + data['preparation']
        else:
            return None
    elif kind == 'task':
        if obj.action_type == 'software' or obj.schedule_run_id or not obj.job_id or db.session.get(SoftwareDeployment, obj.job_id):
            return None
        tasks = lightweight(AgentTask).filter_by(job_id=obj.job_id).all()
        if not tasks or any(t.status not in TERMINAL for t in tasks):
            return None
        good = sum(t.status == 'Success' for t in tasks)
        unknown = any(t.outcome == 'ResultUnknown' or t.status == 'ResultUnknown' for t in tasks)
        category, kind, source_id, revision = 'tasks', 'job', obj.job_id, 'complete'
        severity = 'warning' if unknown or all(t.status == 'Cancelled' for t in tasks) else 'success' if good == len(tasks) else 'error'
        title = (f'Task completed: {good}/{len(tasks)} successful' if not unknown else 'Task result requires verification') + ' — ' + str(obj.title or 'Task')
    elif kind == 'deployment':
        if state in ('Running', 'Paused', 'Cancelling'):
            return None
        category, title = 'software', f'Software deployment: {state}'
    elif kind == 'schedule':
        if not obj.finished_at:
            return None
        category, title = 'scheduler', f'{obj.name}: {state}'
    elif kind == 'report':
        if state != 'Waiting Review':
            return None
        category, title = 'reports', 'Report ready for review'
    elif kind in ('delivery', 'ai_report'):
        if state not in ('Success', 'Sent', 'Completed', 'Ready', 'Error', 'Failed', 'Cancelled'):
            return None
        category, title = 'reports', f'{"Report delivery" if kind == "delivery" else "AI report"}: {state}'
        severity = 'success' if state in ('Success', 'Sent', 'Completed', 'Ready') else 'error'
    elif kind == 'fleet':
        if state in ('Running', 'Paused', 'Pending'):
            return None
        category, title = 'fleet', f'Agent rollout: {state}'
    elif kind == 'newsletter':
        if not obj.ended_at:
            return None
        category, title = 'newsletter', f'Mailing: {state}'
    else:
        return None
    if kind in ('deployment', 'schedule', 'fleet', 'newsletter'):
        severity = 'success' if state in ('Success', 'Completed', 'Sent') else 'warning' if state in ('Warning', 'Cancelled', 'ResultUnknown', 'RebootRequired') else 'error'
    if kind == 'fleet' and state == 'Completed':
        severity, title = 'info', 'Agent rollout scheduling finished — check host results'
    key = hashlib.sha256(f'{kind}:{source_id}:{revision}'.encode()).hexdigest()
    return dict(kind=kind, source_id=source_id, category=category, severity=severity, title=title,
                event_key=key), owner, admin


def process_signals(limit=100):
    for signal in NotificationSignal.query.order_by(NotificationSignal.created_at).limit(limit).with_for_update(skip_locked=True).all():
        try:
            info = descriptor(signal)
        except (ValueError, TypeError, AttributeError):
            # A malformed legacy source must not stall every other user's inbox.
            log.warning('Ignoring invalid notification source kind=%s signal=%s', signal.kind, signal.id)
            db.session.delete(signal)
            continue
        if info:
            data, owner, admin = info
            users = User.query.filter_by(is_active=True, is_admin=True).all() if admin else ([db.session.get(User, owner)] if owner else [])
            watched = set()
            if owner and not admin:
                for watcher in User.query.filter_by(is_active=True, is_admin=True):
                    if watcher.id != owner and data['category'] in settings(watcher.id).get('watch_users', {}).get(str(owner), []):
                        users.append(watcher)
                        watched.add(watcher.id)
            for user in users:
                recipient_data = dict(data)
                if user and user.id in watched:
                    author = db.session.get(User, owner)
                    recipient_data['title'] = f'{author.username}: {data["title"]}'
                    recipient_data['event_key'] = f'watch:{owner}:{data["event_key"]}'
                candidate = Notification(user_id=user.id, **recipient_data) if user else None
                if not candidate or not permitted(user, candidate):
                    continue
                if Notification.query.filter_by(user_id=user.id, event_key=candidate.event_key).first():
                    continue
                db.session.add(candidate)
                db.session.flush()
                for device in PushSubscription.query.filter_by(user_id=user.id, active=True):
                    db.session.add(PushDelivery(notification_id=candidate.id, subscription_id=device.id))
        db.session.delete(signal)
    db.session.commit()


def current_user():
    if not session.get('logged_in') or session.get('api_key_auth'):
        abort(403)
    user = db.session.get(User, session.get('user_id'))
    if not user or not user.is_active:
        abort(403)
    return user


def json_body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        abort(400)
    return value


def visible_rows(user):
    # Retention bounds inbox work. Recheck permissions, including old notifications.
    rows = Notification.query.filter_by(user_id=user.id, dismissed_at=None).filter(
        Notification.created_at >= datetime.utcnow() - timedelta(days=90)).order_by(Notification.created_at.desc()).limit(500).all()
    grouped = {}
    for row in rows:
        grouped.setdefault(row.kind, set()).add(row.source_id)
    sources = {}
    for kind, ids in grouped.items():
        if kind == 'job':
            for task in lightweight(AgentTask).filter(AgentTask.job_id.in_(ids)):
                sources.setdefault((kind,task.job_id),[]).append(task)
        elif kind in MODELS:
            for obj in lightweight(MODELS[kind]).filter(MODELS[kind].id.in_(ids)):
                sources[kind,str(obj.id)] = obj
    return [r for r in rows if (r.kind,r.source_id) in sources and permitted(user, r, sources[r.kind,r.source_id])]


def serialize(row):
    resolved = False
    if row.category == 'approvals':
        obj = source(row)
        if row.kind == 'host':
            resolved = obj.approval_status != 'Pending' and not obj.identity_warning
        elif row.kind == 'identity':
            resolved = obj.status != 'Open'
        elif row.kind == 'template':
            from core.template_security import template_approval_valid
            resolved = template_approval_valid(obj)
        elif row.kind == 'package':
            from core.software import recipe_hash
            record = json.loads(obj.record)
            resolved = record.get('approved_hash') == recipe_hash(record)
    return dict(id=row.id, category=row.category, severity=row.severity, title=row.title,
        created_at=row.created_at.isoformat() + 'Z', read=bool(row.read_at), resolved=bool(resolved), url='/notifications/' + row.id)


@bp.get('/api/notifications')
def inbox():
    user = current_user()
    rows = visible_rows(user)
    return jsonify(items=[serialize(r) for r in rows], unread=sum(not r.read_at for r in rows), settings=settings(user.id))


@bp.post('/api/notifications/read')
@bp.post('/api/notifications/clear')
def mark():
    user = current_user()
    data = json_body()
    ids = data.get('ids')
    if ids is not None and (not isinstance(ids, list) or len(ids) > 500 or any(not isinstance(x, str) for x in ids)):
        abort(400)
    for row in visible_rows(user):
        if ids is None or row.id in ids:
            if request.path.endswith('/clear'):
                if data.get('read_only') and not row.read_at:
                    continue
                row.dismissed_at = datetime.utcnow()
            else:
                row.read_at = datetime.utcnow()
    db.session.commit()
    return jsonify(success=True)


@bp.route('/api/notifications/preferences', methods=['GET', 'PUT'])
def preferences():
    user = current_user()
    if request.method == 'PUT':
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) - {'toasts', 'push_categories', 'errors_only', 'quiet_start', 'quiet_end'}:
            abort(400)
        for key in ('toasts', 'errors_only'):
            if key in data and not isinstance(data[key], bool):
                abort(400)
        if 'push_categories' in data and (not isinstance(data['push_categories'], list) or any(x not in CATEGORIES for x in data['push_categories'])):
            abort(400)
        for key in ('quiet_start', 'quiet_end'):
            if key in data and data[key] is not None and (type(data[key]) is not int or not 0 <= data[key] <= 23):
                abort(400)
        row = db.session.get(NotificationPreference, user.id) or NotificationPreference(user_id=user.id)
        value = settings(user.id); value.update(data)
        row.settings = json.dumps(value); db.session.add(row); db.session.commit()
    return jsonify(settings=settings(user.id))


@bp.route('/api/notifications/watch-users', methods=['GET', 'PUT'])
def watch_users():
    user = current_user()
    if not user.is_admin:
        abort(403)
    if request.method == 'PUT':
        value = json_body().get('watch_users')
        if not isinstance(value, dict) or len(value) > 100:
            abort(400)
        for key, categories in value.items():
            if not key.isdecimal() or str(int(key)) != key or int(key) == user.id:
                abort(400)
            target = db.session.get(User, int(key))
            if not target or not target.is_active or not isinstance(categories, list) or any(c not in CATEGORIES for c in categories):
                abort(400)
        row = db.session.get(NotificationPreference, user.id) or NotificationPreference(user_id=user.id)
        prefs = settings(user.id); prefs['watch_users'] = value
        row.settings = json.dumps(prefs); db.session.add(row); db.session.commit()
    return jsonify(users=[dict(id=u.id, username=u.username) for u in User.query.filter_by(is_active=True).order_by(User.username) if u.id != user.id],
                   watch_users=settings(user.id).get('watch_users', {}))


@bp.get('/notifications/<notification_id>')
def detail(notification_id):
    user = current_user()
    row = db.session.get(Notification, notification_id)
    if not row or row.user_id != user.id or not permitted(user, row):
        abort(404)
    obj = source(row)
    name, body, target = '', '', '/module/infrastructure'
    review_code, review_revision = '', ''
    if row.kind == 'job':
        name = obj[0].title
        body = '\n'.join(f'{t.endpoint_name_snapshot or t.endpoint_hostname_snapshot or t.endpoint_id}: {t.outcome or t.status}' for t in obj)
        target += '?view=queue&queueType=ALL&queueStatus=ALL&queueUser=&queueContent=&queueDateFrom=&queueDateTo=&queueSearch=' + quote(row.source_id)
    elif row.kind == 'package':
        data = json.loads(obj.record); name = data.get('name', 'Software')
        body = 'Preparation: ' + str(data.get('preparation', 'Unknown'))
        target += '?view=software&notification_package=' + quote(row.source_id)
        if user.is_admin and row.category == 'approvals':
            from core.software import recipe_hash
            review_code = json.dumps({k:v for k,v in data.items() if k in ('name','version','blob_sha256','package_type','architecture','install_command','update_command','uninstall_command','detection_type','detection_value','expected_exit_codes','timeout_seconds','install_template_id','update_template_id','uninstall_template_id','update_requires_installer')}, indent=2, ensure_ascii=False)
            if data.get('approved_hash') != recipe_hash(data):
                review_revision = recipe_hash(data)
            else:
                body += '\nAlready approved.'
    elif row.kind == 'host':
        name = obj.display_name or obj.hostname or obj.id
        body = 'Approval: ' + obj.approval_status
        target += '?view=hosts&nodeTab=review&reviewTab=' + ('conflicts' if row.kind == 'identity' else 'duplicates' if getattr(obj, 'identity_warning', None) else 'pending')
        if user.is_admin and host_reviewable(obj):
            body += '\nOS: ' + str(obj.os_version or '') + '\nAddress: ' + str(obj.connection_ip or '') + '\nBlocked: ' + str(bool(obj.is_blocked))
            review_revision = host_revision(obj)
    elif row.kind == 'identity':
        name = 'Agent identity conflict'
        body = 'Status: ' + obj.status + '\n' + obj.reason
        target += '?view=hosts&nodeTab=review&reviewTab=' + ('conflicts' if row.kind == 'identity' else 'duplicates' if getattr(obj, 'identity_warning', None) else 'pending')
    elif row.kind == 'system':
        name = obj.action; body = 'A system operation failed. Review the audit history for details.'
        target = '/module/history'
    elif row.kind == 'template':
        name = obj.name; body = 'Review the current code and parameters before approving.'
        target += '?view=deploy&notification_template=' + quote(row.source_id)
        from core.template_security import current_template_hash, template_approval_valid
        if user.is_admin:
            review_code = obj.payload
            if not template_approval_valid(obj):
                review_revision = current_template_hash(obj)
            else:
                body = 'Already approved.'
    else:
        name = getattr(obj, 'name', None) or getattr(obj, 'title', None) or row.title
        body = 'Current status: ' + str(getattr(obj, 'status', ''))
        if row.kind == 'fleet':
            body += '\nRollout status describes wave scheduling. Check Fleet Center and task results to confirm each installed agent version.'
        target += '?view=' + {'deployment':'software','schedule':'scheduler','report':'reports','delivery':'reports','ai_report':'reports','fleet':'hosts'}.get(row.kind, 'queue')
        if row.kind == 'newsletter':
            target = '/module/newsletter'
    target += ('&' if '?' in target else '?') + 'notification=1'
    return render_template('notification_detail.html', notification=row, source_name=name, source_body=body,
                           source_url=target, review_code=review_code, review_revision=review_revision)


def host_revision(obj):
    return hashlib.sha256(json.dumps([obj.id, obj.public_key_pem_plain or obj.public_key_pem, obj.identity_fingerprint,
        obj.approval_status, obj.identity_warning, obj.connection_ip, obj.hostname, obj.os_version]).encode()).hexdigest()


def host_reviewable(obj):
    return (obj.approval_status == 'Pending' and not obj.identity_warning
            and not EndpointIdentityConflict.query.filter_by(endpoint_id=obj.id, status='Open').first())


@bp.post('/api/notifications/<notification_id>/approve')
def approve(notification_id):
    user = current_user()
    row = db.session.get(Notification, notification_id)
    if not user.is_admin or not row or row.user_id != user.id or row.category != 'approvals' or not permitted(user, row):
        abort(403)
    data = json_body()
    if row.kind == 'package':
        # Reuse the existing software lock, preparation checks, hash and audit.
        from modules.Infrastructure.software import approve_package
        package_id = row.source_id
        db.session.expire_all()
        return approve_package(package_id)
    obj = db.session.query(MODELS[row.kind]).filter_by(id=row.source_id).populate_existing().with_for_update().first()
    if not obj:
        abort(404)
    if row.kind == 'host':
        if data.get('revision') != host_revision(obj) or not host_reviewable(obj):
            return jsonify(message='Host changed or already reviewed. Refresh before approving.'), 409
        if data.get('status') != 'Approved':
            abort(400)
        from modules.Infrastructure.routes import update_host_approval
        return update_host_approval(obj.id)
    if row.kind == 'template':
        from core.template_security import current_template_hash, template_approval_valid
        from modules.Infrastructure.routes import validate_report_template_payload, ai_template_validation_valid
        if data.get('revision') != current_template_hash(obj) or template_approval_valid(obj):
            return jsonify(message='Template changed or already approved. Refresh before approving.'), 409
        payload = json.loads(obj.payload or '{}')
        if not isinstance(payload, dict):
            return jsonify(message='Invalid template payload. Review it in Workspace.'), 400
        try:
            validate_report_template_payload(obj.type, payload)
            if payload.get('__ai_generated') and not ai_template_validation_valid(payload):
                return jsonify(message='Validate this AI template in Workspace before approval.'), 400
        except Exception:
            return jsonify(message='Template validation failed. Review it in Workspace.'), 400
        obj.is_approved = True; obj.approved_content_hash = current_template_hash(obj)
        obj.approved_at = datetime.utcnow(); obj.approved_by = user.username
        from core.sdk import WinHubCore
        WinHubCore.audit(user_id=user.id, module='Infrastructure', action='Template Approval',
                         details={'template_id':obj.id,'revision':obj.approved_content_hash}, status='Success')
        db.session.commit()
        return jsonify(success=True, message='Template approved.')
    abort(400)


def start_worker(app):
    """Dedicated thread: never use the agent task executor or scheduler pool."""
    if app.extensions.get('notification_worker'):
        return
    def work(push_only=False):
        import time
        from core.notification_push import deliver_pending
        last_cleanup = 0
        while True:
            with app.app_context():
                try:
                    if push_only:
                        deliver_pending()
                    else:
                        process_signals()
                    if not push_only and time.monotonic() - last_cleanup > 3600:
                        cleanup()
                        last_cleanup = time.monotonic()
                except Exception:
                    db.session.rollback()
                    log.exception('Notification worker iteration failed')
                finally:
                    db.session.remove()
            time.sleep(5)
    thread = threading.Thread(target=work, name='winhub-notifications', daemon=True)
    app.extensions['notification_worker'] = thread
    thread.start()
    threading.Thread(target=work, args=(True,), name='winhub-web-push', daemon=True).start()


def cleanup():
    cutoff = datetime.utcnow() - timedelta(days=90)
    old_ids = db.session.query(Notification.id).filter(Notification.created_at < cutoff)
    PushDelivery.query.filter(PushDelivery.notification_id.in_(old_ids)).delete(synchronize_session=False)
    Notification.query.filter(Notification.created_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
