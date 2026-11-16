"""Editable re-runs use current template authorization and fixed historical targets."""
import json
import re

from flask import jsonify, request, session

from core.database import AgentTask, Endpoint, TaskTemplate, db
from core.sdk import WinHubCore
from core.sensitive_data import is_sensitive_name, mask_sensitive_text
from core.template_security import current_template_hash


def fields_for(template):
    from .routes import load_template_payload, template_variable_schema, VARIABLE_PATTERN
    payload = load_template_payload(template)
    schema = template_variable_schema(payload)
    names = list(schema)
    for key, value in payload.items():
        if isinstance(value, str) and not str(key).startswith('__'):
            names.extend(VARIABLE_PATTERN.findall(value))
    names = list(dict.fromkeys(names))
    fields = []
    for name in names:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(name)):
            continue
        spec = schema.get(name)
        spec = dict(spec) if isinstance(spec, dict) else {'type':'text', 'label':str(spec or name)}
        fields.append((name, spec))
    return sorted(fields, key=lambda field: field[1].get('order') if isinstance(field[1].get('order'), (float, int)) else float('inf'))


def launch_snapshot(template, variables, timeout_minutes=0, **metadata):
    names = {name for name, spec in fields_for(template)}
    snapshot = dict(version=1, template_hash=current_template_hash(template),
        variables={key:value for key,value in variables.items() if key in names}, timeout_minutes=timeout_minutes, **metadata)
    if len(json.dumps(snapshot, ensure_ascii=False).encode('utf-8')) > 65536:
        raise ValueError('Task input snapshot exceeds 64 KiB')
    return snapshot


def read_snapshot(task):
    try:
        value = json.loads(task.launch_context or '{}')
        return value if isinstance(value, dict) and value.get('version') == 1 else {}
    except (TypeError, ValueError):
        return {}


def protected_field(name, spec, value):
    return (is_sensitive_name(name) or str(spec.get('type','')).lower() in ('password','secret') or bool(spec.get('sensitive'))
        or isinstance(value, str) and mask_sensitive_text(value) != value)


def register(bp):
    def execute(job_id=None, task_id=None):
        from . import routes
        for permission in ('view_queue','run_tasks'):
            denied = routes.require_permission(permission)
            if denied:
                return denied
        if session.get('api_key_auth'):
            return jsonify(success=False, message='Use an interactive session to edit and re-run a task'), 403
        query = AgentTask.query.filter_by(id=task_id) if task_id else AgentTask.query.filter_by(job_id=job_id)
        tasks = query.order_by(AgentTask.created_at, AgentTask.id).all()
        if not tasks:
            return jsonify(success=False, message='Original task not found'), 404
        # Never shrink a group silently: every original endpoint must still exist and be authorized.
        targets = list(dict.fromkeys(task.endpoint_id_snapshot or task.endpoint_id for task in tasks))
        if None in targets:
            return jsonify(success=False, message='An original target no longer exists'), 409
        if request.method == 'POST':
            # Keep endpoint deletion from shrinking the selection during dispatch.
            Endpoint.query.filter(Endpoint.id.in_(targets)).order_by(Endpoint.id).with_for_update().all()
        for permission in ('view_queue','run_tasks'):
            allowed = WinHubCore.authorized_target_ids(session.get('user_id'), targets, permission)
            if set(targets) != set(allowed):
                return jsonify(success=False, message='An original target is missing or outside your current permissions. No tasks were created.'), 403
        if any(task.status not in ('Success','Error','Cancelled') or task.outcome == 'ResultUnknown' for task in tasks):
            return jsonify(success=False, message='The original execution is active or unresolved. Wait for completion or resolve its unknown result first.'), 409
        template_ids = {task.template_id for task in tasks}
        if len(template_ids) != 1 or not tasks[0].template_id:
            return jsonify(success=False, message='This task has no single source template. Open Deployment Builder to create a new task.'), 409
        template = db.session.get(TaskTemplate, tasks[0].template_id)
        if not template:
            return jsonify(success=False, message='The source template was deleted'), 409
        if not routes.can_run_template(template):
            return jsonify(success=False, message=routes.template_run_denial_message(template)), 403
        if any(task.action_type == 'software' or task.module_source == 'Software' for task in tasks):
            return jsonify(success=False, message='Re-run software installations from Software deployment'), 409
        snapshots = [read_snapshot(task) for task in tasks]
        saved = snapshots[0]
        if any(snapshot != saved for snapshot in snapshots[1:]):
            return jsonify(success=False, message='This job has different input snapshots. Re-run its individual host tasks.'), 409
        values = saved.get('variables') or {}
        fields = fields_for(template)
        template_hash = current_template_hash(template)
        can_reuse_secrets = (routes.is_interactive_superadmin() or all(task.actor_user_id == session.get('user_id') for task in tasks)
            or all(routes.can_view_sensitive_reports(host_id=host_id) for host_id in targets))
        if request.method == 'GET':
            schema = []
            for name, spec in fields:
                value = values.get(name, spec.get('default',''))
                secret = protected_field(name, spec, value)
                safe_spec = {key:value for key,value in spec.items() if key not in ('default','value')}
                schema.append(dict(name=name, spec=safe_spec, value='' if secret else value, secret=secret,
                    has_saved=bool(secret and name in values and can_reuse_secrets)))
            return jsonify(success=True, template=dict(id=template.id, name=template.name, hash=template_hash),
                fields=schema, saved_parameters=bool(saved), template_changed=bool(saved and saved.get('template_hash') != template_hash),
                original_code_edited=bool(saved.get('script_overridden')),
                timeout_minutes=saved.get('timeout_minutes',0),
                targets=[dict(id=target, name=next((task.endpoint_name_snapshot or task.endpoint_hostname_snapshot or target
                    for task in tasks if (task.endpoint_id_snapshot or task.endpoint_id) == target), target)) for target in targets],
                target_kind=saved.get('target_kind','hosts'), group_name=saved.get('group_name'),
                launch_reason=mask_sensitive_text(tasks[0].launch_reason or ''))
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get('template_hash') != template_hash:
            return jsonify(success=False, message='The template changed. Reopen Re-run to review its current fields.'), 409
        supplied, keep = data.get('variables',{}), data.get('keep_secrets',[])
        names = {name for name, spec in fields}
        if not isinstance(supplied, dict) or not isinstance(keep, list) or any(not isinstance(name,str) for name in keep) or (set(supplied) | set(keep)) - names:
            return jsonify(success=False, message='Parameters must match the current template fields'), 400
        variables = dict(supplied)
        for name in keep:
            spec = dict(fields)[name]
            if not can_reuse_secrets or name not in values or not protected_field(name,spec,values[name]):
                return jsonify(success=False, message='A saved secret is unavailable. Enter its value explicitly.'), 403
            if name in supplied:
                return jsonify(success=False, message='Choose either a replacement value or the saved secret'), 400
            variables[name] = values[name]
        prepared = dict(action='run_template', template_id=template.id, template_type=template.type, title=template.name,
            target_type='hosts', target_ids=targets, variables=variables, launch_reason=data.get('launch_reason'),
            timeout_minutes=data.get('timeout_minutes',saved.get('timeout_minutes',0)))
        result = routes.create_task(data_override=prepared, rerun_parent=tasks[0].job_id or tasks[0].id)
        return result

    @bp.route('/api/infrastructure/job/<job_id>/rerun', methods=['GET','POST'])
    def rerun_job(job_id):
        return execute(job_id=job_id)

    @bp.route('/api/infrastructure/task/<task_id>/rerun', methods=['GET','POST'])
    def rerun_task(task_id):
        return execute(task_id=task_id)
