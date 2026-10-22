"""Software UI API. Package source credentials never leave the server."""
import hashlib
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from sqlalchemy.orm import defer
from sqlalchemy import func

from flask import Response, current_app, jsonify, request, session, stream_with_context
from core import software as service
from core.database import (db, AgentTask, Endpoint, EndpointGroup, SoftwareDeployment,
                           SoftwarePackage, SoftwareStep, TaskTemplate)
from core.template_security import template_approval_valid
from core.group_access import group_action_allowed
from core.permissions import has_permission
from core.sdk import WinHubCore
from core.task_reason import validate_launch_reason


def helpers():
    from modules.Infrastructure import routes
    return routes


def interactive(permission):
    denied = helpers().require_permission(permission)
    if denied:
        return denied
    if session.get('api_key_auth'):
        return jsonify(success=False, message='Software доступний лише через інтерактивну сесію.'), 403


def registry():
    denied = helpers().require_any_permission('run_tasks', 'manage_software')
    if denied:
        return denied
    if session.get('api_key_auth'):
        return jsonify(success=False, message='Software API keys не підтримуються.'), 403
    with service.LOCAL_LOCK:
        control = service.lock_control()
        service.import_legacy(control)
        db.session.commit()
    user = helpers().current_user()
    manager = has_permission(user, 'Infrastructure', 'manage_software')
    packages = [service.public_package(p, manager) for p in service.catalogue()]
    packages.sort(key=lambda p: (p.get('order', 100), p['name'].casefold(), p['id']))
    allowed = WinHubCore.get_allowed_hosts(user.id, 'run_tasks')
    hosts = [dict(id=h.id, name=h.display_name or h.hostname or h.id, os_type=h.os_type,
                  groups=[g.id for g in h.groups]) for h in allowed
             if h.approval_status == 'Approved' and not h.is_blocked]
    cfg = service.settings()
    if not user.is_admin:
        cfg.pop('source_origin', None)
        cfg.pop('ca_bundle', None)
    groups = [dict(id=g.id, name=g.name) for g in EndpointGroup.query.order_by(EndpointGroup.name).all()
              if group_action_allowed(user, g.id, 'run_tasks')]
    templates = []
    if manager:
        for template in TaskTemplate.query.filter_by(type='action', action_type='run_script', is_approved=True).all():
            try:
                payload = json.loads(template.payload or '{}')
            except (TypeError, ValueError):
                continue
            if (template_approval_valid(template) and isinstance(payload, dict) and isinstance(payload.get('script'), str)
                    and not payload.get('variables_schema') and not payload.get('__ai_generated')
                    and '{{' not in payload['script'] and '{%' not in payload['script']):
                templates.append(dict(id=template.id, name=template.name, category=template.category))
    return jsonify(success=True, packages=packages, hosts=hosts, groups=groups, settings=cfg,
                   templates=templates,
                   can_view_queue=has_permission(user, 'Infrastructure', 'view_queue'))


def package_write(package_id=None):
    denied = interactive('manage_software')
    if denied:
        return denied
    with service.LOCAL_LOCK:
        control = service.lock_control()
        service.import_legacy(control)
        if request.method == 'DELETE':
            row = db.session.get(SoftwarePackage, package_id)
            if not row:
                return jsonify(success=False, message='Програму не знайдено.'), 404
            db.session.delete(row)
            # Immutable blobs are retained: active deployments/history may reference them.
            helpers().write_infra_audit('Software Delete', 'software_package', package_id, {})
            db.session.commit()
            return jsonify(success=True)
        if package_id and not db.session.get(SoftwarePackage, package_id):
            return jsonify(success=False, message='Програму не знайдено.'), 404
        package_id = package_id or str(uuid.uuid4())
        try:
            record = service.save_package(package_id, request.form, request.files.get('file'), helpers().current_user())
        except PermissionError as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)), 403
        except ValueError as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)), 400
        except OSError:
            db.session.rollback()
            return jsonify(success=False, message='Не вдалося підготувати пакет. Перевірте поля, доступ до OMV, SHA-256, HTTPS і ліміти.'), 400
        helpers().write_infra_audit('Software Save', 'software_package', package_id,
                                   dict(name=record['name'], version=record['version'], sha256=record.get('sha256')))
        db.session.commit()
        return jsonify(success=True, package=service.public_package(record, True))


def create_deployment():
    denied = interactive('run_tasks')
    if denied:
        return denied
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict):
            raise ValueError('Очікується JSON-об’єкт.')
        reason = validate_launch_reason(data.get('launch_reason'))
        operation = data.get('operation', 'install')
        if operation not in ('install', 'update', 'uninstall', 'detect'):
            raise ValueError('Невідома дія Software.')
        def array(key):
            value = data.get(key, [])
            if not isinstance(value, list) or len(value) > 1000 or any(not isinstance(x, str) for x in value):
                raise ValueError('Очікується список ідентифікаторів: ' + key)
            return list(dict.fromkeys(value))
        ids = array('package_ids')
        if not ids and data.get('package_id'):
            ids = [str(data['package_id'])]
        sets = array('sets')
        target_ids = set(array('target_ids'))
        groups = array('group_ids')
        if data.get('group_id'):
            groups.append(str(data['group_id']))
        for group_id in set(groups):
            group = db.session.get(EndpointGroup, group_id)
            if not group or not group_action_allowed(helpers().current_user(), group_id, 'run_tasks'):
                raise PermissionError('Немає доступу до однієї з вибраних груп.')
            target_ids.update(h.id for h in group.endpoints)
        if not target_ids or len(target_ids) > 1000:
            raise ValueError('Виберіть від 1 до 1000 хостів.')
        if 'expected_target_ids' in data and set(array('expected_target_ids')) != target_ids:
            raise ValueError('Склад груп змінився після попереднього перегляду. Оновіть цілі та повторіть підтвердження.')
        allowed = WinHubCore.authorized_target_ids(session['user_id'], target_ids)
        if target_ids - allowed:
            raise PermissionError('У виборі є хости без дозволу на запуск. Перегляньте цілі.')
        hosts = Endpoint.query.filter(Endpoint.id.in_(target_ids)).all()
        if any(h.is_blocked or h.approval_status != 'Approved' for h in hosts):
            raise PermissionError('У виборі є заблоковані або непогоджені хости.')
        if any((h.os_type or '').lower() != 'windows' for h in hosts):
            raise ValueError('Ці рецепти Software підтримують лише Windows. Виключіть Linux/macOS із цілей.')
        base_url = helpers().usable_agent_public_base_url() or request.url_root.rstrip('/')
        if urlsplit(base_url).scheme != 'https':
            raise ValueError('Для доставки ПЗ потрібен HTTPS WinHUB.')
        with service.LOCAL_LOCK:
            control = service.lock_control()
            service.import_legacy(control)
            packages = service.catalogue()
            known = {p['id'] for p in packages}
            if set(ids) - known:
                raise ValueError('Одна з програм більше не існує. Оновіть каталог.')
            if set(sets) - {s for p in packages for s in p.get('sets', [])}:
                raise ValueError('Набір більше не існує. Оновіть каталог.')
            chosen = [p for p in packages if p['id'] in ids or set(p.get('sets', [])) & set(sets)]
            chosen.sort(key=lambda p: (p.get('order', 100), p['name'].casefold(), p['id']))
            if 'expected_packages' in data:
                expected = data['expected_packages']
                actual = [dict(id=p['id'], revision=service.recipe_hash(p)) for p in chosen]
                if expected != actual:
                    raise ValueError('Склад набору або версія програми змінилися. Оновіть каталог і повторіть підтвердження.')
            if not chosen or len(chosen) > 100 or len(chosen) * len(hosts) > 10000:
                raise ValueError('Виберіть до 100 програм; не більше 10000 операцій за запуск.')
            if (SoftwareDeployment.query.filter(SoftwareDeployment.status.in_(('Running', 'Paused', 'Cancelling'))).count() >= 50
                    or SoftwareStep.query.filter(SoftwareStep.status.in_(('Queued', 'Active'))).count() + len(chosen) * len(hosts) > 20000):
                raise ValueError('Черга заповнена: до 50 активних розгортань і 20000 незавершених операцій. Дочекайтеся завершення або скасуйте зайве.')
            plans = []
            for package in chosen:
                if not service.public_package(package)['approved']:
                    raise ValueError('Спочатку superadmin має погодити рецепт: ' + package['name'])
                snapshot = dict(package)
                snapshot['resolved_script'] = service.resolve_recipe(package, operation)
                snapshot.setdefault('timeout_seconds', 1800)
                snapshot.setdefault('expected_exit_codes', '0,3010')
                if operation not in ('uninstall', 'detect') and snapshot.get('blob_sha256'):
                    if not service.blob_path(snapshot['blob_sha256']).is_file():
                        raise ValueError('Відсутній підготовлений файл: ' + package['name'])
                elif operation not in ('uninstall', 'detect') and snapshot.get('external_url'):
                    raise ValueError('Спочатку підготуйте пакет з OMV: ' + package['name'])
                snapshot.pop('external_url', None)
                snapshot.pop('approved_hash', None)
                plans.append(dict(package=snapshot, operation=operation, base_url=base_url))
            parallelism = int(data.get('parallelism', 2))
            if not 1 <= parallelism <= service.settings(control)['max_hosts']:
                raise ValueError('Кількість паралельних хостів перевищує глобальний ліміт.')
            deployment = SoftwareDeployment(id=str(uuid.uuid4()), actor_user_id=session['user_id'],
                                            created_by=helpers().current_actor_label(), launch_reason=reason,
                                            parallelism=parallelism, expires_at=datetime.utcnow() + timedelta(days=1))
            db.session.add(deployment)
            db.session.flush()
            for host in hosts:
                for position, plan in enumerate(plans):
                    db.session.add(SoftwareStep(deployment_id=deployment.id, endpoint_id=host.id, package_name=plan['package']['name'],
                                               position=position, snapshot=json.dumps(plan, ensure_ascii=False)))
            helpers().write_infra_audit('Software Deployment', 'software_deployment', deployment.id,
                                       dict(hosts=len(hosts), packages=[p['package']['id'] for p in plans], operation=operation))
            db.session.commit()
        return jsonify(success=True, job_id=deployment.id, targets=len(hosts), packages=len(plans),
                       tasks=len(hosts) * len(plans))
    except (ValueError, TypeError) as exc:
        db.session.rollback()
        return jsonify(success=False, message=str(exc)), 400
    except PermissionError as exc:
        db.session.rollback()
        return jsonify(success=False, message=str(exc)), 403


def register(bp):
    @bp.route('/api/infrastructure/software/settings', methods=['PUT'])
    def software_settings():
        denied = interactive('manage_software')
        if denied:
            return denied
        if not helpers().current_user().is_admin:
            return jsonify(success=False, message='Налаштування сховища доступні лише superadmin.'), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(success=False, message='Очікується JSON-об’єкт.'), 400
        try:
            with service.LOCAL_LOCK:
                control = service.lock_control()
                cfg = service.settings(control)
                for key, upper in dict(max_hosts=20, max_downloads=20, bandwidth_mib=1000, max_package_mib=16384).items():
                    if key in data:
                        value = int(data[key])
                        if not 1 <= value <= upper:
                            raise ValueError('Неприпустимий ліміт: ' + key)
                        cfg[key] = value
                if 'source_origin' in data:
                    origin = str(data['source_origin']).strip().rstrip('/')
                    parsed = urlsplit(origin)
                    if origin and (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                                   or parsed.path or parsed.query or parsed.fragment):
                        raise ValueError('Вкажіть лише HTTPS-адресу OMV з портом, без шляху.')
                    cfg['source_origin'] = origin
                if 'ca_bundle' in data:
                    cfg['ca_bundle'] = str(data['ca_bundle']).strip()[:1024]
                control.settings = json.dumps(cfg)
                helpers().write_infra_audit('Software Settings', 'software_control', '1',
                                           {k: cfg[k] for k in ('max_hosts', 'max_downloads', 'bandwidth_mib')})
                db.session.commit()
                return jsonify(success=True)
        except (ValueError, TypeError):
            db.session.rollback()
            return jsonify(success=False, message='Перевірте HTTPS-адресу та числові ліміти.'), 400

    @bp.route('/api/infrastructure/software/deployments', methods=['GET', 'POST'])
    def software_deployments():
        if request.method == 'POST':
            return create_deployment()
        denied = interactive('run_tasks')
        if denied:
            return denied
        user = helpers().current_user()
        query = SoftwareDeployment.query
        if not user.is_admin:
            query = query.filter_by(actor_user_id=user.id)
        allowed = WinHubCore.authorized_target_ids(user.id, [h.id for h in WinHubCore.get_allowed_hosts(user.id, 'run_tasks')])
        result = []
        for deployment in query.order_by(SoftwareDeployment.created_at.desc()).limit(20).all():
            try:
                page = max(0, min(100, int(request.args.get('page_' + deployment.id, '0'))))
            except ValueError:
                page = 0
            visible = SoftwareStep.query.filter_by(deployment_id=deployment.id).filter(SoftwareStep.endpoint_id.in_(allowed))
            counts = dict(visible.with_entities(SoftwareStep.status, func.count(SoftwareStep.id)).group_by(SoftwareStep.status).all())
            total = sum(counts.values())
            rows = visible.options(defer(SoftwareStep.snapshot)).order_by(SoftwareStep.endpoint_id, SoftwareStep.position).offset(page * 100).limit(100).all()
            result.append(dict(id=deployment.id, status=deployment.status, created_at=deployment.created_at.isoformat() + 'Z',
                               total=total, completed=total-counts.get('Queued', 0)-counts.get('Active', 0),
                               page=page, has_more=(page + 1) * 100 < total,
                               steps=[dict(id=s.id, host=s.endpoint_id, position=s.position, status=s.status,
                                           name=s.package_name, message=s.message, task_id=s.task_id,
                                           resolve_allowed=bool(user.is_admin and s.status == 'Active' and s.message))
                                      for s in rows if s.endpoint_id in allowed]))
        return jsonify(success=True, deployments=result)

    @bp.route('/api/infrastructure/software/deployments/<deployment_id>', methods=['PATCH'])
    def software_control_deployment(deployment_id):
        denied = interactive('run_tasks')
        if denied:
            return denied
        with service.LOCAL_LOCK:
            service.lock_control()
            row = db.session.get(SoftwareDeployment, deployment_id)
            user = helpers().current_user()
            if not row or (row.actor_user_id != user.id and not user.is_admin):
                return jsonify(success=False, message='Немає доступу.'), 403
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify(success=False, message='Очікується JSON-об’єкт.'), 400
            action = data.get('action')
            if action == 'resolve':
                step = SoftwareStep.query.filter_by(id=data.get('step_id'), deployment_id=row.id, status='Active').first()
                if not user.is_admin or not step or not step.message or data.get('execution_stopped') is not True:
                    return jsonify(success=False, message='Потрібне підтвердження superadmin, що виконання на хості завершено.'), 403
                try:
                    reason = validate_launch_reason(data.get('launch_reason'))
                except ValueError as exc:
                    return jsonify(success=False, message=str(exc)), 400
                task = db.session.get(AgentTask, step.task_id)
                if task and task.status in service.ACTIVE:
                    task.status, task.finished_at = 'Error', datetime.utcnow()
                    task.result_log = 'Оператор підтвердив завершення виконання на хості. ' + reason
                step.token_hash = None
                helpers().write_infra_audit('Software Resolve Stalled', 'software_step', step.id, {'reason': reason})
                db.session.commit()
                return jsonify(success=True)
            if action not in ('pause', 'resume', 'cancel') or row.status not in ('Running', 'Paused'):
                return jsonify(success=False, message='Дія недоступна.'), 400
            row.status = 'Paused' if action == 'pause' else 'Cancelling' if action == 'cancel' else 'Running'
            if action in ('pause', 'cancel'):
                for step in SoftwareStep.query.filter_by(deployment_id=row.id, status='Active').all():
                    task = AgentTask.query.filter_by(id=step.task_id).populate_existing().with_for_update().first()
                    if task and task.status == 'Pending':
                        # Gateway takes the same task lock before delivering it.
                        task.status = 'SoftwareQueued' if action == 'pause' else 'Cancelled'
                        step.status = 'Queued' if action == 'pause' else 'Skipped'
                        step.token_hash = None
                        if action == 'cancel':
                            step.message, task.finished_at = 'Скасовано до отримання агентом.', datetime.utcnow()
            if action == 'cancel':
                for step in SoftwareStep.query.filter_by(deployment_id=row.id, status='Queued').all():
                    step.status, step.message = 'Skipped', 'Наступні операції скасовано оператором.'
                    if step.task_id:
                        task = db.session.get(AgentTask, step.task_id)
                        if task and task.status == 'SoftwareQueued':
                            task.status, task.finished_at = 'Cancelled', datetime.utcnow()
            helpers().write_infra_audit('Software ' + action, 'software_deployment', row.id, {})
            db.session.commit()
            return jsonify(success=True)

    @bp.route('/api/public/software-delivery/<step_id>', methods=['GET'])
    def software_delivery(step_id):
        authorization = request.headers.get('Authorization', '')
        token = authorization[7:] if authorization.startswith('Bearer ') else ''
        if not token or len(token) > 256:
            return Response(status=403)
        with service.LOCAL_LOCK:
            control = service.lock_control()
            cfg, now = service.settings(control), datetime.utcnow()
            step = db.session.get(SoftwareStep, step_id)
            task = db.session.get(AgentTask, step.task_id) if step else None
            host = db.session.get(Endpoint, step.endpoint_id) if step else None
            if (not step or not task or not host or host.is_blocked or host.approval_status != 'Approved'
                    or step.status != 'Active' or task.status not in ('PickedUp', 'Running')
                    or not step.token_until or step.token_until < now or not step.token_hash
                    or not secrets.compare_digest(step.token_hash, hashlib.sha256(token.encode()).hexdigest())):
                return Response(status=403)
            plan = json.loads(step.snapshot)
            path = service.blob_path(plan['package'].get('blob_sha256'))
            if not path.is_file():
                return Response(status=404)
            leases = SoftwareStep.query.filter(SoftwareStep.download_until > now).count()
            if (step.download_until and step.download_until > now) or leases >= cfg['max_downloads']:
                return Response(status=429, headers={'Retry-After': '15'})
            lease_id = str(uuid.uuid4())
            step.download_lease, step.download_until = lease_id, now + timedelta(minutes=2)
            db.session.commit()
        # A fixed per-stream share is conservative: all streams together stay below the global cap.
        rate = cfg['bandwidth_mib'] * 1024 * 1024 / cfg['max_downloads']
        app = current_app._get_current_object()
        def release():
            with app.app_context():
                SoftwareStep.query.filter_by(id=step_id, download_lease=lease_id).update(
                    dict(download_lease=None, download_until=None))
                db.session.commit()
        def stream():
            started, sent, renewed = time.monotonic(), 0, time.monotonic()
            try:
                with path.open('rb') as source:
                    while chunk := source.read(64 * 1024):
                        if time.monotonic() - renewed > 15:
                            db.session.expire_all()
                            live = db.session.get(SoftwareStep, step_id)
                            if not live or live.download_lease != lease_id or live.status != 'Active' or live.token_until < datetime.utcnow():
                                break
                            live.download_until = datetime.utcnow() + timedelta(minutes=2)
                            db.session.commit()
                            renewed = time.monotonic()
                        sent += len(chunk)
                        delay = sent / rate - (time.monotonic() - started)
                        if delay > 0:
                            time.sleep(delay)
                        yield chunk
            finally:
                release()
        response = Response(stream_with_context(stream()), mimetype='application/octet-stream',
                            headers={'Content-Length': str(path.stat().st_size), 'Cache-Control': 'no-store',
                                     'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff'})
        response.call_on_close(release)
        return response
