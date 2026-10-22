"""Durable Software catalogue, immutable blobs and globally bounded deployment queue.

The singleton control row serializes writers across PostgreSQL web/worker processes.
No source URL or OMV credential is delivered to an endpoint.
"""
import hashlib
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time
import uuid
from http.client import HTTPException
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from flask import current_app
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import defer

from core.config import Config
from core.database import (db, AgentTask, Endpoint, SoftwareControl, SoftwareDeployment,
                           SoftwarePackage, SoftwareStep, TaskTemplate, User)
from core.group_access import allowed_host_ids_for_action
from core.outbound_security import pinned_outbound_url
from core.permissions import has_permission
from core.template_security import template_approval_valid

LOCAL_LOCK = threading.RLock()
DEFAULTS = dict(max_hosts=2, max_downloads=2, bandwidth_mib=10, max_package_mib=4096,
                source_origin='', ca_bundle='', imported=False)
ACTIVE = ('Pending', 'PickedUp', 'Running')
TERMINAL = ('Success', 'Error', 'Cancelled')


def lock_control():
    if db.session.get(SoftwareControl, 1) is None:
        try:
            with db.session.begin_nested():
                db.session.add(SoftwareControl(id=1, settings=json.dumps(DEFAULTS)))
                db.session.flush()
        except IntegrityError:
            pass
    return SoftwareControl.query.filter_by(id=1).populate_existing().with_for_update().one()


def settings(control=None):
    row = control or db.session.get(SoftwareControl, 1)
    return {**DEFAULTS, **json.loads(row.settings or '{}')} if row else dict(DEFAULTS)


def blob_dir():
    path = Path(Config.DATA_DIR) / 'software_blobs'
    path.mkdir(parents=True, exist_ok=True)
    return path


def blob_path(digest):
    if not re.fullmatch('[a-f0-9]{64}', str(digest or '')):
        raise ValueError('Пакет ще не підготовлено. Збережіть його з файлом або посиланням OMV.')
    return blob_dir() / digest


def store_blob(stream, expected='', max_bytes=None):
    """Commit complete bytes by content hash; never overwrite an existing version."""
    limit = max_bytes or settings()['max_package_mib'] * 1024 * 1024
    fd, temporary = tempfile.mkstemp(prefix='prepare-', dir=blob_dir())
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, 'wb') as output:
            for chunk in stream:
                if not chunk:
                    continue
                size += len(chunk)
                if size > limit:
                    raise ValueError('Файл перевищує налаштований ліміт пакета.')
                digest.update(chunk)
                output.write(chunk)
        if not size:
            raise ValueError('Порожній інсталятор.')
        value = digest.hexdigest()
        if expected and not secrets.compare_digest(value, expected.lower()):
            raise ValueError('SHA-256 файла не збігається з очікуваним.')
        destination = blob_path(value)
        if not destination.exists():
            os.replace(temporary, destination)
        return value, size
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_url(url, expected=''):
    cfg = settings()
    if str(Config.OUTBOUND_POLICY_MODE).lower() != 'enforce':
        raise ValueError('Для підготовки OMV потрібен OUTBOUND_POLICY_MODE=enforce та дозволений хост.')
    origin = urlsplit(cfg['source_origin'])
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or '\\' in url or any(ord(c) < 32 for c in url)
            or (parsed.scheme, parsed.hostname, parsed.port) != (origin.scheme, origin.hostname, origin.port)):
        raise ValueError('Посилання повинно належати налаштованому HTTPS-сховищу OMV.')
    # A private OMV must also be explicitly permitted by OUTBOUND_ALLOWED_HOSTS.
    started = time.monotonic()
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    try:
        context = ssl.create_default_context(cafile=cfg['ca_bundle'] or None)
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        with pinned_outbound_url(url, purpose='Software package preparation'):
            with opener.open(Request(url, headers={'Accept-Encoding': 'identity'}), timeout=30) as response:
                if response.status != 200:
                    raise ValueError('OMV не повернув файл (очікується HTTP 200 без перенаправлень).')
                if ('text/html' in response.headers.get('Content-Type', '').lower()
                        or response.headers.get('Content-Encoding', 'identity').lower() != 'identity'):
                    raise ValueError('OMV повинен повернути файл без HTML та HTTP-стиснення.')
                expected_length = response.headers.get('Content-Length')
                if expected_length and (not expected_length.isdigit() or int(expected_length) > cfg['max_package_mib'] * 1024 * 1024):
                    raise ValueError('Неприпустимий розмір пакета OMV.')
                def chunks():
                    received = 0
                    # read1 performs at most one underlying read, allowing the
                    # body deadline check between partial/slow responses.
                    while True:
                        if time.monotonic() - started > 300:
                            raise ValueError('Перевищено час підготовки пакета (5 хвилин).')
                        chunk = response.read1(256 * 1024)
                        if not chunk:
                            break
                        received += len(chunk)
                        yield chunk
                    if expected_length and received != int(expected_length):
                        raise ValueError('Файл OMV отримано не повністю.')
                return store_blob(chunks(), expected)
    except (URLError, ssl.SSLError, HTTPException):
        # Exception text may contain the OMV public-link capability.
        raise ValueError('Не вдалося отримати файл OMV. Перевірте доступ, HTTPS-сертифікат і розмір.') from None


def import_legacy(control):
    cfg = settings(control)
    if cfg['imported']:
        return
    from modules.Infrastructure import routes
    for old in routes.load_software_packages():
        if not isinstance(old, dict) or not old.get('id') or db.session.get(SoftwarePackage, old['id']):
            continue
        record = dict(old)
        record['sets'] = [old.get('category') or 'Загальні']
        filename = str(old.get('filename') or '')
        if filename and Path(filename).name == filename:
            path = Path(routes.SOFTWARE_PACKAGES_DIR) / filename
            if path.is_file():
                with path.open('rb') as source:
                    digest, size = store_blob(iter(lambda: source.read(256 * 1024), b''), old.get('sha256', ''))
                record.update(blob_sha256=digest, sha256=digest, size=size)
        record.pop('download_url', None)
        # Legacy recipes require an explicit review, never silently approve them.
        record.pop('approved_hash', None)
        db.session.add(SoftwarePackage(id=record['id'], record=json.dumps(record, ensure_ascii=False)))
    cfg['imported'] = True
    control.settings = json.dumps(cfg)


def catalogue():
    return [json.loads(row.record) for row in SoftwarePackage.query.order_by(SoftwarePackage.id).all()]


def recipe_hash(record):
    keys = ('name', 'version', 'blob_sha256', 'package_type', 'architecture', 'install_command',
            'update_command', 'uninstall_command', 'detection_type', 'detection_value',
            'expected_exit_codes', 'timeout_seconds', 'install_template_id', 'update_template_id',
            'uninstall_template_id')
    return hashlib.sha256(json.dumps({k: record.get(k) for k in keys}, sort_keys=True,
                                     ensure_ascii=False).encode()).hexdigest()


def public_package(record, manager=False):
    result = dict(record)
    result['approved'] = secrets.compare_digest(str(record.get('approved_hash') or ''), recipe_hash(record))
    result['revision'] = recipe_hash(record)
    result['prepared'] = bool(record.get('blob_sha256') and blob_path(record['blob_sha256']).is_file())
    result.pop('approved_hash', None)
    result.pop('download_url', None)
    if not manager:
        result.pop('external_url', None)
    return result


def save_package(package_id, form, upload, user):
    old = db.session.get(SoftwarePackage, package_id)
    record = json.loads(old.record) if old else {'id': package_id}
    previous = dict(record)
    for key, limit in dict(name=160, version=80, vendor=160, notes=4096, external_url=2048,
                           install_command=12000, update_command=12000, uninstall_command=12000,
                           detection_type=40, detection_value=4096, expected_exit_codes=120,
                           package_type=32, architecture=32, install_template_id=36,
                           update_template_id=36, uninstall_template_id=36).items():
        if key in form:
            record[key] = str(form[key]).strip()[:limit]
    if not record.get('name') or not record.get('version'):
        raise ValueError('Вкажіть назву та версію програми.')
    record.setdefault('package_type', 'msi')
    if record['package_type'] not in ('msi', 'exe', 'zip', 'ps1', 'bat', 'custom'):
        raise ValueError('Непідтримуваний тип пакета.')
    record.setdefault('architecture', 'any')
    if record['architecture'] not in ('any', 'x64', 'x86', 'arm64'):
        raise ValueError('Непідтримувана архітектура.')
    if record.get('detection_type', 'none') not in ('none', 'command', 'file_exists', 'folder_exists', 'registry_key_exists'):
        raise ValueError('Невідомий тип перевірки стану.')
    if record.get('detection_type', 'none') != 'none' and not record.get('detection_value'):
        raise ValueError('Вкажіть скрипт або шлях перевірки стану.')
    record.setdefault('expected_exit_codes', '0,3010')
    if not re.fullmatch(r'-?\d+(?:\s*,\s*-?\d+)*', record['expected_exit_codes']):
        raise ValueError('Коди завершення: цілі числа через кому.')
    if any(not -2147483648 <= int(code) <= 2147483647 for code in record['expected_exit_codes'].split(',')):
        raise ValueError('Код завершення виходить за межі Int32.')
    record['timeout_seconds'] = max(60, min(86400, int(form.get('timeout_seconds') or record.get('timeout_seconds') or 1800)))
    record['order'] = max(0, min(10000, int(form.get('order') or record.get('order') or 100)))
    names = str(form.get('sets', ','.join(record.get('sets') or [record.get('category') or 'Загальні'])))
    record['sets'] = list(dict.fromkeys(x.strip()[:80] for x in names.split(',') if x.strip()))[:30] or ['Загальні']
    expected = str(form.get('sha256') or '').strip().lower()
    if expected and not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('SHA-256 повинен містити 64 шістнадцяткові символи.')
    if upload and upload.filename:
        digest, size = store_blob(iter(lambda: upload.stream.read(256 * 1024), b''), expected)
        record.update(blob_sha256=digest, sha256=digest, size=size, preparation='Ready',
                      preparation_id=str(uuid.uuid4()), original_filename=Path(upload.filename.replace('\\', '/')).name[:200])
    elif record.get('external_url') and (record['external_url'] != previous.get('external_url')
                                       or record['version'] != previous.get('version')
                                       or not record.get('blob_sha256') or form.get('prepare') == '1'):
        if not settings()['source_origin']:
            raise ValueError('Спочатку налаштуйте адресу сховища OMV.')
        record.update(blob_sha256=None, sha256=expected, size=0,
                      preparation='Queued', preparation_id=str(uuid.uuid4()),
                      preparation_expected=expected, preparation_error='',
                      original_filename='package.' + record['package_type'])
    if not record.get('install_command') and not record.get('install_template_id'):
        if record['package_type'] == 'msi' and (record.get('blob_sha256') or record.get('external_url')):
            record['install_command'] = 'Start-Process msiexec.exe -ArgumentList @("/i", "`"{file}`"", "/qn", "/norestart") -Wait -PassThru | ForEach-Object { $global:LASTEXITCODE = $_.ExitCode }'
        else:
            raise ValueError('Вкажіть скрипт встановлення або погоджений шаблон Workspace.')
    if recipe_hash(record) != recipe_hash(previous):
        record.pop('approved_hash', None)
    if form.get('approve') == '1':
        if not user.is_admin:
            raise PermissionError('Погоджувати рецепт може лише superadmin.')
        record['approved_hash'] = recipe_hash(record)
    record['updated_by'] = user.username
    row = old or SoftwarePackage(id=package_id)
    row.record = json.dumps(record, ensure_ascii=False)
    db.session.add(row)
    return record


def process_preparation():
    """Claim one preparation in a short DB transaction, fetch outside the queue lock.

    A lease survives worker restarts; an old worker cannot replace a newer edit.
    """
    now = datetime.utcnow()
    with LOCAL_LOCK:
        lock_control()
        packages = catalogue()
        if any(p.get('preparation') == 'Preparing' and
               p.get('preparation_until', '') > now.isoformat() for p in packages):
            db.session.commit()
            return
        record = next((p for p in packages if p.get('preparation') in ('Queued', 'Preparing')), None)
        if record is None:
            db.session.commit()
            return
        record['preparation'] = 'Preparing'
        record['preparation_until'] = (now + timedelta(minutes=6)).isoformat()
        row = db.session.get(SoftwarePackage, record['id'])
        row.record = json.dumps(record, ensure_ascii=False)
        db.session.commit()
    error, prepared = '', None
    try:
        prepared = prepare_url(record['external_url'], record.get('preparation_expected', ''))
    except (ValueError, OSError):
        error = 'Перевірте HTTPS, доступ до OMV, OUTBOUND_ALLOWED_HOSTS, очікуваний SHA-256 та ліміти.'
    with LOCAL_LOCK:
        lock_control()
        row = db.session.get(SoftwarePackage, record['id'])
        current = json.loads(row.record) if row else {}
        if current.get('preparation_id') == record.get('preparation_id'):
            if prepared:
                approved = current.get('approved_hash') == recipe_hash(current)
                digest, size = prepared
                current.update(blob_sha256=digest, sha256=digest, size=size, preparation='Ready')
                if approved:
                    current['approved_hash'] = recipe_hash(current)
            else:
                current.update(preparation='Error', preparation_error=error)
                current.pop('approved_hash', None)
            current.pop('preparation_until', None)
            row.record = json.dumps(current, ensure_ascii=False)
        db.session.commit()


def run_preparation_job():
    from core import global_app
    if not global_app:
        return
    with global_app.app_context():
        try:
            process_preparation()
        except Exception:
            db.session.rollback()
            current_app.logger.error('Software preparation failed; inspect storage settings (source URL withheld).')
        finally:
            db.session.remove()


def resolve_recipe(record, operation):
    if operation == 'detect':
        if record.get('detection_type', 'none') == 'none' or not record.get('detection_value'):
            raise ValueError('Не налаштовано перевірку стану: ' + record['name'])
        return ''
    template_id = record.get(operation + '_template_id')
    if template_id:
        template = db.session.get(TaskTemplate, template_id)
        if (not template or template.type != 'action' or template.action_type != 'run_script'
                or not template_approval_valid(template)):
            raise ValueError('Потрібен чинний погоджений action/run_script шаблон Workspace.')
        payload = json.loads(template.payload or '{}')
        if not isinstance(payload, dict):
            raise ValueError('Шаблон Workspace має містити JSON-об’єкт зі script.')
        if payload.get('variables_schema') or payload.get('__ai_generated'):
            raise ValueError('Для Software виберіть шаблон без змінних та AI provenance; використайте окремий погоджений рецепт.')
        script = payload.get('script')
        if not isinstance(script, str) or not script.strip() or '{{' in script or '{%' in script:
            raise ValueError('Шаблон Software повинен містити готовий PowerShell-скрипт без Jinja-підстановок.')
        return script
    script = record.get(operation + '_command')
    if not script:
        raise ValueError(f'Для «{record["name"]}» не налаштовано дію {operation}.')
    return script


def make_script(record, operation, url='', token=''):
    """Embed data as base64 JSON; only the reviewed recipe is executable code."""
    import base64
    data = {k: record.get(k) for k in ('name', 'version', 'sha256', 'package_type',
                                      'detection_type', 'detection_value', 'expected_exit_codes')}
    data.update(url=url, token=token, operation=operation)
    data['timeout_seconds'] = int(record.get('timeout_seconds') or 1800)
    encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    script = record['resolved_script']
    # Expand only the three documented path tokens. Names/versions are variables, not source substitution.
    script = script.replace('{file}', '$PackageFile').replace('{extract_dir}', '$ExtractDir').replace('{package_dir}', '$WorkDir')
    child = 'param([string]$PackageFile,[string]$ExtractDir,[string]$WorkDir,[string]$PackageName,[string]$PackageVersion)\n$ErrorActionPreference = \'Stop\'\n$global:LASTEXITCODE = 0\n' + script + '\nexit $global:LASTEXITCODE\n'
    recipe = base64.b64encode(child.encode()).decode()
    return '''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + "'" + encoded + "'" + ''')) | ConvertFrom-Json
$PackageName = $cfg.name
$PackageVersion = $cfg.version
$WorkRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$WorkDir = Join-Path $WorkRoot ('software_' + [guid]::NewGuid().ToString('N'))
$PowerShellExe = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\\v1.0\\powershell.exe'
$ExtractDir = Join-Path $WorkDir 'extracted'
$PackageFile = Join-Path $WorkDir ('package.' + $cfg.package_type)
function Test-SoftwareState {
    if ($cfg.detection_type -eq 'file_exists') { return Test-Path -LiteralPath $cfg.detection_value -PathType Leaf }
    if ($cfg.detection_type -eq 'folder_exists') { return Test-Path -LiteralPath $cfg.detection_value -PathType Container }
    if ($cfg.detection_type -eq 'registry_key_exists') { return Test-Path -LiteralPath $cfg.detection_value }
    if ($cfg.detection_type -eq 'command') {
        $check = Join-Path $WorkDir 'detect.ps1'
        Set-Content -LiteralPath $check -Value $cfg.detection_value -Encoding UTF8
        & $PowerShellExe -NoProfile -NonInteractive -File $check | Out-Host
        return $LASTEXITCODE -eq 0
    }
    return $false
}
try {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    if ($cfg.operation -eq 'detect') {
        if (Test-SoftwareState) { Write-Output 'Потрібну версію встановлено.'; exit 0 }
        Write-Output 'Потрібну версію не знайдено.'
        exit 1
    }
    if ($cfg.operation -eq 'install' -and (Test-SoftwareState)) {
        Write-Output 'Потрібний стан уже досягнуто; пропущено.'
        exit 0
    }
    if ($cfg.url) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $downloaded = $false
        $DownloadDeadline = [DateTime]::UtcNow.AddSeconds($cfg.timeout_seconds)
        while (-not $downloaded -and [DateTime]::UtcNow -lt $DownloadDeadline) {
            try {
                Invoke-WebRequest -Uri $cfg.url -Headers @{Authorization=('Bearer ' + $cfg.token)} -OutFile $PackageFile -UseBasicParsing -TimeoutSec 300
                $downloaded = $true
                break
            } catch {
                $code = 0
                if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                if ($code -ne 429) { throw 'Не вдалося завантажити пакет із WinHUB.' }
                Start-Sleep -Seconds 15
            }
        }
        if (-not $downloaded) { throw 'Завантаження не завершене.' }
        if ((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $cfg.sha256) { throw 'SHA-256 mismatch' }
        if ($cfg.package_type -eq 'zip') { Expand-Archive -LiteralPath $PackageFile -DestinationPath $ExtractDir -Force }
    }
    $global:LASTEXITCODE = 0
    $RecipePath = Join-Path $WorkDir 'recipe.ps1'
    $RecipeText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + "'" + recipe + "'" + '''))
    Set-Content -LiteralPath $RecipePath -Value $RecipeText -Encoding UTF8
    & $PowerShellExe -NoProfile -NonInteractive -File $RecipePath -PackageFile $PackageFile -ExtractDir $ExtractDir -WorkDir $WorkDir -PackageName $PackageName -PackageVersion $PackageVersion | Out-Host
    $code = $LASTEXITCODE
    $expected = @($cfg.expected_exit_codes -split ',' | ForEach-Object { [int]$_.Trim() })
    if ($expected -notcontains $code) { throw "Неочікуваний код завершення: $code" }
    if ($code -eq 3010) { Write-Output 'WINHUB_REBOOT_REQUIRED'; exit 0 }
    if ($cfg.detection_type -and $cfg.detection_type -ne 'none') {
        $detected = Test-SoftwareState
        if ($cfg.operation -ne 'uninstall' -and -not $detected) { throw 'Перевірка встановленої версії не пройшла.' }
        if ($cfg.operation -eq 'uninstall' -and $detected) { throw 'Після видалення програма досі визначається.' }
    }
    Write-Output 'Операцію завершено.'
    exit 0
} catch {
    Write-Output ('Software error: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($WorkDir -and (Test-Path -LiteralPath $WorkDir)) {
        $ResolvedWorkDir = [IO.Path]::GetFullPath($WorkDir)
        if ($ResolvedWorkDir.StartsWith($WorkRoot.TrimEnd('\\') + '\\', [StringComparison]::OrdinalIgnoreCase) -and
            ([IO.Path]::GetFileName($ResolvedWorkDir) -match '^software_[a-f0-9]{32}$')) {
            Remove-Item -LiteralPath $ResolvedWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
'''


def process_queue():
    """One transaction per tick. All workers must acquire control before queue writes."""
    with LOCAL_LOCK:
        control = lock_control()
        cfg, now = settings(control), datetime.utcnow()
        deployments = SoftwareDeployment.query.filter(SoftwareDeployment.status.in_(('Running', 'Paused', 'Cancelling'))).order_by(SoftwareDeployment.created_at).all()
        active_steps = SoftwareStep.query.filter_by(status='Active').order_by(SoftwareStep.id).all()
        busy = set()
        for step in active_steps:
            task = AgentTask.query.filter_by(id=step.task_id).with_for_update().first()
            if not task or task.status in TERMINAL:
                step.status = task.status if task else 'Error'
                step.token_hash = None
                if task and task.status == 'Success' and 'WINHUB_REBOOT_REQUIRED' in (task.result_log or ''):
                    step.status, step.message = 'RebootRequired', 'Потрібне перезавантаження; наступні програми не запускаються.'
                continue
            if task.status == 'Pending' and step.started_at < now - timedelta(minutes=2):
                # Same task is held again; gateway locks it before pickup.
                task.status, step.status, step.token_hash = 'SoftwareQueued', 'Queued', None
                continue
            # No speculative timeout/retry of a picked-up installer: retain its slot
            # until an authenticated result or explicit operator cancellation.
            plan = json.loads(step.snapshot)
            if step.started_at + timedelta(seconds=plan['package']['timeout_seconds'] + 300) < now:
                step.message = 'Немає результату після таймауту. Перевірте хост перед ручним завершенням.'
            busy.add(step.endpoint_id)
        db.session.flush()
        for deployment in deployments:
            steps = SoftwareStep.query.options(defer(SoftwareStep.snapshot)).filter_by(deployment_id=deployment.id).order_by(SoftwareStep.position, SoftwareStep.id).all()
            by_host = {}
            own_active = sum(s.status == 'Active' for s in steps)
            for step in steps:
                earlier = by_host.setdefault(step.endpoint_id, [])
                previous = list(earlier)
                earlier.append(step)
                if step.status != 'Queued':
                    continue
                if any(s.status in ('Error', 'Cancelled', 'Skipped', 'RebootRequired') for s in previous):
                    step.status, step.message = 'Skipped', 'Зупинено після помилки або запиту перезавантаження.'
                    continue
                if deployment.expires_at < now:
                    step.status, step.message = 'Skipped', 'Строк очікування завершився.'
                    continue
                if deployment.status != 'Running' or any(s.status != 'Success' for s in previous):
                    continue
                if step.endpoint_id in busy or len(busy) >= cfg['max_hosts']:
                    continue
                if own_active >= deployment.parallelism:
                    continue
                host = db.session.get(Endpoint, step.endpoint_id)
                actor = db.session.get(User, deployment.actor_user_id)
                permitted = (actor and actor.is_active and has_permission(actor, 'Infrastructure', 'run_tasks')
                             and step.endpoint_id in allowed_host_ids_for_action(actor, 'run_tasks'))
                if not host or host.is_blocked or host.approval_status != 'Approved' or not permitted:
                    step.status, step.message = 'Error', 'Хост недоступний для запуску або права відкликано.'
                    continue
                if (host.last_seen or datetime.min) < now - timedelta(minutes=2):
                    continue
                # Also avoid overlap with another Software launch or ordinary task.
                if AgentTask.query.filter(AgentTask.endpoint_id == host.id, AgentTask.status.in_(ACTIVE)).first():
                    continue
                plan = json.loads(step.snapshot)
                token = secrets.token_urlsafe(32)
                step.token_hash = hashlib.sha256(token.encode()).hexdigest()
                step.token_until = now + timedelta(seconds=plan['package']['timeout_seconds'] + 300)
                task_id = step.task_id or str(uuid.uuid4())
                download_url = plan['base_url'] + '/api/public/software-delivery/' + step.id
                needs_file = bool(plan['package'].get('blob_sha256') and plan['operation'] not in ('uninstall', 'detect'))
                script = make_script(plan['package'], plan['operation'], download_url if needs_file else '', token if needs_file else '')
                payload = json.dumps(dict(script=script, __software_step_id=step.id,
                                          __agent_timeout_seconds=plan['package']['timeout_seconds']))
                task = db.session.get(AgentTask, task_id)
                if not task:
                    task = AgentTask(id=task_id, job_id=deployment.id, endpoint_id=host.id,
                                     endpoint_id_snapshot=host.id, endpoint_hostname_snapshot=host.hostname,
                                     endpoint_name_snapshot=host.display_name,
                                     endpoint_groups_snapshot=json.dumps([{'id': g.id, 'name': g.name} for g in host.groups]),
                                     actor_user_id=actor.id, created_by=deployment.created_by,
                                     launch_reason=deployment.launch_reason, module_source='Infrastructure',
                                     action_type='run_script', source_type='manual',
                                     title=f"Software: {plan['operation']} {plan['package']['name']} {plan['package']['version']}"[:150])
                    db.session.add(task)
                task.payload, task.status, task.created_at = payload, 'Pending', now
                step.task_id, step.started_at, step.status = task_id, now, 'Active'
                busy.add(host.id)
                own_active += 1
            if steps and all(s.status not in ('Queued', 'Active') for s in steps):
                deployment.status = ('Cancelled' if deployment.status == 'Cancelling' else
                                     'Success' if all(s.status == 'Success' for s in steps) else
                                     'RebootRequired' if any(s.status == 'RebootRequired' for s in steps)
                                     and not any(s.status == 'Error' for s in steps) else 'Error')
            held = [s.task_id for s in steps if s.status in ('Skipped', 'Error') and s.task_id]
            if held:
                AgentTask.query.filter(AgentTask.id.in_(held), AgentTask.status == 'SoftwareQueued').update(
                    dict(status='Cancelled', finished_at=now), synchronize_session=False)
        db.session.commit()


def run_queue_job():
    from core import global_app
    if not global_app:
        return
    with global_app.app_context():
        try:
            process_queue()
        except Exception:
            db.session.rollback()
            current_app.logger.exception('Software queue failed')
        finally:
            db.session.remove()
