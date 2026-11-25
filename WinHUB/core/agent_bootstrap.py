"""Agentless bootstrap uses Software blobs, scoped capabilities and one identity enrollment."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import stat
import uuid
import zipfile
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import has_request_context, session
from core.database import db, AgentBootstrapGrant, AgentTask, Endpoint, SoftwarePackage
from core import software
from core.permissions import has_permission
from core.template_security import template_approval_valid

MARKER = 'BootstrapDescriptor=WINHUB_BOOTSTRAP_DESCRIPTOR_V1'
KIND = 'agent_bootstrap'


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('Runtime configuration must be a JSON object')
    origin = urlsplit(str(config.get('ServerUrl', '')))
    if (origin.scheme != 'https' or not origin.hostname or origin.username or origin.password
            or origin.path not in ('', '/') or origin.query or origin.fragment):
        raise ValueError('ServerUrl must be an HTTPS origin, including the agent port')
    origin.port  # Validate malformed ports.
    for name in ('ServerCertificateSha256', 'ServerCertificateSha256Next'):
        value = str(config.get(name, '') or '')
        if name.endswith('Next') and not value:
            continue
        if not re.fullmatch('[a-fA-F0-9]{64}', value):
            raise ValueError('Provide trusted SHA-256 certificate pins without colons')
    if config.get('IgnoreTlsCertificateErrors') is not False or config.get('RequireTaskSignature') is not True:
        raise ValueError('TLS and task signature verification must remain enabled')
    if any(config.get(k) for k in ('GlobalApiKey', 'TaskHmacSecret', 'TaskSigningPublicKeyPem', 'TaskSigningKeyId', 'TaskSigningLastSequence')):
        raise ValueError('Do not upload enrollment keys or another endpoint identity/signing state')
    # Leave no unknown configuration field capable of changing bootstrap identity.
    allowed = {'ServerUrl', 'GlobalApiKey', 'PollIntervalSeconds', 'PollJitterSeconds', 'StartupSpreadSeconds',
               'TaskHmacSecret', 'DefaultTaskTimeoutSeconds', 'MaxResultLogBytes', 'TaskMemoryLimitMb', 'TaskProcessLimit',
               'TaskCpuPercent', 'IgnoreTlsCertificateErrors', 'ServerCertificateSha256', 'ServerCertificateSha256Next',
               'RequireTaskSignature', 'TaskSigningPublicKeyPem', 'TaskSigningKeyId', 'TaskSigningLastSequence',
               'RestartAfterConsecutivePollFailures'}
    if set(config) - allowed:
        raise ValueError('Unsupported runtime config fields: ' + ', '.join(sorted(set(config) - allowed)))
    clean = dict(config, ServerUrl=config['ServerUrl'].rstrip('/'), GlobalApiKey='', StartupSpreadSeconds=0)
    return clean


def verify_zip(path, public_pem, version):
    """Verify publisher and all archived bytes before the package can be approved."""
    if not public_pem.strip().startswith('-----BEGIN PUBLIC KEY-----') or 'PRIVATE KEY' in public_pem:
        raise ValueError('Provide only the trusted SPKI public release key')
    key = serialization.load_pem_public_key(public_pem.encode())
    if not isinstance(key, rsa.RSAPublicKey) or not 3072 <= key.key_size <= 8192:
        raise ValueError('RSA 3072..8192 release public key required')
    required = {'WinHUBAgent.exe', 'install-service.ps1', 'uninstall-service.ps1', 'update-service.ps1',
                'update-protocol.json', 'release-signing-public.pem', 'appsettings.json'}
    with zipfile.ZipFile(path) as archive:
        entries, total = {}, 0
        for entry in archive.infolist():
            name = entry.filename
            if (name in entries or name.lower() in {n.lower() for n in entries} or entry.is_dir()
                    or name.startswith('/') or '\\' in name or ':' in name
                    or any(x in ('', '.', '..') or x.endswith((' ', '.')) for x in name.split('/'))
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('Unsafe ZIP inventory')
            total += entry.file_size
            if len(entries) >= 256 or entry.file_size > 256 * 1024**2 or total > 256 * 1024**2:
                raise ValueError('Bootstrap ZIP exceeds 256 MiB / 256 files')
            entries[name] = entry
        if 'release-manifest.json' not in entries or entries['release-manifest.json'].file_size > 1024**2:
            raise ValueError('Signed release-manifest.json is required')
        envelope = json.loads(archive.read('release-manifest.json'))
        if envelope.get('algorithm') != 'rsa-pss-sha256':
            raise ValueError('Unsupported release signature algorithm')
        payload = base64.b64decode(envelope['payload'], validate=True)
        key.verify(base64.b64decode(envelope['signature'], validate=True), payload,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        manifest = json.loads(payload)
        key_id = hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if (manifest.get('schema') != 1 or manifest.get('platform') != 'windows' or manifest.get('architecture') != 'x64'
                or manifest.get('version') != version or manifest.get('key_id') != key_id or int(manifest.get('serial', 0)) <= 0):
            raise ValueError('Expected a signed Windows x64 release with the specified version')
        files = manifest['files']
        names = [x['path'] for x in files]
        if len(set(names)) != len(names) or set(entries) != set(names) | {'release-manifest.json'} or required != set(names):
            raise ValueError('Release inventory mismatch or missing native Windows installer files')
        if any(Path(n).name.lower() in ('winhub_agent.conf', 'winhub_agent.bootstrap.conf', 'agent.secrets')
               or (n.lower().endswith(('.pem', '.key', '.pfx', '.p12')) and n != 'release-signing-public.pem') for n in names):
            raise ValueError('Runtime credentials/private keys are forbidden in bootstrap ZIP')
        for item in files:
            name = item['path']
            if entries[name].file_size != item['size']:
                raise ValueError('Release file size mismatch')
            with archive.open(name) as source:
                checksum = hashlib.file_digest(source, 'sha256').hexdigest()
            if checksum != item['sha256']:
                raise ValueError('Release file hash mismatch')
        bundled = serialization.load_pem_public_key(archive.read('release-signing-public.pem'))
        if bundled.public_numbers() != key.public_numbers():
            raise ValueError('Bundled release key differs from trusted publisher key')
        if json.loads(archive.read('update-protocol.json')) != {'protocol': 2, 'platform': 'windows'}:
            raise ValueError('Windows update protocol 2 is required')
    return key_id


def revision(record):
    return digest(json.dumps({k: record.get(k) for k in ('kind', 'name', 'version', 'blob_sha256', 'runtime_config', 'public_key')}, sort_keys=True))


def profile(package_id):
    row = db.session.get(SoftwarePackage, package_id)
    p = json.loads(row.record) if row else {}
    if p.get('kind') != KIND or p.get('approved_hash') != revision(p) or not software.blob_path(p.get('blob_sha256')).is_file():
        raise ValueError('Select an approved, prepared Agent Bootstrap package ID from Software')
    return p


def attach(task, user):
    payload = json.loads(task.payload)
    if payload.get('__agent_bootstrap'):
        raise ValueError('Bootstrap descriptors are reserved for server dispatch')
    package_id = str(payload.pop('bootstrap_package_id', '') or '').strip()
    mode = payload.pop('bootstrap_mode', '')
    script = payload.get('script', '')
    if not package_id:
        payload['script'] = script.replace(MARKER, 'BootstrapDescriptor=')
        task.payload = json.dumps(payload)
        return
    from core.database import TaskTemplate
    template = db.session.get(TaskTemplate, task.template_id) if task.template_id else None
    if (not has_request_context() or session.get('api_key_auth') or task.source_type != 'manual'
            or not has_permission(user, 'Infrastructure', 'manage_software')
            or task.action_type != 'run_script' or not template or not template_approval_valid(template)
            or MARKER not in str(template.payload) or script.count(MARKER) != 1):
        raise PermissionError('Bootstrap requires interactive manual launch, manage_software and an approved bootstrap template')
    host = db.session.get(Endpoint, task.endpoint_id)
    if not host or host.is_blocked or host.approval_status != 'Approved' or (host.os_type or '').lower() != 'linux':
        raise ValueError('Bootstrap target must be one approved Linux Proxmox endpoint')
    record = profile(package_id)
    if mode not in ('Create', 'Validate'):
        raise ValueError('Invalid bootstrap mode')
    if mode == 'Validate':
        payload['script'] = script.replace(MARKER, 'BootstrapDescriptor=')
        task.payload = json.dumps(payload)
        return
    # Select the Windows identity before task signing. The VM script uses it unchanged.
    lines = script.splitlines()
    indexes = [i for i, line in enumerate(lines) if line.startswith('WindowsHostname=')]
    if len(indexes) != 1:
        raise ValueError('Expected exactly one WindowsHostname data field')
    index = indexes[0]
    hostname = lines[index].split('=', 1)[1].strip() or 'WIN-' + secrets.token_hex(5).upper()
    if not re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,14}', hostname) or hostname.endswith('-'):
        raise ValueError('Invalid Windows hostname for bootstrap')
    lines[index] = 'WindowsHostname=' + hostname
    download, enrollment = secrets.token_urlsafe(32), 'boot_' + secrets.token_urlsafe(32)
    grant = AgentBootstrapGrant(id=str(uuid.uuid4()), parent_task_id=task.id, snapshot=json.dumps(record),
        download_hash=digest(download), enrollment_hash=digest(enrollment), expected_hostname=hostname,
        expires_at=datetime.utcnow() + timedelta(minutes=60))
    db.session.add(grant)
    descriptor = dict(package_id=record['id'], url=record['runtime_config']['ServerUrl'] + '/api/public/software-delivery/bootstrap/' + grant.id,
                      token=download, enrollment_token=enrollment, runtime_config=record['runtime_config'],
                      sha256=record['blob_sha256'], size=record['size'], version=record['version'], grant_id=grant.id,
                      public_key=record['public_key'], expires_at=int(grant.expires_at.replace(tzinfo=timezone.utc).timestamp()))
    payload['__agent_bootstrap'] = descriptor
    payload['script'] = '\n'.join(lines).replace(MARKER, 'BootstrapDescriptor=attached') + '\n'
    task.payload = json.dumps(payload)


def active_grant(grant):
    if not grant or grant.expires_at < datetime.utcnow():
        return False
    task = db.session.get(AgentTask, grant.parent_task_id)
    host = db.session.get(Endpoint, task.endpoint_id) if task else None
    if not task or task.status not in ('PickedUp', 'Running', 'Success') or not host or host.is_blocked or host.approval_status != 'Approved':
        return False
    from core.sdk import WinHubCore
    from core.database import User
    user = db.session.get(User, task.actor_user_id) if task.actor_user_id else None
    return bool(user and user.is_active and has_permission(user, 'Infrastructure', 'manage_software')
                and WinHubCore.can_manage_host(user.id, host.id, 'run_tasks'))


def enrollment_grant(data):
    token = str(data.get('global_token') or '')
    row = AgentBootstrapGrant.query.filter_by(enrollment_hash=digest(token)).with_for_update().first()
    if not active_grant(row) or data.get('os_type') != 'Windows' or str(data.get('hostname', '')).upper() != row.expected_hostname.upper():
        return None
    from core.agent_gateway import agent_key_fingerprint, verify_agent_signature
    pem = str(data.get('agent_public_key_pem') or '')
    key = agent_key_fingerprint(pem)
    hw_id = str(data.get('hw_id') or '')
    if not key or not hw_id or len(hw_id) > 100 or data.get('previous_auth_token') or data.get('previous_hw_id'):
        return None
    if row.enrolled_endpoint_id:
        if (hw_id, key) != (row.enrolled_endpoint_id, row.enrolled_key_fingerprint):
            return None
    elif db.session.get(Endpoint, hw_id):
        return None  # A bootstrap grant cannot take over an existing endpoint.
    ok, _ = verify_agent_signature(pem, data, '/api/agent/enroll', '')
    if not ok:
        return None
    row.enrolled_endpoint_id, row.enrolled_key_fingerprint = hw_id, key
    return row
