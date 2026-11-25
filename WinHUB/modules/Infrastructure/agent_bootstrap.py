"""Separate Software catalogue mode; no anonymous permanent package URLs."""
import hashlib
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta

from flask import Response, current_app, jsonify, request, stream_with_context
from core import agent_bootstrap as bootstrap, software
from core.database import db, AgentBootstrapGrant, Endpoint, SoftwarePackage, SoftwareStep


def register(bp):
    @bp.route('/api/infrastructure/software/bootstrap', methods=['GET', 'POST'])
    def bootstrap_packages():
        from modules.Infrastructure.software import interactive, helpers
        denied = interactive('manage_software')
        if denied:
            return denied
        if request.method == 'GET':
            records = [json.loads(row.record) for row in SoftwarePackage.query.all()]
            packages = [dict(p, approved=p.get('approved_hash') == bootstrap.revision(p))
                        for p in records if p.get('kind') == bootstrap.KIND]
            for p in packages:
                p.pop('approved_hash', None)
            return jsonify(success=True, packages=packages)
        user = helpers().current_user()
        try:
            package_id = str(request.form.get('id') or uuid.uuid4())
            uuid.UUID(package_id)
            old = db.session.get(SoftwarePackage, package_id)
            previous = json.loads(old.record) if old else {}
            if old and previous.get('kind') != bootstrap.KIND:
                raise ValueError('This ID belongs to an ordinary Software package')
            name, version = request.form.get('name', '').strip(), request.form.get('version', '').strip()
            if not name or len(name) > 160 or not version or len(version) > 80:
                raise ValueError('Name and exact signed package version are required')
            runtime_text = request.form.get('runtime_config', '{}')
            if len(runtime_text) > 32768:
                raise ValueError('Runtime config too large')
            runtime = bootstrap.validate_config(json.loads(runtime_text))
            public_key = request.form.get('public_key', '').strip()
            if len(public_key) > 16384:
                raise ValueError('Public key too large')
            upload = request.files.get('file')
            if upload and upload.filename:
                checksum, size = software.store_blob(iter(lambda: upload.stream.read(262144), b''),
                    str(request.form.get('sha256') or '').strip().lower(), max_bytes=256 * 1024**2)
            elif previous.get('blob_sha256'):
                checksum, size = previous['blob_sha256'], previous['size']
            else:
                raise ValueError('Upload a signed native Windows x64 ZIP package')
            key_id = bootstrap.verify_zip(software.blob_path(checksum), public_key, version)
            record = dict(id=package_id, kind=bootstrap.KIND, name=name, version=version, blob_sha256=checksum,
                          sha256=checksum, size=size, public_key=public_key, key_id=key_id, runtime_config=runtime)
            if previous.get('approved_hash') == bootstrap.revision(record):
                record['approved_hash'] = previous['approved_hash']
            if request.form.get('approve') == '1':
                if not user.is_admin:
                    raise PermissionError('Only a superadmin can approve a bootstrap package and configuration')
                record['approved_hash'] = bootstrap.revision(record)
            row = old or SoftwarePackage(id=package_id)
            row.record = json.dumps(record)
            db.session.add(row)
            db.session.commit()
            helpers().write_infra_audit('Agent Bootstrap Package Saved', 'software_package', package_id,
                                       dict(version=version, sha256=checksum, key_id=key_id))
            return jsonify(success=True, id=package_id)
        except PermissionError as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)), 403
        except Exception:
            db.session.rollback()
            # PEM/archive/parser exceptions can contain submitted content. Do not echo them.
            return jsonify(success=False, message='Bootstrap package rejected. Check signed ZIP, trusted public key, exact version, checksum and clean runtime configuration.'), 400

    def authorized(grant_id):
        token = request.headers.get('Authorization', '')
        token = token[7:] if token.startswith('Bearer ') else ''
        row = AgentBootstrapGrant.query.filter_by(id=grant_id).with_for_update().first()
        if not token or len(token) > 256 or not bootstrap.active_grant(row) or not secrets.compare_digest(row.download_hash, bootstrap.digest(token)):
            return None
        return row

    @bp.route('/api/public/software-delivery/bootstrap/<grant_id>/status', methods=['GET'])
    def bootstrap_status(grant_id):
        row = authorized(grant_id)
        if not row:
            return Response(status=403)
        endpoint = db.session.get(Endpoint, row.enrolled_endpoint_id) if row.enrolled_endpoint_id else None
        return jsonify(success=True, registered=bool(endpoint), endpoint_id=endpoint.id if endpoint else None,
                       approval_status=endpoint.approval_status if endpoint else 'NotRegistered',
                       agent_version=endpoint.agent_version if endpoint else None)

    @bp.route('/api/public/software-delivery/bootstrap/<grant_id>', methods=['GET'])
    def bootstrap_delivery(grant_id):
        with software.LOCAL_LOCK:
            control = software.lock_control()
            cfg = software.settings(control)
            row = authorized(grant_id)
            now = datetime.utcnow()
            if not row or row.enrolled_endpoint_id:
                return Response(status=403)
            if (row.download_until and row.download_until > now) or (AgentBootstrapGrant.query.filter(AgentBootstrapGrant.download_until > now).count() + SoftwareStep.query.filter(SoftwareStep.download_until > now).count()) >= cfg['max_downloads']:
                return Response(status=429, headers={'Retry-After': '15'})
            record = json.loads(row.snapshot)
            path = software.blob_path(record['blob_sha256'])
            if not path.is_file():
                return Response(status=404)
            row.download_until = min(row.expires_at, now + timedelta(minutes=5))
            db.session.commit()
        app = current_app._get_current_object()
        rate = cfg['bandwidth_mib'] * 1024**2 / cfg['max_downloads']
        def stream():
            started, sent, checked = time.monotonic(), 0, time.monotonic()
            try:
                with path.open('rb') as source:
                    while chunk := source.read(65536):
                        if time.monotonic() - started > 290:
                            break
                        if time.monotonic() - checked > 10:
                            db.session.expire_all()
                            live = db.session.get(AgentBootstrapGrant, grant_id)
                            if not bootstrap.active_grant(live):
                                break
                            checked = time.monotonic()
                        sent += len(chunk)
                        yield chunk
                        delay = sent / rate - (time.monotonic() - started)
                        if delay > 0:
                            time.sleep(min(delay, 1))
            finally:
                with app.app_context():
                    AgentBootstrapGrant.query.filter_by(id=grant_id).update(dict(download_until=None))
                    db.session.commit()
        return Response(stream_with_context(stream()), mimetype='application/zip', headers={
            'Content-Length': str(record['size']), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
