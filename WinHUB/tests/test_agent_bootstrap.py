"""Bootstrap is a separate catalogue and a task/identity-scoped capability, never global enrollment."""
import base64
from datetime import datetime, timedelta
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import session

import test_software_deployments as fixtures
from core import agent_bootstrap as bootstrap
from core.database import db, AgentBootstrapGrant, AgentTask, Endpoint, SoftwarePackage, TaskTemplate
from core.sdk import WinHubCore
from core.template_security import current_template_hash
from core import agent_gateway

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('bootstrap_release_signer', ROOT / 'WinHUBLinuxAgent/tools/sign-release.py')
SIGNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNER)


class AgentBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.SoftwareTests.setUpClass.__func__(cls)
        cls.app.register_blueprint(agent_gateway.agent_gateway_bp)
    tearDownClass = classmethod(fixtures.SoftwareTests.tearDownClass.__func__)
    setUp = fixtures.SoftwareTests.setUp
    tearDown = fixtures.SoftwareTests.tearDown
    post = fixtures.SoftwareTests.post

    def package(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        source = Path(self.temp.name) / ('publish-' + uuid.uuid4().hex)
        source.mkdir()
        for name in ('WinHUBAgent.exe', 'install-service.ps1', 'update-service.ps1', 'uninstall-service.ps1', 'appsettings.json'):
            (source / name).write_text('synthetic nonexecuted fixture')
        (source / 'update-protocol.json').write_text('{"protocol":2,"platform":"windows"}')
        output = source.parent / (uuid.uuid4().hex + '.zip')
        SIGNER.create_package(source, output, key, 'windows', 'x64', '2.0.1-rc.4', 123, bundle_public_key=True)
        config = dict(ServerUrl='https://winhub.test', ServerCertificateSha256='A' * 64,
                      IgnoreTlsCertificateErrors=False, RequireTaskSignature=True, GlobalApiKey='')
        return output.read_bytes(), public, config

    def create_profile(self):
        archive, public, config = self.package()
        response = self.post('/api/infrastructure/software/bootstrap', data=dict(
            name='WinHUB Bootstrap', version='2.0.1-rc.4', approve='1',
            public_key=public, runtime_config=json.dumps(config), file=(io.BytesIO(archive), 'agent.zip')))
        self.assertEqual(response.status_code, 200, response.json)
        return response.json['id']

    def dispatch(self, package_id, mode='Create'):
        template_id = str(uuid.uuid4())
        script = 'WindowsHostname=BOOT-TEST\n' + bootstrap.MARKER
        template = TaskTemplate(id=template_id, name='Provision', type='action', action_type='run_script',
                                payload=json.dumps(dict(script=script)), is_approved=True)
        template.approved_content_hash = current_template_hash(template)
        db.session.add(template)
        self.hosts[0].os_type = 'Linux'
        db.session.commit()
        with self.app.test_request_context('/api/infrastructure/tasks', base_url='https://winhub.test'):
            session.update(user_id=self.user.id, is_admin=True)
            job = WinHubCore.dispatch_task(self.user.id, 'Infrastructure', 'run_script', ['h1'],
                dict(script=script, __template_id=template.id, bootstrap_package_id=package_id, bootstrap_mode=mode),
                launch_reason='Isolated bootstrap validation')
        task = AgentTask.query.filter_by(job_id=job).one()
        return task, json.loads(task.payload)

    def test_catalogue_separated_signed_and_approval_bound_to_config(self):
        package_id = self.create_profile()
        records = self.client.get('/api/infrastructure/software/bootstrap').json['packages']
        self.assertTrue(records[0]['approved'])
        ordinary = self.client.get('/api/infrastructure/software-packages').json
        self.assertFalse(any(p['id'] == package_id for p in ordinary['packages'] + ordinary['installers']))
        response = self.post('/api/infrastructure/software/deployments', json=dict(
            package_ids=[package_id], target_ids=['h1'], operation='install', launch_reason='Isolated invalid deployment'))
        self.assertEqual(response.status_code, 400)
        row = db.session.get(SoftwarePackage, package_id)
        p = json.loads(row.record)
        p['runtime_config']['ServerUrl'] = 'https://changed.test'
        row.record = json.dumps(p)
        db.session.commit()
        with self.assertRaises(ValueError):
            bootstrap.profile(package_id)

    def test_private_credentials_and_unsigned_archives_rejected(self):
        archive, public, config = self.package()
        for data in [dict(config, GlobalApiKey='must-never-leave-server'), dict(config, IgnoreTlsCertificateErrors=True)]:
            response = self.post('/api/infrastructure/software/bootstrap', data=dict(
                name='Invalid', version='2.0.1-rc.4', approve='1', public_key=public,
                runtime_config=json.dumps(data), file=(io.BytesIO(archive), 'agent.zip')))
            self.assertEqual(response.status_code, 400)
            self.assertNotIn('must-never-leave-server', response.get_data(as_text=True))
        response = self.post('/api/infrastructure/software/bootstrap', data=dict(
            name='Invalid', version='2.0.1-rc.4', public_key=public,
            runtime_config=json.dumps(config), file=(io.BytesIO(b'not signed'), 'agent.zip')))
        self.assertEqual(response.status_code, 400)

    def test_validate_creates_no_grants_and_no_embedded_tokens(self):
        package_id = self.create_profile()
        _, payload = self.dispatch(package_id, mode='Validate')
        self.assertNotIn('__agent_bootstrap', payload)
        self.assertEqual(AgentBootstrapGrant.query.count(), 0)

    def test_delivery_scoped_expiring_and_denied_after_enrollment_or_cancellation(self):
        task, payload = self.dispatch(self.create_profile())
        descriptor = payload['__agent_bootstrap']
        self.assertNotIn(descriptor['enrollment_token'], payload['script'])
        grant = AgentBootstrapGrant.query.one()
        self.assertNotIn(descriptor['enrollment_token'], grant.snapshot)
        url = '/api/public/software-delivery/bootstrap/' + grant.id
        headers = {'Authorization': 'Bearer ' + descriptor['token']}
        self.assertEqual(self.client.get(url, headers=headers).status_code, 403)  # not picked up
        task.status = 'PickedUp'
        db.session.commit()
        self.assertEqual(self.client.get(url).status_code, 403)
        response = self.client.get(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(hashlib.sha256(response.data).hexdigest(), descriptor['sha256'])
        response.close()
        grant.enrolled_endpoint_id = 'new-vm'
        db.session.commit()
        self.assertEqual(self.client.get(url, headers=headers).status_code, 403)
        grant.enrolled_endpoint_id = None
        grant.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.get(url, headers=headers).status_code, 403)
        grant.expires_at = datetime.utcnow() + timedelta(minutes=1)
        task.status = 'Cancelled'
        db.session.commit()
        self.assertEqual(self.client.get(url + '/status', headers=headers).status_code, 403)

    def signed_enrollment(self, token, key, hw_id='NEW-WINDOWS'):
        pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        import time
        data = dict(global_token=token, hw_id=hw_id, hostname='BOOT-TEST', os_type='Windows', agent_version='2.0.1-rc.4',
                    agent_public_key_pem=pem, agent_key_fingerprint=agent_gateway.agent_key_fingerprint(pem),
                    signed_at=str(int(time.time())), signed_nonce=uuid.uuid4().hex)
        data['body_hash'] = agent_gateway.agent_request_body_hash(data)
        message = agent_gateway.canonical_agent_signature_message('/api/agent/enroll', hw_id, '', data['agent_version'],
            data['body_hash'], data['signed_at'], data['signed_nonce'])
        data['signature'] = base64.b64encode(key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
        return data

    def test_enrollment_requires_signed_matching_identity_and_never_takes_existing_host(self):
        task, payload = self.dispatch(self.create_profile())
        task.status = 'PickedUp'
        db.session.commit()
        token = payload['__agent_bootstrap']['enrollment_token']
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with self.app.test_request_context('/api/agent/enroll'):
            data = self.signed_enrollment(token, key)
            data['signature'] = ''
            self.assertIsNone(bootstrap.enrollment_grant(data))
            row = bootstrap.enrollment_grant(self.signed_enrollment(token, key))
            self.assertIsNotNone(row)
            db.session.commit()
            self.assertIsNotNone(bootstrap.enrollment_grant(self.signed_enrollment(token, key)))  # lost-response retry
            other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            self.assertIsNone(bootstrap.enrollment_grant(self.signed_enrollment(token, other)))
            self.assertIsNone(bootstrap.enrollment_grant(self.signed_enrollment(token, key, 'OTHER-WINDOWS')))
            row.enrolled_endpoint_id = row.enrolled_key_fingerprint = None
            self.assertIsNone(bootstrap.enrollment_grant(self.signed_enrollment(token, key, 'h2')))

    def test_dispatch_denies_api_and_unapproved_source(self):
        package_id = self.create_profile()
        task = AgentTask(id=str(uuid.uuid4()), endpoint_id='h1', source_type='manual', action_type='run_script',
                         payload=json.dumps(dict(script=bootstrap.MARKER, bootstrap_package_id=package_id)))
        with self.app.test_request_context('/api/infrastructure/tasks'):
            session['api_key_auth'] = True
            with self.assertRaises(PermissionError):
                bootstrap.attach(task, self.user)

    def test_actual_enrollment_route_registers_pending_and_binds_exact_identity(self):
        task, payload = self.dispatch(self.create_profile())
        task.status = 'PickedUp'
        db.session.commit()
        token = payload['__agent_bootstrap']['enrollment_token']
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with mock.patch.object(agent_gateway, 'enrollment_source_allowed', return_value=True):
            response = self.post('/api/agent/enroll', json=self.signed_enrollment(token, key))
            self.assertEqual(response.status_code, 200, response.json)
            self.assertEqual(response.json['approval_status'], 'Pending')
            endpoint = db.session.get(Endpoint, 'NEW-WINDOWS')
            self.assertEqual(endpoint.approval_status, 'Pending')
            self.assertTrue(agent_gateway.get_agent_public_key(endpoint))
            other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            self.assertEqual(self.post('/api/agent/enroll', json=self.signed_enrollment(token, other, 'OTHER-VM')).status_code, 401)
            # Same signed identity can retry a lost enrollment response.
            self.assertEqual(self.post('/api/agent/enroll', json=self.signed_enrollment(token, key)).status_code, 200)

    def test_migration_creates_and_drops_grant_table(self):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        import sqlalchemy as sa
        spec = importlib.util.spec_from_file_location('bootstrap_migration', ROOT / 'WinHUB/migrations/versions/20261124_01_agent_bootstrap.py')
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        engine = sa.create_engine('sqlite://')
        with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            self.assertIn('agent_bootstrap_grants', sa.inspect(connection).get_table_names())
            migration.downgrade()
            self.assertNotIn('agent_bootstrap_grants', sa.inspect(connection).get_table_names())
        engine.dispose()
