"""Isolated catalogue/queue/download contracts. No installers or agents are run."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import tempfile
import subprocess
import sys
import uuid
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from alembic.migration import MigrationContext
from alembic.operations import Operations
from flask import Flask
import sqlalchemy as sa

from core import software
from core.config import Config
from core.database import (db, AgentTask, Endpoint, EndpointGroup, SoftwareControl,
                           SoftwareDeployment, SoftwarePackage, SoftwareStep, TaskTemplate, User)
from core.template_security import current_template_hash
from modules.Infrastructure import routes

ROOT = Path(__file__).resolve().parents[1]


class SoftwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = 'isolated-software-tests'
        cls.app.config.update(TESTING=True, SERVER_NAME='winhub.test', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
                              SQLALCHEMY_TRACK_MODIFICATIONS=False)
        cls.pg_schema = None
        if os.environ.get('WINHUB_SOFTWARE_TEST_PG'):
            cls.pg_schema = 'software_test_' + uuid.uuid4().hex
            cls.pg_engine = sa.create_engine(os.environ['WINHUB_SOFTWARE_TEST_PG'])
            with cls.pg_engine.begin() as connection:
                connection.execute(sa.schema.CreateSchema(cls.pg_schema))
            cls.app.config.update(SQLALCHEMY_DATABASE_URI=os.environ['WINHUB_SOFTWARE_TEST_PG'],
                                  SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'options': '-csearch_path=' + cls.pg_schema}})
        db.init_app(cls.app)
        cls.app.register_blueprint(routes.infrastructure_bp)
        with cls.app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        if cls.pg_schema:
            with cls.pg_engine.begin() as connection:
                connection.execute(sa.schema.DropSchema(cls.pg_schema, cascade=True))
            cls.pg_engine.dispose()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        self.temp = tempfile.TemporaryDirectory(prefix='winhub-software-')
        self.addCleanup(self.temp.cleanup)
        self.patches = [mock.patch.object(Config, 'DATA_DIR', self.temp.name),
                        mock.patch.object(Config, 'AGENT_PUBLIC_BASE_URL', ''),
                        mock.patch.object(routes, 'SOFTWARE_PACKAGES_FILE', str(Path(self.temp.name) / 'legacy.json')),
                        mock.patch.object(routes, 'auto_thread_started', True)]
        for patch in self.patches:
            patch.start()
        self.user = User(username='software-admin', is_admin=True, is_active=True)
        self.groups = [EndpointGroup(id='g1', name='A'), EndpointGroup(id='g2', name='B')]
        self.hosts = [Endpoint(id=f'h{i}', hostname=f'Host {i}', os_type='Windows', approval_status='Approved',
                               last_seen=datetime.utcnow(), groups=self.groups if i == 1 else [self.groups[i % 2]])
                      for i in (1, 2, 3)]
        db.session.add_all([self.user, *self.hosts])
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess.update(user_id=self.user.id, username=self.user.username, is_admin=True)

    def tearDown(self):
        db.session.remove()
        self.context.pop()
        for patch in reversed(self.patches):
            patch.stop()

    def post(self, url, **kwargs):
        return self.client.post(url, base_url='https://winhub.test', **kwargs)

    def package(self, name='A', sets='Стандарт, Архіватори', **overrides):
        data = dict(name=name, version='1', package_type='custom', install_command='Write-Output installed',
                    update_command='Write-Output updated', uninstall_command='Write-Output removed',
                    detection_type='none', sets=sets, approve='1')
        data.update(overrides)
        response = self.post('/api/infrastructure/software-packages', data=data)
        self.assertEqual(response.status_code, 200, response.json)
        return response.json['package']

    def launch(self, package=None, **overrides):
        data = dict(package_ids=[package['id']] if package else [], target_ids=['h1'],
                    operation='install', launch_reason='Погоджене тестове розгортання', parallelism=2)
        data.update(overrides)
        return self.post('/api/infrastructure/software/deployments', json=data)

    def test_deduplicates_sets_hosts_and_multiple_groups_and_orders_steps(self):
        self.package('B', order='20')
        a = self.package('A', order='10')
        response = self.launch(a, sets=['Стандарт', 'Архіватори'], group_ids=['g1', 'g2'])
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual((response.json['targets'], response.json['packages'], response.json['tasks']), (3, 2, 6))
        self.assertEqual(AgentTask.query.count(), 0)
        for host in self.hosts:
            steps = SoftwareStep.query.filter_by(endpoint_id=host.id).order_by(SoftwareStep.position).all()
            self.assertEqual([json.loads(s.snapshot)['package']['name'] for s in steps], ['A', 'B'])

    def test_global_limit_across_launches_and_one_task_per_host(self):
        package = self.package()
        self.assertEqual(self.launch(package, target_ids=['h1', 'h2', 'h3']).status_code, 200)
        self.assertEqual(self.launch(package, target_ids=['h1', 'h2', 'h3']).status_code, 200)
        software.process_queue()
        software.process_queue()
        active = SoftwareStep.query.filter_by(status='Active').all()
        self.assertEqual(len(active), 2)
        self.assertEqual(len({s.endpoint_id for s in active}), 2)
        self.assertEqual(AgentTask.query.count(), 2)

    def test_success_releases_next_program_and_error_skips_rest(self):
        self.package('A', order='1')
        self.package('B', order='2')
        self.package('C', order='3')
        self.launch(sets=['Стандарт'])
        software.process_queue()
        step = SoftwareStep.query.filter_by(status='Active').one()
        task = db.session.get(AgentTask, step.task_id)
        task.status = 'Success'
        db.session.commit()
        software.process_queue()
        step = SoftwareStep.query.filter_by(status='Active').one()
        self.assertEqual(step.position, 1)
        db.session.get(AgentTask, step.task_id).status = 'Error'
        db.session.commit()
        software.process_queue()
        self.assertEqual([s.status for s in SoftwareStep.query.order_by(SoftwareStep.position)], ['Success', 'Error', 'Skipped'])

    def test_pause_cancel_and_restart_keep_current_installer(self):
        self.package('A', order='1')
        self.package('B', order='2')
        response = self.launch(sets=['Стандарт'])
        job = response.json['job_id']
        software.process_queue()
        AgentTask.query.one().status = 'PickedUp'
        db.session.commit()
        r = self.client.patch('/api/infrastructure/software/deployments/' + job, json={'action': 'pause'})
        self.assertEqual(r.status_code, 200)
        task = AgentTask.query.one()
        task.status = 'Success'
        db.session.commit()
        software.process_queue()
        self.assertEqual(SoftwareStep.query.filter_by(status='Queued').count(), 1)
        r = self.client.patch('/api/infrastructure/software/deployments/' + job, json={'action': 'resume'})
        self.assertEqual(r.status_code, 200)
        db.session.remove()  # simulate losing all in-process queue state
        software.process_queue()
        task = AgentTask.query.filter_by(status='Pending').one()
        task.status = 'PickedUp'
        db.session.commit()
        self.client.patch('/api/infrastructure/software/deployments/' + job, json={'action': 'cancel'})
        self.assertEqual(task.status, 'PickedUp')

    def test_pause_withdraws_unpicked_task_and_cancel_does_not_execute_it(self):
        package = self.package()
        job = self.launch(package).json['job_id']
        software.process_queue()
        self.client.patch('/api/infrastructure/software/deployments/' + job, json={'action':'pause'})
        self.assertEqual(SoftwareStep.query.one().status, 'Queued')
        self.assertEqual(AgentTask.query.one().status, 'SoftwareQueued')
        self.client.patch('/api/infrastructure/software/deployments/' + job, json={'action':'cancel'})
        software.process_queue()
        self.assertEqual(AgentTask.query.one().status, 'Cancelled')
        self.assertEqual(SoftwareDeployment.query.one().status, 'Cancelled')

    def test_offline_expiry_and_revoked_access(self):
        package = self.package()
        for host in self.hosts:
            host.last_seen = datetime.utcnow() - timedelta(hours=1)
        db.session.commit()
        self.launch(package, target_ids=['h1', 'h2'])
        software.process_queue()
        self.assertEqual(AgentTask.query.count(), 0)
        deployment = SoftwareDeployment.query.one()
        deployment.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        software.process_queue()
        self.assertEqual(SoftwareStep.query.filter_by(status='Skipped').count(), 2)
        self.hosts[2].last_seen = datetime.utcnow()
        self.launch(package, target_ids=['h3'])
        self.user.is_active = False
        db.session.commit()
        software.process_queue()
        self.assertEqual(SoftwareStep.query.filter_by(status='Error').count(), 1)

    def test_reboot_holds_remaining_programs(self):
        self.package('A', order='1')
        self.package('B', order='2')
        self.launch(sets=['Стандарт'])
        software.process_queue()
        task = AgentTask.query.one()
        task.status, task.result_log = 'Success', 'WINHUB_REBOOT_REQUIRED'
        db.session.commit()
        software.process_queue()
        self.assertEqual({s.status for s in SoftwareStep.query.all()}, {'RebootRequired', 'Skipped'})

    def test_recipe_approval_invalidated_by_edit_and_non_admin_cannot_approve(self):
        package = self.package()
        response = self.client.put('/api/infrastructure/software-packages/' + package['id'], data={'install_command': 'exit 42'})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertFalse(response.json['package']['approved'])
        self.assertEqual(self.launch(package).status_code, 400)
        self.user.is_admin = False
        self.user.allowed_modules = json.dumps(['Infrastructure:manage_software'])
        db.session.commit()
        response = self.client.put('/api/infrastructure/software-packages/' + package['id'], data={'approve':'1'})
        self.assertEqual(response.status_code, 403)

    def test_package_snapshot_immutable_after_edit_or_delete(self):
        package = self.package()
        self.launch(package)
        self.client.put('/api/infrastructure/software-packages/' + package['id'], data={'install_command': 'exit 42', 'approve': '1'})
        self.client.delete('/api/infrastructure/software-packages/' + package['id'])
        software.process_queue()
        snapshot = json.loads(SoftwareStep.query.one().snapshot)
        self.assertEqual(snapshot['package']['resolved_script'], 'Write-Output installed')

    def test_file_download_requires_active_task_capability_and_revokes_on_finish(self):
        content = b'fixture-installer-not-executable'
        package = self.package(package_type='msi', file=(io.BytesIO(content), 'fixture.msi'))
        self.launch(package)
        software.process_queue()
        step = SoftwareStep.query.one()
        task = AgentTask.query.one()
        script = json.loads(task.payload)['script']
        encoded = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        cfg = json.loads(base64.b64decode(encoded))
        self.assertNotIn('/api/public/dl/', script)
        url = '/api/public/software-delivery/' + step.id
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get(url).status_code, 403)
        self.assertEqual(anonymous.get(url, headers={'Authorization': 'Bearer invalid'}).status_code, 403)
        delivery = json.loads(task.payload)['__software_package']
        self.assertEqual(delivery['path'], url)
        self.assertNotIn('https://', delivery['path'])
        self.assertTrue(cfg['agent_download'])
        self.assertEqual(cfg['url'], '')
        headers = {'Authorization': 'Bearer ' + delivery['token']}
        self.assertEqual(anonymous.get(url, headers=headers).status_code, 403)  # not picked up
        task.status = 'PickedUp'
        db.session.commit()
        # Exercise the real global auth hook, not only the Infrastructure blueprint guard.
        from core import handle_security_and_auth
        with mock.patch.dict(self.app.before_request_funcs, {None: [handle_security_and_auth]}):
            self.assertEqual(anonymous.get(url).status_code, 403)
            self.assertEqual(anonymous.get(url, headers={'Authorization': 'Bearer invalid'}).status_code, 403)
            response = anonymous.get(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, content)
        response.close()
        db.session.expire_all()
        self.assertIsNone(db.session.get(SoftwareStep, step.id).download_lease)
        task = db.session.get(AgentTask, task.id)
        task.status = 'Success'
        db.session.commit()
        self.assertEqual(anonymous.get(url, headers=headers).status_code, 403)
        self.assertEqual(anonymous.get('/api/public/software-packages/' + package['id'] + '/download').status_code, 410)

    def test_leases_limit_downloads_and_token_expiry(self):
        package = self.package(file=(io.BytesIO(b'bytes'), 'fixture.exe'))
        self.launch(package)
        software.process_queue()
        step, task = SoftwareStep.query.one(), AgentTask.query.one()
        step.token_hash = hashlib.sha256(b'test-capability').hexdigest()
        step.download_until = datetime.utcnow() + timedelta(minutes=1)
        task.status = 'PickedUp'
        db.session.commit()
        url, headers = '/api/public/software-delivery/' + step.id, {'Authorization': 'Bearer test-capability'}
        self.assertEqual(self.app.test_client().get(url, headers=headers).status_code, 429)
        step.token_until = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.app.test_client().get(url, headers=headers).status_code, 403)

    def test_preparation_is_background_and_never_overwrites_new_edit(self):
        control = software.lock_control()
        cfg = software.settings(control)
        cfg['source_origin'] = 'https://omv.test:3670'
        control.settings = json.dumps(cfg)
        db.session.commit()
        with mock.patch.object(software, 'prepare_url') as prepare:
            package = self.package(package_type='msi', install_command='', external_url='https://omv.test:3670/api/public/dl/key/a.msi')
            prepare.assert_not_called()
        self.assertEqual(package['preparation'], 'Queued')
        self.assertEqual(self.launch(package).status_code, 400)
        digest, size = software.store_blob([b'prepared'])
        with mock.patch.object(software, 'prepare_url', return_value=(digest, size)):
            software.process_preparation()
        record = json.loads(db.session.get(SoftwarePackage, package['id']).record)
        self.assertEqual(record['preparation'], 'Ready')
        self.assertTrue(software.public_package(record)['approved'])
        self.assertEqual(self.launch(package).status_code, 200)
        self.client.put('/api/infrastructure/software-packages/' + package['id'], data={'prepare':'1', 'approve':'1'})
        def edit_during_fetch(*args):
            current = json.loads(db.session.get(SoftwarePackage, package['id']).record)
            current.update(preparation_id='new-edit', name='New edit', preparation='Queued')
            db.session.get(SoftwarePackage, package['id']).record = json.dumps(current)
            db.session.commit()
            return digest, size
        with mock.patch.object(software, 'prepare_url', side_effect=edit_during_fetch):
            software.process_preparation()
        current = json.loads(db.session.get(SoftwarePackage, package['id']).record)
        self.assertEqual(current['preparation_id'], 'new-edit')
        self.assertEqual(current['preparation'], 'Queued')
        self.assertEqual(current['name'], 'New edit')

    def test_workspace_requires_valid_approval_and_freezes_exact_code(self):
        template = TaskTemplate(id='workspace-1', name='Install', action_type='run_script', type='action',
                                payload=json.dumps({'script': 'Write-Output workspace'}), is_approved=True)
        template.approved_content_hash = current_template_hash(template)
        db.session.add(template)
        db.session.commit()
        package = self.package(install_template_id=template.id)
        self.assertEqual(self.launch(package).status_code, 200)
        template.payload = json.dumps({'script': 'exit 42'})
        db.session.commit()
        self.assertEqual(self.launch(package).status_code, 400)
        self.assertEqual(json.loads(SoftwareStep.query.one().snapshot)['package']['resolved_script'], 'Write-Output workspace')

    def test_reject_invalid_input_non_windows_unknown_group_and_http(self):
        package = self.package()
        for extra in ({'operation':'invalid'}, {'group_ids':['unknown']}, {'target_ids':['missing']},
                      {'package_ids':[]}, {'parallelism':100}, {'sets':'bad'}, {'launch_reason':''}):
            with self.subTest(extra=extra):
                self.assertIn(self.launch(package, **extra).status_code, (400, 403))
        self.hosts[0].os_type = 'Linux'
        db.session.commit()
        self.assertEqual(self.launch(package).status_code, 400)

    def test_no_unscoped_api_key_dispatch_or_generic_job_retry(self):
        package = self.package()
        response = self.launch(package)
        job = response.json['job_id']
        self.assertEqual(self.post('/api/infrastructure/job/' + job + '/retry-failed', json={'launch_reason':'test'}).status_code, 409)
        with self.client.session_transaction() as sess:
            sess['api_key_auth'] = True
        self.assertEqual(self.launch(package).status_code, 403)

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Windows PowerShell required')
    def test_agent_delivered_package_wrapper_executes_detect_and_rejects_bad_hash(self):
        root = Path(self.temp.name)
        source = root / 'downloaded.bin'
        source.write_bytes(b'verified fixture')
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        record = dict(name='Fixture', version='1', sha256=digest, package_type='exe', detection_type='none',
                      expected_exit_codes='0,3010', resolved_script='Write-Output "fixture recipe executed"')
        wrapper = root / 'wrapper.ps1'
        env = dict(os.environ, WINHUB_SOFTWARE_PACKAGE_FILE=str(source))
        def run():
            wrapper.write_text(software.make_script(record, 'install', agent_download=True), encoding='utf-8-sig')
            return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(wrapper)], env=env, capture_output=True, text=True, timeout=30)
        result = run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('fixture recipe executed', result.stdout)
        record['sha256'] = '0' * 64
        result = run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA-256 mismatch', result.stdout)
        record.update(detection_type='file_exists', detection_value=str(source))
        result = run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('already satisfied', result.stdout)
        self.assertFalse(list(root.glob('software_*')))

    def test_script_preserves_tls_and_captures_child_exit_and_quoted_metadata(self):
        script = software.make_script(dict(name="a'$(bad)", version='1', sha256='a'*64, package_type='msi',
                                           resolved_script='exit 3010', expected_exit_codes='0,3010'),
                                      'install', 'https://winhub.test/file', 'secret')
        self.assertNotIn('ServerCertificateValidationCallback', script)
        self.assertNotIn('Invoke-Expression', script)
        self.assertNotIn("a'$(bad)", script)
        self.assertIn('$code = $LASTEXITCODE', script)
        self.assertIn('WINHUB_REBOOT_REQUIRED', script)

    def test_detect_never_downloads_or_installs(self):
        package = self.package(detection_type='command', detection_value='exit 0')
        self.assertEqual(self.launch(package, operation='detect').status_code, 200)
        software.process_queue()
        plan = json.loads(SoftwareStep.query.one().snapshot)
        self.assertEqual(plan['package']['resolved_script'], '')
        self.assertEqual(plan['operation'], 'detect')

    def test_long_poll_jitter_does_not_withdraw_before_agent_can_collect(self):
        host = self.hosts[0]
        now = datetime.utcnow()
        host.last_poll_at = host.last_seen = now - timedelta(seconds=150)
        host.next_contact_max = host.last_poll_at + timedelta(seconds=240)
        package = self.package(file=(io.BytesIO(b'installer'), 'fixture.exe'))
        self.launch(package)
        with mock.patch.object(Config, 'AGENT_IDLE_POLL_SECONDS', 120), mock.patch.object(Config, 'AGENT_POLL_JITTER_SECONDS', 120):
            software.process_queue()
            step = SoftwareStep.query.one()
            task = AgentTask.query.one()
            self.assertEqual(task.status, 'Pending')
            task_id = task.id
            step.started_at = now - timedelta(seconds=150)
            db.session.commit()
            software.process_queue()
            self.assertEqual(task.status, 'Pending')
            self.assertEqual(step.status, 'Active')
            self.assertEqual(task.id, task_id)
            self.assertGreater((step.token_until - now).total_seconds(), 1800 + 300)
            from core.agent_gateway import get_pending_task_for_agent, pending_task_miss_cache
            pending_task_miss_cache.clear()
            self.assertEqual(get_pending_task_for_agent(host.id).id, task_id)
            # Once the entire 240s poll + 60s grace has elapsed, genuine silence releases capacity.
            step.started_at = host.last_seen = now - timedelta(seconds=310)
            db.session.commit()
            software.process_queue()
            self.assertEqual(task.status, 'SoftwareQueued')
            self.assertEqual(AgentTask.query.count(), 1)

    def test_pending_offline_is_held_without_duplicate_and_stalled_keeps_slot(self):
        package = self.package()
        self.launch(package)
        software.process_queue()
        step = SoftwareStep.query.one()
        old_id = step.task_id
        step.started_at = datetime.utcnow() - timedelta(minutes=3)
        self.hosts[0].last_seen = datetime.utcnow() - timedelta(minutes=3)
        db.session.commit()
        software.process_queue()
        self.assertEqual(step.status, 'Queued')
        self.assertEqual(AgentTask.query.one().status, 'SoftwareQueued')
        self.hosts[0].last_seen = datetime.utcnow()
        db.session.commit()
        software.process_queue()
        self.assertEqual(step.task_id, old_id)
        self.assertEqual(AgentTask.query.count(), 1)
        task = AgentTask.query.one()
        task.status = 'PickedUp'
        step.started_at = datetime.utcnow() - timedelta(days=2)
        db.session.commit()
        software.process_queue()
        self.assertEqual(step.status, 'Active')
        self.assertTrue(step.message)
        response = self.client.patch('/api/infrastructure/software/deployments/' + step.deployment_id,
            json={'action': 'resolve', 'step_id': step.id, 'execution_stopped': True, 'launch_reason': 'Перевірено процеси хоста'})
        self.assertEqual(response.status_code, 200, response.json)
        software.process_queue()
        self.assertEqual(step.status, 'Error')

    def test_installer_library_binding_and_explicit_approval(self):
        control = software.lock_control()
        cfg = software.settings(control)
        cfg['source_origin'] = 'https://omv.test'
        control.settings = json.dumps(cfg)
        db.session.commit()
        response = self.client.post('/api/infrastructure/software/installers', data={
            'name': 'WireGuard MSI', 'version': '1', 'external_url': 'https://omv.test/file', 'package_type': 'msi'})
        self.assertEqual(response.status_code, 200, response.json)
        registry = self.client.get('/api/infrastructure/software-packages').json
        self.assertEqual(registry['packages'], [])
        installer = registry['installers'][0]
        with self.assertRaises(ValueError):
            software.save_package('app1', {'name': 'App', 'version': '1', 'installer_id': installer['id']}, None, self.user)
        digest, size = software.store_blob([b'msi fixture'])
        with mock.patch.object(software, 'prepare_url', return_value=(digest, size)):
            software.process_preparation()
        package = software.save_package('app1', {'name': 'App', 'version': '1', 'installer_id': installer['id']}, None, self.user)
        db.session.commit()
        self.assertEqual(package['blob_sha256'], digest)
        self.assertFalse(software.public_package(package)['approved'])
        url = '/api/infrastructure/software/app1/approve'
        self.assertEqual(self.client.post(url, json={'revision': 'stale'}).status_code, 409)
        self.assertEqual(self.client.post(url, json={'revision': software.recipe_hash(package)}).status_code, 200)
        record = json.loads(db.session.get(SoftwarePackage, 'app1').record)
        self.assertTrue(software.public_package(record)['approved'])
        # Library deletion retains bound application snapshots and immutable bytes.
        response = self.client.delete('/api/infrastructure/software-packages/' + installer['id'])
        self.assertEqual(response.status_code, 200, response.json)
        self.assertIsNone(db.session.get(SoftwarePackage, installer['id']))
        self.assertEqual(json.loads(db.session.get(SoftwarePackage, 'app1').record)['blob_sha256'], digest)
        self.assertTrue(software.blob_path(digest).is_file())


    def test_update_script_only_has_no_download_capability(self):
        package = self.package(file=(io.BytesIO(b'msi'), 'fixture.msi'), update_command='exit 0', update_requires_installer='0')
        self.launch(package, operation='update')
        software.process_queue()
        payload = json.loads(AgentTask.query.one().payload)
        self.assertNotIn('__software_package', payload)

    def test_link_probe_api_and_safe_errors(self):
        with mock.patch.object(software, 'prepare_url', return_value={'content_length': 42}) as probe:
            response = self.client.post('/api/infrastructure/software/test-link', json={'url': 'https://omv.test/file'})
            self.assertEqual(response.status_code, 200, response.json)
            probe.assert_called_once_with('https://omv.test/file', probe=True)
            self.assertEqual(response.json['content_length'], 42)
        with mock.patch.object(software, 'prepare_url', side_effect=OSError('secret-url-token')):
            response = self.client.post('/api/infrastructure/software/test-link', json={'url': 'https://omv.test/file'})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn('secret-url-token', response.get_data(as_text=True))
        self.assertEqual(self.client.post('/api/infrastructure/software/test-link', json={'url': 42}).status_code, 400)

    def test_source_policy_rejects_other_origin_http_and_missing_enforcement(self):
        control = software.lock_control()
        cfg = software.settings(control)
        cfg['source_origin'] = 'https://omv.test:3670'
        control.settings = json.dumps(cfg)
        db.session.commit()
        with mock.patch.object(Config, 'OUTBOUND_POLICY_MODE', 'enforce'):
            for url in ('http://omv.test:3670/file', 'https://evil.test/file', 'https://user:pass@omv.test:3670/file'):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    software.prepare_url(url)
        with mock.patch.object(Config, 'OUTBOUND_POLICY_MODE', 'audit'), self.assertRaises(ValueError):
            software.prepare_url('https://omv.test:3670/file')

    def test_real_https_source_validates_ca_rejects_redirect_html_and_truncation(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Software test')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = Path(self.temp.name)/'cert.pem', Path(self.temp.name)/'key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        payload = b'test installer bytes'
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(302 if self.path == '/redirect' else 200)
                self.send_header('Content-Type', 'text/html' if self.path == '/html' else 'application/octet-stream')
                self.send_header('Content-Length', str(len(payload) + (5 if self.path == '/truncated' else 0)))
                self.send_header('Location', '/file')
                self.end_headers()
                self.wfile.write(payload)
        server = HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        control = software.lock_control()
        cfg = software.settings(control)
        origin = f'https://127.0.0.1:{server.server_port}'
        cfg.update(source_origin=origin, ca_bundle=str(cert_path))
        control.settings = json.dumps(cfg)
        db.session.commit()
        try:
            with mock.patch.object(Config, 'OUTBOUND_POLICY_MODE', 'enforce'), mock.patch.object(Config, 'OUTBOUND_ALLOWED_HOSTS', '127.0.0.1'):
                with mock.patch.object(software, 'store_blob', side_effect=AssertionError('Probe must not store files')):
                    self.assertIsInstance(software.prepare_url(origin + '/file', probe=True), dict)
                digest, size = software.prepare_url(origin + '/file')
                self.assertEqual((digest, size), (hashlib.sha256(payload).hexdigest(), len(payload)))
                for path in ('/redirect', '/html', '/truncated'):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        software.prepare_url(origin + path)
                cfg['ca_bundle'] = ''
                control.settings = json.dumps(cfg)
                db.session.commit()
                with self.assertRaises(ValueError):
                    software.prepare_url(origin + '/file')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_blob_hash_mismatch_never_leaves_partial_file(self):
        with self.assertRaises(ValueError):
            software.store_blob([b'bad'], expected='0' * 64)
        self.assertEqual(list(software.blob_dir().iterdir()), [])

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_generated_powershell_synthetic_exit_reboot_detect_and_safe_cleanup(self):
        cases = [('success', 'Write-Output $PackageName', 0, 'install'),
                 ('failure', 'exit 23', 1, 'install'), ('reboot', 'exit 3010', 0, 'install'),
                 ('detect', 'throw "must not execute"', 0, 'detect')]
        for name, recipe, expected, operation in cases:
            with self.subTest(name=name):
                record = dict(name="Fixture'$(bad)", version='1', resolved_script=recipe,
                              expected_exit_codes='0,3010', package_type='custom',
                              detection_type='command' if operation == 'detect' else 'none', detection_value='exit 0')
                path = Path(self.temp.name) / (name + '.ps1')
                path.write_text(software.make_script(record, operation), encoding='utf-8-sig')
                result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                                         'Bypass', '-File', str(path)], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, expected, result.stderr.decode(errors='replace'))
                if name == 'reboot':
                    self.assertIn(b'WINHUB_REBOOT_REQUIRED', result.stdout)
        self.assertEqual(list(Path(self.temp.name).glob('software_*')), [])

    @unittest.skipUnless(os.environ.get('WINHUB_SOFTWARE_TEST_PG'), 'Optional isolated PostgreSQL integration test')
    def test_postgres_global_admission_in_independent_processes(self):
        package = self.package()
        for _ in range(3):
            self.assertEqual(self.launch(package, target_ids=['h1', 'h2', 'h3']).status_code, 200)
        code = '''import os
from flask import Flask
from core.database import db
from core.software import process_queue
app=Flask(__name__)
app.config.update(SQLALCHEMY_DATABASE_URI=os.environ['WINHUB_SOFTWARE_TEST_PG'],
 SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'options': '-csearch_path=' + os.environ['WINHUB_SOFTWARE_TEST_SCHEMA']}})
db.init_app(app)
with app.app_context():
 process_queue()
 db.session.remove()
'''
        env = {**os.environ, 'WINHUB_SOFTWARE_TEST_SCHEMA': self.pg_schema}
        processes = [subprocess.Popen([sys.executable, '-W', 'ignore::DeprecationWarning', '-c', code],
                                     cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for _ in range(4)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr.decode(errors='replace')[-2000:])
        db.session.expire_all()
        active = SoftwareStep.query.filter_by(status='Active').all()
        self.assertEqual(len(active), 2)
        self.assertEqual(len({s.endpoint_id for s in active}), 2)
        self.assertEqual(AgentTask.query.count(), 2)

    def test_migration_upgrade_idempotent_without_touching_existing_tables(self):
        spec = importlib.util.spec_from_file_location('software_migration', ROOT / 'migrations/versions/20261022_01_software_deployments.py')
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        engine = sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE existing_data (value TEXT)'))
            connection.execute(sa.text("INSERT INTO existing_data VALUES ('preserved')"))
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                migration.upgrade()
            self.assertEqual(connection.execute(sa.text('SELECT value FROM existing_data')).scalar(), 'preserved')
            self.assertIn('software_steps', sa.inspect(connection).get_table_names())
        engine.dispose()


if __name__ == '__main__':
    unittest.main()
