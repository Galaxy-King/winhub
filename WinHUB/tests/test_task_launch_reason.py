"""No network, agents, scheduler threads or submitted scripts run in these tests."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

from alembic.migration import MigrationContext
from alembic.operations import Operations
from flask import Flask, session
import sqlalchemy as sa

from core.database import (
    db, AgentTask, AgentUpdateRollout, AiReportRequest, Endpoint, EndpointGroup,
    ScheduledTask, TaskTemplate, TriggerRule, User,
)
from core.sdk import WinHubCore
from core.task_reason import validate_launch_reason
from core.template_security import current_template_hash
from modules.Infrastructure import routes

ROOT = Path(__file__).resolve().parents[1]
REASON = 'Планова перевірка за заявкою INC-123'


class LaunchReasonValidationTests(unittest.TestCase):
    def test_required_plain_text_limits(self):
        for value in (None, 7, False, [], {}, '', ' \r\n\t', '\u200b\u200d', 'x' * 2001, 'x\x00', 'x\ud800'):
            with self.subTest(value=repr(value)[:40]), self.assertRaises(ValueError):
                validate_launch_reason(value)
        self.assertEqual(validate_launch_reason(' \n' + REASON + '\t'), REASON)
        self.assertEqual(validate_launch_reason('x' * 2000), 'x' * 2000)
        literal = '<script>alert(1)</script> {{ dangerous() }} $(command)\nSecond line'
        self.assertEqual(validate_launch_reason(literal), literal)

    def test_migration_preserves_legacy_rows_and_existing_reason_columns(self):
        path = ROOT / 'migrations/versions/20260904_02_task_launch_reason.py'
        spec = importlib.util.spec_from_file_location('launch_reason_migration', path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        engine = sa.create_engine('sqlite:///:memory:')
        try:
            with engine.begin() as connection:
                for table in migration.TABLES:
                    connection.execute(sa.text(f'CREATE TABLE {table} (id TEXT PRIMARY KEY, title TEXT)'))
                    connection.execute(sa.text(f"INSERT INTO {table} VALUES ('old', 'History preserved')"))
                with Operations.context(MigrationContext.configure(connection)):
                    migration.upgrade()
                    migration.upgrade()  # create_all/partial legacy schemas are supported.
                for table in migration.TABLES:
                    row = connection.execute(sa.text(f'SELECT title, launch_reason FROM {table}')).one()
                    self.assertEqual(tuple(row), ('History preserved', None))
                with Operations.context(MigrationContext.configure(connection)):
                    migration.downgrade()
                self.assertEqual(connection.execute(sa.text('SELECT COUNT(*) FROM agent_tasks')).scalar(), 1)
        finally:
            engine.dispose()


class LaunchReasonIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = 'launch-reason-isolated-tests'
        cls.app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
                              SQLALCHEMY_TRACK_MODIFICATIONS=False)
        db.init_app(cls.app)
        cls.app.register_blueprint(routes.infrastructure_bp)
        from modules.HistoryAudit.routes import history_bp
        cls.app.register_blueprint(history_bp)
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        self.admin = User(username='reason-test-admin', is_admin=True, is_active=True)
        self.group = EndpointGroup(id='group-1', name='Test group')
        self.hosts = [Endpoint(id=f'host-{i}', hostname=f'TEST-{i}', approval_status='Approved',
                               groups=[self.group]) for i in (1, 2)]
        self.template = TaskTemplate(id='template-1', name='Test inventory', action_type='run_script',
                                     type='action', payload=json.dumps({'script': 'echo fixture'}),
                                     is_approved=True, created_by=self.admin.username)
        self.template.approved_content_hash = current_template_hash(self.template)
        db.session.add_all([self.admin, self.template, *self.hosts])
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess.update(user_id=self.admin.id, username=self.admin.username, is_admin=True)
        self.thread_guard = mock.patch.object(routes, 'auto_thread_started', True)
        self.thread_guard.start()

    def tearDown(self):
        self.thread_guard.stop()
        db.session.remove()
        self.context.pop()

    def schedule(self, reason=REASON):
        st = ScheduledTask(id='schedule-1', name='Weekly inventory', template_id=self.template.id,
                           target_type='host', target_id='host-1', cron_expr='0 7 * * 1',
                           created_by=self.admin.username, launch_reason=reason, is_active=True)
        db.session.add(st)
        db.session.commit()
        return st

    def test_all_manual_entry_points_reject_invalid_reason_without_dispatch(self):
        self.schedule()
        old = AgentTask(id='old-task', job_id='old-job', endpoint_id='host-1', status='Error',
                        created_by=self.admin.username, payload='{}')
        db.session.add(old)
        db.session.commit()
        paths = ('/tasks/create', '/templates/template-1/run', '/software/install', '/fleet/update',
                 '/schedule', '/triggers', '/schedule/schedule-1/run-now', '/job/old-job/retry-failed')
        for path in paths:
            for value in (None, '', ' \t\n', {}, 1, 'x' * 2001):
                with self.subTest(path=path, value=repr(value)[:20]):
                    response = self.client.post('/api/infrastructure' + path, json={'launch_reason': value})
                    self.assertEqual(response.status_code, 400, response.json)
                    self.assertIn('Launch reason', response.json['message'])
                    self.assertEqual(AgentTask.query.count(), 1)
                    self.assertEqual(AgentUpdateRollout.query.count(), 0)
                    self.assertEqual(AiReportRequest.query.count(), 0)

    def test_dispatch_helpers_require_reason_even_without_http_validation(self):
        with self.app.test_request_context('/'):
            session.update(user_id=self.admin.id, username=self.admin.username, is_admin=True)
            with self.assertRaisesRegex(ValueError, 'Launch reason'):
                WinHubCore.dispatch_task(self.admin.id, 'Infrastructure', 'reboot', ['host-1'], {})
            with self.assertRaisesRegex(ValueError, 'Launch reason'):
                routes.dispatch_infrastructure_task(self.admin.id, 'reboot', ['host-1'], {}, 'Test')
            with self.assertRaisesRegex(ValueError, 'Launch reason'):
                routes.create_agent_update_wave([], self.admin.username, 1, 1)
        self.assertEqual(AgentTask.query.count(), 0)

    def test_multi_host_reason_snapshot_encryption_details_queue_and_history(self):
        reason = REASON + '\n<script>alert(1)</script> {{ 7 * 7 }}'
        response = self.client.post('/api/infrastructure/tasks/create', json={
            'title': 'Audit', 'action': 'run_script', 'payload': {'script': 'echo fixture'},
            'target_type': 'hosts', 'target_ids': ['host-1', 'host-2'], 'launch_reason': '  ' + reason + '\n',
        })
        self.assertEqual(response.status_code, 200, response.json)
        tasks = AgentTask.query.order_by(AgentTask.endpoint_id).all()
        self.assertEqual(len(tasks), 2)
        for task in tasks:
            self.assertEqual(task.launch_reason, reason)
            self.assertNotIn('launch_reason', json.loads(task.payload))
            self.assertEqual(json.loads(task.payload)['script'], 'echo fixture')
        raw = db.session.execute(sa.text('SELECT launch_reason FROM agent_tasks LIMIT 1')).scalar_one()
        self.assertNotIn(REASON, raw)
        detail = self.client.get('/api/infrastructure/task/' + tasks[0].id)
        self.assertEqual(detail.json['data']['launch_reason'], reason)
        queue = self.client.get('/api/infrastructure/tasks/all').json
        self.assertEqual(queue['jobs'][0]['launch_reason'], reason)
        status = self.client.get('/api/infrastructure/jobs/' + tasks[0].job_id + '/status')
        self.assertEqual(status.json['launch_reason'], reason)
        history = self.client.get('/api/history/log/agent_' + tasks[0].id)
        self.assertEqual(history.status_code, 200, history.json)
        self.assertIn(REASON, history.json['log'])
        # A deleted endpoint cannot remove the stored explanation.
        tasks[0].endpoint = None
        db.session.commit()
        detail = self.client.get('/api/infrastructure/task/' + tasks[0].id)
        self.assertEqual(detail.json['data']['launch_reason'], reason)

    def test_template_api_saves_reason_and_retry_requires_a_fresh_reason(self):
        response = self.client.post('/api/infrastructure/templates/template-1/run', json={
            'target_type': 'host', 'target_id': 'host-1', 'launch_reason': REASON,
        })
        self.assertEqual(response.status_code, 200, response.json)
        original = AgentTask.query.one()
        self.assertEqual(original.launch_reason, REASON)
        original.status = 'Error'
        db.session.commit()
        response = self.client.post(f'/api/infrastructure/job/{original.job_id}/retry-failed', json={
            'launch_reason': 'Повтор після відновлення мережі',
        })
        self.assertEqual(response.status_code, 200, response.json)
        retried = AgentTask.query.filter(AgentTask.id != original.id).one()
        self.assertEqual(retried.launch_reason, 'Повтор після відновлення мережі')
        self.assertEqual(original.launch_reason, REASON)
        self.assertEqual(retried.payload, original.payload)

    def test_reason_does_not_grant_execution_or_read_permission(self):
        user = User(username='no-permissions', is_admin=False, allowed_modules='[]')
        db.session.add(user)
        db.session.commit()
        with self.client.session_transaction() as sess:
            sess.update(user_id=user.id, username=user.username, is_admin=False)
        response = self.client.post('/api/infrastructure/tasks/create', json={'launch_reason': REASON})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AgentTask.query.count(), 0)
        response = self.client.get('/api/infrastructure/task/anything')
        self.assertEqual(response.status_code, 403)

    def test_scoped_api_key_requires_reason_and_keeps_group_policy(self):
        with self.client.session_transaction() as sess:
            sess.update(api_key_auth=True, api_permissions=['Infrastructure:run_tasks', 'scope:group:group-1'])
        payload = {'target_type': 'host', 'target_id': 'host-1'}
        response = self.client.post('/api/infrastructure/templates/template-1/run', json=payload)
        self.assertEqual(response.status_code, 400, response.json)
        self.assertEqual(AgentTask.query.count(), 0)
        response = self.client.post('/api/infrastructure/templates/template-1/run', json={**payload, 'launch_reason': REASON})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(AgentTask.query.one().launch_reason, REASON)
        outside = Endpoint(id='outside', hostname='Outside', approval_status='Approved')
        db.session.add(outside)
        db.session.commit()
        response = self.client.post('/api/infrastructure/templates/template-1/run', json={
            **payload, 'target_id': 'outside', 'launch_reason': REASON,
        })
        self.assertEqual(response.status_code, 403, response.json)
        self.assertEqual(AgentTask.query.count(), 1)

    def test_scheduler_copies_configured_reason_and_manual_run_uses_new_reason(self):
        import core
        st = self.schedule()
        with mock.patch.object(core, 'global_app', self.app):
            result = core.run_scheduled_job(st.id)
            self.assertTrue(result['success'], result)
            original = AgentTask.query.one()
            self.assertEqual(original.launch_reason, REASON)
            self.assertEqual(original.source_type, 'scheduler')
            st.launch_reason = 'Updated schedule reason'
            db.session.commit()
            missing = self.client.post('/api/infrastructure/schedule/schedule-1/run-now', json={})
            self.assertEqual(missing.status_code, 400)
            response = self.client.post('/api/infrastructure/schedule/schedule-1/run-now', json={'launch_reason': 'Extra check'})
            self.assertEqual(response.status_code, 200, response.json)
            manual = AgentTask.query.filter(AgentTask.id != original.id).one()
            self.assertEqual(manual.launch_reason, 'Extra check')
            self.assertEqual(original.launch_reason, REASON)
            self.assertEqual(st.launch_reason, 'Updated schedule reason')

    def test_legacy_automations_fail_closed(self):
        import core
        st = self.schedule(reason=None)
        with mock.patch.object(core, 'global_app', self.app):
            result = core.run_scheduled_job(st.id)
        self.assertFalse(result['success'])
        db.session.refresh(st)
        self.assertEqual(st.last_status, 'Launch reason required')
        rollout = AgentUpdateRollout(id='rollout-1', target_ids='["host-1"]', status='Running')
        db.session.add(rollout)
        db.session.commit()
        self.assertFalse(routes.process_one_agent_update_rollout(rollout))
        self.assertEqual(rollout.status, 'Reason required')
        self.assertIsNone(rollout.next_run_at)
        self.assertEqual(AgentTask.query.count(), 0)

    def test_trigger_uses_saved_reason_not_metric_output(self):
        from core.agent_gateway import evaluate_and_fire_triggers
        rule = TriggerRule(name='Service recovery', metric_name='health', operator='==', threshold_value='bad',
                           action_template_id=self.template.id, is_active=True, launch_reason=None)
        db.session.add(rule)
        db.session.commit()
        evaluate_and_fire_triggers('host-1', 'health', 'bad')
        self.assertEqual(AgentTask.query.count(), 0)
        self.assertEqual(rule.last_status, 'Reason required')
        rule.launch_reason = REASON
        db.session.commit()
        evaluate_and_fire_triggers('host-1', 'health', 'bad')
        self.assertEqual(AgentTask.query.one().launch_reason, REASON)

    def test_schedule_and_trigger_save_configured_reason(self):
        with mock.patch('core.reload_scheduler_jobs'):
            response = self.client.post('/api/infrastructure/schedule', json={
                'name': 'Weekly', 'template_id': self.template.id, 'target_type': 'host',
                'target_id': 'host-1', 'cron': '0 7 * * 1', 'launch_reason': REASON,
            })
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(ScheduledTask.query.one().launch_reason, REASON)
        response = self.client.post('/api/infrastructure/triggers', json={
            'name': 'Recover', 'metric_name': 'health', 'operator': '==', 'threshold_value': 'bad',
            'action_template_id': self.template.id, 'launch_reason': REASON,
        })
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(TriggerRule.query.one().launch_reason, REASON)

    def test_software_tasks_keep_reason_out_of_script(self):
        package = {'id': 'package-1', 'name': 'Fixture', 'version': '1', 'uninstall_command': 'echo uninstall'}
        for operation in ('install', 'uninstall'):
            with mock.patch.object(routes, 'find_software_package', return_value=package), \
                 mock.patch.object(routes, 'build_software_install_script', return_value='echo fixture'):
                response = self.client.post('/api/infrastructure/software/install', json={
                    'package_id': 'package-1', 'target_ids': ['host-1'], 'operation': operation, 'launch_reason': REASON,
                })
            self.assertEqual(response.status_code, 200, response.json)
        for task in AgentTask.query.all():
            self.assertEqual(task.launch_reason, REASON)
            self.assertEqual(json.loads(task.payload), {'script': 'echo fixture'})

    def test_update_prepare_and_execution_waves_have_same_reason(self):
        package = {'id': 'test-package', 'version': 'test', 'sha256': 'a' * 64}
        items = [{'host_id': 'host-1', 'platform': 'windows', 'package': package}]
        with mock.patch.object(routes, 'agent_updater_bootstrap_script', return_value='echo fixture'), \
             mock.patch.object(routes, 'resolved_agent_package_update_url', return_value='https://example.test/agent'):
            routes.create_agent_update_wave(items, self.admin.username, 1, 2, launch_reason=REASON)
        db.session.commit()
        self.assertEqual(AgentTask.query.count(), 2)
        self.assertEqual({task.launch_reason for task in AgentTask.query.all()}, {REASON})
        self.assertTrue(all('launch_reason' not in json.loads(task.payload) for task in AgentTask.query.all()))

    def test_fleet_api_persists_reason_for_later_waves(self):
        package = {'id': 'test-package', 'version': 'test', 'sha256': 'a' * 64, 'platform': 'windows'}
        items = [{'host_id': host.id, 'platform': 'windows', 'package': package} for host in self.hosts]
        with mock.patch.object(routes, 'find_agent_package', return_value=package), \
             mock.patch.object(routes, 'agent_package_response', side_effect=lambda value: dict(value)), \
             mock.patch.object(routes, 'build_agent_update_plan', return_value=(items, [])), \
             mock.patch.object(routes, 'resolved_agent_package_update_url', return_value='https://example.test/agent'), \
             mock.patch.object(routes, 'process_due_agent_update_rollouts'):
            response = self.client.post('/api/infrastructure/fleet/update', json={
                'package_id': package['id'], 'target_mode': 'selected', 'target_ids': ['host-1', 'host-2'],
                'wave_size': 1, 'wave_delay_seconds': 300, 'launch_reason': REASON,
            })
        self.assertEqual(response.status_code, 200, response.json)
        rollout = AgentUpdateRollout.query.one()
        self.assertEqual(rollout.launch_reason, REASON)
        with mock.patch.object(routes, 'find_agent_package', return_value=package), \
             mock.patch.object(routes, 'build_agent_update_plan', return_value=(items, [])), \
             mock.patch.object(routes, 'resolved_agent_package_update_url', return_value='https://example.test/agent'), \
             mock.patch.object(routes, 'agent_package_public_url', return_value='https://example.test/agent'), \
             mock.patch.object(routes, 'create_agent_update_wave') as wave:
            self.assertTrue(routes.process_one_agent_update_rollout(rollout))
            self.assertTrue(routes.process_one_agent_update_rollout(rollout))
        self.assertEqual(wave.call_count, 2)
        self.assertTrue(all(call.kwargs['launch_reason'] == REASON for call in wave.call_args_list))


if __name__ == '__main__':
    unittest.main()
