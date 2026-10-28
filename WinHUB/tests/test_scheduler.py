"""Isolated recurrence, durable dispatch, result-contract and scoped API regression."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

import core
from core import scheduling as sched
from core.database import db, AgentTask, ScheduledTask, ScheduleRun, User
from modules.Infrastructure import routes
import test_task_launch_reason as fixture


class CalendarTests(unittest.TestCase):
    def rule(self, **values):
        return sched.normalize_spec(dict(kind='weekly', timezone='UTC', start='2026-10-05T03:00', every=2, weekdays=[6], **values))

    def test_fortnight_anchor_does_not_reset_at_month_boundary(self):
        dates = sched.preview(self.rule(), datetime(2026, 10, 10), 3)
        self.assertEqual(dates, ['2026-10-11T03:00:00Z', '2026-10-25T03:00:00Z', '2026-11-08T03:00:00Z'])

    def test_month_day_last_day_nth_and_last_weekday(self):
        base = dict(kind='monthly', timezone='UTC', start='2028-01-01T03:00', every=1)
        spec = sched.normalize_spec(dict(base, mode='day', day=31))
        self.assertEqual(sched.next_fire(spec, datetime(2028, 1, 31, 3)), datetime(2028, 3, 31, 3))
        spec = sched.normalize_spec(dict(base, mode='last_day'))
        self.assertEqual(sched.next_fire(spec, datetime(2028, 2, 1)), datetime(2028, 2, 29, 3))
        spec = sched.normalize_spec(dict(base, mode='weekday', weekday=5, ordinal=2))
        self.assertEqual(sched.next_fire(spec, datetime(2028, 2, 1)), datetime(2028, 2, 12, 3))
        spec = sched.normalize_spec(dict(base, mode='weekday', weekday=5, ordinal=-1))
        self.assertEqual(sched.next_fire(spec, datetime(2028, 2, 1)), datetime(2028, 2, 26, 3))

    def test_interval_is_elapsed_time_and_end_is_inclusive(self):
        spec = sched.normalize_spec(dict(kind='interval', timezone='UTC', start='2026-01-01T03:00', every=30, unit='days', end='2026-03-02T03:00'))
        self.assertEqual(sched.preview(spec, datetime(2026, 1, 1, 3)), ['2026-01-31T03:00:00Z', '2026-03-02T03:00:00Z'])

    def test_dst_gap_skips_and_fold_runs_once(self):
        spec = sched.normalize_spec(dict(kind='daily', timezone='Europe/Kyiv', start='2026-03-28T03:30', every=1))
        self.assertEqual(sched.next_fire(spec, datetime(2026, 3, 28, 4)), datetime(2026, 3, 30, 0, 30))
        self.assertEqual(sched.next_fire(spec, datetime(2026, 10, 25, 0, 31)), datetime(2026, 10, 26, 1, 30))

    def test_invalid_specs_and_ambiguous_exit_codes_rejected(self):
        for raw in [None, {}, dict(kind='weekly', timezone='UTC', start='2026-01-01T03:00', every=2, weekdays=[]),
                    dict(kind='daily', timezone='Invalid/Zone', start='2026-01-01T03:00', every=1)]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                sched.normalize_spec(raw)
        with self.assertRaises(ValueError):
            sched.normalize_policy(dict(success_codes=[0, 10], warning_codes=[10]))
        with self.assertRaises(ValueError):
            sched.normalize_policy(dict(delivery_seconds=True))

    def test_migration_is_additive_and_idempotent(self):
        path = Path(__file__).resolve().parents[1] / 'migrations/versions/20261028_01_scheduler_runs.py'
        module = importlib.util.spec_from_file_location('scheduler_migration', path)
        migration = importlib.util.module_from_spec(module)
        module.loader.exec_module(migration)
        engine = sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE scheduled_tasks (id VARCHAR(36) PRIMARY KEY, cron_expr TEXT)'))
            connection.execute(sa.text("INSERT INTO scheduled_tasks VALUES ('legacy','0 3 * * 0')"))
            connection.execute(sa.text('CREATE TABLE agent_tasks (id VARCHAR(36) PRIMARY KEY)'))
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                migration.upgrade()
            self.assertEqual(connection.execute(sa.text('SELECT cron_expr FROM scheduled_tasks')).scalar_one(), '0 3 * * 0')
        engine.dispose()


class SchedulerIntegrationTests(unittest.TestCase):
    setUpClass = classmethod(fixture.LaunchReasonIntegrationTests.setUpClass.__func__)
    setUp = fixture.LaunchReasonIntegrationTests.setUp
    tearDown = fixture.LaunchReasonIntegrationTests.tearDown
    schedule = fixture.LaunchReasonIntegrationTests.schedule

    def configured(self, **policy):
        st = self.schedule()
        st.schedule_spec = json.dumps(sched.normalize_spec(dict(kind='weekly', timezone='UTC', start='2026-10-05T03:00', every=2, weekdays=[6])))
        st.execution_policy = json.dumps(sched.normalize_policy(policy))
        st.next_run_at = datetime.utcnow() - timedelta(seconds=20)
        db.session.commit()
        return st

    def dispatch(self, st, **kwargs):
        with mock.patch.object(core, 'global_app', self.app):
            return core.run_scheduled_job(st.id, **kwargs)

    def test_dispatch_captures_policy_and_excludes_duplicate_occurrence(self):
        st = self.configured(warning_codes=[10])
        due = st.next_run_at
        first = self.dispatch(st, due_at=due)
        self.assertTrue(first['success'], first)
        self.assertEqual(ScheduleRun.query.count(), 1)
        task = AgentTask.query.one()
        self.assertIsNotNone(task.delivery_deadline)
        self.assertIn('WINHUB_RESULT_V1:', json.loads(task.payload)['script'])
        second = self.dispatch(st, due_at=due)
        self.assertFalse(second['success'])
        self.assertEqual(AgentTask.query.count(), 1)

    def test_explicit_codes_and_missing_or_forged_marker(self):
        st = self.configured(warning_codes=[10])
        self.dispatch(st)
        task = AgentTask.query.one()
        nonce = json.loads(task.payload)['__schedule_contract']['nonce']
        for code, expected in [(0, 'Success'), (10, 'Warning'), (20, 'ScriptFailed'), (21, 'VerificationFailed')]:
            cleaned = sched.receive_result(task, 'Success', f'backup output\nWINHUB_RESULT_V1:{nonce}:{code}\n')
            self.assertEqual(task.outcome, expected)
            self.assertEqual(task.exit_code, code)
            self.assertNotIn(nonce, cleaned)
        sched.receive_result(task, 'Success', 'WINHUB_RESULT_V1:wrong-nonce:0')
        self.assertEqual(task.outcome, 'ResultUnknown')
        sched.receive_result(task, 'Error', f'WINHUB_RESULT_V1:{nonce}:0')
        self.assertNotEqual(task.outcome, 'Success')

    def test_delivery_retry_reuses_task_and_expiration_never_means_script_failure(self):
        st = self.configured(retries=1, delivery_seconds=60, retry_delay_seconds=60)
        self.dispatch(st)
        task = AgentTask.query.one()
        sched.maintain(task.delivery_deadline + timedelta(seconds=1))
        self.assertEqual(task.retry_count, 1)
        self.assertEqual(task.status, 'Pending')
        self.assertIsNotNone(task.retry_after)
        sched.maintain(task.delivery_deadline + timedelta(seconds=1))
        self.assertEqual(task.outcome, 'DeliveryExpired')
        self.assertIsNone(task.exit_code)
        self.assertEqual(AgentTask.query.count(), 1)

    def test_picked_up_timeout_blocks_overlap_without_automatic_retry(self):
        st = self.configured(overlap='skip', retries=3)
        self.dispatch(st)
        task = AgentTask.query.one()
        task.status, task.picked_up_at = 'PickedUp', datetime.utcnow()
        task.result_deadline = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        sched.maintain()
        self.assertEqual(task.outcome, 'ResultUnknown')
        self.assertEqual(task.retry_count, 0)
        response = self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, launch_reason='Check overlap')
        self.assertEqual(response['state'], 'Skipped')
        self.assertEqual(AgentTask.query.count(), 1)

    def test_queue_one_retains_only_one_waiting_occurrence(self):
        st = self.configured(overlap='queue_one')
        self.dispatch(st)
        self.assertEqual(self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, launch_reason='Queue one')['state'], 'Queued')
        self.assertEqual(self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, launch_reason='Skip extra')['state'], 'Skipped')
        self.assertEqual(AgentTask.query.count(), 1)

    def test_queued_occurrence_is_claimed_once_and_disabled_schedule_pauses_it(self):
        st = self.configured(overlap='queue_one')
        self.dispatch(st)
        queued = self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, launch_reason='Queued pilot')
        task = AgentTask.query.one()
        task.status, task.outcome, task.finished_at = 'Success', 'Success', datetime.utcnow()
        sched.refresh_run(db.session.get(ScheduleRun, task.schedule_run_id))
        st.is_active = False
        db.session.commit()
        self.assertFalse(self.dispatch(st, manual_run=True, queued_run_id=queued['run_id'])['success'])
        self.assertEqual(AgentTask.query.count(), 1)
        st.is_active = True
        db.session.commit()
        result = self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, launch_reason='Queued pilot', queued_run_id=queued['run_id'])
        self.assertTrue(result['success'], result)
        self.assertEqual(AgentTask.query.count(), 2)
        self.assertFalse(self.dispatch(st, manual_run=True, queued_run_id=queued['run_id'])['success'])
        self.assertEqual(AgentTask.query.count(), 2)

    def test_cancelling_after_pickup_is_not_proof_of_process_completion(self):
        st = self.configured()
        self.dispatch(st)
        task = AgentTask.query.one()
        task.status, task.picked_up_at = 'Cancelled', datetime.utcnow()
        run = db.session.get(ScheduleRun, task.schedule_run_id)
        sched.refresh_run(run)
        self.assertEqual(run.status, 'ResultUnknown')
        self.assertIsNone(run.finished_at)

    def test_preview_save_and_scoped_history(self):
        recurrence = dict(kind='monthly', timezone='Europe/Kyiv', start='2030-01-01T03:00', every=1, mode='last_day')
        response = self.client.post('/api/infrastructure/schedule/preview', json={'recurrence': recurrence})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(len(response.json['dates']), 5)
        with mock.patch.object(core, 'reload_scheduler_jobs'):
            response = self.client.post('/api/infrastructure/schedule', json=dict(name='Monthly backup', launch_reason='Scheduled backup',
                template_id=self.template.id, target_type='host', target_id='host-1', recurrence=recurrence, execution_policy={}, is_active=True))
        self.assertEqual(response.status_code, 200, response.json)
        st = ScheduledTask.query.one()
        result = self.dispatch(st, manual_run=True, actor_user_id=self.admin.id, actor_name=self.admin.username, launch_reason='Pilot backup')
        self.assertTrue(result['success'], result)
        history = self.client.get('/api/infrastructure/schedule/history').json
        self.assertEqual(history['total'], 1)
        self.assertEqual(len(history['runs'][0]['tasks']), 1)
        outsider = User(username='outside', is_admin=False, allowed_modules='[]', is_active=True)
        db.session.add(outsider)
        db.session.commit()
        with self.client.session_transaction() as session:
            session.update(user_id=outsider.id, username=outsider.username, is_admin=False)
        self.assertEqual(self.client.get('/api/infrastructure/schedule/history').status_code, 403)

    def test_owner_revocation_blocks_new_dispatch(self):
        st = self.configured()
        self.admin.is_active = False
        db.session.commit()
        result = self.dispatch(st)
        self.assertFalse(result['success'])
        self.assertEqual(AgentTask.query.count(), 0)
        self.assertEqual(ScheduleRun.query.one().status, 'DispatchFailed')

    def test_resolve_unknown_requires_confirmation_and_does_not_claim_success(self):
        st = self.configured()
        self.dispatch(st)
        task = AgentTask.query.one()
        task.status, task.outcome, task.finished_at = 'Error', 'ResultUnknown', datetime.utcnow()
        run = ScheduleRun.query.one()
        sched.refresh_run(run)
        db.session.commit()
        url = '/api/infrastructure/schedule/history/' + run.id + '/resolve'
        self.assertEqual(self.client.post(url, json={'launch_reason':'Checked process'}).status_code, 400)
        self.assertEqual(self.client.post(url, json={'launch_reason':'Checked process', 'execution_stopped':True}).status_code, 200)
        self.assertEqual(run.status, 'ResolvedManually')
        self.assertNotEqual(task.outcome, 'Success')


class WrapperTests(unittest.TestCase):
    def test_windows_wrapper_executes_real_powershell_and_preserves_codes(self):
        if os.name != 'nt':
            self.skipTest('Windows PowerShell execution test')
        powershell = shutil.which('powershell.exe')
        if not powershell:
            self.skipTest('Windows PowerShell unavailable')
        environment = os.environ.copy()
        environment.pop('PSModulePath', None)  # Do not inherit PowerShell 7's module paths into Windows PowerShell.
        policy = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', 'Get-ExecutionPolicy'],
                                capture_output=True, text=True, timeout=10, env=environment)
        if policy.returncode or policy.stdout.strip() in ('Restricted', 'AllSigned'):
            self.skipTest('Local PowerShell policy does not permit unsigned test scripts; no policy override used')
        with tempfile.TemporaryDirectory(prefix='winhub-schedule-contract-') as temporary:
            file = Path(temporary) / 'wrapper.ps1'
            for code in (0, 10, 20, 21):
                payload = sched.script_payload({'script':f'Write-Output "fixture"; exit {code}', '__schedule_contract':{'nonce':'fixture'}}, 'Windows')
                file.write_text(payload['script'], encoding='utf-8')
                result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File', str(file)], capture_output=True, text=True, timeout=30, env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'WINHUB_RESULT_V1:fixture:{code}', result.stdout)

    def test_unix_wrapper_has_no_downloads_or_untrusted_source_interpolation(self):
        payload = sched.script_payload({'script':'printf "%s" "a\"b"; exit 21', '__schedule_contract':{'nonce':'fixture'}}, 'Linux')
        self.assertIn('base64 -d', payload['script'])
        if os.name != 'nt' and shutil.which('bash'):
            result = subprocess.run(['bash'], input=payload['script'], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertIn('WINHUB_RESULT_V1:fixture:21', result.stdout)


if __name__ == '__main__':
    unittest.main()
