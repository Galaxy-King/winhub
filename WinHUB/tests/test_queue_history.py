"""Queue retention and archives must preserve permissions and active work."""
import io
import json
import unittest
import zipfile
from datetime import datetime, timedelta
from unittest import mock

from core.database import db, AgentTask, ScheduleRun, ScheduledTask, SoftwareDeployment, SoftwareStep, User
from modules.Infrastructure import routes, queue_history
import test_task_launch_reason as fixture


class QueueHistoryTests(unittest.TestCase):
    setUpClass = classmethod(fixture.LaunchReasonIntegrationTests.setUpClass.__func__)
    setUp = fixture.LaunchReasonIntegrationTests.setUp
    tearDown = fixture.LaunchReasonIntegrationTests.tearDown

    def task(self, id, **values):
        defaults = dict(id=id, job_id='job-' + id, endpoint_id='host-1', endpoint_id_snapshot='host-1',
            endpoint_hostname_snapshot='TEST-1', status='Success', payload='{}', created_at=datetime(2026, 10, 24, 12),
            finished_at=datetime(2026, 10, 24, 13), result_log='fixture output')
        defaults.update(values)
        task = AgentTask(**defaults)
        db.session.add(task)
        db.session.commit()
        return task

    def test_range_has_actual_oldest_newest_and_includes_deleted_host_snapshots(self):
        self.task('a', created_at=datetime(2026, 10, 1), endpoint_id=None, endpoint_id_snapshot='deleted-host')
        self.task('b')
        data = self.client.get('/api/infrastructure/tasks/history-range').json
        self.assertEqual(data['oldest'], '2026-10-01T00:00:00Z')
        self.assertEqual(data['newest'], '2026-10-24T12:00:00Z')
        self.assertEqual(data['tasks'], 2)

    def test_archive_range_is_kyiv_inclusive_and_masks_nested_and_script_secrets(self):
        self.task('before', created_at=datetime(2026, 10, 23, 20, 59))
        self.task('first', created_at=datetime(2026, 10, 23, 21), endpoint_hostname_snapshot='../../unsafe',
            payload=json.dumps({'nested':{'password':'private'}, 'script':'echo password=private-value'}), result_log='token=private-token')
        self.task('last', created_at=datetime(2026, 10, 24, 20, 59))
        self.task('after', created_at=datetime(2026, 10, 24, 21))
        response = self.client.post('/api/infrastructure/tasks/export', json={'date_from':'2026-10-24','date_to':'2026-10-24'})
        self.assertEqual(response.status_code, 200, response.data[:100])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            self.assertEqual(manifest['tasks'], 2)
            self.assertTrue(manifest['input_included'])
            self.assertTrue(all('..' not in path.split('/') for path in archive.namelist()))
            content = '\n'.join(archive.read(path).decode() for path in archive.namelist())
            self.assertNotIn('private-value', content)
            self.assertNotIn('private-token', content)
            self.assertNotIn('"private"', content)
            self.assertIn('2026-10-24/jobs/job-first/hosts/host-1/first/task.json', archive.namelist())
        self.assertEqual(AgentTask.query.count(), 4)  # Export never deletes records.

    def test_export_empty_bad_dates_reversed_dates_and_size_limit(self):
        for body in ({}, [], {'date_from':'not-a-date','date_to':'2026-10-24'}, {'date_from':'2026-10-25','date_to':'2026-10-24'}):
            self.assertEqual(self.client.post('/api/infrastructure/tasks/export', json=body).status_code, 400)
        body = {'date_from':'2026-10-24','date_to':'2026-10-24'}
        self.assertEqual(self.client.post('/api/infrastructure/tasks/export', json=body).status_code, 404)
        self.task('a')
        with mock.patch.object(queue_history, 'MAX_BYTES', 10):
            self.assertEqual(self.client.post('/api/infrastructure/tasks/export', json=body).status_code, 413)

    def test_nonadmin_export_is_host_scoped_and_does_not_include_inputs(self):
        user = User(username='queue-reader', is_admin=False, is_active=True, allowed_modules=json.dumps(['Infrastructure:view_queue']))
        db.session.add(user)
        db.session.commit()
        self.task('allowed')
        self.task('denied', endpoint_id='host-2', endpoint_id_snapshot='host-2')
        with self.client.session_transaction() as session:
            session.update(user_id=user.id, username=user.username, is_admin=False)
        with mock.patch.object(routes, 'infra_allowed_host_ids', return_value=['host-1']):
            response = self.client.post('/api/infrastructure/tasks/export', json={'date_from':'2026-10-24','date_to':'2026-10-24'})
            self.assertEqual(response.status_code, 200, response.json)
            with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
                self.assertEqual(json.loads(archive.read('manifest.json'))['tasks'], 1)
                self.assertFalse(any(path.endswith('/input.json') for path in archive.namelist()))
            self.assertEqual(self.client.get('/api/infrastructure/tasks/history-range').json['tasks'], 1)
        self.assertEqual(self.client.post('/api/infrastructure/tasks/cleanup', json={'days':30}).status_code, 403)

    def test_cleanup_previews_custom_days_and_keeps_active_jobs_and_unknown_results(self):
        old = datetime.utcnow() - timedelta(days=80)
        self.task('expired', created_at=old, finished_at=old)
        self.task('pending', status='Pending', created_at=old, finished_at=None)
        self.task('unknown', outcome='ResultUnknown', status='Error', created_at=old, finished_at=old)
        self.task('sibling', job_id='job-pending', created_at=old, finished_at=old)
        self.task('recently-finished', created_at=old, finished_at=datetime.utcnow())
        preview = self.client.post('/api/infrastructure/tasks/cleanup', json={'days':45,'preview':True}).json
        self.assertEqual(preview['eligible'], 1)
        self.assertEqual(AgentTask.query.count(), 5)
        result = self.client.post('/api/infrastructure/tasks/cleanup', json={'days':45,'cutoff':preview['cutoff']}).json
        self.assertEqual(result['deleted'], 1)
        self.assertIsNotNone(db.session.get(AgentTask, 'pending'))
        self.assertIsNotNone(db.session.get(AgentTask, 'unknown'))
        self.assertEqual(AgentTask.query.count(), 4)

    def test_cleanup_rejects_invalid_days_and_batches_without_silent_clamping(self):
        for days in (0, -1, 3651, 1.5, True, 'text', None):
            self.assertEqual(self.client.post('/api/infrastructure/tasks/cleanup', json={'days':days}).status_code, 400)
        old = datetime.utcnow() - timedelta(days=80)
        self.task('a', created_at=old, finished_at=old)
        self.task('b', created_at=old, finished_at=old)
        with mock.patch.object(queue_history, 'BATCH_SIZE', 1):
            data = self.client.post('/api/infrastructure/tasks/cleanup', json={'days':30}).json
            self.assertEqual(data['deleted'], 1)
            self.assertTrue(data['has_more'])
        self.assertEqual(self.client.post('/api/infrastructure/tasks/cleanup', json={'days':30}).json['deleted'], 1)

    def test_api_keys_cannot_export_or_delete_history(self):
        with self.client.session_transaction() as session:
            session['api_key_auth'] = True
        self.assertEqual(self.client.post('/api/infrastructure/tasks/export', json={'date_from':'2026-10-24','date_to':'2026-10-24'}).status_code, 403)
        self.assertEqual(self.client.post('/api/infrastructure/tasks/cleanup', json={'days':30}).status_code, 403)

    def test_cleanup_protects_open_scheduler_run_and_active_software_step(self):
        old = datetime.utcnow() - timedelta(days=80)
        schedule = ScheduledTask(id='s1', name='Protected', cron_expr='0 3 * * *')
        db.session.add(schedule)
        db.session.flush()
        run = ScheduleRun(id='r1', schedule_id=schedule.id, name='Protected', category='Test',
            occurrence_key='fixture', source='scheduler', scheduled_at=old, status='ResultUnknown')
        deployment = SoftwareDeployment(id='d1', actor_user_id=self.admin.id, created_by=self.admin.username,
            launch_reason='Fixture deployment', expires_at=datetime.utcnow()+timedelta(days=1))
        db.session.add_all([run, deployment])
        db.session.commit()
        self.task('scheduled', schedule_run_id=run.id, created_at=old, finished_at=old)
        task = self.task('software', created_at=old, finished_at=old)
        db.session.add(SoftwareStep(deployment_id=deployment.id, endpoint_id='host-1', position=1,
            snapshot='{}', status='Active', task_id=task.id))
        db.session.commit()
        data = self.client.post('/api/infrastructure/tasks/cleanup', json={'days':30,'preview':True}).json
        self.assertEqual(data['eligible'], 0)
        self.assertEqual(AgentTask.query.count(), 2)

    def test_legacy_records_without_job_are_archived_instead_of_silently_omitted(self):
        self.task('legacy', job_id=None)
        response = self.client.post('/api/infrastructure/tasks/export', json={'date_from':'2026-10-24','date_to':'2026-10-24'})
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            self.assertEqual(json.loads(archive.read('manifest.json'))['tasks'], 1)
        self.assertEqual(self.client.get('/api/infrastructure/tasks/history-range').json['tasks'], 1)

    def test_date_range_respects_25_hour_dst_day(self):
        start, end = queue_history.date_range({'date_from':'2026-10-25','date_to':'2026-10-25'})
        self.assertEqual((end-start).total_seconds(), 25*3600)
