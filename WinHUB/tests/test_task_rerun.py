"""Editable repeats preserve inputs and targets without replaying stale commands."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa

from core.database import db, AgentTask, Endpoint, User
from core.template_security import current_template_hash
from modules.Infrastructure import routes
import test_task_launch_reason as fixture


class TaskRerunTests(unittest.TestCase):
    setUpClass = classmethod(fixture.LaunchReasonIntegrationTests.setUpClass.__func__)
    setUp = fixture.LaunchReasonIntegrationTests.setUp
    tearDown = fixture.LaunchReasonIntegrationTests.tearDown

    def launch(self, group=False, endpoint='host-1'):
        self.template.payload = json.dumps({'script':'echo {{Folder}} {{Enabled}} {{Password}}', '__variable_schema':{
            'Folder':{'type':'text','label':'Folder'}, 'Enabled':{'type':'checkbox'}, 'Password':{'type':'password'}}})
        self.template.approved_content_hash = current_template_hash(self.template)
        db.session.commit()
        response = self.client.post('/api/infrastructure/tasks/create', json=dict(template_id=self.template.id,
            action='run_template', template_type='action', target_type='group' if group else 'hosts', target_id=self.group.id,
            target_ids=[endpoint], title='Original launch', variables={'Folder':'C:\\Archive','Enabled':'true','Password':'private-value'},
            launch_reason='Original maintenance', timeout_minutes=15))
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(response.json['success'], response.json)
        for task in AgentTask.query.filter_by(job_id=response.json['job_id']):
            task.status='Success'
        db.session.commit()
        return response.json['job_id']

    def repeat(self, job, **changes):
        context = self.client.get(f'/api/infrastructure/job/{job}/rerun')
        self.assertEqual(context.status_code, 200, context.json)
        body=dict(template_hash=context.json['template']['hash'], variables={'Folder':'C:\\New','Enabled':'false'},
            keep_secrets=['Password'], launch_reason='Repeat maintenance', timeout_minutes=20)
        body.update(changes)
        response=self.client.post(f'/api/infrastructure/job/{job}/rerun',json=body)
        return response

    def test_success_and_error_can_both_repeat_with_changed_values_and_fresh_task_ids(self):
        for status in ('Success','Error'):
            job=self.launch()
            original=AgentTask.query.filter_by(job_id=job).one()
            original.status=status
            db.session.commit()
            response=self.repeat(job)
            self.assertEqual(response.status_code,200,response.json)
            new=AgentTask.query.filter_by(job_id=response.json['job_id']).one()
            self.assertNotEqual(new.id,original.id)
            self.assertEqual(original.status,status)
            self.assertEqual(new.endpoint_id,original.endpoint_id)
            self.assertEqual(json.loads(new.payload)['script'],'echo C:\\New false private-value')
            self.assertEqual(json.loads(new.launch_context)['variables']['Folder'],'C:\\New')
            self.assertNotIn('launch_context',json.loads(new.payload))
            self.assertNotEqual(json.loads(new.payload)['__deadline_utc'],json.loads(original.payload)['__deadline_utc'])
            self.assertEqual(new.launch_reason,'Repeat maintenance')

    def test_group_membership_changes_do_not_change_original_targets(self):
        job=self.launch(group=True)
        third=Endpoint(id='host-3',hostname='NEW',approval_status='Approved',groups=[self.group])
        self.hosts[0].groups=[]
        db.session.add(third)
        db.session.commit()
        response=self.repeat(job,target_ids=['host-3'],target_type='group',target_id='attacker-group')
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual({t.endpoint_id for t in AgentTask.query.filter_by(job_id=response.json['job_id'])},{'host-1','host-2'})

    def test_deleted_target_blocks_entire_group_instead_of_partial_dispatch(self):
        job=self.launch(group=True)
        db.session.delete(self.hosts[1])
        db.session.commit()
        count=AgentTask.query.count()
        self.assertEqual(self.client.get(f'/api/infrastructure/job/{job}/rerun').status_code,403)
        self.assertEqual(AgentTask.query.count(),count)

    def test_secrets_are_not_returned_and_replacements_are_saved(self):
        from modules.Infrastructure.task_rerun import protected_field
        self.assertTrue(protected_field('Value',{'type':'Password'},'opaque-secret'))
        job=self.launch()
        context=self.client.get(f'/api/infrastructure/job/{job}/rerun')
        self.assertNotIn(b'private-value',context.data)
        secret=next(field for field in context.json['fields'] if field['name']=='Password')
        self.assertTrue(secret['has_saved'])
        response=self.repeat(job,keep_secrets=[],variables={'Folder':'X','Enabled':'true','Password':'replacement'})
        self.assertEqual(response.status_code,200,response.json)
        task=AgentTask.query.filter_by(job_id=response.json['job_id']).one()
        self.assertIn('replacement',json.loads(task.payload)['script'])
        raw=db.session.execute(sa.text('SELECT launch_context FROM agent_tasks WHERE id=:id'),{'id':task.id}).scalar()
        self.assertNotIn('replacement',raw)

    def test_changed_template_is_signalled_and_stale_preview_cannot_dispatch(self):
        job=self.launch()
        old_hash=current_template_hash(self.template)
        self.template.payload=json.dumps({'script':'echo changed {{Folder}}'})
        self.template.approved_content_hash=current_template_hash(self.template)
        db.session.commit()
        context=self.client.get(f'/api/infrastructure/job/{job}/rerun').json
        self.assertTrue(context['template_changed'])
        self.assertEqual(self.repeat(job,template_hash=old_hash).status_code,409)
        response=self.repeat(job,keep_secrets=[],variables={'Folder':'current'})
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(json.loads(AgentTask.query.filter_by(job_id=response.json['job_id']).one().payload)['script'],'echo changed current')

    def test_legacy_task_has_fields_but_no_fabricated_original_values(self):
        job=self.launch()
        task=AgentTask.query.filter_by(job_id=job).one()
        task.launch_context=None
        db.session.commit()
        context=self.client.get(f'/api/infrastructure/job/{job}/rerun').json
        self.assertFalse(context['saved_parameters'])
        self.assertEqual(next(f for f in context['fields'] if f['name']=='Folder')['value'],'')

    def test_single_host_repeat_and_repeat_of_repeat_preserve_new_input_values(self):
        job=self.launch(group=True)
        task=AgentTask.query.filter_by(job_id=job,endpoint_id='host-1').one()
        url=f'/api/infrastructure/task/{task.id}/rerun'
        context=self.client.get(url).json
        self.assertEqual(len(context['targets']),1)
        response=self.client.post(url,json=dict(template_hash=context['template']['hash'],variables={'Folder':'Single','Enabled':'true'},keep_secrets=['Password'],launch_reason='Single host repeat'))
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(AgentTask.query.filter_by(job_id=response.json['job_id']).count(),1)
        AgentTask.query.filter_by(job_id=response.json['job_id']).one().status='Success'
        db.session.commit()
        next_context=self.client.get(f'/api/infrastructure/job/{response.json["job_id"]}/rerun').json
        self.assertEqual(next(f for f in next_context['fields'] if f['name']=='Folder')['value'],'Single')

    def test_api_key_and_revoked_permissions_cannot_repeat(self):
        job=self.launch()
        with self.client.session_transaction() as session:
            session['api_key_auth']=True
        self.assertEqual(self.client.get(f'/api/infrastructure/job/{job}/rerun').status_code,403)
        with self.client.session_transaction() as session:
            session.pop('api_key_auth',None)
        with mock.patch.object(routes,'can_run_template',return_value=False):
            self.assertEqual(self.client.get(f'/api/infrastructure/job/{job}/rerun').status_code,403)
        with mock.patch.object(routes.WinHubCore,'authorized_target_ids',return_value=set()):
            self.assertEqual(self.client.get(f'/api/infrastructure/job/{job}/rerun').status_code,403)

    def test_active_or_unknown_executions_cannot_be_duplicated(self):
        job=self.launch()
        task=AgentTask.query.filter_by(job_id=job).one()
        for status,outcome in [('Pending',None),('Running',None),('Error','ResultUnknown')]:
            task.status,task.outcome=status,outcome
            db.session.commit()
            self.assertEqual(self.client.get(f'/api/infrastructure/job/{job}/rerun').status_code,409)

    def test_other_operator_cannot_reuse_saved_secrets_without_sensitive_access(self):
        job=self.launch()
        other=User(username='other',is_active=True,is_admin=False,allowed_modules=json.dumps(['Infrastructure:view_queue','Infrastructure:run_tasks']))
        db.session.add(other);db.session.commit()
        with self.client.session_transaction() as session:
            session.update(user_id=other.id,username=other.username,is_admin=False)
        with mock.patch.object(routes.WinHubCore,'authorized_target_ids',return_value={'host-1'}), mock.patch.object(routes,'can_run_template',return_value=True), mock.patch.object(routes,'can_view_sensitive_reports',return_value=False):
            context=self.client.get(f'/api/infrastructure/job/{job}/rerun')
            self.assertEqual(context.status_code,200,context.json)
            self.assertFalse(next(f for f in context.json['fields'] if f['name']=='Password')['has_saved'])
            response=self.repeat(job)
            self.assertEqual(response.status_code,403,response.json)

    def test_empty_reason_and_unknown_fields_do_not_create_new_tasks(self):
        job=self.launch()
        before=AgentTask.query.count()
        self.assertEqual(self.repeat(job,launch_reason='').status_code,400)
        self.assertEqual(self.repeat(job,variables={'NotDeclared':'value'}).status_code,400)
        self.assertEqual(AgentTask.query.count(),before)

    def test_rerun_does_not_replay_template_report_delivery_flags(self):
        job=self.launch()
        payload=json.loads(self.template.payload)
        payload.update(__auto_email_toggle=True,__auto_email_recipients='recipient@example.invalid',__auto_confluence_toggle=True)
        self.template.payload=json.dumps(payload)
        self.template.approved_content_hash=current_template_hash(self.template)
        db.session.commit()
        response=self.repeat(job)
        self.assertEqual(response.status_code,200,response.json)
        new_payload=json.loads(AgentTask.query.filter_by(job_id=response.json['job_id']).one().payload)
        self.assertFalse(any(key.startswith(('__auto_email','__auto_confluence')) for key in new_payload))

    def test_edited_original_script_is_marked_and_rerun_uses_template_code(self):
        self.template.payload=json.dumps({'script':'echo template {{Folder}}'})
        self.template.approved_content_hash=current_template_hash(self.template)
        db.session.commit()
        response=self.client.post('/api/infrastructure/tasks/create',json=dict(template_id=self.template.id,
            action='run_script',payload={'script':'echo custom {{Folder}}'},variables={'Folder':'original'},
            target_type='hosts',target_ids=['host-1'],launch_reason='Custom code fixture'))
        self.assertEqual(response.status_code,200,response.json)
        original=AgentTask.query.filter_by(job_id=response.json['job_id']).one()
        original.status='Success';db.session.commit()
        context=self.client.get(f'/api/infrastructure/job/{original.job_id}/rerun').json
        self.assertTrue(context['original_code_edited'])

    def test_template_api_also_saves_inputs(self):
        self.template.payload=json.dumps({'script':'echo {{Folder}}'})
        self.template.approved_content_hash=current_template_hash(self.template)
        db.session.commit()
        response=self.client.post(f'/api/infrastructure/templates/{self.template.id}/run',json=dict(
            target_type='hosts',target_ids=['host-1'],variables={'Folder':'API value'},launch_reason='API fixture'))
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(json.loads(AgentTask.query.filter_by(job_id=response.json['job_id']).one().launch_context)['variables']['Folder'],'API value')

    def test_additive_migration_preserves_old_tasks_and_is_idempotent(self):
        path=Path(__file__).resolve().parents[1]/'migrations/versions/20261116_01_task_launch_context.py'
        spec=importlib.util.spec_from_file_location('rerun_migration',path)
        migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
        engine=sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE agent_tasks (id TEXT PRIMARY KEY, payload TEXT)'))
            connection.execute(sa.text("INSERT INTO agent_tasks VALUES ('old', 'original')"))
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade();migration.upgrade()
            self.assertEqual(connection.execute(sa.text('SELECT payload, launch_context FROM agent_tasks')).one(),('original',None))
        engine.dispose()
