"""Template guides are authorized text metadata, not executable content."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from core.database import db, TaskTemplate, User
from core.template_security import current_template_hash, template_approval_valid
from modules.Infrastructure import routes
import test_task_launch_reason as fixture


class TemplateDescriptionTests(unittest.TestCase):
    setUpClass=classmethod(fixture.LaunchReasonIntegrationTests.setUpClass.__func__)
    setUp=fixture.LaunchReasonIntegrationTests.setUp
    tearDown=fixture.LaunchReasonIntegrationTests.tearDown

    def url(self):
        return f'/api/infrastructure/templates/{self.template.id}/description'

    def test_description_save_does_not_change_code_or_approval(self):
        before=(self.template.payload,self.template.approved_content_hash,self.template.approved_at)
        text='Purpose\nЩо це робить\nUsage: select hosts and supply values.\n<script>alert(1)</script> {{NotAVariable}}'
        response=self.client.patch(self.url(),json={'description':text,'payload':{'script':'changed'},'is_approved':False})
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual((self.template.payload,self.template.approved_content_hash,self.template.approved_at),before)
        self.assertTrue(template_approval_valid(self.template))
        self.assertEqual(self.client.get(self.url()).json['description'],text)
        self.assertNotIn('NotAVariable',routes.template_variable_names(self.template))
        raw=db.session.execute(sa.text('SELECT description FROM task_templates WHERE id=:id'),{'id':self.template.id}).scalar()
        self.assertNotIn('Що це робить',raw)

    def test_create_with_description_and_old_save_keeps_existing_notes(self):
        data=dict(name='Documented',category='Test',action='run_script',type='action',payload={'script':'echo fixture'},description='How to use',is_approved=True)
        response=self.client.post('/api/infrastructure/templates',json=data)
        self.assertEqual(response.status_code,200,response.json)
        template=TaskTemplate.query.filter_by(name='Documented').one()
        self.assertEqual(template.description,'How to use')
        data['id']=template.id;data.pop('description')
        self.assertEqual(self.client.post('/api/infrastructure/templates',json=data).status_code,200)
        self.assertEqual(template.description,'How to use')

    def test_clone_export_and_import_preserve_description(self):
        self.template.description='Purpose\nUsage\nExpected results';db.session.commit()
        response=self.client.get(f'/api/infrastructure/templates/{self.template.id}/export')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['templates'][0]['description'],self.template.description)
        clone=self.client.post(f'/api/infrastructure/templates/{self.template.id}/clone')
        self.assertEqual(clone.status_code,201,clone.json)
        self.assertEqual(TaskTemplate.query.filter(TaskTemplate.id!=self.template.id).one().description,self.template.description)
        self.template.description='changed';db.session.commit()
        imported=self.client.post('/api/infrastructure/templates/import',json=response.json)
        self.assertEqual(imported.status_code,200,imported.json)
        self.assertEqual(self.template.description,'Purpose\nUsage\nExpected results')
        library=self.client.get('/api/infrastructure/templates/export').json
        self.assertTrue(all('description' in item for item in library['templates']))

    def test_import_without_description_does_not_clear_existing_text(self):
        self.template.description='Keep these notes';db.session.commit()
        data=self.client.get(f'/api/infrastructure/templates/{self.template.id}/export').json
        data['templates'][0].pop('description')
        self.assertEqual(self.client.post('/api/infrastructure/templates/import',json=data).status_code,200)
        self.assertEqual(self.template.description,'Keep these notes')

    def test_readonly_user_can_read_notes_but_cannot_edit(self):
        self.template.description='Instructions';db.session.commit()
        user=User(username='reader',is_active=True,is_admin=False,allowed_modules=json.dumps(['Infrastructure:run_tasks']))
        db.session.add(user);db.session.commit()
        with self.client.session_transaction() as session:
            session.update(user_id=user.id,username=user.username,is_admin=False)
        with mock.patch.object(routes,'can_access_template_library_entry',return_value=True):
            response=self.client.get(self.url())
            self.assertEqual(response.status_code,200,response.json)
            self.assertFalse(response.json['can_edit'])
            self.assertNotIn('payload',response.json)
            self.assertEqual(self.client.patch(self.url(),json={'description':'overwrite'}).status_code,403)

    def test_template_edit_lock_and_api_key_cannot_save_notes(self):
        with mock.patch.object(routes,'can_edit_template',return_value=False):
            self.assertEqual(self.client.patch(self.url(),json={'description':'overwrite'}).status_code,403)
        with self.client.session_transaction() as session:
            session['api_key_auth']=True
        self.assertEqual(self.client.get(self.url()).status_code,403)
        self.assertEqual(self.client.patch(self.url(),json={'description':'overwrite'}).status_code,403)

    def test_invalid_description_and_empty_description(self):
        for value in (1,[],{},'x'*32001,'invalid\x00text','\ud800'):
            response=self.client.patch(self.url(),json={'description':value})
            self.assertEqual(response.status_code,400,response.json)
        self.template.description='Existing';db.session.commit()
        self.assertEqual(self.client.patch(self.url(),json={'description':''}).status_code,200)
        self.assertEqual(self.template.description,'')

    def test_migration_is_additive_idempotent_and_preserves_existing_approval(self):
        file=Path(__file__).resolve().parents[1]/'migrations/versions/20261116_02_template_description.py'
        spec=importlib.util.spec_from_file_location('description_migration',file)
        migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
        engine=sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE task_templates (id TEXT PRIMARY KEY,payload TEXT,is_approved BOOLEAN)'))
            connection.execute(sa.text("INSERT INTO task_templates VALUES ('old','original',1)"))
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade();migration.upgrade()
            self.assertEqual(connection.execute(sa.text('SELECT payload,is_approved,description FROM task_templates')).one(),('original',1,None))
        engine.dispose()
