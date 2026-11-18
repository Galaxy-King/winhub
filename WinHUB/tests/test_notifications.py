"""Notification integration: transactions, recipient isolation, approval and push safety."""
import base64
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from flask import Flask
from sqlalchemy import event
from sqlalchemy.orm import Session
from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa

from core.database import db, User, Endpoint, AgentTask, TaskTemplate, EndpointIdentityConflict, SoftwareDeployment, SoftwareStep
from core import notifications as service
from core.notification_models import Notification, NotificationSignal, PushIdentity, PushSubscription, PushDelivery, RememberedDevice
from core import notification_push as push
from core import notification_devices as devices
from core.auth import auth_bp
from core.config import Config
from core.template_security import current_template_hash


class NotificationTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.app = Flask(__name__, template_folder=str(root/'templates'), static_folder=str(root/'static'))
        self.app.config.update(SECRET_KEY='notification-test', TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        self.app.register_blueprint(service.bp)
        self.app.register_blueprint(auth_bp)
        self.context = self.app.app_context(); self.context.push()
        db.create_all()
        self.admin = User(username='admin', is_admin=True, is_active=True)
        self.other = User(username='other', is_admin=True, is_active=True)
        self.host = Endpoint(id='host', hostname='Host', approval_status='Approved')
        db.session.add_all([self.admin, self.other, self.host]);db.session.commit()
        service.install_listeners()
        self.client = self.app.test_client()
        self.login(self.admin)

    def tearDown(self):
        db.session.remove();db.drop_all();self.context.pop()
        for name, fn in [('before_flush',service._collect),('after_flush_postexec',service._store_signals),('do_orm_execute',service._bulk_task_update)]:
            if event.contains(Session,name,fn):event.remove(Session,name,fn)

    def login(self,user):
        with self.client.session_transaction() as session:
            session.clear();session.update(logged_in=True,user_id=user.id,username=user.username,is_admin=user.is_admin,csrf_token='test',login_at=time.time(),last_activity=time.time())

    def host_event(self):
        self.host.approval_status='Pending';db.session.commit();service.process_signals()
        return Notification.query.filter_by(user_id=self.admin.id).one()

    def test_transaction_rollback_and_deduplication(self):
        self.host.approval_status='Pending';db.session.flush()
        self.assertEqual(NotificationSignal.query.count(),1)
        db.session.rollback();self.assertEqual(NotificationSignal.query.count(),0)
        row=self.host_event()
        self.host.hostname='Changed';db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.count(),2)
        self.assertEqual(Notification.query.filter_by(user_id=self.admin.id).one().id,row.id)

    def test_inbox_read_clear_are_personal_and_do_not_delete_source(self):
        row=self.host_event()
        self.assertEqual(self.client.get('/api/notifications').json['unread'],1)
        self.client.post('/api/notifications/read',json={'ids':[row.id]})
        self.assertEqual(self.client.get('/api/notifications').json['unread'],0)
        self.client.post('/api/notifications/clear',json={})
        self.assertEqual(self.client.get('/api/notifications').json['items'],[])
        self.assertIsNotNone(db.session.get(Endpoint,self.host.id))
        self.login(self.other)
        self.assertEqual(self.client.get('/api/notifications').json['unread'],1)
        self.assertEqual(self.client.get('/notifications/'+row.id).status_code,404)

    def test_revoked_rights_and_api_key_cannot_read_old_notifications(self):
        row=self.host_event();self.admin.is_admin=False;db.session.commit()
        self.assertEqual(self.client.get('/api/notifications').json['items'],[])
        self.assertEqual(self.client.get('/notifications/'+row.id).status_code,404)
        with self.client.session_transaction() as s:s['api_key_auth']=True
        self.assertEqual(self.client.get('/api/notifications').status_code,403)

    def test_group_task_has_one_completion_and_only_initiator(self):
        tasks=[AgentTask(id=str(i),job_id='job',endpoint_id='host',actor_user_id=self.admin.id,title='Example',status='Pending') for i in (1,2)]
        db.session.add_all(tasks);db.session.commit()
        tasks[0].status='Success';db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.count(),0)
        tasks[1].status='Error';tasks[1].outcome='ExecutionFailed';db.session.commit();service.process_signals()
        rows=Notification.query.all();self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].user_id,self.admin.id)
        self.assertEqual(rows[0].severity,'error');self.assertIn('1/2',rows[0].title)
        tasks[1].status='Success';db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.count(),1)

    def test_inbox_poll_does_not_extend_idle_session_but_post_requires_csrf(self):
        from core import handle_security_and_auth
        self.app.before_request(handle_security_and_auth)
        with self.client.session_transaction() as s:s['last_activity']=time.time()-20;old=s['last_activity']
        self.assertEqual(self.client.get('/api/notifications').status_code,200)
        with self.client.session_transaction() as s:self.assertEqual(s['last_activity'],old)
        self.assertEqual(self.client.post('/api/notifications/read',json={}).status_code,403)
        self.assertEqual(self.client.post('/api/notifications/read',json={},headers={'X-CSRF-Token':'test'}).status_code,200)

    def test_bulk_cancellation_is_not_lost(self):
        db.session.add(AgentTask(id='bulk',job_id='bulk-job',endpoint_id='host',actor_user_id=self.admin.id,status='Pending'))
        db.session.commit()
        AgentTask.query.filter_by(job_id='bulk-job',status='Pending').update({'status':'Cancelled'},synchronize_session=False)
        db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.filter_by(kind='job').count(),1)

    def test_real_vapid_encryption_without_network(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        import requests
        first=self.client.post('/api/notifications/push/key',json={},base_url='https://localhost')
        self.assertEqual(first.status_code,200,first.json)
        second=self.client.post('/api/notifications/push/key',json={},base_url='https://localhost')
        self.assertEqual(first.json,second.json)
        private=ec.generate_private_key(ec.SECP256R1())
        public=private.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        subscription=dict(endpoint='https://web.push.apple.com/test',keys=dict(p256dh=base64.urlsafe_b64encode(public).decode().rstrip('='),auth=base64.urlsafe_b64encode(b'1234567890123456').decode().rstrip('=')))
        response=self.client.post('/api/notifications/push/devices',json={'subscription':subscription},base_url='https://localhost')
        self.assertEqual(response.status_code,200,response.json)
        self.host_event()
        result=requests.Response();result.status_code=201;result._content=b''
        with patch.object(push.PinnedPushTransport,'post',return_value=result) as transport:
            push.deliver_pending();self.assertEqual(transport.call_count,1)
            self.assertIn('Authorization',transport.call_args.kwargs['headers'])
            self.assertNotIn(b'WinHUB',transport.call_args.kwargs['data'])

    def test_template_review_stale_revision_and_literal_code(self):
        template=TaskTemplate(id='template',name='<script>bad</script>',action_type='run_script',type='action',payload=json.dumps({'script':'echo ok'}),created_by='admin')
        db.session.add(template);db.session.commit();service.process_signals()
        row=Notification.query.filter_by(user_id=self.admin.id,kind='template').one()
        response=self.client.get('/notifications/'+row.id)
        self.assertEqual(response.status_code,200)
        self.assertIn('&lt;script&gt;bad&lt;/script&gt;',response.text)
        self.assertEqual(self.client.post('/api/notifications/'+row.id+'/approve',json={'revision':'stale'}).status_code,409)
        result=self.client.post('/api/notifications/'+row.id+'/approve',json={'revision':current_template_hash(template)})
        self.assertEqual(result.status_code,200,result.json)
        self.assertTrue(template.is_approved)

    def test_host_review_checks_revision_and_blocks_identity_conflicts(self):
        row=self.host_event();revision=service.host_revision(self.host)
        url='/api/notifications/'+row.id+'/approve'
        self.assertEqual(self.client.post(url,json={'revision':'stale','status':'Approved'}).status_code,409)
        conflict=EndpointIdentityConflict(endpoint_id=self.host.id,status='Open',reason='Cloned identity')
        db.session.add(conflict);db.session.commit()
        self.assertEqual(self.client.post(url,json={'revision':revision,'status':'Approved'}).status_code,409)
        self.assertEqual(self.host.approval_status,'Pending')
        conflict.status='Resolved';db.session.commit()
        response=self.client.post(url,json={'revision':revision,'status':'Approved'})
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.host.approval_status,'Approved')
        self.assertTrue(service.serialize(row)['resolved'])

    def test_software_internal_tasks_do_not_duplicate_deployment_result(self):
        deployment=SoftwareDeployment(id='deployment',actor_user_id=self.admin.id,created_by=self.admin.username,
            launch_reason='Test',expires_at=datetime.utcnow()+timedelta(hours=1),status='Running')
        db.session.add(deployment);db.session.flush()
        db.session.add(SoftwareStep(deployment_id=deployment.id,endpoint_id=self.host.id,position=0,snapshot='{}'))
        task=AgentTask(job_id=deployment.id,endpoint_id=self.host.id,actor_user_id=self.admin.id,action_type='run_script',status='Success')
        db.session.add(task);db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.count(),0)
        deployment.status='Success';db.session.commit();service.process_signals()
        self.assertEqual(Notification.query.count(),1)
        self.assertEqual(Notification.query.one().kind,'deployment')

    def test_push_endpoint_rejects_private_hosts_ports_credentials_and_spoofs(self):
        for value in ['http://fcm.googleapis.com/x','https://127.0.0.1/x','https://fcm.googleapis.com.attacker.test/x','https://fcm.googleapis.com:444/x','https://x@fcm.googleapis.com/x']:
            with self.subTest(value=value),self.assertRaises(ValueError):push.endpoint_url(value)
        self.assertEqual(push.endpoint_url('https://web.push.apple.com/abc').hostname,'web.push.apple.com')

    def test_push_uses_generic_text_and_rechecks_current_permissions(self):
        row=self.host_event()
        db.session.add(PushIdentity(id=1,private_key='private',public_key='public',subject='https://example.test'))
        device=PushSubscription(id='device',user_id=self.admin.id,endpoint_hash='hash',subscription=json.dumps({'endpoint':'https://web.push.apple.com/x'}),active=True)
        db.session.add(device);db.session.flush()
        delivery=PushDelivery(notification_id=row.id,subscription_id=device.id)
        db.session.add(delivery);db.session.commit()
        with patch('pywebpush.webpush') as send:
            push.deliver_pending();self.assertEqual(send.call_count,1)
            payload=json.loads(send.call_args.kwargs['data']);self.assertEqual(payload['title'],'WinHUB');self.assertNotIn('Host',payload['body'])
        delivery.done=False;delivery.next_attempt=datetime.utcnow();self.admin.is_admin=False;db.session.commit()
        with patch('pywebpush.webpush') as send:push.deliver_pending();send.assert_not_called()
        self.assertTrue(delivery.done)

    def test_push_subscription_transfer_does_not_deliver_old_user_notifications(self):
        row=self.host_event()
        db.session.add(PushIdentity(id=1,private_key='private',public_key='public',subject='https://example.test'))
        device=PushSubscription(id='device',user_id=self.other.id,endpoint_hash='hash',subscription='{}',active=True)
        db.session.add(device);db.session.flush();db.session.add(PushDelivery(notification_id=row.id,subscription_id=device.id));db.session.commit()
        with patch('pywebpush.webpush') as send:push.deliver_pending();send.assert_not_called()

    def test_remembered_device_revocation_and_password_change(self):
        with self.app.test_request_context('/api/auth/login'):
            from flask import session
            session['user_id']=self.admin.id;devices.remember(self.admin)
            self.assertTrue(devices.remembered_valid())
            self.admin.password_hash='new-password';db.session.commit();self.assertFalse(devices.remembered_valid())

    def test_preferences_validation_and_quiet_hours(self):
        self.assertEqual(self.client.put('/api/notifications/preferences',json={'quiet_start':99}).status_code,400)
        self.assertEqual(self.client.put('/api/notifications/preferences',json={'toasts':False,'push_categories':['tasks']}).status_code,200)
        self.assertFalse(self.client.get('/api/notifications/preferences').json['settings']['toasts'])
        self.assertTrue(push.quiet_now({'quiet_start':22,'quiet_end':7},datetime(2026,1,1,23)))
        self.assertFalse(push.quiet_now({'quiet_start':22,'quiet_end':7},datetime(2026,1,1,12)))

    def test_service_worker_does_not_cache_authenticated_pages(self):
        response=self.client.get('/winhub-sw.js');self.assertEqual(response.status_code,200)
        self.assertNotIn("addEventListener('fetch'",response.text)
        self.assertEqual(self.client.get('/manifest.webmanifest').json['display'],'standalone')

    def test_migration_idempotent_and_preserves_existing_users(self):
        path=Path(__file__).resolve().parents[1]/'migrations/versions/20261118_01_notifications.py'
        spec=importlib.util.spec_from_file_location('notification_migration',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        engine=sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE users (id INTEGER PRIMARY KEY)'))
            connection.execute(sa.text('INSERT INTO users VALUES (1)'))
            with Operations.context(MigrationContext.configure(connection)):module.upgrade();module.upgrade()
            self.assertIn('notifications',sa.inspect(connection).get_table_names())
            with Operations.context(MigrationContext.configure(connection)):module.downgrade()
            self.assertEqual(connection.execute(sa.text('SELECT id FROM users')).scalar(),1)
