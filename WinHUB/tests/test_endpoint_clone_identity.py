import unittest
import os
import uuid
import sqlalchemy as sa
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from datetime import datetime
from pathlib import Path

from flask import Flask
from unittest import mock
import json

from core.database import (
    db, Endpoint, EndpointDuplicateException, EndpointGroup, EndpointIdentityCommand,
    EndpointIdentityConflict, EndpointInstance, User,
)
from core import agent_gateway
from modules.Infrastructure import routes


ROOT = Path(__file__).resolve().parents[1]


class EndpointCloneIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = "clone-identity-tests"
        cls.app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
        )
        cls.pg_schema = None
        if os.environ.get('WINHUB_SOFTWARE_TEST_PG'):
            cls.pg_schema = 'clone_test_' + uuid.uuid4().hex
            cls.pg_engine = sa.create_engine(os.environ['WINHUB_SOFTWARE_TEST_PG'])
            with cls.pg_engine.begin() as connection:
                connection.execute(sa.schema.CreateSchema(cls.pg_schema))
            cls.app.config.update(SQLALCHEMY_DATABASE_URI=os.environ['WINHUB_SOFTWARE_TEST_PG'],
                SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'options': '-csearch_path=' + cls.pg_schema}})
        db.init_app(cls.app)
        cls.app.register_blueprint(routes.infrastructure_bp)
        cls.app.register_blueprint(agent_gateway.agent_gateway_bp)
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
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        self.admin = User(username="clone-admin", is_admin=True, is_active=True)
        self.group = EndpointGroup(id="clone-group", name="Clone test")
        self.endpoint = Endpoint(
            id="WINHUB-original",
            hostname="VPN-NODE",
            auth_token="agt_original",
            approval_status="Approved",
            identity_fingerprint="a" * 64,
            groups=[self.group],
        )
        db.session.add_all([self.admin, self.endpoint])
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session.update(user_id=self.admin.id, username=self.admin.username, is_admin=True)

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def record(self, session_id, fingerprint, ip):
        data = {
            "instance_session_id": session_id,
            "boot_session_id": f"boot-{session_id}",
            "instance_fingerprint": fingerprint,
            "identity_capabilities": "identity-session-v1,identity-split-v1",
            "agent_version": "3.0.0",
        }
        with self.app.test_request_context("/api/agent/poll", headers={"X-Real-IP": ip}):
            result = agent_gateway.record_endpoint_instance(self.endpoint, data)
            db.session.commit()
            return result

    def test_service_replacement_does_not_immediately_create_conflict(self):
        self.record("session-a", "1" * 64, "10.0.0.10")
        _instance, conflict = self.record("session-b", "2" * 64, "10.0.0.11")
        self.assertIsNone(conflict)
        self.assertEqual(EndpointIdentityConflict.query.count(), 0)

    def test_interleaved_sessions_create_fail_closed_conflict(self):
        self.record("session-a", "1" * 64, "10.0.0.10")
        self.record("session-b", "2" * 64, "10.0.0.11")
        _instance, conflict = self.record("session-a", "1" * 64, "10.0.0.10")
        self.assertIsNotNone(conflict)
        self.assertEqual(conflict.status, "Open")
        self.assertIn("Cloned agent identity", self.endpoint.identity_warning)

    def test_duplicate_exception_is_pair_scoped(self):
        second = Endpoint(id="WINHUB-second", hostname="VPN-NODE", approval_status="Approved", identity_fingerprint="a" * 64)
        third = Endpoint(id="WINHUB-third", hostname="VPN-NODE", approval_status="Approved", identity_fingerprint="a" * 64)
        db.session.add_all([second, third])
        db.session.add(EndpointDuplicateException(
            endpoint_a_id="WINHUB-original", endpoint_b_id="WINHUB-second", reason="confirmed distinct"
        ))
        db.session.commit()

        match, _reasons = agent_gateway.find_approved_duplicate_endpoint(
            "WINHUB-second", "VPN-NODE", "10.0.0.2", "a" * 64
        )
        self.assertEqual(match.id, "WINHUB-third")

    def test_split_api_creates_independent_endpoint_and_targeted_command(self):
        self.endpoint.network_info = '[{"name":"copied-nic"}]'
        self.endpoint.host_info = '{"machine_name":"old-vm"}'
        conflict = EndpointIdentityConflict(
            endpoint_id=self.endpoint.id,
            status="Open",
            reason="Concurrent agent sessions",
            detected_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        instance = EndpointInstance(
            endpoint_id=self.endpoint.id,
            session_id="session-target",
            boot_id="boot-target",
            instance_fingerprint="2" * 64,
            hostname="VPN-NODE-CLONE",
            connection_ip="10.0.0.11",
            capabilities="identity-session-v1,identity-split-v1",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.session.add_all([conflict, instance])
        db.session.commit()

        response = self.client.post(
            f"/api/infrastructure/identity-conflict/{conflict.id}/split",
            json={"target_session_id": "session-target", "display_name": "VPN clone"},
        )
        self.assertEqual(response.status_code, 200, response.json)
        command = EndpointIdentityCommand.query.one()
        clone = db.session.get(Endpoint, command.new_endpoint_id)
        self.assertEqual(command.target_session_id, "session-target")
        self.assertEqual(clone.display_name, "VPN clone")
        self.assertEqual(clone.approval_status, "Approved")
        self.assertEqual({group.id for group in clone.groups}, {"clone-group"})
        self.assertIsNone(clone.network_info)
        self.assertIsNone(clone.host_info)
        self.assertEqual(db.session.get(EndpointIdentityConflict, conflict.id).status, "Resolving")

    def test_three_clones_do_not_resolve_until_every_extra_session_splits(self):
        self.record('a', '1' * 64, '10.0.0.1')
        self.record('b', '2' * 64, '10.0.0.2')
        self.record('c', '3' * 64, '10.0.0.3')
        self.record('a', '1' * 64, '10.0.0.1')
        conflict = EndpointIdentityConflict.query.one()
        for sid in ('b', 'c'):
            response = self.client.post(f'/api/infrastructure/identity-conflict/{conflict.id}/split', json={'target_session_id': sid})
            self.assertEqual(response.status_code, 200, response.json)
            command = EndpointIdentityCommand.query.filter_by(target_session_id=sid).one()
            clone = db.session.get(Endpoint, command.new_endpoint_id)
            self.assertIsNone(clone.last_seen)
            command.status = 'Delivered'
            db.session.commit()
            with self.app.test_request_context('/api/agent/poll'):
                agent_gateway.complete_identity_command_for_new_endpoint(clone, {})
                db.session.commit()
            self.assertEqual(command.status, 'Completed')
            self.assertEqual(conflict.status, 'Resolving' if sid == 'b' else 'Resolved')
        self.assertEqual(EndpointDuplicateException.query.count(), 3)
        self.assertEqual(EndpointInstance.query.filter_by(endpoint_id=self.endpoint.id).count(), 1)

    @unittest.skipUnless(os.environ.get('WINHUB_SOFTWARE_TEST_PG'), 'Requires isolated PostgreSQL')
    def test_five_clones_complete_concurrently_without_lost_resolution(self):
        for i in range(5):
            self.record(f's{i}', str(i + 1) * 64, f'10.0.0.{i + 1}')
        self.record('s0', '1' * 64, '10.0.0.1')
        conflict = EndpointIdentityConflict.query.one()
        targets = []
        for i in range(1, 5):
            response = self.client.post(f'/api/infrastructure/identity-conflict/{conflict.id}/split', json={'target_session_id': f's{i}'})
            self.assertEqual(response.status_code, 200, response.json)
            command = db.session.get(EndpointIdentityCommand, response.json['command_id'])
            command.status = 'Delivered'
            targets.append(command.new_endpoint_id)
        db.session.commit()
        barrier = Barrier(4)
        def complete(target):
            with self.app.app_context():
                with self.app.test_request_context('/api/agent/poll'):
                    clone = db.session.get(Endpoint, target)
                    barrier.wait(timeout=10)
                    agent_gateway.complete_identity_command_for_new_endpoint(clone, {})
                    db.session.commit()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(complete, targets))
        db.session.expire_all()
        self.assertEqual(db.session.get(EndpointIdentityConflict, conflict.id).status, 'Resolved')
        self.assertEqual(EndpointDuplicateException.query.count(), 10)
        self.assertEqual(EndpointIdentityCommand.query.filter_by(status='Completed').count(), 4)

    def test_old_agent_can_receive_upgrade_preparation_past_software(self):
        from core.database import AgentTask
        from datetime import timedelta
        older = AgentTask(endpoint_id=self.endpoint.id, action_type='run_script', status='Pending', payload=json.dumps({'__software_package': {'path': '/delivery'}}), created_at=datetime.utcnow() - timedelta(minutes=1))
        preparation = AgentTask(endpoint_id=self.endpoint.id, action_type='run_script', status='Pending', payload=json.dumps({'script': 'prepare updater'}))
        db.session.add_all([older, preparation])
        db.session.commit()
        agent_gateway.pending_task_miss_cache.clear()
        self.assertEqual(agent_gateway.get_pending_task_for_agent(self.endpoint.id, software_capable=False).id, preparation.id)
        self.assertEqual(agent_gateway.get_pending_task_for_agent(self.endpoint.id, software_capable=True).id, older.id)

    def test_lean_poll_refreshes_only_passport_without_telemetry(self):
        from core.database import TelemetryHistory
        data = dict(hw_id=self.endpoint.id, auth_token=self.endpoint.auth_token,
                    agent_version='2.0.1-rc.1', identity_capabilities='lean-agent-v1',
                    host_info={'machine_name': 'CLONE-REAL-NAME', 'os_architecture': 'X64', 'collection_mode': 'on-demand'})
        with mock.patch.object(agent_gateway, 'get_poll_agent', return_value=self.endpoint), mock.patch.object(agent_gateway, 'verify_poll_signature_cached', return_value=(True, '')), mock.patch.object(agent_gateway, 'update_agent_connection', return_value=False):
            response = self.client.post('/api/agent/poll', json=data)
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json['status'], 'idle')
        self.assertEqual(self.endpoint.hostname, 'CLONE-REAL-NAME')
        self.assertEqual(json.loads(self.endpoint.host_info)['collection_mode'], 'on-demand')
        self.assertEqual(TelemetryHistory.query.count(), 0)
        self.assertIsNotNone(self.endpoint.last_poll_at)

    def test_contact_migration_upgrades_existing_endpoint_without_touching_secrets(self):
        import importlib.util
        import sqlalchemy as sa
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        from unittest import mock
        spec = importlib.util.spec_from_file_location('contact_migration', ROOT / 'migrations/versions/20261023_01_agent_contacts.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        engine = sa.create_engine('sqlite:///:memory:')
        with engine.begin() as connection:
            connection.execute(sa.text('CREATE TABLE endpoints (id VARCHAR(100) PRIMARY KEY, auth_token TEXT)'))
            connection.execute(sa.text("INSERT INTO endpoints VALUES ('existing', 'preserved')"))
            with mock.patch.object(module, 'op', Operations(MigrationContext.configure(connection))):
                module.upgrade()
                module.upgrade()
            self.assertIn('next_contact_max', {c['name'] for c in sa.inspect(connection).get_columns('endpoints')})
            self.assertEqual(connection.execute(sa.text('SELECT auth_token FROM endpoints')).scalar(), 'preserved')
        engine.dispose()

    def test_contacts_are_hourly_aggregates_and_track_lateness(self):
        from core.database import AgentContactHour
        from datetime import timedelta
        self.endpoint.last_poll_at = datetime.utcnow() - timedelta(minutes=10)
        self.endpoint.next_contact_max = datetime.utcnow() - timedelta(minutes=8)
        with self.app.test_request_context('/api/agent/poll'):
            agent_gateway.record_agent_contact(self.endpoint, {'next_poll_after': 75, 'poll_jitter_seconds': 30})
            db.session.commit()
            agent_gateway.record_agent_contact(self.endpoint, {'next_poll_after': 75, 'poll_jitter_seconds': 30})
            db.session.commit()
        hour = AgentContactHour.query.one()
        self.assertEqual(hour.contacts, 2)
        self.assertEqual(hour.late_contacts, 1)
        self.assertGreaterEqual(hour.max_gap_seconds, 599)
        self.assertEqual((self.endpoint.next_contact_max - self.endpoint.next_contact_min).total_seconds(), 30)

    def test_ui_exposes_clone_conflict_actions(self):
        template = (ROOT / "modules/Infrastructure/templates/tabs/_hosts.html").read_text(encoding="utf-8")
        javascript = (ROOT / "static/js/infrastructure.js").read_text(encoding="utf-8")
        self.assertIn("nodesIdentityConflictsPanel", template)
        self.assertIn("Split this VM identity", template)
        self.assertIn("splitIdentityConflict", javascript)
        self.assertIn("identity-conflict/", javascript)

    def test_gateway_no_longer_auto_adopts_duplicate_enrollment(self):
        source = (ROOT / "core/agent_gateway.py").read_text(encoding="utf-8")
        enroll = source[source.index("def enroll_agent") : source.index("def agent_poll")]
        self.assertNotIn("adopt_duplicate_endpoint_identity(", enroll)

    def test_all_agents_expose_clone_template_preparation(self):
        windows_program = (ROOT.parent / "WinHUBAgentWindows/Program.cs").read_text(encoding="utf-8")
        windows_worker = (ROOT.parent / "WinHUBAgentWindows/Worker.cs").read_text(encoding="utf-8")
        linux_program = (ROOT.parent / "WinHUBLinuxAgent/Program.cs").read_text(encoding="utf-8")
        unix_worker = (ROOT.parent / "WinHUBLinuxAgent/Worker.cs").read_text(encoding="utf-8")
        mac_program = (ROOT.parent / "WinHUBMacAgent/Program.cs").read_text(encoding="utf-8")
        for source in (windows_program, linux_program, mac_program):
            self.assertIn("--prepare-clone-template", source)
        for source in (windows_worker, unix_worker):
            self.assertIn("PrepareCloneTemplate", source)
            self.assertIn("clone-template-prepared", source)
            self.assertIn("identity-split.pending", source)
            self.assertIn("RecoverPendingIdentitySplit", source)


if __name__ == "__main__":
    unittest.main()
