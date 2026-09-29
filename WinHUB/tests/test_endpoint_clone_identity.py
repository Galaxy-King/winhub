import unittest
from datetime import datetime
from pathlib import Path

from flask import Flask

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
        db.init_app(cls.app)
        cls.app.register_blueprint(routes.infrastructure_bp)
        with cls.app.app_context():
            db.create_all()

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
