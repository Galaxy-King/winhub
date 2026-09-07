"""Regression coverage for node inventory and group workspace UX contracts."""
from pathlib import Path
import unittest
from unittest import mock

from flask import Flask
from jinja2 import Environment

from core.database import db, Endpoint, EndpointGroup, User
from modules.Infrastructure import routes


ROOT = Path(__file__).resolve().parents[1]


class InfrastructureInventoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = 'inventory-ux-isolated-tests'
        cls.app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
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
        self.admin = User(username='inventory-admin', is_admin=True, is_active=True)
        self.group = EndpointGroup(id='group-ux', name='Terminal servers', description='Production RDS nodes')
        self.hosts = [
            Endpoint(
                id=f'host-{index}',
                hostname=f'NODE-{index}',
                approval_status='Approved',
                is_blocked=False,
                groups=[self.group] if index < 3 else [],
            )
            for index in (1, 2, 3)
        ]
        db.session.add_all([self.admin, *self.hosts])
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session.update(user_id=self.admin.id, username=self.admin.username, is_admin=True)
        self.thread_guard = mock.patch.object(routes, 'auto_thread_started', True)
        self.thread_guard.start()

    def tearDown(self):
        self.thread_guard.stop()
        db.session.remove()
        self.context.pop()

    def post_bulk(self, action, endpoint_ids):
        return self.client.post(
            '/api/infrastructure/group/group-ux/members/bulk',
            json={'action': action, 'endpoint_ids': endpoint_ids},
        )

    def test_group_detail_exposes_block_state(self):
        response = self.client.get('/api/infrastructure/group/group-ux')
        self.assertEqual(response.status_code, 200, response.json)
        members = {item['id']: item for item in response.json['data']['members']}
        self.assertFalse(members['host-1']['is_blocked'])
        self.assertFalse(members['host-2']['is_blocked'])

    def test_selected_hosts_can_be_blocked_and_unblocked(self):
        response = self.post_bulk('block', ['host-1'])
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json['updated'], 1)
        db.session.expire_all()
        self.assertTrue(db.session.get(Endpoint, 'host-1').is_blocked)
        self.assertFalse(db.session.get(Endpoint, 'host-2').is_blocked)

        response = self.post_bulk('unblock', ['host-1'])
        self.assertEqual(response.status_code, 200, response.json)
        db.session.expire_all()
        self.assertFalse(db.session.get(Endpoint, 'host-1').is_blocked)

    def test_remove_detaches_selected_host_without_deleting_node(self):
        response = self.post_bulk('remove', ['host-1'])
        self.assertEqual(response.status_code, 200, response.json)
        db.session.expire_all()
        self.assertIsNotNone(db.session.get(Endpoint, 'host-1'))
        member_ids = {endpoint.id for endpoint in db.session.get(EndpointGroup, 'group-ux').endpoints}
        self.assertEqual(member_ids, {'host-2'})

    def test_bulk_validation_is_atomic_and_bounded(self):
        response = self.post_bulk('block', ['host-1', 'host-3'])
        self.assertEqual(response.status_code, 400, response.json)
        db.session.expire_all()
        self.assertFalse(db.session.get(Endpoint, 'host-1').is_blocked)
        self.assertFalse(db.session.get(Endpoint, 'host-2').is_blocked)

        response = self.post_bulk('remove', [f'host-{index}' for index in range(201)])
        self.assertEqual(response.status_code, 400, response.json)
        self.assertIn('limited to 200', response.json['message'])
        member_ids = {endpoint.id for endpoint in db.session.get(EndpointGroup, 'group-ux').endpoints}
        self.assertEqual(member_ids, {'host-1', 'host-2'})

    def test_bulk_action_requires_permission(self):
        user = User(username='inventory-viewer', is_admin=False, is_active=True, allowed_modules='[]')
        db.session.add(user)
        db.session.commit()
        with self.client.session_transaction() as session:
            session.update(user_id=user.id, username=user.username, is_admin=False)
        response = self.post_bulk('block', ['host-1'])
        self.assertEqual(response.status_code, 403, response.json)
        db.session.expire_all()
        self.assertFalse(db.session.get(Endpoint, 'host-1').is_blocked)


class InfrastructureInventoryStaticContractTests(unittest.TestCase):
    def read(self, relative_path):
        return (ROOT / relative_path).read_text(encoding='utf-8')

    def test_inventory_templates_parse_and_expose_compact_controls(self):
        environment = Environment()
        fleet = self.read('modules/Infrastructure/templates/tabs/_fleet.html')
        groups = self.read('modules/Infrastructure/templates/tabs/_groups.html')
        hosts = self.read('modules/Infrastructure/templates/tabs/_hosts.html')
        for source in (fleet, groups, hosts):
            environment.parse(source)

        self.assertIn('id="fleetFilterDialog"', fleet)
        self.assertIn('Apply filters', fleet)
        self.assertIn('id="fleetFilterSummary"', fleet)
        self.assertIn('id="nodesPackageRegistryPanel"', fleet)
        self.assertNotIn('id="packageRegistryCard"', fleet)
        self.assertIn('id="nodeTab-packages"', hosts)
        self.assertIn('id="groupListSearch"', groups)
        self.assertIn("bulkGroupMemberAction('remove')", groups)
        self.assertIn("bulkGroupMemberAction('block')", groups)
        self.assertIn("bulkGroupMemberAction('unblock')", groups)

    def test_launch_reason_labels_are_english(self):
        paths = (
            'modules/Infrastructure/templates/modals/_launch_reason.html',
            'modules/Infrastructure/templates/modals/_modals.html',
            'modules/Infrastructure/templates/modals/_quick_launch.html',
            'modules/Infrastructure/templates/tabs/_deploy.html',
        )
        combined = '\n'.join(self.read(path) for path in paths)
        self.assertIn('Task launch reason', combined)
        self.assertNotIn('Причина запуску', combined)
        self.assertNotIn('Вкажіть причину', combined)

    def test_validator_installer_allows_isolated_python_import(self):
        installer = self.read('deploy/debian/install_code_validator.sh')
        self.assertIn('chmod 0755 "${APP_DIR}/core"', installer)
        self.assertIn('chmod 0644 "${APP_DIR}/core/${name}"', installer)


if __name__ == '__main__':
    unittest.main()
