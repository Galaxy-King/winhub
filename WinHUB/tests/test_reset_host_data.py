import unittest
from pathlib import Path

from sqlalchemy import create_engine, insert, select

from core.database import db
from core.reset_host_data import RESET_TABLES, erase_host_data


class ResetHostDataTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        db.metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_reset_clears_host_state_and_preserves_users_templates_and_api_keys(self):
        tables = db.metadata.tables
        with self.engine.begin() as connection:
            connection.execute(insert(tables["users"]), {
                "id": 1, "username": "admin", "email": "admin@example.invalid",
                "password_hash": "x", "is_admin": True, "is_active": True,
            })
            connection.execute(insert(tables["api_keys"]), {
                "id": 1, "user_id": 1, "name": "automation", "key_hash": "h",
                "prefix": "p", "permissions": "[]", "allowed_networks": "[]",
            })
            connection.execute(insert(tables["task_templates"]), {
                "id": "template-1", "name": "Inventory", "action_type": "powershell",
                "payload": "Write-Output ok",
            })
            connection.execute(insert(tables["endpoint_groups"]), {"id": "group-1", "name": "Windows"})
            connection.execute(insert(tables["endpoints"]), {"id": "host-1", "hostname": "PC-1"})
            connection.execute(insert(tables["endpoint_group_membership"]), {"endpoint_id": "host-1", "group_id": "group-1"})
            connection.execute(insert(tables["agent_tasks"]), {"id": "task-1", "endpoint_id": "host-1", "title": "Inventory"})
            connection.execute(insert(tables["telemetry_history"]), {"endpoint_id": "host-1", "cpu_usage": 1.0})
            connection.execute(insert(tables["registration_history"]), {"hw_id": "host-1", "hostname": "PC-1"})
            connection.execute(insert(tables["audit_logs"]), {"id": 1, "module": "Infrastructure", "action": "Enroll"})
            counts = erase_host_data(connection, db.metadata)

            self.assertEqual(counts["endpoints"], 1)
            for name in RESET_TABLES:
                self.assertEqual(connection.execute(select(tables[name])).all(), [], name)
            self.assertEqual(len(connection.execute(select(tables["users"])).all()), 1)
            self.assertEqual(len(connection.execute(select(tables["api_keys"])).all()), 1)
            self.assertEqual(len(connection.execute(select(tables["task_templates"])).all()), 1)

    def test_reset_is_idempotent(self):
        with self.engine.begin() as connection:
            first = erase_host_data(connection, db.metadata)
            second = erase_host_data(connection, db.metadata)
        self.assertTrue(all(value == 0 for value in first.values()))
        self.assertEqual(first, second)

    def test_debian_wrapper_runs_reset_as_package_module(self):
        wrapper = (
            Path(__file__).resolve().parents[1] / "deploy/debian/reset_host_data.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('cd "${APP_DIR}"', wrapper)
        self.assertIn('"${APP_DIR}/venv/bin/python" -m core.reset_host_data "$@"', wrapper)
        self.assertNotIn(
            '"${APP_DIR}/venv/bin/python" "${APP_DIR}/core/reset_host_data.py"',
            wrapper,
        )


if __name__ == "__main__":
    unittest.main()
