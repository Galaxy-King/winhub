import json
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class MobileOperatorContractTests(unittest.TestCase):
    def test_mobile_risk_hint_flags_destructive_actions(self):
        from modules.Infrastructure.routes import mobile_template_risk

        self.assertEqual(
            mobile_template_risk(types.SimpleNamespace(action_type="reboot", name="Restart endpoint")),
            "high",
        )
        self.assertEqual(
            mobile_template_risk(types.SimpleNamespace(action_type="run_script", name="Inventory audit")),
            "standard",
        )

    def test_mobile_schema_never_exposes_sensitive_defaults(self):
        from modules.Infrastructure.routes import mobile_variable_schema

        template = types.SimpleNamespace(payload=json.dumps({
            "script": "echo {{message}} {{api_token}}",
            "__variable_schema": {
                "message": {"type": "text", "default": "hello"},
                "api_token": {"type": "password", "default": "do-not-send"},
            },
        }))

        schema = mobile_variable_schema(template)

        self.assertEqual(schema["message"]["default"], "hello")
        self.assertNotIn("default", schema["api_token"])

    def test_launch_options_only_return_runnable_targets(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "mobile-operator-test"
        runnable = types.SimpleNamespace(
            id="template-1",
            name="Endpoint audit",
            category="Audit",
            action_type="run_script",
            type="action",
            created_by="admin",
            is_approved=True,
            payload=json.dumps({
                "script": "echo {{message}} {{api_token}}",
                "__variable_schema": {
                    "message": {"type": "text", "default": "hello"},
                    "api_token": {"type": "password", "default": "hidden"},
                },
            }),
        )
        report = types.SimpleNamespace(
            id="report-template",
            name="Report",
            category="Reports",
            action_type="report",
            type="report",
            created_by="admin",
            is_approved=True,
            payload="{}",
        )
        allowed = types.SimpleNamespace(
            id="host-1",
            hostname="PHONE-QA-01",
            display_name="QA workstation",
            connection_ip="10.0.0.10",
            os_type="Windows",
            approval_status="Approved",
            is_blocked=False,
            last_seen=datetime.utcnow(),
        )
        blocked = types.SimpleNamespace(
            id="host-2",
            hostname="PHONE-QA-02",
            display_name="Blocked workstation",
            connection_ip="10.0.0.11",
            os_type="Windows",
            approval_status="Approved",
            is_blocked=True,
            last_seen=datetime.utcnow(),
        )
        group = types.SimpleNamespace(id="group-1", name="QA group", endpoints=[allowed, blocked])
        template_query = mock.Mock()
        template_query.order_by.return_value.all.return_value = [runnable, report]
        template_model = types.SimpleNamespace(category=object(), name=object(), query=template_query)
        core = types.SimpleNamespace(get_allowed_groups=mock.Mock(return_value=[group]))

        with app.test_request_context("/api/infrastructure/task-launch/options"):
            session["user_id"] = "user-1"
            session["username"] = "admin"
            with mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(
                routes, "TaskTemplate", template_model
            ), mock.patch.object(routes, "can", return_value=True), mock.patch.object(
                routes, "can_use_template", return_value=True
            ), mock.patch.object(
                routes, "get_allowed_hosts_light", return_value=[allowed, blocked]
            ), mock.patch.object(routes, "WinHubCore", core):
                response = routes.task_launch_options()
                data = response.get_json()

        self.assertTrue(data["success"])
        self.assertEqual([item["id"] for item in data["templates"]], ["template-1"])
        self.assertEqual([item["id"] for item in data["hosts"]], ["host-1"])
        self.assertEqual(data["groups"], [{"id": "group-1", "name": "QA group", "hosts_count": 1}])
        self.assertNotIn("default", data["templates"][0]["variable_schema"]["api_token"])

    def test_mobile_shell_uses_cards_and_dedicated_assets(self):
        template = (ROOT / "modules/Infrastructure/templates/mobile_operator.html").read_text(encoding="utf-8")
        base = (ROOT / "templates/mobile_base.html").read_text(encoding="utf-8")

        self.assertRegex(template, r"\{%\s*extends\s+['\"]mobile_base\.html['\"]\s*%\}")
        self.assertIn('data-mobile-view="tasks"', template)
        self.assertIn('data-mobile-view="launch"', template)
        self.assertIn('data-mobile-view="reports"', template)
        self.assertNotIn("<table", template.lower())
        self.assertIn("mobile_operator.css", base)
        self.assertIn('name="csrf-token"', base)
        self.assertIn("window.fetch", base)

    def test_mobile_javascript_reuses_server_contracts_and_renders_report_as_text(self):
        javascript = (ROOT / "static/js/mobile_operator.js").read_text(encoding="utf-8")

        self.assertIn("/api/infrastructure/task-launch/options", javascript)
        self.assertIn("/api/infrastructure/tasks/all", javascript)
        self.assertIn("/api/infrastructure/templates/${encodeURIComponent(template.id)}/run", javascript)
        self.assertIn("state.launching", javascript)
        self.assertIn("moReportBody').textContent = readableReportBody", javascript)
        self.assertNotIn("moReportBody').innerHTML", javascript)


if __name__ == "__main__":
    unittest.main()
