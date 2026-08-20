import json
import re
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

    def test_mobile_interface_contains_no_ukrainian_ui_copy(self):
        template = (ROOT / "modules/Infrastructure/templates/mobile_operator.html").read_text(encoding="utf-8")
        base = (ROOT / "templates/mobile_base.html").read_text(encoding="utf-8")
        javascript = (ROOT / "static/js/mobile_operator.js").read_text(encoding="utf-8")

        self.assertIsNone(re.search(r"[А-Яа-яІіЇїЄєҐґ]", template))
        self.assertIsNone(re.search(r"[А-Яа-яІіЇїЄєҐґ]", javascript))
        self.assertIn('<html lang="en">', base)

    def test_task_history_pagination_is_bounded(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "mobile-pagination-test"
        with app.test_request_context("/api/infrastructure/tasks/all?page=2&page_size=500"):
            session["user_id"] = "user-1"
            with mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(
                routes, "infra_allowed_host_ids", return_value=[]
            ):
                data = routes.get_tasks().get_json()

        self.assertEqual(data["jobs"], [])
        self.assertEqual(data["pagination"], {"page": 2, "page_size": 50, "total": 0, "has_more": False})

    def test_mobile_live_stream_only_subscribes_to_permitted_sections(self):
        from flask import Flask
        from modules.Infrastructure import routes

        app = Flask(__name__)
        with app.test_request_context("/api/infrastructure/mobile/events"), mock.patch.object(
            routes, "can", side_effect=lambda permission: permission == "view_queue"
        ), mock.patch.object(
            routes, "infrastructure_live_event_response", return_value="queue-stream"
        ) as stream:
            response = routes.mobile_live_events()

        self.assertEqual(response, "queue-stream")
        stream.assert_called_once_with(["queue"])

    def test_report_download_is_inert_plain_text(self):
        from modules.Infrastructure.routes import report_text_download_body

        rendered = report_text_download_body(
            "<h1>Summary</h1><p>One endpoint passed.</p><script>alert('x')</script><br>Done"
        )

        self.assertIn("Summary", rendered)
        self.assertIn("One endpoint passed.", rendered)
        self.assertIn("Done", rendered)
        self.assertNotIn("script", rendered.lower())
        self.assertNotIn("alert", rendered.lower())

    def test_report_download_route_enforces_plain_text_attachment(self):
        from flask import Flask
        from modules.Infrastructure import routes

        app = Flask(__name__)
        report = types.SimpleNamespace(
            id="report-1",
            title="Endpoint Compliance",
            report_data="<h1>Summary</h1><p>Passed</p>",
        )
        report_model = types.SimpleNamespace(query=types.SimpleNamespace(get=mock.Mock(return_value=report)))
        with app.test_request_context("/api/infrastructure/reports/report-1/download"), mock.patch.object(
            routes, "require_permission", return_value=None
        ), mock.patch.object(routes, "AggregatedJob", report_model), mock.patch.object(
            routes, "can_access_report", return_value=True
        ), mock.patch.object(
            routes, "report_body_for_current_user", side_effect=lambda value: value
        ):
            response = routes.download_report_text("report-1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/plain")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.get_data(as_text=True), "Summary\nPassed")

    def test_report_email_uses_visible_masked_body_and_existing_delivery_service(self):
        from flask import Flask
        from modules.Infrastructure import routes

        app = Flask(__name__)
        report = types.SimpleNamespace(
            id="report-1",
            title="Endpoint Compliance",
            report_data="token=unmasked-secret",
            status="Ready",
        )
        report_model = types.SimpleNamespace(query=types.SimpleNamespace(get=mock.Mock(return_value=report)))
        fake_session = mock.Mock()
        with app.test_request_context(
            "/api/infrastructure/reports/report-1/action",
            method="POST",
            json={
                "action": "send",
                "sender": "reports@example.com",
                "email": "first@example.com, second@example.com",
                "subject": "Endpoint Compliance",
                "custom_message": "Please review.",
                "use_gpg": True,
            },
        ), mock.patch.object(routes, "AggregatedJob", report_model), mock.patch.object(
            routes, "can_access_report", return_value=True
        ), mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(
            routes, "report_body_for_current_user", return_value="token=***"
        ) as visible_body, mock.patch.object(
            routes, "send_report_email", return_value=(True, "Report sent to 2 recipient(s).", 2)
        ) as send_email, mock.patch.object(
            routes, "write_infra_audit"
        ) as audit, mock.patch.object(
            routes, "update_report_send_status"
        ) as update_status, mock.patch.object(
            routes, "db", types.SimpleNamespace(session=fake_session)
        ):
            response = routes.action_report("report-1")

        self.assertTrue(response.get_json()["success"])
        visible_body.assert_called_once_with("token=unmasked-secret")
        send_email.assert_called_once_with(
            title="Endpoint Compliance",
            report_body="token=***",
            sender_email="reports@example.com",
            recipient_list=["first@example.com", "second@example.com"],
            custom_message="Please review.",
            use_gpg=True,
        )
        audit.assert_called_once()
        update_status.assert_called_once_with("report-1", True, 2)

    def test_report_email_rejects_header_injection_before_smtp_delivery(self):
        from flask import Flask
        from modules.Infrastructure import routes

        app = Flask(__name__)
        report = types.SimpleNamespace(id="report-1", title="Report", report_data="Body", status="Ready")
        report_model = types.SimpleNamespace(query=types.SimpleNamespace(get=mock.Mock(return_value=report)))
        with app.test_request_context(
            "/api/infrastructure/reports/report-1/action",
            method="POST",
            json={
                "action": "send",
                "sender": "reports@example.com",
                "email": "user@example.com",
                "subject": "Report\nBcc: attacker@example.com",
            },
        ), mock.patch.object(routes, "AggregatedJob", report_model), mock.patch.object(
            routes, "can_access_report", return_value=True
        ), mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(
            routes, "send_report_email"
        ) as send_email:
            response, status = routes.action_report("report-1")

        self.assertEqual(status, 400)
        self.assertIn("one line", response.get_json()["message"])
        send_email.assert_not_called()

    def test_mobile_javascript_uses_live_updates_pagination_and_safe_structured_reports(self):
        javascript = (ROOT / "static/js/mobile_operator.js").read_text(encoding="utf-8")
        routes = (ROOT / "modules/Infrastructure/routes.py").read_text(encoding="utf-8")
        template = (ROOT / "modules/Infrastructure/templates/mobile_operator.html").read_text(encoding="utf-8")
        nginx = (ROOT / "deploy/debian/nginx-winhub.conf").read_text(encoding="utf-8")

        self.assertIn("/api/infrastructure/task-launch/options", javascript)
        self.assertIn("/api/infrastructure/tasks/all?page=", javascript)
        self.assertIn("/api/infrastructure/templates/${encodeURIComponent(template.id)}/run", javascript)
        self.assertIn("state.launching", javascript)
        self.assertIn("new EventSource('/api/infrastructure/mobile/events')", javascript)
        self.assertIn("renderStructuredReport(readableBody)", javascript)
        self.assertIn("document.createElement('article')", javascript)
        self.assertNotIn("moReportBody').innerHTML", javascript)
        self.assertIn("/api/infrastructure/reports/<report_id>/download", routes)
        self.assertIn('"pagination": {', routes)
        self.assertIn("/api/infrastructure/smtp", javascript)
        self.assertIn("sendCurrentReportEmail", javascript)
        self.assertIn('data.get(\'use_gpg\') is True', routes)
        self.assertIn("mobile_permissions.send_reports", template)
        self.assertIn("moReportEmailForm", template)
        self.assertIn("(?:live|mobile)/events", nginx)
        self.assertIn("proxy_buffering off", nginx)


if __name__ == "__main__":
    unittest.main()
