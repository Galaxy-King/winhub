import contextlib
import json
import unittest
import uuid
from unittest import mock

from flask import Flask, session

from core.ai_reports import build_ai_input, process_ai_report_queue, render_safe_markdown
from core.database import AgentTask, AggregatedJob, AiReportRequest, Endpoint, ReportRevision, User, db
from core.report_versions import create_report_revision


class AiReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = "ai-report-tests"
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
        )
        db.init_app(cls.app)
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        with self.app.app_context():
            db.session.remove()
            for table in reversed(db.metadata.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()

    def _job(self):
        job_id = str(uuid.uuid4())
        user = User(username="operator", email=f"{job_id}@example.com", is_admin=True)
        endpoint = Endpoint(id=f"host-{job_id}", hostname="WG-01", display_name="WireGuard 01", approval_status="Approved")
        task = AgentTask(
            job_id=job_id,
            endpoint=endpoint,
            endpoint_id_snapshot=endpoint.id,
            endpoint_hostname_snapshot=endpoint.hostname,
            endpoint_name_snapshot=endpoint.display_name,
            title="WireGuard inventory",
            action_type="run_script",
            payload="{}",
            result_log=json.dumps({
                "endpoint": "vpn.example.test:51820",
                "api_key": "must-not-leave-winhub",
            }),
            status="Success",
            created_by=user.username,
        )
        report = AggregatedJob(id=job_id, title=task.title, status="Waiting Review", report_data="Fallback report")
        db.session.add_all([user, endpoint, task, report])
        db.session.flush()
        create_report_revision(report, report.report_data, kind="generated", actor_name="System")
        request = AiReportRequest(
            job_id=job_id,
            report_id=job_id,
            actor_user_id=user.id,
            actor_name=user.username,
            prompt="Create a Host and endpoint table",
            model="local-model",
            status="Queued",
            prompt_hash="0" * 64,
        )
        db.session.add(request)
        db.session.commit()
        return job_id, request.id

    def test_safe_markdown_supports_table_but_escapes_active_content(self):
        rendered = render_safe_markdown(
            "# Result\n\n| Host | Endpoint |\n| --- | --- |\n| WG-01 | `vpn:51820` |\n\n<script>alert(1)</script> [bad](javascript:alert(1))"
        )
        self.assertIn("<table>", rendered)
        self.assertIn("<code>vpn:51820</code>", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("href=", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_safe_delivery_html_keeps_formatting_without_active_content(self):
        from modules.Infrastructure.routes import report_email_bodies, safe_report_html

        source = (
            '<h1 onclick="alert(1)">Welcome</h1>'
            '<p style="color:red">Formatted report</p>'
            '<script>alert(2)</script>'
            '<table><tr><td onmouseover="alert(3)">WG-01</td></tr></table>'
            '<img src="x" onerror="alert(4)">'
            '<a href="javascript:alert(5)">unsafe link</a>'
        )
        rendered = safe_report_html(source)

        self.assertIn("<h1>Welcome</h1>", rendered)
        self.assertIn("<table><tr><td>WG-01</td></tr></table>", rendered)
        self.assertIn("unsafe link", rendered)
        for forbidden in ("<script", "<img", "<a ", "onclick", "onmouseover", "onerror", "javascript:", "alert(", "style="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered.lower())

        plain_body, html_body = report_email_bodies(source, "Please review <carefully>.")
        self.assertIn("Welcome", plain_body)
        self.assertIn("Formatted report", plain_body)
        self.assertIn("<h1>Welcome</h1>", html_body)
        self.assertIn("Please review &lt;carefully&gt;.", html_body)
        self.assertNotIn("onclick", html_body)

    def test_email_alternative_and_pgp_mime_preserve_formatted_part(self):
        from modules.Infrastructure.routes import pgp_mime_message, report_email_alternative

        alternative = report_email_alternative("<h1>Report</h1><p>Ready</p>")
        self.assertEqual(alternative.get_content_type(), "multipart/alternative")
        self.assertEqual(
            [part.get_content_type() for part in alternative.get_payload()],
            ["text/plain", "text/html"],
        )
        html_part = alternative.get_payload()[1].get_payload(decode=True).decode("utf-8")
        self.assertIn("<h1>Report</h1>", html_part)

        encrypted = pgp_mime_message(
            "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----"
        )
        self.assertEqual(encrypted.get_content_type(), "multipart/encrypted")
        self.assertEqual(encrypted.get_param("protocol"), "application/pgp-encrypted")
        self.assertEqual(
            [part.get_content_type() for part in encrypted.get_payload()],
            ["application/pgp-encrypted", "application/octet-stream"],
        )

    def test_confluence_safe_mode_formats_and_sanitizes_report(self):
        from modules.Infrastructure.routes import confluence_report_storage_html

        report = mock.Mock(
            title="Formatted report",
            status="Waiting Review",
            created_at=None,
            total_count=1,
            success_count=1,
            error_count=0,
        )
        storage = confluence_report_storage_html(
            report,
            '<h1>Summary</h1><table><tr><td onclick="x()">Ready</td></tr></table><script>x()</script>',
            "Published safely",
            formatted=True,
        )

        self.assertIn("<h1>Summary</h1>", storage)
        self.assertIn("<table><tr><td>Ready</td></tr></table>", storage)
        self.assertIn("Published safely", storage)
        self.assertNotIn("onclick", storage)
        self.assertNotIn("<script", storage)

    def test_smtp_delivery_uses_formatted_mime_with_and_without_gpg(self):
        from modules.Infrastructure import routes

        smtp = mock.MagicMock()
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        profile = {
            "reports@example.com": {
                "host": "smtp.example.com",
                "port": 465,
                "password": "encrypted-password",
            }
        }
        common_patches = (
            mock.patch.object(routes, "load_smtp_profiles", return_value=profile),
            mock.patch.object(routes.smtplib, "SMTP_SSL", return_value=smtp),
            mock.patch.object(routes, "pinned_outbound_host", return_value=contextlib.nullcontext()),
            mock.patch.object(routes.sec_manager, "decrypt_data", return_value="smtp-password"),
        )
        with common_patches[0], common_patches[1], common_patches[2], common_patches[3]:
            success, _, sent = routes.send_report_email(
                "Formatted report",
                "<h1>Summary</h1><p>Ready</p>",
                "reports@example.com",
                ["user@example.com"],
                use_gpg=False,
            )
        self.assertTrue(success)
        self.assertEqual(sent, 1)
        unencrypted_message = smtp.send_message.call_args.args[0]
        self.assertEqual(unencrypted_message.get_content_type(), "multipart/alternative")

        smtp.send_message.reset_mock()
        common_patches = (
            mock.patch.object(routes, "load_smtp_profiles", return_value=profile),
            mock.patch.object(routes.smtplib, "SMTP_SSL", return_value=smtp),
            mock.patch.object(routes, "pinned_outbound_host", return_value=contextlib.nullcontext()),
            mock.patch.object(routes.sec_manager, "decrypt_data", return_value="smtp-password"),
            mock.patch.object(routes, "encrypt_report_body", return_value=(
                True,
                "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----",
                None,
            )),
        )
        with common_patches[0], common_patches[1], common_patches[2], common_patches[3], common_patches[4] as encrypt:
            success, _, sent = routes.send_report_email(
                "Encrypted formatted report",
                "<h1>Summary</h1><p>Ready</p>",
                "reports@example.com",
                ["user@example.com"],
                use_gpg=True,
            )
        self.assertTrue(success)
        self.assertEqual(sent, 1)
        self.assertIn("multipart/alternative", encrypt.call_args.args[0])
        encrypted_message = smtp.send_message.call_args.args[0]
        self.assertEqual(encrypted_message.get_content_type(), "multipart/encrypted")

    def test_ai_input_masks_structured_secrets(self):
        with self.app.app_context():
            job_id, _ = self._job()
            serialized = build_ai_input(job_id)
            self.assertIn("vpn.example.test:51820", serialized)
            self.assertNotIn("must-not-leave-winhub", serialized)
            self.assertIn('"api_key":"***"', serialized)

    def test_worker_creates_immutable_ai_revision(self):
        with self.app.app_context():
            job_id, request_id = self._job()
            fake_client = mock.Mock()
            fake_client.chat_completion.return_value = "| Host | Endpoint |\n| --- | --- |\n| WG-01 | vpn.example.test:51820 |"
            with mock.patch("core.ai_reports.load_ai_provider", return_value={"enabled": True}), \
                    mock.patch("core.ai_reports.OpenWebUIClient", return_value=fake_client):
                self.assertTrue(process_ai_report_queue(self.app))

            request = AiReportRequest.query.get(request_id)
            report = AggregatedJob.query.get(job_id)
            revisions = ReportRevision.query.filter_by(report_id=job_id).order_by(ReportRevision.revision_number).all()
            self.assertEqual(request.status, "Success")
            self.assertEqual(len(revisions), 2)
            self.assertEqual(revisions[-1].kind, "ai_generated")
            self.assertEqual(request.output_revision_id, revisions[-1].id)
            self.assertIn("<table>", report.report_data)
            sent_messages = fake_client.chat_completion.call_args.args[0]
            self.assertNotIn("must-not-leave-winhub", json.dumps(sent_messages))

    def test_provider_error_preserves_fallback_revision(self):
        with self.app.app_context():
            job_id, request_id = self._job()
            fake_client = mock.Mock()
            fake_client.chat_completion.side_effect = ValueError("provider unavailable")
            with mock.patch("core.ai_reports.load_ai_provider", return_value={"enabled": True}), \
                    mock.patch("core.ai_reports.OpenWebUIClient", return_value=fake_client):
                self.assertFalse(process_ai_report_queue(self.app))

            request = AiReportRequest.query.get(request_id)
            report = AggregatedJob.query.get(job_id)
            self.assertEqual(request.status, "Error")
            self.assertIn("provider unavailable", request.error)
            self.assertEqual(report.report_data, "Fallback report")
            self.assertEqual(ReportRevision.query.filter_by(report_id=job_id).count(), 1)

    def test_ai_can_process_retained_report_when_task_results_are_gone(self):
        with self.app.app_context():
            report_id = str(uuid.uuid4())
            user = User(username="retained-operator", email=f"{report_id}@example.com", is_admin=True)
            report = AggregatedJob(
                id=report_id,
                title="Retained WireGuard report",
                status="Dismissed",
                report_data=json.dumps({
                    "endpoint": "vpn.retained.example:51820",
                    "api_key": "must-not-leave-winhub",
                }),
            )
            db.session.add_all([user, report])
            db.session.flush()
            create_report_revision(report, report.report_data, kind="generated", actor_name=user.username)
            request = AiReportRequest(
                job_id=report_id,
                report_id=report_id,
                actor_user_id=user.id,
                actor_name=user.username,
                prompt="Create a short endpoint table",
                model="local-model",
                status="Queued",
                prompt_hash="1" * 64,
            )
            db.session.add(request)
            db.session.commit()

            fake_client = mock.Mock()
            fake_client.chat_completion.return_value = "# Retained report"
            with mock.patch("core.ai_reports.load_ai_provider", return_value={"enabled": True}), \
                    mock.patch("core.ai_reports.OpenWebUIClient", return_value=fake_client):
                self.assertTrue(process_ai_report_queue(self.app))

            db.session.refresh(report)
            db.session.refresh(request)
            self.assertEqual(request.status, "Success")
            self.assertEqual(report.status, "Dismissed")
            self.assertEqual(ReportRevision.query.filter_by(report_id=report_id).count(), 2)
            sent_messages = json.dumps(fake_client.chat_completion.call_args.args[0])
            self.assertIn("vpn.retained.example:51820", sent_messages)
            self.assertNotIn("must-not-leave-winhub", sent_messages)

    def test_sent_split_report_can_be_queued_for_ai_as_a_new_version(self):
        from modules.Infrastructure import routes

        with self.app.app_context():
            source_job_id = str(uuid.uuid4())
            report_id = f"{uuid.UUID(source_job_id).hex}.001"
            user = User(username="split-operator", email=f"{source_job_id}@example.com", is_admin=True)
            endpoint = Endpoint(
                id=f"host-{source_job_id}",
                hostname="SPLIT-01",
                approval_status="Approved",
            )
            task = AgentTask(
                job_id=source_job_id,
                endpoint=endpoint,
                endpoint_id_snapshot=endpoint.id,
                endpoint_hostname_snapshot=endpoint.hostname,
                title="Split report source",
                action_type="run_script",
                payload="{}",
                result_log='{"value":"available"}',
                status="Success",
                created_by=user.username,
            )
            report = AggregatedJob(
                id=report_id,
                title="Previously sent split report",
                status="Sent",
                report_data="Previously sent content",
            )
            db.session.add_all([user, endpoint, task, report])
            db.session.flush()
            create_report_revision(report, report.report_data, kind="generated", actor_name=user.username)
            db.session.commit()

            with self.app.test_request_context(
                f"/api/infrastructure/reports/{report_id}/ai-regenerate",
                method="POST",
                json={"prompt": "Create a concise new version"},
            ):
                session.update({"user_id": user.id, "is_admin": True})
                with mock.patch.object(routes, "require_any_permission", return_value=None), \
                        mock.patch.object(routes, "can", return_value=True), \
                        mock.patch.object(routes, "can_access_report", return_value=True), \
                        mock.patch.object(routes, "current_actor_label", return_value=user.username), \
                        mock.patch.object(routes, "validate_ai_report_payload", return_value={
                            "enabled": True,
                            "prompt": "Create a concise new version",
                            "model": "local-model",
                        }), \
                        mock.patch.object(routes.WinHubCore, "audit"):
                    response = routes.regenerate_report_with_ai(report_id)

            self.assertEqual(response.status_code, 200)
            queued = AiReportRequest.query.filter_by(report_id=report_id).one()
            self.assertEqual(queued.job_id, source_job_id)
            self.assertEqual(queued.status, "Queued")
            self.assertEqual(report.status, "Sent")
            self.assertEqual(ReportRevision.query.filter_by(report_id=report_id).count(), 1)


if __name__ == "__main__":
    unittest.main()
