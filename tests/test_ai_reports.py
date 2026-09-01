import json
import unittest
import uuid
from unittest import mock

from flask import Flask

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


if __name__ == "__main__":
    unittest.main()
