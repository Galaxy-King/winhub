import hashlib
import json
import unittest
import uuid

from flask import Flask, session
from sqlalchemy import text

from core.config import Config
from core.database import (
    AgentTask,
    AggregatedJob,
    AuditLog,
    Endpoint,
    ReportDelivery,
    ReportRevision,
    User,
    db,
)
from core.history_search import index_agent_task, matching_entity_ids
from core.report_versions import create_report_revision, record_report_delivery, report_content_hash
from core.sdk import WinHubCore


class SearchableAuditHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = "history-search-tests"
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
        )
        db.init_app(cls.app)
        from modules.HistoryAudit.routes import history_bp
        cls.app.register_blueprint(history_bp)
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        with self.app.app_context():
            db.session.remove()
            for table in reversed(db.metadata.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()

    def test_default_history_retention_is_five_years(self):
        self.assertEqual(Config.HISTORY_RETENTION_DAYS, 1825)

    def test_encrypted_task_content_is_searchable_without_plaintext_in_database(self):
        with self.app.app_context():
            endpoint = Endpoint(id="host-1", hostname="APP-SERVER-01", approval_status="Approved")
            task = AgentTask(
                id="task-1", job_id="job-1", endpoint=endpoint,
                endpoint_id_snapshot="host-1", endpoint_hostname_snapshot="APP-SERVER-01",
                title="Check service", payload="service AlphaNeedle requested",
                result_log="Result contains FailureNeedle", status="Success", created_by="alice",
            )
            db.session.add_all([endpoint, task])
            db.session.flush()
            index_agent_task(task)
            db.session.commit()

            raw_payload = db.session.execute(
                text("SELECT payload FROM agent_tasks WHERE id='task-1'")
            ).scalar_one()
            self.assertNotIn("AlphaNeedle", raw_payload)
            input_ids = matching_entity_ids("task", "alphaneedle", fields=["input"]).all()
            output_ids = matching_entity_ids("task", "failureneedle", fields=["output"]).all()
            combined_ids = matching_entity_ids("task", "alphaNeedle failureNeedle", fields=["input", "output"]).all()
            self.assertEqual(input_ids, [("task-1",)])
            self.assertEqual(output_ids, [("task-1",)])
            self.assertEqual(combined_ids, [("task-1",)])

    def test_report_original_edits_and_exact_delivery_snapshot_are_immutable(self):
        with self.app.app_context():
            report = AggregatedJob(id="report-1", title="Compliance", report_data="Original body")
            db.session.add(report)
            db.session.flush()
            original = create_report_revision(report, "Original body", kind="generated", actor_name="System")
            edited = create_report_revision(report, "Edited body", kind="edited", actor_name="alice", reason="Clarified")
            sent_body = "Operator note\n\nEdited body"
            delivery, linked_revision = record_report_delivery(
                report, channel="email", destination="security@example.com",
                content_snapshot=sent_body, actor_name="alice", status="Sending",
            )
            db.session.commit()

            self.assertEqual(original.revision_number, 1)
            self.assertEqual(original.content, "Original body")
            self.assertEqual(edited.revision_number, 2)
            self.assertEqual(report.report_data, "Edited body")
            self.assertEqual(linked_revision.id, edited.id)
            self.assertEqual(delivery.content_snapshot, sent_body)
            self.assertEqual(delivery.content_hash, report_content_hash(sent_body))
            self.assertEqual(ReportRevision.query.filter_by(report_id=report.id).count(), 2)
            self.assertEqual(ReportDelivery.query.filter_by(report_id=report.id).count(), 1)
            self.assertEqual(
                matching_entity_ids("report", "operator", fields=["deliveries"]).all(),
                [("report-1",)],
            )

    def test_forced_report_regeneration_adds_revision_without_deleting_delivery(self):
        with self.app.app_context():
            job_id = str(uuid.uuid4())
            endpoint = Endpoint(id="host-regenerate", hostname="WEB-01", approval_status="Approved")
            task = AgentTask(
                id=str(uuid.uuid4()), job_id=job_id, endpoint=endpoint,
                endpoint_id_snapshot=endpoint.id, endpoint_hostname_snapshot=endpoint.hostname,
                title="Regeneration", module_source="Infrastructure", action_type="run_script",
                payload="{}", result_log="new host result", status="Success", created_by="alice",
            )
            report = AggregatedJob(id=job_id, title="Regeneration", report_data="Original report")
            db.session.add_all([endpoint, task, report])
            db.session.flush()
            original = create_report_revision(report, report.report_data, kind="generated", actor_name="alice")
            delivery, _ = record_report_delivery(
                report, channel="email", destination="audit@example.com",
                content_snapshot="Original report", actor_name="alice", status="Success",
            )
            db.session.commit()
            original_id, delivery_id = original.id, delivery.id

            WinHubCore.process_job_completion(job_id, include_statuses=["Success"], force=True)

            self.assertIsNotNone(ReportRevision.query.get(original_id))
            self.assertIsNotNone(ReportDelivery.query.get(delivery_id))
            revisions = ReportRevision.query.filter_by(report_id=job_id).order_by(
                ReportRevision.revision_number
            ).all()
            self.assertEqual(len(revisions), 2)
            self.assertEqual(revisions[0].content, "Original report")
            self.assertEqual(revisions[1].kind, "regenerated")

    def test_audit_records_actor_role_session_source_and_searchable_details(self):
        with self.app.app_context():
            user = User(username="security-admin", email="security@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            with self.app.test_request_context("/module/infrastructure", headers={"User-Agent": "AuditBrowser/1.0"}):
                session.update({
                    "user_id": user.id, "username": user.username, "logged_in": True,
                    "is_admin": True, "audit_session_id": "session-123",
                })
                WinHubCore.audit(
                    user_id=user.id, module="Infrastructure", action="Run Template",
                    details={"template": "SecurityNeedle"}, target_type="template",
                    target_id="tpl-1", status="Success", source_type="manual",
                )

            entry = AuditLog.query.one()
            self.assertEqual(entry.actor_user_id, user.id)
            self.assertEqual(entry.actor_role, "superadmin")
            self.assertEqual(entry.source_type, "manual")
            self.assertEqual(entry.session_id_hash, hashlib.sha256(b"session-123").hexdigest())
            self.assertIn("AuditBrowser", entry.user_agent)
            self.assertEqual(matching_entity_ids("audit", "securityneedle", fields=["details"]).all(), [(str(entry.id),)])

    def test_unified_api_combines_actor_content_target_and_date_filters(self):
        with self.app.app_context():
            admin = User(username="admin", email="admin@example.com", is_admin=True)
            endpoint = Endpoint(id="host-2", hostname="DB-SERVER-02", approval_status="Approved")
            task = AgentTask(
                id="task-2", job_id="job-2", endpoint=endpoint,
                endpoint_id_snapshot=endpoint.id, endpoint_hostname_snapshot=endpoint.hostname,
                title="Inspect database", payload="check UniqueQueryNeedle now",
                result_log="database check completed", status="Success", created_by="alice",
            )
            db.session.add_all([admin, endpoint, task])
            db.session.flush()
            index_agent_task(task)
            db.session.commit()
            admin_id = admin.id

        client = self.app.test_client()
        with client.session_transaction() as browser_session:
            browser_session.update({
                "user_id": admin_id, "username": "admin", "logged_in": True,
                "is_admin": True, "audit_session_id": "browser-session",
            })
        response = client.get(
            "/api/history/search",
            query_string={
                "type": "task", "actor": "alice", "content": "uniquequeryneedle",
                "target": "DB-SERVER", "status": "Success", "date_from": "2020-01-01",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual([item["id"] for item in payload["history"]], ["agent_task-2"])

    def test_non_admin_cannot_hard_delete_history_even_with_legacy_token(self):
        with self.app.app_context():
            operator = User(
                username="operator", email="operator@example.com", is_admin=False,
                allowed_modules=json.dumps(["HistoryAudit:view_history", "HistoryAudit:manage_history"]),
            )
            task = AgentTask(id="protected-task", title="Protected", status="Success")
            db.session.add_all([operator, task])
            db.session.commit()
            operator_id = operator.id
        client = self.app.test_client()
        with client.session_transaction() as browser_session:
            browser_session.update({"user_id": operator_id, "username": "operator", "logged_in": True})
        response = client.post("/api/history/delete_selected", json={"task_ids": ["agent_protected-task"]})
        self.assertEqual(response.status_code, 403)
        with self.app.app_context():
            self.assertIsNotNone(AgentTask.query.get("protected-task"))


if __name__ == "__main__":
    unittest.main()
