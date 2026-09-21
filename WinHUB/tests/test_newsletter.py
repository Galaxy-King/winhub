import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

from core.database import NewsletterCampaign, NewsletterDelivery, Task, User, db
from core.permissions import has_permission
from modules.Newsletter import routes


class NewsletterSafetyTests(unittest.TestCase):
    def test_list_names_cannot_escape_storage(self):
        for value in ("../smtp_profiles", "..\\smtp_profiles", "/tmp/list", "C:\\temp\\list", "", "two words"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    routes.normalize_list_name(value)
        self.assertEqual(routes.normalize_list_name("it-support_2026.eu"), "it-support_2026.eu")

    def test_atomic_list_write_and_recipient_validation(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(routes, "LISTS_DIR", directory):
            routes.atomic_json_write(routes.list_file_path("team"), ["alice", "bob@example.com"])
            recipients, invalid, counts = routes.resolve_campaign_recipients(["team"], "@example.org")
            self.assertEqual(recipients, ["alice@example.org", "bob@example.com"])
            self.assertEqual(invalid, [])
            self.assertEqual(counts, {"team": 2})

    def test_inbound_decrypt_requires_valid_signature_status(self):
        completed = mock.Mock(returncode=0, stdout=b"Subject: signed\n\nbody", stderr=b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 2026")
        with mock.patch("subprocess.run", return_value=completed):
            ok, payload, fingerprints = routes.decrypt_with_gpg("gpg", b"ciphertext", "passphrase")
        self.assertTrue(ok)
        self.assertIn(b"signed", payload)
        self.assertEqual(fingerprints, ["A" * 40])

    def test_newsletter_html_keeps_formatting_without_active_content(self):
        rendered = routes.sanitize_newsletter_html(
            '<p style="text-align:center" onclick="bad()"><b>Hello</b>'
            '<script>alert(1)</script><a href="javascript:bad()">bad</a>'
            '<a href="https://example.com">good</a></p>'
        )
        self.assertIn('text-align:center', rendered)
        self.assertIn('<b>Hello</b>', rendered)
        self.assertNotIn('script', rendered)
        self.assertNotIn('javascript:', rendered)
        self.assertIn('https://example.com', rendered)

    def test_campaign_error_details_are_admin_only(self):
        campaign = mock.Mock(
            id="campaign-1", task_id="task-1", source="manual",
            sender_email="sender@example.com", status="Failed", use_gpg=False,
            total_count=1, sent_count=0, failed_count=1, skipped_count=0,
            cancel_requested=False, created_at=None, started_at=None, ended_at=None,
            error_summary="SMTP password for sender@example.com was rejected",
        )
        public = routes.campaign_summary(campaign)
        admin = routes.campaign_summary(campaign, include_error=True)
        self.assertEqual(public["error_summary"], "Campaign processing failed. Contact an administrator.")
        self.assertEqual(admin["error_summary"], campaign.error_summary)

    def test_legacy_view_permission_does_not_allow_sending(self):
        viewer = mock.Mock(is_admin=False, allowed_modules=json.dumps(["Newsletter:view"]))
        editor = mock.Mock(is_admin=False, allowed_modules=json.dumps(["Newsletter:change"]))
        self.assertTrue(has_permission(viewer, "Newsletter", "view_newsletter"))
        self.assertFalse(has_permission(viewer, "Newsletter", "send_campaigns"))
        self.assertTrue(has_permission(editor, "Newsletter", "send_campaigns"))

    def test_frontend_keeps_failed_draft_and_has_preflight(self):
        template = Path(routes.MODULE_DIR, "templates", "newsletter_index.html").read_text(encoding="utf-8")
        self.assertIn("runCampaignPreflight", template)
        self.assertIn("Your draft was preserved", template)
        self.assertIn("switchNewsletterGuide('en')", template)
        self.assertIn("New campaign", template)
        self.assertNotIn("Нова розсилка", template)
        self.assertIn("currentLdapProfileId = profile.id", template)
        self.assertNotIn("currentLdapProfileId = id;\n        renderLdapProfiles", template)

    def test_dedicated_worker_is_packaged_and_managed(self):
        root = Path(routes.MODULE_DIR).parents[1]
        allowlist = (root / "deploy" / "server-files.txt").read_text(encoding="utf-8")
        install = (root / "deploy" / "debian" / "install_debian.sh").read_text(encoding="utf-8")
        update = (root / "deploy" / "debian" / "update_winhub.sh").read_text(encoding="utf-8")
        service = (root / "deploy" / "debian" / "winhub-newsletter.service").read_text(encoding="utf-8")
        self.assertIn("newsletter_worker.py", allowlist)
        self.assertIn("winhub-newsletter.service", install)
        self.assertIn("winhub-newsletter.service", update)
        self.assertIn("WINHUB_DISABLE_SCHEDULER=true", service)


class NewsletterQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = "newsletter-tests"
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            DATA_DIR=tempfile.mkdtemp(prefix="winhub-newsletter-tests-"),
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

    def test_enqueue_creates_durable_task_and_deduplicated_deliveries(self):
        with self.app.app_context():
            user = User(username="newsletter-operator", email="operator@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            campaign = routes.enqueue_campaign(
                user_id=user.id,
                source="manual",
                sender_email="sender@example.com",
                subject="Maintenance",
                body_text="Body",
                body_html="<p>Body</p>",
                attachments=[],
                recipients=["a@example.com", "a@example.com", "b@example.com"],
                selected_lists=["ops"],
                use_gpg=True,
            )
            self.assertEqual(campaign.status, "Queued")
            self.assertEqual(NewsletterDelivery.query.filter_by(campaign_id=campaign.id).count(), 2)
            self.assertEqual(db.session.get(Task, campaign.task_id).status, "Queued")

    def test_recovery_never_retries_uncertain_delivery(self):
        with self.app.app_context():
            user = User(username="newsletter-recovery", email="recovery@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            campaign = routes.enqueue_campaign(
                user_id=user.id, source="manual", sender_email="sender@example.com",
                subject="Recovery", body_text="Body", body_html="", attachments=[],
                recipients=["a@example.com", "b@example.com"], selected_lists=["ops"], use_gpg=False,
            )
            campaign.status = "Sending"
            deliveries = NewsletterDelivery.query.filter_by(campaign_id=campaign.id).all()
            deliveries[0].status = "Sending"
            db.session.commit()
            routes.recover_interrupted_campaigns()
            db.session.refresh(campaign)
            self.assertEqual(campaign.status, "Queued")
            self.assertEqual(deliveries[0].status, "Unknown")
            self.assertEqual(deliveries[1].status, "Pending")

    def test_worker_leaves_inbound_mail_unread_until_signer_is_configured(self):
        mailbox = {"name": "legacy-inbound", "enabled": True, "allowed_signer_fingerprints": []}
        with (
            mock.patch.object(routes, "recover_interrupted_campaigns"),
            mock.patch.object(routes, "atomic_json_write"),
            mock.patch.object(routes, "inbound_relay_enabled", return_value=True),
            mock.patch.object(routes, "inbound_mailboxes", return_value=[mailbox]),
            mock.patch.object(routes, "poll_inbound_mailbox") as poll_mailbox,
            mock.patch.object(routes, "claim_next_campaign", return_value=None),
        ):
            routes.run_newsletter_worker(self.app, once=True)
        poll_mailbox.assert_not_called()


if __name__ == "__main__":
    unittest.main()
