import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask
from sqlalchemy import event, select

from core.database import NewsletterCampaign, NewsletterDelivery, Task, User, db
from core.permissions import has_permission
from modules.Newsletter import routes


class NewsletterSafetyTests(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("gpg") and __import__("shutil").which("gpgconf"),
                         "GnuPG is required for real bundle inspection")
    def test_real_armored_and_binary_public_bundles_without_runtime_import(self):
        import os
        import subprocess
        app = Flask(__name__)
        with tempfile.TemporaryDirectory(prefix="winhub-bundle-fixture-") as directory:
            environment = {**os.environ, "GNUPGHOME": directory}
            command = ["gpg", "--no-options", "--homedir", directory, "--batch",
                       "--pinentry-mode", "loopback", "--passphrase", ""]
            def run(*arguments):
                return subprocess.run(command + list(arguments), capture_output=True, check=True,
                                      timeout=20, env=environment).stdout
            try:
                run("--quick-generate-key", "Newsletter Fixture <alice@example.org>", "ed25519", "sign", "0")
                keys = run("--with-colons", "--list-keys").decode("utf-8")
                fingerprint = next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))
                run("--quick-add-uid", fingerprint, "Other Domain <outside@other.example>")
                binary = run("--export", fingerprint)
                armored = run("--armor", "--export", fingerprint)
                secret = run("--export-secret-keys", fingerprint)
                with app.app_context(), mock.patch.object(routes, "gpg_env", side_effect=AssertionError("Runtime keyring must not be used")):
                    for payload in (binary, armored):
                        with self.subTest(armored=payload is armored):
                            listing = routes.inspect_public_key_bundle(payload)
                            self.assertEqual(routes.parse_public_key_bundle_listing(listing, "example.org"), ["alice@example.org"])
                    with self.assertRaisesRegex(ValueError, "secret keys"):
                        routes.parse_public_key_bundle_listing(routes.inspect_public_key_bundle(secret), "example.org")
                    with self.assertRaisesRegex(ValueError, "could not read"):
                        routes.inspect_public_key_bundle(b"<html>not a key bundle</html>")
            finally:
                subprocess.run(["gpgconf", "--homedir", directory, "--kill", "gpg-agent"],
                               capture_output=True, timeout=10, env=environment)

    @staticmethod
    def bundle_listing_record(kind, validity="-", uid="", expires="", capabilities="scESC"):
        fields = [kind, validity, "2048", "1", "A" * 16, "1", expires, "", "", uid, "", capabilities, ""]
        return ":".join(fields)

    def test_bundle_listing_filters_domain_validity_and_escaped_uids(self):
        record = self.bundle_listing_record
        listing = "\n".join([
            record("pub"), record("uid", uid=r"Alice\x3a Team <alice@example.org>"),
            record("uid", uid="alice@example.org"), record("uid", uid="outside@sub.example.org"),
            record("uid", uid="outside@example.org.evil"), record("uid", "r", "revoked@example.org"),
            record("uid", uid="expired@example.org", expires="5"),
            record("pub", "r"), record("uid", uid="revoked-key@example.org"),
            record("pub", expires="5"), record("uid", uid="expired-key@example.org"),
            record("pub", capabilities="scESCD"), record("uid", uid="disabled@example.org"),
            record("pub"), record("uid", uid="Bob <bob@example.org>"),
        ])
        self.assertEqual(routes.parse_public_key_bundle_listing(listing, "example.org", now=10),
                         ["alice@example.org", "bob@example.org"])
        for listing in ("", "<html>error</html>", record("sec"), record("pub") + "\n" + record("ssb"), "pub:bad"):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                routes.parse_public_key_bundle_listing(listing, "example.org")

    def test_bundle_discovery_uses_file_instead_of_hkp_and_upgrades_http(self):
        listing = self.bundle_listing_record("pub") + "\n" + self.bundle_listing_record("uid", uid="alice@example.org")
        with (mock.patch.object(routes, "download_recipient_source", return_value=b"public-bundle") as download,
              mock.patch.object(routes, "inspect_public_key_bundle", return_value=listing),
              mock.patch.object(routes, "discover_keyserver_recipients") as hkp):
            self.assertEqual(routes.discover_list_source("hkps://broken.example.org", "@example.org", "http://keys.example.org/all.pgp"),
                             ["alice@example.org"])
        hkp.assert_not_called()
        self.assertEqual(download.call_args.args[0], "https://keys.example.org/all.pgp")
        self.assertEqual(download.call_args.args[2], 32 * 1024 * 1024)
        for url in ("file:///tmp/keys.pgp", "https://keys.example.org", "https://user:secret@keys.example.org/all.pgp"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                routes.validate_key_bundle_source(url, "example.org")

    def test_bundle_inspection_uses_disposable_home_and_bounded_output(self):
        import io
        app = Flask(__name__)
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.returncode = 0
        process.stdout = io.BytesIO(b"pub:metadata")
        with (app.app_context(), mock.patch.object(routes.subprocess, "Popen", return_value=process) as popen,
              mock.patch.object(routes, "gpg_env", side_effect=AssertionError("Runtime keyring must not be used"))):
            self.assertEqual(routes.inspect_public_key_bundle(b"public-bundle"), "pub:metadata")
            command = popen.call_args.args[0]
            home = command[command.index("--homedir") + 1]
            self.assertFalse(Path(home).exists())
            for option in ("--no-options", "--no-autostart", "--dry-run", "show-only"):
                self.assertIn(option, command)
            self.assertEqual(popen.call_args.kwargs["env"]["GNUPGHOME"], home)
            self.assertEqual(popen.call_args.kwargs["stdin"], routes.subprocess.DEVNULL)
            process.stdout = io.BytesIO(b"x" * (8 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "exceeds 8 MiB"):
                routes.inspect_public_key_bundle(b"public-bundle")
            process.kill.assert_called()
            process.stdout = io.BytesIO(b"")
            process.wait.side_effect = [routes.subprocess.TimeoutExpired("gpg", 30), 0]
            with self.assertRaisesRegex(ValueError, "exceeded 30 seconds"):
                routes.inspect_public_key_bundle(b"public-bundle")

    def test_nightly_bundle_sync_preserves_existing_entries_and_failure_state(self):
        from datetime import datetime
        app = Flask(__name__)
        with (app.app_context(), tempfile.TemporaryDirectory() as directory,
              mock.patch.object(routes, "LISTS_DIR", directory),
              mock.patch.object(routes.WinHubCore, "audit"),
              mock.patch.object(routes, "download_recipient_source", return_value=b"public-bundle"),
              mock.patch.object(routes, "inspect_public_key_bundle") as inspect,
              mock.patch.object(routes, "discover_keyserver_recipients") as hkp):
            path = routes.list_file_path("team")
            routes.atomic_json_write(path, {"domain": "@example.org", "entries": ["alice", "manual@other.org"],
                                          "key_bundle_url": "https://keys.example.org/all.pgp", "keyserver_auto_sync": True})
            inspect.return_value = self.bundle_listing_record("pub") + "\n" + self.bundle_listing_record("uid", uid="bob@example.org")
            now = datetime(2026, 11, 25, tzinfo=routes.KYIV_TZ)
            routes.sync_keyserver_lists(now)
            routes.sync_keyserver_lists(now)
            inspect.assert_called_once()
            hkp.assert_not_called()
            record = routes.load_list_records()["team"]
            self.assertEqual(record["entries"], ["alice", "manual@other.org", "bob@example.org"])
            inspect.side_effect = ValueError("Invalid bundle")
            routes.sync_keyserver_lists(datetime(2026, 11, 26, tzinfo=routes.KYIV_TZ))
            failed = routes.load_list_records()["team"]
            self.assertEqual(failed["entries"], record["entries"])
            self.assertEqual(failed["keyserver_sync"]["status"], "Failed")

    def test_bundle_url_is_saved_without_keyserver_and_resets_sync_on_change(self):
        app = Flask(__name__)
        with (tempfile.TemporaryDirectory() as directory, mock.patch.object(routes, "LISTS_DIR", directory),
              mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(routes.WinHubCore, "audit")):
            data = {"list_name": "team", "users": [], "domain": "@example.org", "key_bundle_url": "http://keys.example.org/all.pgp", "keyserver_auto_sync": True}
            with app.test_request_context(json=data):
                self.assertTrue(routes.save_list().get_json()["success"])
            record = routes.load_list_records()["team"]
            self.assertEqual(record["key_bundle_url"], "https://keys.example.org/all.pgp")
            record["keyserver_sync"] = {"date": "2020-01-01", "status": "Failed"}
            routes.atomic_json_write(routes.list_file_path("team"), record)
            with app.test_request_context(json={**data, "key_bundle_url": "https://keys.example.org/new.pgp"}):
                self.assertTrue(routes.save_list().get_json()["success"])
            self.assertNotIn("status", routes.load_list_records()["team"]["keyserver_sync"])

    def test_encryption_ignores_extra_recipients_from_local_gpg_configuration(self):
        def encrypt(command, **kwargs):
            self.assertIn("--no-options", command)
            self.assertIn("--no-encrypt-to", command)
            self.assertEqual(command.count("-r"), 1)
            self.assertEqual(command[command.index("-r") + 1], "alice@example.org")
            Path(command[command.index("-o") + 1]).write_text("ciphertext-for-alice", encoding="utf-8")
            return mock.Mock(returncode=0, stderr="")
        with mock.patch.object(routes.subprocess, "run", side_effect=encrypt):
            self.assertEqual(routes.encrypt_with_gpg("gpg", "alice@example.org", b"private body"),
                             (True, "ciphertext-for-alice"))

    def test_keyserver_index_filters_exact_domain_and_unusable_keys(self):
        payload = "\n".join([
            "info:1:4",
            "pub:" + "A" * 40 + ":1:2048:1:::",
            "uid:Alice%20%3Calice%40example.org%3E:1::",
            "uid:alice%40example.org:1::",
            "uid:other%40sub.example.org:1::",
            "uid:other%40example.org.evil:1::",
            "uid:old%40example.org:1:5:",
            "uid:revoked%40example.org:1::r",
            "pub:" + "B" * 40 + ":1:2048:1::r:",
            "uid:revoked-key%40example.org:1::",
            "pub:" + "C" * 40 + ":1:2048:1:5::",
            "uid:expired-key%40example.org:1::",
            "pub:" + "D" * 40 + ":1:2048:1:::",
            "uid:Bob%20%3Cbob%40example.org%3E:1::",
        ])
        self.assertEqual(routes.parse_keyserver_index(payload, "example.org", now=10),
                         ["alice@example.org", "bob@example.org"])

    def test_keyserver_index_rejects_html_truncation_and_bad_records(self):
        for payload in ("<html>Error</html>", "info:1:2\npub:" + "A" * 40 + ":1:2048:1::",
                        "info:2:0", "uid:alice%40example.org:1::", "info:1:1\npub:bad"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                routes.parse_keyserver_index(payload, "example.org")
        self.assertEqual(routes.parse_keyserver_index("info:1:0", "example.org"), [])

    def test_discovery_requires_tls_and_valid_domain(self):
        self.assertEqual(routes.validate_keyserver_discovery("hkps://keys.example.org", "@EXAMPLE.ORG"),
                         ("https://keys.example.org", "example.org"))
        for server, domain in (("http://keys.example.org", "example.org"),
                               ("https://user:secret@keys.example.org", "example.org"),
                               ("https://keys.example.org?q=1", "example.org"),
                               ("https://keys.example.org", "example.org/path"),
                               ("https://keys.example.org", "example..org"),
                               ("https://keys.example.org", "")):
            with self.subTest(server=server, domain=domain), self.assertRaises(ValueError):
                routes.validate_keyserver_discovery(server, domain)

    def test_discovery_uses_bounded_pinned_https_without_redirects(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read1.side_effect = [b"info:1:0", b""]
        opener = mock.Mock()
        opener.open.return_value = response
        with (mock.patch.object(routes, "pinned_outbound_url") as pin,
              mock.patch.object(routes.urllib.request, "build_opener", return_value=opener)):
            self.assertEqual(routes.discover_keyserver_recipients("hkps://keys.example.org", "@example.org"), [])
        self.assertIn("search=%40example.org", pin.call_args.args[0])
        self.assertEqual(pin.call_args.kwargs["allowed_schemes"], ("https",))
        self.assertEqual(response.__enter__.return_value.read1.call_count, 2)
        response.__enter__.return_value.read1.assert_called_with(65536)

    def test_discovery_api_requires_manage_lists(self):
        with mock.patch.object(routes, "require_permission", return_value=("Forbidden", 403)) as permission:
            self.assertEqual(routes.discover_list_recipients(), ("Forbidden", 403))
        permission.assert_called_once_with("manage_lists")

    def test_nightly_discovery_is_additive_deduplicated_and_once_per_date(self):
        from datetime import datetime
        with (tempfile.TemporaryDirectory() as directory,
              mock.patch.object(routes, "LISTS_DIR", directory),
              mock.patch.object(routes, "discover_keyserver_recipients", return_value=["alice@example.org", "bob@example.org"]) as discover,
              mock.patch.object(routes.WinHubCore, "audit")):
            routes.atomic_json_write(routes.list_file_path("team"), {
                "domain": "@example.org", "keyserver": "hkps://keys.example.org", "entries": ["alice", "manual@elsewhere.org"],
                "keyserver_auto_sync": True, "keyserver_sync": {"date": "2026-11-24"},
            })
            now = datetime(2026, 11, 25, 0, 0, tzinfo=routes.KYIV_TZ)
            routes.sync_keyserver_lists(now)
            routes.sync_keyserver_lists(now)
            discover.assert_called_once()
            record = routes.load_list_records()["team"]
            self.assertEqual(record["entries"], ["alice", "manual@elsewhere.org", "bob@example.org"])
            self.assertEqual(record["keyserver_sync"]["added"], 1)
            self.assertEqual(record["keyserver_sync"]["status"], "Completed")
            discover.side_effect = ValueError("unavailable")
            routes.sync_keyserver_lists(datetime(2026, 11, 26, 9, 0, tzinfo=routes.KYIV_TZ))
            failed = routes.load_list_records()["team"]
            self.assertEqual(failed["entries"], record["entries"])
            self.assertEqual(failed["keyserver_sync"]["status"], "Failed")
            self.assertEqual(failed["keyserver_sync"]["date"], "2026-11-26")

    def test_nightly_discovery_does_not_apply_if_source_changed_during_fetch(self):
        from datetime import datetime
        with (tempfile.TemporaryDirectory() as directory,
              mock.patch.object(routes, "LISTS_DIR", directory),
              mock.patch.object(routes.WinHubCore, "audit")):
            path = routes.list_file_path("team")
            record = {"domain": "@example.org", "keyserver": "hkps://keys.example.org", "entries": ["alice"], "keyserver_auto_sync": True}
            routes.atomic_json_write(path, record)
            def changed(*args):
                routes.atomic_json_write(path, {**record, "keyserver_auto_sync": False})
                return ["bob@example.org"]
            with mock.patch.object(routes, "discover_keyserver_recipients", side_effect=changed):
                routes.sync_keyserver_lists(datetime(2026, 11, 25, tzinfo=routes.KYIV_TZ))
            self.assertEqual(routes.load_list_records()["team"]["entries"], ["alice"])

    def test_auto_sync_save_can_start_empty_and_preserves_status_on_rename(self):
        app = Flask(__name__)
        app.secret_key = "test-only"
        with (tempfile.TemporaryDirectory() as directory,
              mock.patch.object(routes, "LISTS_DIR", directory),
              mock.patch.object(routes, "require_permission", return_value=None),
              mock.patch.object(routes.WinHubCore, "audit"),
              mock.patch.object(routes, "load_inbound_settings", return_value={})):
            data = {"list_name": "team", "users": [], "domain": "@example.org", "keyserver": "hkps://keys.example.org", "keyserver_auto_sync": True}
            with app.test_request_context(json=data):
                self.assertTrue(routes.save_list().get_json()["success"])
            state = routes.load_list_records()["team"]["keyserver_sync"]
            with app.test_request_context(json={**data, "original_list_name": "team", "list_name": "renamed"}):
                self.assertTrue(routes.save_list().get_json()["success"])
            self.assertNotIn("team", routes.load_list_records())
            self.assertEqual(routes.load_list_records()["renamed"]["keyserver_sync"], state)
            for change in ({"keyserver_auto_sync": False}, {"domain": ""}, {"keyserver": "http://keys.example.org"}):
                with app.test_request_context(json={**data, **change}):
                    self.assertEqual(routes.save_list()[1], 400)

    def test_discovery_rejects_oversized_slow_and_redirect_responses(self):
        response = mock.MagicMock()
        opener = mock.Mock()
        opener.open.return_value = response
        with (mock.patch.object(routes, "pinned_outbound_url"),
              mock.patch.object(routes.urllib.request, "build_opener", return_value=opener)):
            response.__enter__.return_value.read1.side_effect = None
            response.__enter__.return_value.read1.return_value = b"x" * 65536
            with self.assertRaisesRegex(ValueError, "exceeds 2 MiB"):
                routes.discover_keyserver_recipients("hkps://keys.example.org", "example.org")
            with mock.patch.object(routes.time, "monotonic", side_effect=[0, 31]):
                with self.assertRaisesRegex(ValueError, "time limit"):
                    routes.discover_keyserver_recipients("hkps://keys.example.org", "example.org")
        self.assertIsNone(routes._NewsletterNoRedirectHandler().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.org"))

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
            self.assertEqual(recipients, ["bob@example.com"])
            self.assertEqual(invalid, [{"list": "team", "value": "alice"}])
            self.assertEqual(counts, {"team": 1})

            routes.atomic_json_write(routes.list_file_path("team"), {
                "schema": 2,
                "domain": "@example.org",
                "keyserver": "hkps://keys.example.org",
                "entries": ["alice", "bob@example.com"],
            })
            recipients, invalid, counts = routes.resolve_campaign_recipients(["team"])
            self.assertEqual(recipients, ["alice@example.org", "bob@example.com"])
            self.assertEqual(invalid, [])
            self.assertEqual(counts, {"team": 2})

    def test_inbound_uses_list_domain_and_ignores_legacy_route_domain(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(routes, "LISTS_DIR", directory):
            routes.atomic_json_write(routes.list_file_path("team"), {
                "schema": 2, "domain": "example.org", "entries": ["alice"],
            })
            recipients, _ = routes.resolve_mailbox_recipients({
                "name": "relay", "lists": ["team"], "ldap_groups": [],
                "recipient_domain": "@wrong.example",
            })
            self.assertEqual(recipients, ["alice@example.org"])

    def test_expired_key_refresh_uses_known_fingerprint_not_email_search(self):
        fingerprint = "A" * 40
        with (
            mock.patch.object(routes, "get_gpg_key_status", side_effect=[
                {"exists": True, "usable": False, "reason": "Public key is expired", "fingerprint": fingerprint},
                {"exists": True, "usable": True, "reason": "Public key is usable", "fingerprint": fingerprint},
            ]),
            mock.patch.object(routes, "fetch_gpg_key", return_value=(True, "ok")) as fetch,
        ):
            ok, _ = routes.ensure_gpg_key_ready("gpg", "hkps://keys.example.org", "alice@example.org")
        self.assertTrue(ok)
        fetch.assert_called_once_with("gpg", "hkps://keys.example.org", f"0x{fingerprint}")

    def test_missing_key_is_not_silently_discovered_during_delivery(self):
        with (
            mock.patch.dict(routes.os.environ, {"NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT": "false"}),
            mock.patch.object(routes, "get_gpg_key_status", return_value={
                "exists": False, "usable": False, "reason": "Missing public key",
            }),
            mock.patch.object(routes, "fetch_gpg_key") as fetch,
        ):
            ok, message = routes.ensure_gpg_key_ready("gpg", "hkps://keys.example.org", "alice@example.org")
        self.assertFalse(ok)
        self.assertIn("explicitly discover", message)
        fetch.assert_not_called()

    def test_missing_key_is_fetched_once_during_delivery_when_policy_allows(self):
        missing = {"exists": False, "usable": False, "reason": "Missing public key"}
        ready = {"exists": True, "usable": True, "reason": "Public key is usable", "fingerprint": "A" * 40}
        with (mock.patch.dict(routes.os.environ, {"NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT": "true"}),
              mock.patch.object(routes, "get_gpg_key_status", side_effect=[missing, ready]),
              mock.patch.object(routes, "fetch_gpg_key", return_value=(True, "ok")) as fetch):
            self.assertTrue(routes.ensure_gpg_key_ready("gpg", "hkps://keys.example.org", "alice@example.org")[0])
        fetch.assert_called_once_with("gpg", "hkps://keys.example.org", "alice@example.org")
        with (mock.patch.dict(routes.os.environ, {"NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT": "true"}),
              mock.patch.object(routes, "get_gpg_key_status", return_value=missing),
              mock.patch.object(routes, "fetch_gpg_key", return_value=(False, "Unavailable")) as fetch):
            ok, message = routes.ensure_gpg_key_ready("gpg", "hkps://keys.example.org", "alice@example.org")
            self.assertFalse(ok)
            self.assertIn("Unavailable", message)
            fetch.assert_called_once()

    def test_fetched_keys_must_match_address_or_known_fingerprint_before_import(self):
        pub = self.bundle_listing_record("pub")
        uid = self.bundle_listing_record("uid", uid="alice@example.org")
        fingerprint = "A" * 40
        listing = pub + "\nfpr:::::::::" + fingerprint + ":\n" + uid
        with (mock.patch.object(routes, "download_recipient_source", return_value=b"public"),
              mock.patch.object(routes, "inspect_public_key_bundle", return_value=listing),
              mock.patch.object(routes.subprocess, "run", return_value=mock.Mock(returncode=0)) as run):
            self.assertTrue(routes.fetch_gpg_key("gpg", "hkps://keys.example.org", "alice@example.org")[0])
            run.assert_called_once()
            run.reset_mock()
            self.assertFalse(routes.fetch_gpg_key("gpg", "hkps://keys.example.org", "bob@example.org")[0])
            self.assertFalse(routes.fetch_gpg_key("gpg", "hkps://keys.example.org", "0x" + "B" * 40)[0])
            self.assertFalse(routes.fetch_gpg_key("gpg", "http://keys.example.org", "alice@example.org")[0])
            run.assert_not_called()
        with (mock.patch.object(routes, "download_recipient_source", return_value=b"public"),
              mock.patch.object(routes, "inspect_public_key_bundle", return_value=listing + "\n" + pub),
              mock.patch.object(routes.subprocess, "run") as run):
            self.assertFalse(routes.fetch_gpg_key("gpg", "hkps://keys.example.org", "alice@example.org")[0])
            run.assert_not_called()

    def test_preflight_marks_missing_keys_for_delivery_time_fetch_when_enabled(self):
        app = Flask(__name__)
        with (app.test_request_context(json={"sender": "relay@example.org", "lists": ["team"], "use_gpg": True}),
              mock.patch.dict(routes.os.environ, {"NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT": "true"}),
              mock.patch.object(routes, "require_permission", return_value=None),
              mock.patch.object(routes, "load_smtp_profiles", return_value={"relay@example.org": {"keyserver": "hkps://keys.example.org"}}),
              mock.patch.object(routes, "resolve_campaign_recipients", return_value=(["alice@example.org"], [], {"team": 1})),
              mock.patch.object(routes, "validate_gpg", return_value=(True, "ok")),
              mock.patch.object(routes, "get_gpg_key_status", return_value={"exists": False, "usable": False})):
            data = routes.newsletter_preflight().get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["keys_to_fetch_count"], 1)
        self.assertEqual(data["missing_gpg_keys_count"], 0)

    def test_newsletter_live_logs_and_unused_sender_are_removed(self):
        template = (Path(routes.MODULE_DIR) / "templates/newsletter_index.html").read_text(encoding="utf-8")
        for marker in ("logsModal", "openLogsModal", "appendLog(", "const socket", "socket.io.min.js"):
            self.assertNotIn(marker, template)
        self.assertFalse(hasattr(routes, "bg_send_execution"))
        self.assertFalse(hasattr(routes, "join_newsletter_logs"))

    def test_inbound_decrypt_requires_valid_signature_status(self):
        completed = mock.Mock(returncode=0, stdout=b"Subject: signed\n\nbody", stderr=b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 2026")
        with mock.patch("subprocess.run", return_value=completed):
            ok, payload, fingerprints = routes.decrypt_with_gpg("gpg", b"ciphertext", "passphrase")
        self.assertTrue(ok)
        self.assertIn(b"signed", payload)
        self.assertEqual(fingerprints, ["A" * 40])

    def test_secret_gpg_key_status_returns_metadata_only(self):
        fingerprint = "A" * 40
        completed = mock.Mock(
            returncode=0,
            stdout="\n".join([
                "sec:u:3072:1:ABCDEF0123456789:1700000000:1890000000:::::sc:::::",
                f"fpr:::::::::{fingerprint}:",
                "uid:u::::::::Newsletter Mailbox <newsletter@example.com>:",
                "ssb:u:3072:1:0123456789ABCDEF:1700000000:1890000000:::::e:::::",
            ]),
            stderr="",
        )
        with mock.patch("subprocess.run", return_value=completed) as run:
            ok, message, keys = routes.list_secret_gpg_keys("gpg")

        self.assertTrue(ok)
        self.assertEqual(message, "OK")
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["fingerprint"], fingerprint)
        self.assertEqual(keys[0]["key_id"], "ABCDEF0123456789")
        self.assertEqual(keys[0]["uids"], ["Newsletter Mailbox <newsletter@example.com>"])
        self.assertTrue(keys[0]["can_encrypt"])
        self.assertTrue(keys[0]["can_sign"])
        self.assertEqual(keys[0]["status"], "Ready")
        self.assertNotIn("private", keys[0])
        self.assertEqual(run.call_args.kwargs["stdin"], routes.subprocess.DEVNULL)

    def test_secret_gpg_key_status_requires_mail_profile_permission(self):
        denied = ("Forbidden", 403)
        with mock.patch.object(routes, "require_permission", return_value=denied) as require_permission:
            response = routes.gpg_secret_key_status()

        self.assertEqual(response, denied)
        require_permission.assert_called_once_with("manage_smtp")

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
        self.assertTrue(has_permission(editor, "Newsletter", "manage_inbound_routes"))
        self.assertTrue(has_permission(editor, "Newsletter", "refresh_recipient_keys"))

    def test_newsletter_permissions_can_be_separated(self):
        list_editor = mock.Mock(
            is_admin=False,
            allowed_modules=json.dumps(["Newsletter:view_newsletter", "Newsletter:manage_lists", "Newsletter:check_recipient_keys"]),
        )
        self.assertTrue(has_permission(list_editor, "Newsletter", "manage_lists"))
        self.assertTrue(has_permission(list_editor, "Newsletter", "check_recipient_keys"))
        self.assertFalse(has_permission(list_editor, "Newsletter", "refresh_recipient_keys"))
        self.assertFalse(has_permission(list_editor, "Newsletter", "manage_smtp"))
        self.assertFalse(has_permission(list_editor, "Newsletter", "manage_inbound_routes"))

    def test_result_report_recipients_require_exact_email_addresses(self):
        self.assertEqual(
            routes.normalize_result_recipients(["Admin@Example.com", "admin@example.com"]),
            ["admin@example.com"],
        )
        for invalid in (["admin"], ["*"]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                routes.normalize_result_recipients(invalid)

    def test_frontend_keeps_failed_draft_and_has_preflight(self):
        template = Path(routes.MODULE_DIR, "templates", "newsletter_index.html").read_text(encoding="utf-8")
        self.assertIn("runCampaignPreflight", template)
        self.assertIn("Your draft was preserved", template)
        self.assertIn("switchNewsletterGuide('en')", template)
        self.assertIn("New campaign", template)
        self.assertNotIn("Нова розсилка", template)
        self.assertIn("currentLdapProfileId = profile.id", template)
        self.assertNotIn("currentLdapProfileId = id;\n        renderLdapProfiles", template)
        self.assertIn("Default Email Domain (optional)", template)
        self.assertIn("checkListKeys", template)
        self.assertNotIn('id="routeRecipientDomain"', template)
        self.assertIn("campaignReportModal", template)
        self.assertIn("Campaign Result Report Emails", template)
        self.assertIn("#campaignReportModal > div", template)
        self.assertIn("#campaignReportModal tbody tr:nth-child(even)", template)
        self.assertIn("Install The Mailbox Private Key On Debian", template)
        self.assertIn("Як додати приватний ключ поштової скриньки на Debian", template)
        self.assertIn("runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg", template)
        self.assertIn("--list-secret-keys --keyid-format LONG", template)
        self.assertIn("GPG Key Status", template)
        self.assertIn("/api/newsletter/gpg/secret-keys", template)

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

    def test_each_recipient_has_separate_encryption_headers_and_smtp_envelope(self):
        from email import policy
        from email.parser import BytesParser
        with self.app.app_context():
            user = User(username="isolated-newsletter", email="operator@example.org", is_admin=True)
            db.session.add(user)
            db.session.commit()
            recipients = ["alice@example.org", "bob@example.org"]
            campaign = routes.enqueue_campaign(
                user_id=user.id, source="inbound", sender_email="relay@example.org", subject="Private announcement",
                body_text="Announcement body", body_html="", attachments=[], recipients=recipients,
                selected_lists=["private-team"], use_gpg=True)
            campaign.status = "Sending"
            db.session.commit()
            smtp = mock.Mock()
            plaintexts = {}
            def encrypt(_path, recipient, payload):
                plaintexts[recipient] = payload
                return True, "ciphertext-for-" + recipient
            profile = {"host": "smtp.example.org", "port": 587, "password": routes.encrypt_pass("test-only")}
            with (mock.patch.object(routes, "load_smtp_profiles", return_value={campaign.sender_email: profile}),
                  mock.patch.object(routes, "open_smtp_connection", return_value=smtp),
                  mock.patch.object(routes, "validate_gpg", return_value=(True, "ok")),
                  mock.patch.object(routes, "ensure_gpg_key_ready", return_value=(True, "ok")),
                  mock.patch.object(routes, "encrypt_with_gpg", side_effect=encrypt) as encrypt_call,
                  mock.patch.object(routes.time, "sleep")):
                routes.execute_queued_campaign(self.app, campaign.id)
            self.assertEqual(encrypt_call.call_count, 2)
            self.assertEqual(smtp.send_message.call_count, 2)
            for call in smtp.send_message.call_args_list:
                message = call.args[0]
                recipient = str(message["To"])
                other = next(value for value in recipients if value != recipient)
                self.assertEqual(call.kwargs, {"from_addr": campaign.sender_email, "to_addrs": [recipient]})
                self.assertEqual(message.get_content_type(), "multipart/encrypted")
                self.assertIsNone(message["Cc"])
                self.assertIsNone(message["Bcc"])
                self.assertNotIn(other.encode(), message.as_bytes())
                self.assertNotIn(b"Announcement body", message.as_bytes())
                inner = BytesParser(policy=policy.default).parsebytes(plaintexts[recipient])
                self.assertEqual(str(inner["To"]), recipient)
                self.assertIsNone(inner["Cc"])
                self.assertIsNone(inner["Bcc"])
                self.assertNotIn(other.encode(), plaintexts[recipient])
                self.assertNotIn(b"private-team", plaintexts[recipient])

    def test_retry_only_resets_failed_and_skipped_and_rejects_active_campaign(self):
        with self.app.app_context():
            user = User(username="retry-owner", email="operator@example.org", is_admin=True)
            db.session.add(user)
            db.session.commit()
            campaign = routes.enqueue_campaign(user_id=user.id, source="manual", sender_email="relay@example.org",
                subject="Retry", body_text="Body", body_html="", attachments=[],
                recipients=[f"user{i}@example.org" for i in range(4)], selected_lists=["team"], use_gpg=False)
            rows = NewsletterDelivery.query.filter_by(campaign_id=campaign.id).order_by(NewsletterDelivery.id).all()
            for row, status in zip(rows, ["Sent", "Failed", "Skipped", "Unknown"]):
                row.status = status
                row.attempts = 1
            campaign.status = "Sending"
            db.session.commit()
            with (self.app.test_request_context(method="POST", json={"delivery_ids": [rows[1].id, rows[2].id]}),
                  mock.patch.object(routes, "require_permission", return_value=None),
                  mock.patch.object(routes, "current_user", return_value=user)):
                self.assertEqual(routes.retry_newsletter_campaign(campaign.id)[1], 409)
                campaign.status = "Partial"
                db.session.commit()
                self.assertTrue(routes.retry_newsletter_campaign(campaign.id).get_json()["success"])
            self.assertEqual([row.status for row in rows], ["Sent", "Pending", "Pending", "Unknown"])
            self.assertEqual([row.attempts for row in rows], [1, 1, 1, 1])
            self.assertEqual(campaign.status, "Queued")

    def test_selective_retry_preview_and_server_validation(self):
        with self.app.app_context():
            user = User(username="selective-retry-owner", email="owner@example.org", is_admin=False)
            other = User(username="selective-retry-other", email="other@example.org", is_admin=False)
            db.session.add_all([user, other])
            db.session.commit()
            campaigns = []
            for owner in (user, other):
                campaign = routes.enqueue_campaign(user_id=owner.id, source="manual", sender_email="relay@example.org",
                    subject="Selection", body_text="Body", body_html="", attachments=[],
                    recipients=[f"u{i}@example.org" for i in range(5)], selected_lists=["team"], use_gpg=False)
                campaign.status = "Partial"
                campaigns.append(campaign)
            rows = NewsletterDelivery.query.filter_by(campaign_id=campaigns[0].id).order_by(NewsletterDelivery.id).all()
            for row, status, error in zip(rows, ["Failed", "Failed", "Skipped", "Sent", "Unknown"],
                ["Missing public key; use the list key check", "550 5.1.1 Recipient address rejected", "Cancelled", None, "Uncertain"]):
                row.status, row.error = status, error
            db.session.commit()
            with (mock.patch.object(routes, "require_permission", return_value=None),
                  mock.patch.object(routes, "current_user", return_value=user),
                  mock.patch.object(routes, "has_permission", return_value=False),
                  mock.patch.object(routes.WinHubCore, "audit")):
                with self.app.test_request_context(method="GET"):
                    data = routes.retry_newsletter_campaign(campaigns[0].id).get_json()
                    groups = {group["id"]: group for group in data["groups"]}
                    self.assertEqual(set(groups), {"missing_key", "recipient_address", "skipped"})
                    self.assertEqual(groups["missing_key"]["recipients"][0]["id"], rows[0].id)
                    self.assertEqual(routes.retry_newsletter_campaign(campaigns[1].id)[1], 404)
                foreign = NewsletterDelivery.query.filter_by(campaign_id=campaigns[1].id).first()
                for payload in ({}, {"delivery_ids": []}, {"delivery_ids": [None]}, {"delivery_ids": [rows[3].id]},
                                {"delivery_ids": [rows[4].id]}, {"delivery_ids": [foreign.id]}, {"delivery_ids": [rows[0].id, "missing"]}):
                    with self.subTest(payload=payload), self.app.test_request_context(method="POST", json=payload):
                        response = routes.retry_newsletter_campaign(campaigns[0].id)
                        self.assertIn(response[1], (400, 409))
                    self.assertEqual(rows[0].status, "Failed")
                with self.app.test_request_context(method="POST", json={"delivery_ids": [rows[0].id]}):
                    data = routes.retry_newsletter_campaign(campaigns[0].id).get_json()
                self.assertEqual(data["retry_count"], 1)
                self.assertEqual([row.status for row in rows], ["Pending", "Failed", "Skipped", "Sent", "Unknown"])
                self.assertIsNone(rows[0].error)
                self.assertIn("Recipient address", rows[1].error)

    def test_active_progress_uses_committed_delivery_counts_before_campaign_finishes(self):
        with self.app.app_context():
            user = User(username="progress-owner", email="owner@example.org", is_admin=False)
            other = User(username="progress-other", email="other@example.org", is_admin=False)
            db.session.add_all([user, other])
            db.session.commit()
            campaigns = []
            for owner in (user, user, other):
                campaign = routes.enqueue_campaign(
                    user_id=owner.id, source="manual", sender_email="sender@example.org", subject="Progress",
                    body_text="Body", body_html="", attachments=[], recipients=[f"u{i}@example.org" for i in range(6)],
                    selected_lists=["ops"], use_gpg=False)
                campaign.status = "Sending"
                rows = NewsletterDelivery.query.filter_by(campaign_id=campaign.id).all()
                for row, status in zip(rows, ("Sent", "Failed", "Unknown", "Skipped", "Sending", "Pending")):
                    row.status = status
                campaigns.append(campaign)
            db.session.commit()
            self.assertEqual(campaigns[0].sent_count, 0)
            statements = []
            def record_sql(_connection, _cursor, statement, _parameters, _context, _executemany):
                statements.append(statement)
            with (mock.patch.object(routes, "require_permission", return_value=None),
                  mock.patch.object(routes, "current_user", return_value=user),
                  mock.patch.object(routes, "has_permission", return_value=False)):
                event.listen(db.engine, "before_cursor_execute", record_sql)
                try:
                    with self.app.test_request_context():
                        listed = routes.list_newsletter_campaigns().get_json()["campaigns"]
                    self.assertEqual(len(listed), 2)
                    self.assertTrue(all(row["sent_count"] == 1 and row["failed_count"] == 2 and row["skipped_count"] == 1 for row in listed))
                    self.assertEqual(sum("GROUP BY" in statement for statement in statements), 1)
                    statements.clear()
                    with self.app.test_request_context("/?summary_only=1"):
                        progress = routes.get_newsletter_campaign(campaigns[0].id).get_json()
                    self.assertEqual(progress["campaign"]["status"], "Sending")
                    self.assertEqual(progress["campaign"]["sent_count"], 1)
                    self.assertEqual(progress["delivery_counts"], {"Sent": 1, "Failed": 1, "Unknown": 1, "Skipped": 1, "Sending": 1, "Pending": 1})
                    self.assertNotIn("deliveries", progress)
                    self.assertNotIn("pagination", progress)
                    delivery_queries = [statement for statement in statements if "FROM newsletter_deliveries" in statement]
                    self.assertEqual(len(delivery_queries), 1)
                    self.assertIn("GROUP BY", delivery_queries[0])
                    self.assertNotIn("newsletter_deliveries.recipient", delivery_queries[0])
                    with self.app.test_request_context("/?summary_only=1"):
                        self.assertEqual(routes.get_newsletter_campaign(campaigns[2].id)[1], 404)
                finally:
                    event.remove(db.engine, "before_cursor_execute", record_sql)
            db.session.refresh(campaigns[0])
            self.assertEqual(campaigns[0].sent_count, 0, "Progress reads must not rewrite durable campaign state")

    def test_enqueue_creates_durable_task_and_deduplicated_deliveries(self):
        with self.app.app_context():
            user = User(username="newsletter-operator", email="operator@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            task_exists_before_campaign_insert = []

            def record_parent_visibility(_mapper, connection, target):
                task_exists_before_campaign_insert.append(connection.execute(
                    select(Task.id).where(Task.id == target.task_id)
                ).scalar_one_or_none())

            event.listen(NewsletterCampaign, "before_insert", record_parent_visibility)
            try:
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
            finally:
                event.remove(NewsletterCampaign, "before_insert", record_parent_visibility)

            self.assertEqual(task_exists_before_campaign_insert, [campaign.task_id])
            self.assertEqual(campaign.status, "Queued")
            self.assertEqual(NewsletterDelivery.query.filter_by(campaign_id=campaign.id).count(), 2)
            self.assertEqual(db.session.get(Task, campaign.task_id).status, "Queued")

    def test_result_report_is_durable_and_contains_complete_csv(self):
        with self.app.app_context():
            user = User(username="newsletter-report", email="operator@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            campaign = routes.enqueue_campaign(
                user_id=user.id,
                source="inbound",
                sender_email="sender@example.com",
                subject="Maintenance",
                body_text="Body",
                body_html="",
                attachments=[],
                recipients=["ok@example.com", "failed@example.com"],
                selected_lists=["ops"],
                use_gpg=True,
                result_recipients=["admin1@example.com", "admin2@example.com"],
                result_use_gpg=False,
            )
            deliveries = NewsletterDelivery.query.filter_by(campaign_id=campaign.id).all()
            for delivery in deliveries:
                delivery.status = "Sent" if delivery.recipient == "ok@example.com" else "Failed"
                delivery.error = "=Mailbox rejected" if delivery.status == "Failed" else None
            campaign.status = "Partial"
            campaign.sent_count = 1
            campaign.failed_count = 1
            db.session.commit()

            smtp = mock.Mock()
            with mock.patch.object(routes, "open_smtp_connection", return_value=smtp):
                routes.deliver_campaign_result_report(
                    campaign,
                    {"host": "smtp.example.com", "port": 587, "password": routes.encrypt_pass("secret")},
                    "gpg",
                    "",
                )

            db.session.refresh(campaign)
            self.assertEqual(campaign.result_report_status, "Completed")
            self.assertEqual(smtp.send_message.call_count, 2)
            message = smtp.send_message.call_args_list[0].args[0]
            csv_attachment = next(message.iter_attachments())
            csv_text = csv_attachment.get_content()
            self.assertIn("ok@example.com", csv_text)
            self.assertIn("failed@example.com", csv_text)
            self.assertIn("'=Mailbox rejected", csv_text)

    def test_recovery_does_not_resend_uncertain_result_report(self):
        with self.app.app_context():
            user = User(username="newsletter-report-recovery", email="operator@example.com", is_admin=True)
            db.session.add(user)
            db.session.commit()
            campaign = routes.enqueue_campaign(
                user_id=user.id, source="inbound", sender_email="sender@example.com",
                subject="Recovery", body_text="Body", body_html="", attachments=[],
                recipients=["a@example.com"], selected_lists=["ops"], use_gpg=False,
                result_recipients=["admin@example.com"], result_use_gpg=False,
            )
            campaign.status = "Completed"
            campaign.result_report_status = "Sending"
            campaign.result_report_json = json.dumps([{
                "recipient": "admin@example.com", "status": "Sending", "error": "", "sent_at": None,
            }])
            db.session.commit()
            routes.recover_interrupted_campaigns()
            db.session.refresh(campaign)
            self.assertEqual(campaign.result_report_status, "Unknown")
            self.assertEqual(json.loads(campaign.result_report_json)[0]["status"], "Unknown")

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
