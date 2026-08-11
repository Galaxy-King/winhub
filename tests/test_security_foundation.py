import hashlib
import importlib.util
import json
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_file(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReportRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.renderer = load_file("winhub_report_renderer_test", "core/report_renderer.py")

    def test_known_jinja_escape_paths_are_blocked(self):
        attacks = [
            "{{ ''.__class__.__mro__ }}",
            "{{ cycler.__init__.__globals__ }}",
            "{% include 'secret' %}",
            "{{ lipsum() }}",
        ]
        for attack in attacks:
            with self.subTest(attack=attack), self.assertRaises(Exception):
                self.renderer.render_report(attack, {})

    def test_output_is_html_escaped(self):
        output = self.renderer.render_report("{{ value }}", {"value": '<img src=x onerror="alert(1)">'})
        self.assertNotIn("<img", output)
        self.assertIn("&lt;img", output)

    def test_bundled_report_templates_remain_supported(self):
        for template_path in sorted((ROOT / "deploy/import_templates").glob("**/*.jinja")):
            if "vss_winrar_backup" in template_path.parts:  # user-owned untracked worktree content
                continue
            with self.subTest(template=str(template_path)):
                self.renderer.validate_report_template(template_path.read_text(encoding="utf-8"))

    def test_namespace_aggregation_remains_supported(self):
        template = "{% set ns = namespace(total=0) %}{% set ns.total = ns.total + 1 %}{{ ns.total }}"
        self.assertEqual(self.renderer.render_report(template, {}), "1")


class TemplateApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.security = load_file("winhub_template_security_test", "core/template_security.py")

    def test_any_payload_change_breaks_approval_hash(self):
        original = self.security.template_content_hash("run_script", "action", {"script": "echo safe"})
        changed = self.security.template_content_hash("run_script", "action", {"script": "echo changed"})
        self.assertNotEqual(original, changed)


class OutboundPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.ModuleType("core.config")

        class Config:
            OUTBOUND_ALLOWED_HOSTS = ""
            OUTBOUND_POLICY_MODE = "enforce"

        fake_config.Config = Config
        cls.previous_config_module = sys.modules.get("core.config")
        sys.modules["core.config"] = fake_config
        cls.policy = load_file("winhub_outbound_security_test", "core/outbound_security.py")
        cls.Config = Config

    @classmethod
    def tearDownClass(cls):
        if cls.previous_config_module is None:
            sys.modules.pop("core.config", None)
        else:
            sys.modules["core.config"] = cls.previous_config_module

    def test_private_destination_requires_allowlist(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        with mock.patch.object(self.policy.socket, "getaddrinfo", return_value=answer):
            with self.assertRaises(self.policy.OutboundPolicyError):
                self.policy.validate_outbound_url("https://metadata.invalid/latest", "test")

    def test_explicit_private_destination_is_allowed(self):
        self.Config.OUTBOUND_ALLOWED_HOSTS = "wiki.internal"
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.10", 443))]
        try:
            with mock.patch.object(self.policy.socket, "getaddrinfo", return_value=answer):
                self.policy.validate_outbound_url("https://wiki.internal/rest/api", "test")
        finally:
            self.Config.OUTBOUND_ALLOWED_HOSTS = ""


class TaskSignatureContractTests(unittest.TestCase):
    def test_v2_canonical_contract_matches_agent_self_test(self):
        fields = {
            "sequence": 7,
            "task_id": "task-1",
            "issued_at": 1000,
            "action": "run_script",
            "protocol_version": 2,
            "payload_hash": "def",
            "key_id": "abc",
            "expires_at": 2000,
            "endpoint_id": "endpoint-1",
            "timeout_seconds": 300,
        }
        canonical = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "1e96cb746aad196aee4bfdf4399e3f0af62d52f828e2357b0ea821a9d9f89267",
        )


if __name__ == "__main__":
    unittest.main()
