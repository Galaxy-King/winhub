import hashlib
import importlib.util
import json
import re
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


class TemplateVariableSubstitutionTests(unittest.TestCase):
    def test_windows_and_unc_backslashes_are_inserted_literally(self):
        from modules.Infrastructure.routes import apply_template_variables

        payload = {
            "script": (
                "destination={{backup_destination}}\n"
                "source={{source_folder}}\n"
                "user={{smb_username}}\n"
                "literal={{literal_backreference}}"
            )
        }
        variables = {
            "backup_destination": r"\\192.168.36.201\2Scope_backup\term36_101",
            "source_folder": r"C:\Bases",
            "smb_username": r"DOMAIN\backup-user",
            "literal_backreference": r"value\g<2>\1",
        }

        rendered, unresolved = apply_template_variables(payload, variables)

        self.assertEqual(unresolved, [])
        self.assertEqual(
            rendered["script"],
            "destination=\\\\192.168.36.201\\2Scope_backup\\term36_101\n"
            "source=C:\\Bases\n"
            "user=DOMAIN\\backup-user\n"
            "literal=value\\g<2>\\1",
        )


class TemplateCloneTests(unittest.TestCase):
    def test_clone_name_is_unique_and_limited_to_database_column(self):
        from modules.Infrastructure.routes import next_template_clone_name

        self.assertEqual(next_template_clone_name("Backup", []), "Backup clone")
        self.assertEqual(
            next_template_clone_name("Backup", ["backup CLONE", "Backup clone 2"]),
            "Backup clone 3",
        )
        self.assertLessEqual(len(next_template_clone_name("x" * 200, [])), 150)

    def test_clone_keeps_functional_payload_but_drops_governance_policy(self):
        from modules.Infrastructure.routes import clone_template_payload

        source = types.SimpleNamespace(payload=json.dumps({
            "script": "backup {{destination}}",
            "__variable_schema": {"destination": {"type": "text"}},
            "__report_template_id": "report-id",
            "__auto_email_toggle": True,
            "__template_policy": {"lock_edit": True, "disable_run": True},
        }))

        cloned = clone_template_payload(source)

        self.assertEqual(cloned["script"], "backup {{destination}}")
        self.assertEqual(cloned["__report_template_id"], "report-id")
        self.assertTrue(cloned["__auto_email_toggle"])
        self.assertIn("__variable_schema", cloned)
        self.assertNotIn("__template_policy", cloned)

    def test_template_actions_are_in_the_builder_toolbar(self):
        template = (ROOT / "modules/Infrastructure/templates/tabs/_deploy.html").read_text(encoding="utf-8")
        modals = (ROOT / "modules/Infrastructure/templates/modals/_modals.html").read_text(encoding="utf-8")
        javascript = (ROOT / "static/js/infrastructure.js").read_text(encoding="utf-8")

        self.assertIn('id="btnNewTemplate"', template)
        self.assertIn('id="btnSaveTemplate"', template)
        self.assertIn('id="btnExportTemplate"', template)
        self.assertIn('id="btnCloneTemplate"', template)
        self.assertIn('id="btnDeleteTemplate"', template)
        self.assertIn('onclick="startNewTemplate()"', template)
        self.assertIn('onclick="exportSelectedTemplate()"', template)
        self.assertIn('onclick="cloneSelectedTemplate()"', template)
        self.assertIn('onclick="openTemplateDeleteModal()"', template)
        self.assertNotIn('class="sr-only"', template)
        self.assertIn('aria-label="New template"', template)
        self.assertIn('aria-label="Save template"', template)
        self.assertIn('aria-label="Download selected template"', template)
        self.assertIn('aria-label="Clone selected template"', template)
        self.assertIn('aria-label="Delete selected template"', template)
        self.assertEqual(template.count("cloneTemplate('{{ t.id }}')"), 0)
        self.assertEqual(template.count("exportTemplate('{{ t.id }}')"), 0)
        self.assertNotIn("deleteTemplate('{{ t.id }}')", template)
        self.assertNotIn('id="btnNewScript"', template)
        self.assertIn('id="templateDeleteModal"', modals)
        self.assertIn('id="templateDeleteConfirmation"', modals)
        self.assertIn("'/deletion-impact'", javascript)
        self.assertIn("JSON.stringify({confirm_name: confirmation.value})", javascript)

    def test_template_deletion_impact_summarizes_dependencies(self):
        from modules.Infrastructure import routes

        scheduled_query = mock.Mock()
        scheduled_query.count.return_value = 7
        scheduled_query.order_by.return_value.limit.return_value.all.return_value = [
            types.SimpleNamespace(name="Nightly"),
            types.SimpleNamespace(name="Weekly"),
        ]
        trigger_query = mock.Mock()
        trigger_query.count.return_value = 1
        trigger_query.order_by.return_value.limit.return_value.all.return_value = [
            types.SimpleNamespace(name="Disk alert"),
        ]
        scheduled_model = types.SimpleNamespace(
            name=object(),
            query=types.SimpleNamespace(filter_by=mock.Mock(return_value=scheduled_query)),
        )
        trigger_model = types.SimpleNamespace(
            name=object(),
            query=types.SimpleNamespace(filter_by=mock.Mock(return_value=trigger_query)),
        )

        with mock.patch.object(routes, "ScheduledTask", scheduled_model), mock.patch.object(routes, "TriggerRule", trigger_model):
            impact = routes.template_deletion_impact("template-id", sample_limit=2)

        self.assertEqual(impact["scheduled_tasks"]["count"], 7)
        self.assertEqual(impact["scheduled_tasks"]["names"], ["Nightly", "Weekly"])
        self.assertTrue(impact["scheduled_tasks"]["truncated"])
        self.assertEqual(impact["trigger_rules"]["count"], 1)
        self.assertFalse(impact["trigger_rules"]["truncated"])

    def test_template_delete_requires_exact_name_confirmation(self):
        from flask import Flask
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "template-delete-test"
        template = types.SimpleNamespace(id="template-id", name="Critical Backup", type="action")
        query = types.SimpleNamespace(get=mock.Mock(return_value=template))
        template_model = types.SimpleNamespace(query=query)
        with app.test_request_context(
            "/api/infrastructure/templates/template-id",
            method="DELETE",
            json={"confirm_name": "wrong name"},
        ), mock.patch.object(routes, "require_permission", return_value=None), mock.patch.object(
            routes, "TaskTemplate", template_model
        ), mock.patch.object(routes, "can_access_template_library_entry", return_value=True), mock.patch.object(
            routes, "can_delete_template", return_value=True
        ):
            response, status = routes.delete_template("template-id")

        self.assertEqual(status, 400)
        self.assertFalse(response.get_json()["success"])
        self.assertIn("exact template name", response.get_json()["message"])

    def test_template_library_access_does_not_expose_another_users_private_draft(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "template-access-test"
        with app.test_request_context("/"):
            session["username"] = "alice"
            session["is_admin"] = False
            own_draft = types.SimpleNamespace(created_by="alice", is_approved=False)
            foreign_draft = types.SimpleNamespace(created_by="bob", is_approved=False)
            shared_template = types.SimpleNamespace(created_by="bob", is_approved=True)
            with mock.patch.object(routes, "can", return_value=True), mock.patch.object(routes, "can_use_template", return_value=True):
                self.assertTrue(routes.can_access_template_library_entry(own_draft))
                self.assertFalse(routes.can_access_template_library_entry(foreign_draft))
                self.assertTrue(routes.can_access_template_library_entry(shared_template))


class ContentSecurityPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csp = load_file("winhub_csp_test", "core/csp.py")

    def test_default_policy_uses_nonce_for_script_and_style_blocks(self):
        policy = self.csp.DEFAULT_CSP_POLICY
        self.assertIn("script-src 'self' 'nonce-{nonce}'", policy)
        self.assertIn("style-src 'self' 'nonce-{nonce}'", policy)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", policy)
        self.assertNotIn("style-src 'self' 'unsafe-inline'", policy)

    def test_nonce_is_unique_and_is_rendered_into_policy(self):
        first = self.csp.new_csp_nonce()
        second = self.csp.new_csp_nonce()
        self.assertNotEqual(first, second)
        rendered = self.csp.render_csp_policy(self.csp.DEFAULT_CSP_POLICY, first)
        self.assertNotIn("{nonce}", rendered)
        self.assertIn(f"'nonce-{first}'", rendered)

    def test_transition_keeps_compatibility_enforced_and_reports_nonce_policy(self):
        nonce = self.csp.new_csp_nonce()
        headers = self.csp.build_csp_headers(
            "enforce",
            self.csp.COMPATIBILITY_CSP_POLICY,
            "report-only",
            self.csp.DEFAULT_CSP_POLICY,
            nonce,
        )
        self.assertIn("'unsafe-inline'", headers["Content-Security-Policy"])
        self.assertIn(f"'nonce-{nonce}'", headers["Content-Security-Policy-Report-Only"])

    def test_nonce_enforcement_replaces_compatibility_policy(self):
        nonce = self.csp.new_csp_nonce()
        headers = self.csp.build_csp_headers(
            "enforce",
            self.csp.COMPATIBILITY_CSP_POLICY,
            "enforce",
            self.csp.DEFAULT_CSP_POLICY,
            nonce,
        )
        enforced = headers["Content-Security-Policy"]
        self.assertIn(f"'nonce-{nonce}'", enforced)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", enforced)
        self.assertNotIn("Content-Security-Policy-Report-Only", headers)

    def test_all_template_script_and_style_tags_carry_nonce(self):
        template_paths = list((ROOT / "templates").rglob("*.html"))
        template_paths.extend((ROOT / "modules").glob("*/templates/**/*.html"))
        for template_path in sorted(set(template_paths)):
            source = template_path.read_text(encoding="utf-8")
            for tag in re.findall(r"<(?:script|style)\b[^>]*>", source, flags=re.IGNORECASE):
                with self.subTest(template=str(template_path), tag=tag):
                    self.assertIn('nonce="{{ csp_nonce }}"', tag)


class StoredXssRegressionTests(unittest.TestCase):
    def test_agent_and_user_controlled_infrastructure_fields_are_escaped(self):
        source = (ROOT / "static/js/infrastructure.js").read_text(encoding="utf-8")
        required_escapes = [
            "${escapeHtml(m.item_name)}",
            "${escapeHtml(m.last_value || 'No data')}",
            "${escapeHtml(m.last_updated)}",
            "${escapeHtml(m.os_type)}",
            "${escapeHtml(m.ip)}",
            "${escapeInlineJs(m.id)}",
            "${escapeHtml(s.name)}",
            "${escapeHtml(s.placeholder)}",
            "${escapeInlineJs(s.name)}",
            "${escapeInlineJs(t.task_id)}",
        ]
        for escaped_expression in required_escapes:
            with self.subTest(expression=escaped_expression):
                self.assertIn(escaped_expression, source)

    def test_administration_lists_escape_stored_values_and_do_not_embed_objects_in_handlers(self):
        source = (ROOT / "templates/admin_users.html").read_text(encoding="utf-8")
        required_escapes = [
            "${escapeHtml(u.username)}",
            "${escapeHtml(u.email)}",
            "${escapeHtml(k.name)}",
            "${escapeHtml(k.prefix)}",
            "${escapeHtml(k.user)}",
            "${escapeHtml(k.expires)}",
            "${escapeHtml(g.name)}",
            "${escapeHtml(p.name)}",
            "${escapeHtml(row.module || 'General')}",
        ]
        for escaped_expression in required_escapes:
            with self.subTest(expression=escaped_expression):
                self.assertIn(escaped_expression, source)
        self.assertNotIn("openEditModal(${JSON.stringify(u)})", source)
        self.assertNotIn("openApiAccessModal(${JSON.stringify(k)})", source)


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

    def test_enforce_mode_pins_connection_to_the_validated_dns_answer(self):
        public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        rebound_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        hostname_queries = 0

        def rebinding_resolver(host, port, *args, **kwargs):
            nonlocal hostname_queries
            if str(host).lower() == "public.example":
                hostname_queries += 1
                return public_answer if hostname_queries == 1 else rebound_answer
            if str(host) == "93.184.216.34":
                return public_answer
            return rebound_answer

        with mock.patch.object(self.policy.socket, "getaddrinfo", side_effect=rebinding_resolver):
            with self.policy.pinned_outbound_host("public.example", 443, "test"):
                connected = self.policy.socket.getaddrinfo("public.example", 443, type=socket.SOCK_STREAM)

        self.assertEqual(hostname_queries, 1)
        self.assertEqual({item[4][0] for item in connected}, {"93.184.216.34"})


class RendererDeploymentTests(unittest.TestCase):
    def test_systemd_renderer_is_a_separate_no_network_identity(self):
        service = (ROOT / "deploy/debian/winhub-renderer@.service").read_text(encoding="utf-8")
        socket_unit = (ROOT / "deploy/debian/winhub-renderer.socket").read_text(encoding="utf-8")
        self.assertIn("User=winhub-renderer", service)
        self.assertIn("Group=winhub-renderer", service)
        self.assertIn("PrivateNetwork=true", service)
        self.assertIn("InaccessiblePaths=/etc/winhub /var/lib/winhub /var/log/winhub", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("SystemCallFilter=~@network-io", service)
        self.assertIn("--require-limits", service)
        self.assertIn("SocketMode=0660", socket_unit)



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
