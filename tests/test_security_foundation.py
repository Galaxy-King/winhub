import hashlib
import importlib.util
import json
import re
import socket
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]


def load_file(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BrandingAssetTests(unittest.TestCase):
    def test_all_base_layouts_include_the_local_svg_favicon(self):
        base = (ROOT / "templates/base.html").read_text(encoding="utf-8")
        mobile = (ROOT / "templates/mobile_base.html").read_text(encoding="utf-8")
        favicon = (ROOT / "static/favicon.svg").read_text(encoding="utf-8")

        favicon_link = "filename='favicon.svg'"
        self.assertIn(favicon_link, base)
        self.assertIn(favicon_link, mobile)
        self.assertIn('viewBox="0 0 64 64"', favicon)
        self.assertNotIn("<script", favicon.lower())


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

    def test_bounded_range_and_lower_filter_remain_supported(self):
        template = (
            "{% for value in range(first, last + 1) %}"
            "{{ loop.index0 }}:{{ label|lower }}-{{ value }}{% if not loop.last %}, {% endif %}"
            "{% endfor %}"
        )
        self.assertEqual(
            self.renderer.render_report(template, {"first": 1, "last": 3, "label": "HOST"}),
            "0:host-1, 1:host-2, 2:host-3",
        )

    def test_report_range_rejects_excessive_or_non_integer_iterations(self):
        with self.assertRaises(Exception):
            self.renderer.render_report("{% for value in range(0, 5000) %}{{ value }}{% endfor %}", {})
        with self.assertRaises(Exception):
            self.renderer.render_report("{{ range('0', 5)|list }}", {})

    def test_loop_methods_are_not_exposed(self):
        with self.assertRaises(Exception):
            self.renderer.render_report(
                "{% for value in range(0, 2) %}{{ loop.cycle('a', 'b') }}{% endfor %}",
                {},
            )


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

    def test_template_actions_and_compact_editors_have_safe_layout(self):
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
        self.assertEqual(template.count('id="btnNewTemplate"'), 1)
        self.assertLess(template.index('id="btnNewTemplate"'), template.index('id="btnSaveTemplate"'))
        self.assertEqual(template.count('Execution Time Limit'), 1)
        self.assertLess(template.index('Execution Time Limit'), template.index('Post-Execution'))
        self.assertIn("openTemplateCodeEditor('payload')", template)
        self.assertIn("openTemplateCodeEditor('schema')", template)
        self.assertIn('id="depPayload" spellcheck="false" class="hidden"', template)
        self.assertIn('id="depVariableSchema" spellcheck="false" class="hidden"', template)
        self.assertIn('.cm-s-winhub-studio.CodeMirror', template)
        self.assertIn('background: #bfdbfe !important;', template)
        self.assertNotIn('togglePayloadEditorExpanded()', template)
        self.assertIn('id="templateCodeEditorModal"', modals)
        self.assertIn('id="templateCodeEditorTextarea"', modals)
        self.assertIn('function applyTemplateCodeEditor()', javascript)
        self.assertIn("mode: {name: 'javascript', json: true}", javascript)
        self.assertIn('id="templateDeleteModal"', modals)
        self.assertIn('id="templateDeleteConfirmation"', modals)
        self.assertIn("'/deletion-impact'", javascript)
        self.assertIn("JSON.stringify({confirm_name: confirmation.value})", javascript)

    def test_report_reader_keeps_large_responsive_body_and_reading_controls(self):
        page = (ROOT / "modules/Infrastructure/templates/infrastructure_index.html").read_text(encoding="utf-8")
        modals = (ROOT / "modules/Infrastructure/templates/modals/_modals.html").read_text(encoding="utf-8")
        javascript = (ROOT / "static/js/infrastructure.js").read_text(encoding="utf-8")

        self.assertIn('id="reportViewShell"', modals)
        self.assertIn('id="reportViewerMain"', modals)
        self.assertIn('id="reportTrailPanel"', modals)
        self.assertIn('class="report-body-frame"', modals)
        self.assertIn('id="reportFullscreenToggle"', modals)
        self.assertIn('id="reportWrapToggle"', modals)
        self.assertIn('id="reportFontSizeLabel"', modals)
        self.assertIn('id="reportCopyButton"', modals)
        self.assertIn('id="vrBodyStats"', modals)
        self.assertNotIn('lg:grid-cols-[19rem_1fr]', modals)

        self.assertIn('#reportViewModal .report-body-frame', page)
        self.assertIn('min-height: 18rem;', page)
        self.assertIn('#reportViewModal.is-fullscreen .report-viewer-shell', page)
        self.assertIn('@media (max-width: 960px)', page)
        self.assertIn('transform: translateX(-105%);', page)
        self.assertIn('width: min(88vw, 22rem);', page)

        self.assertIn('function toggleReportTrail()', javascript)
        self.assertIn('function toggleReportFullscreen()', javascript)
        self.assertIn('function toggleReportWrap()', javascript)
        self.assertIn('function changeReportFontSize(delta)', javascript)
        self.assertIn('function updateReportBodyStats()', javascript)
        self.assertIn("storedFontSizeValue !== null", javascript)

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
        ), mock.patch.object(routes, "require_interactive_superadmin", return_value=None), mock.patch.object(
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


class ThemeSurfaceContractTests(unittest.TestCase):
    def test_audit_history_uses_semantic_dark_surfaces(self):
        base = (ROOT / "templates/base.html").read_text(encoding="utf-8")
        history = (ROOT / "modules/HistoryAudit/templates/history_index.html").read_text(encoding="utf-8")

        self.assertIn("Stable semantic surface system", base)
        for component in (
            ".wh-theme-scope",
            ".wh-ui-page",
            ".wh-ui-surface",
            ".wh-ui-control",
            ".wh-ui-chip",
            ".wh-ui-row",
            ".wh-ui-modal",
            ".wh-ui-button-accent",
            ".wh-ui-button-danger",
        ):
            with self.subTest(component=component):
                self.assertIn(component, base)

        self.assertIn("history-audit-shell wh-theme-scope wh-ui-page", history)
        self.assertIn('class="audit-filter-grid"', history)
        self.assertIn("grid-template-columns: minmax(13rem, 5fr)", history)
        self.assertIn('class="wh-ui-surface rounded-3xl', history)
        self.assertIn("audit-input wh-ui-control", history)
        self.assertIn("audit-chip wh-ui-chip", history)
        self.assertIn('class="audit-row wh-ui-row"', history)
        self.assertIn('class="wh-ui-modal rounded-3xl', history)
        self.assertIn("wh-ui-button-accent", history)
        self.assertIn("wh-ui-button-danger", history)

        direct_light_surface = re.compile(
            r"background(?:-color)?\s*:\s*(?:#fff(?:fff)?\b|white\b|#f8fafc\b)",
            re.IGNORECASE,
        )
        self.assertNotRegex(history, direct_light_surface)
        self.assertNotIn("bg-white", history)

    def test_report_preview_keeps_light_rows_and_dark_text_inside_neon_theme(self):
        infrastructure = (
            ROOT / "modules/Infrastructure/templates/infrastructure_index.html"
        ).read_text(encoding="utf-8")

        self.assertIn("body #reportViewModal #vrPreview table", infrastructure)
        self.assertIn(
            "body #reportViewModal #vrPreview tbody tr:nth-child(odd) td",
            infrastructure,
        )
        self.assertIn(
            "body #reportViewModal #vrPreview tbody tr:nth-child(even) td",
            infrastructure,
        )
        self.assertIn(
            "body #reportViewModal #vrPreview tbody tr:hover *",
            infrastructure,
        )
        self.assertIn("color: #0f172a !important;", infrastructure)

    def test_ai_provider_modal_uses_scoped_dark_theme_components(self):
        modals = (
            ROOT / "modules/Infrastructure/templates/modals/_modals.html"
        ).read_text(encoding="utf-8")
        provider_start = modals.index('id="aiProviderModal"')
        provider_end = modals.index("{% endif %}", provider_start)
        provider = modals[provider_start:provider_end]

        self.assertIn("wh-theme-scope", provider)
        self.assertIn("ai-provider-dialog wh-ui-modal", provider)
        self.assertIn("ai-provider-form wh-ui-surface", provider)
        self.assertEqual(provider.count("ai-provider-control wh-ui-control"), 3)
        self.assertIn("ai-provider-button-secondary wh-ui-button-secondary", provider)
        self.assertIn("ai-provider-button-primary wh-ui-button-accent", provider)
        self.assertNotIn('class="bg-white', provider)


class SchedulerRegressionTests(unittest.TestCase):
    def test_scheduler_access_can_be_granted_without_system_admin(self):
        from core.permissions import MODULE_PERMISSION_CATALOG, has_permission
        from modules.Infrastructure import routes

        user = types.SimpleNamespace(
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:scheduler"]),
        )
        self.assertTrue(has_permission(user, "Infrastructure", "manage_scheduler"))
        self.assertIn("scheduler", {
            permission["id"] for permission in MODULE_PERMISSION_CATALOG["Infrastructure"]
        })

        template = types.SimpleNamespace(id="template-1")
        host_schedule = types.SimpleNamespace(target_type="host", target_id="host-1", template=template)
        group_schedule = types.SimpleNamespace(target_type="group", target_id="group-1", template=template)
        foreign_schedule = types.SimpleNamespace(target_type="group", target_id="group-2", template=template)
        scheduled_query = mock.Mock()
        scheduled_query.order_by.return_value.all.return_value = [
            host_schedule,
            group_schedule,
            foreign_schedule,
        ]
        scheduled_model = types.SimpleNamespace(
            category=object(),
            name=object(),
            query=scheduled_query,
        )
        with mock.patch.object(routes, "ScheduledTask", scheduled_model), \
             mock.patch.object(routes, "can_access_template_library_entry", return_value=True), \
             mock.patch.object(routes, "can_use_template", return_value=True):
            visible = routes.scheduled_tasks_visible_to_user(
                user,
                {"manage_scheduler": True},
                {"host-1"},
                {"group-1"},
            )
        self.assertEqual(visible, [host_schedule, group_schedule])

    def test_schedule_expressions_use_strict_24_hour_kyiv_format(self):
        from modules.Infrastructure.routes import validate_schedule_expression

        now = datetime(2026, 8, 18, 10, 0, tzinfo=ZoneInfo("Europe/Kyiv"))
        self.assertEqual(
            validate_schedule_expression("DATE:2026-08-18 23:45", now=now),
            "DATE:2026-08-18 23:45",
        )
        self.assertEqual(validate_schedule_expression("15  7 * * 0,2"), "15 7 * * 0,2")
        with self.assertRaisesRegex(ValueError, "24-hour"):
            validate_schedule_expression("DATE:2026-08-18 11:45 PM", now=now)
        with self.assertRaisesRegex(ValueError, "future"):
            validate_schedule_expression("DATE:2026-08-18 09:59", now=now)
        with self.assertRaisesRegex(ValueError, "invalid cron"):
            validate_schedule_expression("0 24 * * 0")

    def test_schedule_required_variables_ignore_schema_only_fields(self):
        from modules.Infrastructure.routes import schedule_required_variable_names

        template = types.SimpleNamespace(payload=json.dumps({
            "script": "backup {{source}} to {{destination}}",
            "__variable_schema": {
                "source": {"type": "text"},
                "destination": {"type": "text"},
                "optional_note": {"type": "text"},
            },
        }))
        self.assertEqual(schedule_required_variable_names(template), ["destination", "source"])

    def test_scheduler_ui_has_muted_categories_and_24_hour_wheels(self):
        scheduler = (ROOT / "modules/Infrastructure/templates/tabs/_scheduler.html").read_text(encoding="utf-8")
        modals = (ROOT / "modules/Infrastructure/templates/modals/_modals.html").read_text(encoding="utf-8")
        javascript = (ROOT / "static/js/infrastructure.js").read_text(encoding="utf-8")

        self.assertIn("scheduler-tone-{{ loop.index0 % 5 }}", scheduler)
        self.assertIn("rgba(var(--scheduler-tone-rgb), 0.035)", scheduler)
        self.assertIn('max-w-4xl', modals)
        self.assertIn('class="schedule-modal-shell ', modals)
        self.assertIn('class="schedule-modal-body ', modals)
        self.assertIn('aria-label="Schedule form fields" tabindex="0"', modals)
        self.assertIn('class="schedule-modal-footer ', modals)
        self.assertIn("height: min(920px, calc(100dvh - 1rem));", scheduler)
        self.assertIn("#scheduleModal .schedule-modal-body", scheduler)
        self.assertIn("min-height: 0;", scheduler)
        self.assertIn("overflow-y: auto;", scheduler)
        self.assertIn("rgba(2, 8, 20, 0.70)", scheduler)
        self.assertNotIn("rgba(239, 246, 255, 0.72)", scheduler)
        self.assertIn("html body #scheduleModal .schedule-modal-body > .schedule-modal-section", scheduler)
        self.assertIn("--schedule-wheel-row-height: 2.5rem", scheduler)
        self.assertIn("width: 3rem !important", scheduler)
        self.assertIn("height: 3rem !important", scheduler)
        self.assertIn('data-time-target="schTimeOnce"', modals)
        self.assertIn('data-time-target="schTimeRec"', modals)
        self.assertIn('type="hidden" id="schTimeOnce"', modals)
        self.assertIn('type="hidden" id="schTimeRec"', modals)
        self.assertNotRegex(modals, r'<input[^>]+type="time"[^>]+id="schTime(?:Once|Rec)"')
        self.assertIn('id="scheduleTargetPickerButton"', modals)
        self.assertIn('id="scheduleTargetSearch"', modals)
        self.assertIn('id="scheduleTargetResults"', modals)
        self.assertIn('function initScheduleTargetPicker()', javascript)
        self.assertIn("results.addEventListener('click'", javascript)
        self.assertIn('z-index: 180;', scheduler)
        self.assertIn('height: min(50rem, calc(100dvh - 1rem));', scheduler)
        self.assertIn('#scheduleTargetPickerModal .schedule-target-results', scheduler)
        self.assertIn('scrollbar-gutter: stable;', scheduler)
        self.assertIn('class="schedule-target-search-panel ', modals)
        self.assertIn('class="schedule-target-results ', modals)
        expected_days = {
            "Mon": "0", "Tue": "1", "Wed": "2", "Thu": "3",
            "Fri": "4", "Sat": "5", "Sun": "6",
        }
        for label, value in expected_days.items():
            with self.subTest(day=label):
                self.assertRegex(modals, rf'class="sch-day peer hidden" value="{value}"[^>]*>.*?{label}')
        self.assertIn("hourCycle: 'h23'", javascript)
        self.assertIn("function initScheduleTimeWheels()", javascript)
        self.assertIn("function getScheduleWheelRowHeight(column)", javascript)
        self.assertNotIn("value * 48", javascript)
        self.assertIn("function openScheduleTargetPicker()", javascript)
        self.assertIn("function renderScheduleTargetPicker(query = '')", javascript)
        self.assertIn('function scheduleTargetHostData(option)', javascript)
        self.assertIn("function chooseScheduleTarget(button)", javascript)
        self.assertIn("function initScheduleModalScroll()", javascript)
        self.assertIn("body.scrollBy({top: pageStep", javascript)
        self.assertIn("function normalizeScheduleTime(value)", javascript)
        self.assertIn("Array.from(document.querySelectorAll('.sch-day:checked'))", javascript)

    def test_schedule_api_rejects_invalid_cron_before_persistence(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "scheduler-test"
        payload = {
            "name": "Invalid schedule",
            "category": "Test",
            "template_id": "template-1",
            "target_type": "group",
            "target_id": "group-1",
            "cron": "0 24 * * 0",
            "timeout_minutes": 0,
            "variables": {},
            "is_active": True,
        }
        template = types.SimpleNamespace(id="template-1", type="action")
        template_query = mock.Mock()
        template_query.get.return_value = template
        with app.test_request_context(json=payload):
            session.update({"user_id": 1, "username": "tester", "is_admin": True})
            with mock.patch.object(routes, "require_permission", return_value=None), \
                 mock.patch.object(routes.TaskTemplate, "query", template_query), \
                 mock.patch.object(routes, "can_access_template_library_entry", return_value=True), \
                 mock.patch.object(routes, "can_use_template", return_value=True), \
                 mock.patch.object(routes, "validate_schedule_target", return_value=("group", "group-1")), \
                 mock.patch.object(routes.db.session, "commit") as commit:
                response, status = routes.manage_schedule()

        self.assertEqual(status, 400)
        self.assertIn("invalid cron", response.get_json()["message"])
        commit.assert_not_called()

    def test_new_schedule_is_populated_before_database_flush(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "scheduler-test"
        payload = {
            "name": "Morning maintenance",
            "category": "Maintenance",
            "template_id": "template-1",
            "target_type": "group",
            "target_id": "group-1",
            "cron": "15 7 * * 0",
            "timeout_minutes": 30,
            "variables": {},
            "is_active": True,
        }
        template = types.SimpleNamespace(id="template-1", type="action", payload="{}")
        template_query = mock.Mock()
        template_query.get.return_value = template
        created_schedule = types.SimpleNamespace(id="schedule-1")
        schedule_factory = mock.Mock(return_value=created_schedule)

        def assert_required_fields_are_set():
            self.assertEqual(created_schedule.name, payload["name"])
            self.assertEqual(created_schedule.template_id, template.id)
            self.assertEqual(created_schedule.target_type, "group")
            self.assertEqual(created_schedule.target_id, "group-1")
            self.assertEqual(created_schedule.cron_expr, payload["cron"])

        with app.test_request_context(json=payload):
            session.update({"user_id": 1, "username": "tester", "is_admin": True})
            with mock.patch.object(routes, "require_permission", return_value=None), \
                 mock.patch.object(routes.TaskTemplate, "query", template_query), \
                 mock.patch.object(routes, "ScheduledTask", schedule_factory), \
                 mock.patch.object(routes, "can_access_template_library_entry", return_value=True), \
                 mock.patch.object(routes, "can_use_template", return_value=True), \
                 mock.patch.object(routes, "validate_schedule_target", return_value=("group", "group-1")), \
                 mock.patch.object(routes, "validate_schedule_expression", return_value=payload["cron"]), \
                 mock.patch.object(routes, "schedule_required_variable_names", return_value=[]), \
                 mock.patch.object(routes.db.session, "add") as add, \
                 mock.patch.object(routes.db.session, "flush", side_effect=assert_required_fields_are_set) as flush, \
                 mock.patch.object(routes.db.session, "commit") as commit, \
                 mock.patch.object(routes, "write_infra_audit"), \
                 mock.patch("core.reload_scheduler_jobs"):
                response = routes.manage_schedule()

        self.assertTrue(response.get_json()["success"])
        schedule_factory.assert_called_once_with(created_by="tester")
        add.assert_called_once_with(created_schedule)
        flush.assert_called_once_with()
        commit.assert_called_once_with()

    def test_run_now_revalidates_target_access(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "scheduler-test"
        template = types.SimpleNamespace(id="template-1", type="action")
        scheduled = types.SimpleNamespace(
            id="schedule-1", template=template, target_type="host", target_id="host-1"
        )
        schedule_query = mock.Mock()
        schedule_query.get.return_value = scheduled
        with app.test_request_context():
            session.update({"user_id": 1, "username": "tester", "is_admin": False})
            with mock.patch.object(routes, "require_permission", return_value=None), \
                 mock.patch.object(routes.ScheduledTask, "query", schedule_query), \
                 mock.patch.object(routes, "can_access_template_library_entry", return_value=True), \
                 mock.patch.object(routes, "can_use_template", return_value=True), \
                 mock.patch.object(routes, "validate_schedule_target", side_effect=PermissionError("denied")):
                response, status = routes.run_schedule_now("schedule-1")

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["message"], "denied")



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
