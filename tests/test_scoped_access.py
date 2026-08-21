import inspect
import json
import types
import unittest
from unittest import mock


class GranularPermissionTests(unittest.TestCase):
    def test_module_grant_does_not_implicitly_grant_sensitive_or_destructive_access(self):
        from core.permissions import has_permission

        user = types.SimpleNamespace(id=7, is_admin=False, allowed_modules=json.dumps(["Infrastructure"]))
        self.assertTrue(has_permission(user, "Infrastructure", "view_reports"))
        self.assertFalse(has_permission(user, "Infrastructure", "view_sensitive_reports"))
        self.assertFalse(has_permission(user, "Infrastructure", "delete_reports"))
        self.assertFalse(has_permission(user, "Infrastructure", "delete_tasks"))
        self.assertFalse(has_permission(user, "Infrastructure", "delete_hosts"))
        self.assertFalse(has_permission(user, "Infrastructure", "delete_groups"))

    def test_exact_tokens_and_legacy_delete_alias_grant_expected_actions(self):
        from core.permissions import has_permission

        exact = types.SimpleNamespace(
            id=8,
            is_admin=False,
            allowed_modules=json.dumps([
                "Infrastructure:view_sensitive_reports",
                "Infrastructure:delete_hosts",
            ]),
        )
        self.assertTrue(has_permission(exact, "Infrastructure", "view_sensitive_reports"))
        self.assertTrue(has_permission(exact, "Infrastructure", "delete_hosts"))
        self.assertFalse(has_permission(exact, "Infrastructure", "delete_groups"))

        legacy = types.SimpleNamespace(
            id=9,
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:delete"]),
        )
        for permission in ("delete_reports", "delete_tasks", "delete_hosts", "delete_groups"):
            self.assertTrue(has_permission(legacy, "Infrastructure", permission))

        legacy_cleanup = types.SimpleNamespace(
            id=10,
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:cleanup_tasks"]),
        )
        self.assertTrue(has_permission(legacy_cleanup, "Infrastructure", "delete_tasks"))

    def test_granular_catalog_exposes_independent_assignment_controls(self):
        from core.permissions import granular_permission_catalog

        ids = {item["id"] for item in granular_permission_catalog("Infrastructure")}
        self.assertTrue({
            "view_sensitive_reports",
            "delete_reports",
            "delete_tasks",
            "delete_hosts",
            "delete_groups",
        }.issubset(ids))


class PerGroupPermissionTests(unittest.TestCase):
    def test_legacy_group_rows_keep_access_and_explicit_rows_are_filtered(self):
        from core.group_access import (
            GROUP_ACTION_IDS,
            parse_group_permissions,
            serialize_group_permissions,
        )

        self.assertEqual(parse_group_permissions('["*"]'), set(GROUP_ACTION_IDS))
        self.assertEqual(parse_group_permissions(None), set(GROUP_ACTION_IDS))
        self.assertEqual(
            parse_group_permissions('["view_hosts", "delete_hosts", "unknown"]'),
            {"view_hosts", "delete_hosts"},
        )
        self.assertEqual(
            json.loads(serialize_group_permissions(["delete_hosts", "view_hosts", "unknown"])),
            ["view_hosts", "delete_hosts"],
        )

    def test_each_group_can_grant_a_different_action_set(self):
        from flask import Flask
        from core import group_access

        app = Flask(__name__)
        user = types.SimpleNamespace(id=25, is_admin=False)
        grants = {
            "group-a": frozenset({"view_hosts", "delete_hosts"}),
            "group-b": frozenset({"view_hosts"}),
        }
        with app.test_request_context("/"), mock.patch.object(
            group_access, "request_api_group_scope", return_value=None
        ), mock.patch.object(
            group_access, "user_group_permission_map", return_value=grants
        ):
            self.assertEqual(
                group_access.allowed_group_ids_for_action(user, "view_hosts"),
                {"group-a", "group-b"},
            )
            self.assertEqual(
                group_access.allowed_group_ids_for_action(user, "delete_hosts"),
                {"group-a"},
            )
            self.assertTrue(group_access.group_action_allowed(user, "group-a", "delete_hosts"))
            self.assertFalse(group_access.group_action_allowed(user, "group-b", "delete_hosts"))

    def test_group_access_uses_batch_queries_and_deny_wins_for_shared_host_deletion(self):
        from core import group_access

        map_source = inspect.getsource(group_access.user_group_permission_map)
        host_source = inspect.getsource(group_access.allowed_host_ids_for_action)
        batch_source = inspect.getsource(group_access.group_permissions_for_users)
        self.assertIn("winhub_group_permission_maps", map_source)
        self.assertIn("user_group_m2m.c.permissions", map_source)
        self.assertNotIn("for group_id in", host_source)
        self.assertIn('str(action_id) == "delete_hosts"', host_source)
        self.assertIn("denied_rows", host_source)
        self.assertIn("user_group_m2m.c.user_id.in_(ids)", batch_source)

    def test_admin_access_window_exposes_large_structured_group_matrix(self):
        from pathlib import Path

        source = Path("templates/admin_users.html").read_text(encoding="utf-8")
        self.assertIn('class="access-dialog ', source)
        self.assertIn("height: calc(100dvh - 1rem)", source)
        self.assertIn("#editModal .access-layout", source)
        self.assertIn("overflow-y: auto", source)
        self.assertIn("#editModal .group-access-card.is-disabled", source)
        self.assertIn("#editModal .group-access-name", source)
        self.assertIn('id="groupAccessContainer"', source)
        self.assertIn("Permissions by host group", source)
        self.assertIn("group_access: groupAccess", source)


class SensitiveOutputTests(unittest.TestCase):
    def test_nested_json_and_common_text_password_formats_are_masked(self):
        from core.sensitive_data import mask_sensitive_text

        structured = mask_sensitive_text(json.dumps({
            "user": "operator",
            "data": {
                "password": "real-password",
                "api_token": "real-token",
                "clientSecret": "camel-secret",
            },
        }))
        parsed = json.loads(structured)
        self.assertEqual(parsed["data"]["password"], "***")
        self.assertEqual(parsed["data"]["api_token"], "***")
        self.assertEqual(parsed["data"]["clientSecret"], "***")
        self.assertEqual(parsed["user"], "operator")

        self.assertEqual(mask_sensitive_text("password=real-password"), "password=***")
        self.assertEqual(mask_sensitive_text("pwd is real-password"), "pwd is ***")
        self.assertEqual(mask_sensitive_text("Пароль: real-password"), "Пароль: ***")
        self.assertEqual(mask_sensitive_text("Temporary Password: real-password"), "Temporary Password: ***")

        html_report = (
            "<table><tr><td>Password</td><td><code>real-password</code></td></tr></table>"
            "<p><strong>Token:</strong> real-token</p>"
        )
        masked_html = mask_sensitive_text(html_report)
        self.assertNotIn("real-password", masked_html)
        self.assertNotIn("real-token", masked_html)
        self.assertIn("<code>***</code>", masked_html)
        self.assertEqual(mask_sensitive_text("monkey=value"), "monkey=value")


class ScopedAccessPerformanceContractTests(unittest.TestCase):
    def test_current_user_and_group_scope_are_cached_for_the_request(self):
        from flask import Flask, session
        from modules.Infrastructure import routes

        app = Flask(__name__)
        app.secret_key = "scoped-access-test"
        user = types.SimpleNamespace(
            id=17,
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:view_groups"]),
            allowed_host_groups=[types.SimpleNamespace(id="group-a")],
        )
        query = types.SimpleNamespace(get=mock.Mock(return_value=user))
        with app.test_request_context("/api/infrastructure/tasks/all"), mock.patch.object(
            routes, "User", types.SimpleNamespace(query=query)
        ):
            session["user_id"] = 17
            self.assertIs(routes.current_user(), user)
            self.assertIs(routes.current_user(), user)
            self.assertEqual(query.get.call_count, 1)

        with app.test_request_context("/api/infrastructure/groups"), mock.patch.object(
            routes, "current_user", return_value=user
        ) as current_user, mock.patch.object(
            routes, "allowed_group_ids_for_action", return_value={"group-a"}
        ) as scoped_groups:
            session["user_id"] = 17
            self.assertEqual(routes.infra_allowed_group_ids(17), ["group-a"])
            self.assertEqual(routes.infra_allowed_group_ids(17), ["group-a"])
            # The route wrapper is called twice, while current_user() itself
            # (verified above) and the group grant loader cache database work.
            self.assertEqual(current_user.call_count, 2)
            self.assertEqual(scoped_groups.call_count, 2)

    def test_dispatch_and_report_scope_use_batch_checks(self):
        from modules.Infrastructure import routes

        dispatch_source = inspect.getsource(routes.dispatch_infrastructure_task)
        self.assertIn("authorized_target_ids", dispatch_source)
        self.assertIn("Endpoint.query.filter", dispatch_source)
        self.assertNotIn("can_manage_host", dispatch_source)

        report_scope_source = inspect.getsource(routes.accessible_report_id_set)
        self.assertIn("group_by", report_scope_source)
        self.assertIn("count(func.distinct", report_scope_source)
        self.assertNotIn("for report_id in report_ids\n", report_scope_source)

        from core import ensure_performance_indexes
        index_source = inspect.getsource(ensure_performance_indexes)
        self.assertIn("ix_endpoint_group_membership_group_endpoint", index_source)
        self.assertIn("ix_agent_tasks_job_endpoint", index_source)

    def test_destructive_routes_require_granular_permissions_and_scope(self):
        from modules.Infrastructure import routes

        self.assertIn("can_access_report", inspect.getsource(routes.delete_report))
        self.assertIn('require_permission("delete_tasks")', inspect.getsource(routes.delete_job))
        self.assertIn("accessible_report_id_set", inspect.getsource(routes.delete_job))
        host_source = inspect.getsource(routes.host_operations)
        self.assertIn('"DELETE": "delete_hosts"', host_source)
        self.assertIn("infra_allowed_host_ids", host_source)
        self.assertIn('require_permission("delete_groups")', inspect.getsource(routes.manage_group))
        self.assertIn("infra_allowed_group_ids", inspect.getsource(routes.manage_group))


if __name__ == "__main__":
    unittest.main()
