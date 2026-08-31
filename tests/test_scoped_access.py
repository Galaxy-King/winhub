import inspect
import json
import tempfile
import types
import unittest
from pathlib import Path
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

        retired_delete = types.SimpleNamespace(
            id=81, is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:delete_reports", "Infrastructure:delete_tasks"]),
        )
        self.assertFalse(has_permission(retired_delete, "Infrastructure", "delete_reports"))
        self.assertFalse(has_permission(retired_delete, "Infrastructure", "delete_tasks"))

        legacy = types.SimpleNamespace(
            id=9,
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:delete"]),
        )
        for permission in ("delete_hosts", "delete_groups"):
            self.assertTrue(has_permission(legacy, "Infrastructure", permission))
        self.assertFalse(has_permission(legacy, "Infrastructure", "delete_reports"))
        self.assertFalse(has_permission(legacy, "Infrastructure", "delete_tasks"))

        legacy_cleanup = types.SimpleNamespace(
            id=10,
            is_admin=False,
            allowed_modules=json.dumps(["Infrastructure:cleanup_tasks"]),
        )
        self.assertFalse(has_permission(legacy_cleanup, "Infrastructure", "delete_tasks"))

    def test_granular_catalog_exposes_independent_assignment_controls(self):
        from core.permissions import granular_permission_catalog

        ids = {item["id"] for item in granular_permission_catalog("Infrastructure")}
        self.assertTrue({
            "view_sensitive_reports",
            "delete_hosts",
            "delete_groups",
        }.issubset(ids))
        self.assertNotIn("delete_reports", ids)
        self.assertNotIn("delete_tasks", ids)


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

    def test_api_key_uses_exact_actions_per_group(self):
        from flask import Flask, g, session
        from core import group_access

        app = Flask(__name__)
        app.secret_key = "api-group-policy-test"
        user = types.SimpleNamespace(id=25, is_admin=False)
        with app.test_request_context("/api/infrastructure/hosts"):
            session["api_key_auth"] = True
            session["api_permissions"] = ["Infrastructure:view_hosts", "Infrastructure:run_tasks"]
            g.winhub_api_permissions = list(session["api_permissions"])
            g.winhub_api_group_permissions = {
                "group-a": frozenset({"view_hosts"}),
                "group-b": frozenset({"run_tasks"}),
            }
            self.assertEqual(group_access.allowed_group_ids_for_action(user, "view_hosts"), {"group-a"})
            self.assertEqual(group_access.allowed_group_ids_for_action(user, "run_tasks"), {"group-b"})
            self.assertFalse(group_access.group_action_allowed(user, "group-a", "run_tasks"))

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

        self.assertIn("require_interactive_superadmin", inspect.getsource(routes.delete_report))
        self.assertIn("require_interactive_superadmin", inspect.getsource(routes.delete_job))
        host_source = inspect.getsource(routes.host_operations)
        self.assertIn('"DELETE": "delete_hosts"', host_source)
        self.assertIn("require_interactive_superadmin", host_source)
        self.assertIn("infra_allowed_host_ids", host_source)
        self.assertIn('require_permission("delete_groups")', inspect.getsource(routes.manage_group))
        self.assertIn("infra_allowed_group_ids", inspect.getsource(routes.manage_group))


class ApiKeySecurityPolicyTests(unittest.TestCase):
    def test_api_policy_migration_upgrades_legacy_keys_fail_closed(self):
        import sqlalchemy as sa
        from alembic import command
        from alembic.config import Config as AlembicConfig
        from core.config import Config

        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.db"
            uri = f"sqlite:///{database_path.as_posix()}"
            engine = sa.create_engine(uri)
            metadata = sa.MetaData()
            sa.Table(
                "users", metadata,
                sa.Column("id", sa.Integer(), primary_key=True),
            )
            sa.Table(
                "endpoint_groups", metadata,
                sa.Column("id", sa.String(36), primary_key=True),
            )
            sa.Table(
                "task_templates", metadata,
                sa.Column("id", sa.String(36), primary_key=True),
            )
            api_keys = sa.Table(
                "api_keys", metadata,
                sa.Column("id", sa.Integer(), primary_key=True),
                sa.Column("user_id", sa.Integer(), nullable=False),
                sa.Column("permissions", sa.Text()),
            )
            metadata.create_all(engine)
            with engine.begin() as connection:
                connection.execute(sa.text("INSERT INTO users (id) VALUES (1)"))
                connection.execute(sa.text("INSERT INTO endpoint_groups (id) VALUES ('group-a')"))
                connection.execute(api_keys.insert().values(
                    id=5,
                    user_id=1,
                    permissions=json.dumps(["Infrastructure:run_tasks", "scope:group:group-a"]),
                ))

            old_uri = Config.SQLALCHEMY_DATABASE_URI
            try:
                Config.SQLALCHEMY_DATABASE_URI = uri
                alembic = AlembicConfig(str(Path("alembic.ini").resolve()))
                command.upgrade(alembic, "head")
            finally:
                Config.SQLALCHEMY_DATABASE_URI = old_uri

            inspector = sa.inspect(engine)
            columns = {column["name"] for column in inspector.get_columns("api_keys")}
            self.assertTrue({
                "allowed_networks", "ip_allowlist_enforced", "template_scope_enforced",
                "max_targets_per_run", "last_used_at", "last_used_ip", "revoked_at",
            }.issubset(columns))
            with engine.connect() as connection:
                policy = connection.execute(sa.text(
                    "SELECT ip_allowlist_enforced, template_scope_enforced, max_targets_per_run "
                    "FROM api_keys WHERE id = 5"
                )).one()
                grant = connection.execute(sa.text(
                    "SELECT group_id, permissions FROM api_key_group_access WHERE api_key_id = 5"
                )).one()
            self.assertEqual(tuple(policy), (1, 1, 1))
            self.assertEqual(grant.group_id, "group-a")
            self.assertIn("run_tasks", json.loads(grant.permissions))
            engine.dispose()

    def test_api_key_cannot_reveal_sensitive_results_even_with_legacy_token(self):
        from flask import Flask, g, session
        from core.permissions import has_permission

        app = Flask(__name__)
        app.secret_key = "api-sensitive-policy-test"
        user = types.SimpleNamespace(id=7, is_admin=True, allowed_modules="[]")
        with app.test_request_context("/api/infrastructure/tasks/all"):
            session["api_key_auth"] = True
            session["api_permissions"] = ["Infrastructure:view_sensitive_reports"]
            g.winhub_api_permissions = list(session["api_permissions"])
            self.assertFalse(has_permission(user, "Infrastructure", "view_sensitive_reports"))

    def test_networks_are_canonical_and_spoofed_forwarding_is_ignored(self):
        from flask import Flask
        from core.api_access import effective_client_ip, normalize_allowed_networks

        self.assertEqual(
            normalize_allowed_networks("203.0.113.25, 10.20.4.9/16"),
            ["203.0.113.25/32", "10.20.0.0/16"],
        )
        app = Flask(__name__)
        app.config["TRUSTED_PROXY_CIDRS"] = "127.0.0.1/32"
        with app.test_request_context(
            "/api/infrastructure/templates",
            headers={"X-Forwarded-For": "198.51.100.7"},
            environ_base={"REMOTE_ADDR": "203.0.113.10"},
        ):
            self.assertEqual(effective_client_ip(), "203.0.113.10")
        with app.test_request_context(
            "/api/infrastructure/templates",
            headers={"X-Forwarded-For": "192.0.2.99, 198.51.100.7"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            self.assertEqual(effective_client_ip(), "198.51.100.7")

    def test_api_template_variables_require_schema_and_reject_shell_syntax(self):
        from flask import Flask, session
        from modules.Infrastructure.routes import validate_api_template_variables

        app = Flask(__name__)
        app.secret_key = "api-variable-policy-test"
        safe_payload = {
            "script": 'Reset-User -Login "{{user_login}}"',
            "__variable_schema": {
                "user_login": {
                    "type": "text",
                    "pattern": r"[A-Za-z0-9_.-]{1,64}",
                    "max_length": 64,
                }
            },
        }
        with app.test_request_context("/api/infrastructure/templates/t/run"):
            session["api_key_auth"] = True
            self.assertEqual(
                validate_api_template_variables(safe_payload, {"user_login": "operator.1"}),
                {"user_login": "operator.1"},
            )
            with self.assertRaisesRegex(ValueError, "unsafe"):
                validate_api_template_variables(safe_payload, {"user_login": 'operator\"; Restart-Computer'})
            with self.assertRaisesRegex(ValueError, "requires a variable schema"):
                validate_api_template_variables({"script": "echo {{login}}"}, {"login": "operator"})

    def test_api_retry_requires_a_fresh_template_run(self):
        from modules.Infrastructure import routes

        self.assertIn('session.get("api_key_auth")', inspect.getsource(routes.retry_failed_job))
        self.assertIn("run the approved template again", inspect.getsource(routes.retry_failed_job))

    def test_bot_job_status_exposes_no_result_or_delivery_content(self):
        from modules.Infrastructure import routes

        source = inspect.getsource(routes.get_job_status_api)
        self.assertIn('require_permission("view_queue")', source)
        self.assertIn('"view_queue"', source)
        self.assertNotIn("result_log", source)
        self.assertNotIn("content_snapshot", source)
        self.assertNotIn('"destination"', source)

    def test_admin_ui_exposes_network_template_group_and_rotation_controls(self):
        from pathlib import Path

        source = Path("templates/admin_users.html").read_text(encoding="utf-8")
        for marker in (
            "apiAllowedNetworks", "apiTemplateScopeContainer", "apiMaxTargets",
            "collectApiGroupAccess", "rotateApiKey", "toggleApiKey",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
