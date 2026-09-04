"""scoped API key policies

Revision ID: 20260831_01
Revises: 20260825_01
Create Date: 2026-08-31
"""

import json

from alembic import op
import sqlalchemy as sa


revision = "20260831_01"
down_revision = "20260825_01"
branch_labels = None
depends_on = None


GROUP_ACTION_IDS = [
    "view_hosts", "view_groups", "view_queue", "view_reports",
    "view_sensitive_reports", "run_tasks", "send_reports", "edit_reports",
    "dismiss_reports", "manage_hosts", "manage_groups", "delete_hosts",
    "delete_groups",
]


def _add_api_key_columns():
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("api_keys")}
    additions = {
        "allowed_networks": sa.Column("allowed_networks", sa.Text(), nullable=True, server_default="[]"),
        # Fail closed: existing keys have no network/template allowlist yet and
        # therefore stop authenticating until an administrator configures them.
        "ip_allowlist_enforced": sa.Column(
            "ip_allowlist_enforced", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        "template_scope_enforced": sa.Column(
            "template_scope_enforced", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        "max_targets_per_run": sa.Column(
            "max_targets_per_run", sa.Integer(), nullable=False, server_default="1"
        ),
        "last_used_at": sa.Column("last_used_at", sa.DateTime(), nullable=True),
        "last_used_ip": sa.Column("last_used_ip", sa.Text(), nullable=True),
        "revoked_at": sa.Column("revoked_at", sa.DateTime(), nullable=True),
    }
    for name, column in additions.items():
        if name not in existing:
            op.add_column("api_keys", column)


def _backfill_legacy_group_scopes():
    bind = op.get_bind()
    valid_groups = {
        str(row[0]) for row in bind.execute(sa.text("SELECT id FROM endpoint_groups"))
    }
    existing_keys = {
        int(row[0]) for row in bind.execute(sa.text("SELECT DISTINCT api_key_id FROM api_key_group_access"))
    }
    permissions_json = json.dumps(GROUP_ACTION_IDS, ensure_ascii=False)
    rows = bind.execute(sa.text("SELECT id, permissions FROM api_keys")).fetchall()
    for key_id, raw_permissions in rows:
        if int(key_id) in existing_keys:
            continue
        try:
            permissions = json.loads(raw_permissions or "[]")
        except (TypeError, ValueError):
            permissions = []
        for item in permissions if isinstance(permissions, list) else []:
            if not isinstance(item, str) or not item.startswith("scope:group:"):
                continue
            group_id = item[len("scope:group:"):]
            if group_id not in valid_groups:
                continue
            bind.execute(sa.text(
                "INSERT INTO api_key_group_access (api_key_id, group_id, permissions) "
                "VALUES (:api_key_id, :group_id, :permissions)"
            ), {
                "api_key_id": key_id,
                "group_id": group_id,
                "permissions": permissions_json,
            })


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "api_keys" not in tables:
        return
    _add_api_key_columns()

    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "api_key_group_access" not in tables:
        op.create_table(
            "api_key_group_access",
            sa.Column("api_key_id", sa.Integer(), nullable=False),
            sa.Column("group_id", sa.String(length=36), nullable=False),
            sa.Column("permissions", sa.Text(), nullable=False, server_default="[]"),
            sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["group_id"], ["endpoint_groups.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("api_key_id", "group_id"),
        )
    if "api_key_template_access" not in tables:
        op.create_table(
            "api_key_template_access",
            sa.Column("api_key_id", sa.Integer(), nullable=False),
            sa.Column("template_id", sa.String(length=36), nullable=False),
            sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["template_id"], ["task_templates.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("api_key_id", "template_id"),
        )
    _backfill_legacy_group_scopes()


def downgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "api_key_template_access" in tables:
        op.drop_table("api_key_template_access")
    if "api_key_group_access" in tables:
        op.drop_table("api_key_group_access")
    if "api_keys" not in tables:
        return
    columns = {column["name"] for column in inspector.get_columns("api_keys")}
    for name in (
        "revoked_at", "last_used_ip", "last_used_at", "max_targets_per_run",
        "template_scope_enforced", "ip_allowlist_enforced", "allowed_networks",
    ):
        if name in columns:
            op.drop_column("api_keys", name)
