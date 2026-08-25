"""searchable audit history and immutable report versions

Revision ID: 20260825_01
Revises: 20260821_01
Create Date: 2026-08-25
"""

from alembic import op
import sqlalchemy as sa


revision = "20260825_01"
down_revision = "20260821_01"
branch_labels = None
depends_on = None


def _add_columns(table_name, additions):
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    for name, column in additions.items():
        if name not in existing:
            op.add_column(table_name, column)


def _ensure_index(table_name, index_name, columns):
    inspector = sa.inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=False)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if "audit_logs" in tables:
        _add_columns("audit_logs", {
            "actor_user_id": sa.Column("actor_user_id", sa.Integer(), nullable=True),
            "actor_role": sa.Column("actor_role", sa.String(length=30), nullable=True),
            "source_type": sa.Column("source_type", sa.String(length=30), nullable=True),
            "session_id_hash": sa.Column("session_id_hash", sa.String(length=64), nullable=True),
            "user_agent": sa.Column("user_agent", sa.Text(), nullable=True),
        })
        for name in ("actor_user_id", "actor_role", "source_type", "session_id_hash"):
            _ensure_index("audit_logs", f"ix_audit_logs_{name}", [name])
        op.execute(sa.text(
            "UPDATE audit_logs SET actor_user_id = "
            "(SELECT id FROM users WHERE users.username = COALESCE(audit_logs.actor_name, audit_logs.user)) "
            "WHERE actor_user_id IS NULL"
        ))
        op.execute(sa.text(
            "UPDATE audit_logs SET actor_role = CASE "
            "WHEN actor_type = 'api_key' THEN 'api_key' "
            "WHEN actor_user_id IN (SELECT id FROM users WHERE is_admin IS TRUE) THEN 'superadmin' "
            "ELSE 'operator' END WHERE actor_role IS NULL"
        ))
        op.execute(sa.text(
            "UPDATE audit_logs SET source_type = CASE "
            "WHEN actor_type = 'api_key' THEN 'api' ELSE 'web' END "
            "WHERE source_type IS NULL"
        ))

    if "agent_tasks" in tables:
        _add_columns("agent_tasks", {
            "endpoint_id_snapshot": sa.Column("endpoint_id_snapshot", sa.String(length=100), nullable=True),
            "endpoint_hostname_snapshot": sa.Column("endpoint_hostname_snapshot", sa.String(length=100), nullable=True),
            "endpoint_name_snapshot": sa.Column("endpoint_name_snapshot", sa.String(length=120), nullable=True),
            "endpoint_groups_snapshot": sa.Column("endpoint_groups_snapshot", sa.Text(), nullable=True),
            "source_type": sa.Column("source_type", sa.String(length=30), nullable=True, server_default="manual"),
            "actor_user_id": sa.Column("actor_user_id", sa.Integer(), nullable=True),
            "template_id": sa.Column("template_id", sa.String(length=36), nullable=True),
            "schedule_id": sa.Column("schedule_id", sa.String(length=36), nullable=True),
        })
        for name in (
            "endpoint_id_snapshot", "endpoint_hostname_snapshot", "endpoint_name_snapshot",
            "source_type", "actor_user_id", "template_id", "schedule_id",
        ):
            _ensure_index("agent_tasks", f"ix_agent_tasks_{name}", [name])
        op.execute(sa.text(
            "UPDATE agent_tasks SET endpoint_id_snapshot = endpoint_id "
            "WHERE endpoint_id_snapshot IS NULL"
        ))
        op.execute(sa.text(
            "UPDATE agent_tasks SET endpoint_hostname_snapshot = "
            "(SELECT hostname FROM endpoints WHERE endpoints.id = agent_tasks.endpoint_id) "
            "WHERE endpoint_hostname_snapshot IS NULL AND endpoint_id IS NOT NULL"
        ))
        op.execute(sa.text(
            "UPDATE agent_tasks SET endpoint_name_snapshot = "
            "(SELECT display_name FROM endpoints WHERE endpoints.id = agent_tasks.endpoint_id) "
            "WHERE endpoint_name_snapshot IS NULL AND endpoint_id IS NOT NULL"
        ))
        op.execute(sa.text(
            "UPDATE agent_tasks SET source_type = CASE "
            "WHEN title LIKE '[Auto-Fix]%' THEN 'trigger' "
            "WHEN title LIKE '[Auto]%' THEN 'scheduler' "
            "ELSE COALESCE(source_type, 'manual') END"
        ))
        op.execute(sa.text(
            "UPDATE agent_tasks SET actor_user_id = "
            "(SELECT id FROM users WHERE users.username = agent_tasks.created_by) "
            "WHERE actor_user_id IS NULL AND created_by IS NOT NULL"
        ))

    if "aggregated_jobs" in tables:
        _add_columns("aggregated_jobs", {
            "actor_user_id": sa.Column("actor_user_id", sa.Integer(), nullable=True),
            "created_by": sa.Column("created_by", sa.String(length=150), nullable=True),
            "source_type": sa.Column("source_type", sa.String(length=30), nullable=True),
            "template_id": sa.Column("template_id", sa.String(length=36), nullable=True),
            "original_content_hash": sa.Column("original_content_hash", sa.String(length=64), nullable=True),
            "current_revision_number": sa.Column(
                "current_revision_number", sa.Integer(), nullable=False, server_default="0"
            ),
        })
        for name in (
            "actor_user_id", "created_by", "source_type", "template_id",
            "original_content_hash", "created_at", "status",
        ):
            _ensure_index("aggregated_jobs", f"ix_aggregated_jobs_{name}", [name])
        if "agent_tasks" in tables:
            for name in ("actor_user_id", "created_by", "source_type", "template_id"):
                op.execute(sa.text(
                    f"UPDATE aggregated_jobs SET {name} = "
                    f"(SELECT {name} FROM agent_tasks "
                    "WHERE agent_tasks.job_id = aggregated_jobs.id "
                    "ORDER BY agent_tasks.created_at LIMIT 1) "
                    f"WHERE {name} IS NULL"
                ))

    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "report_revisions" not in tables:
        op.create_table(
            "report_revisions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("report_id", sa.String(length=36), sa.ForeignKey("aggregated_jobs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("revision_number", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=30), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.String(length=64), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("actor_name", sa.String(length=150), nullable=True),
            sa.Column("reason", sa.String(length=500), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("report_id", "revision_number", name="uq_report_revision_number"),
        )
        for name in ("report_id", "kind", "content_hash", "actor_user_id", "actor_name", "created_at"):
            op.create_index(f"ix_report_revisions_{name}", "report_revisions", [name], unique=False)

    if "report_deliveries" not in tables:
        op.create_table(
            "report_deliveries",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("report_id", sa.String(length=36), sa.ForeignKey("aggregated_jobs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("revision_id", sa.String(length=36), sa.ForeignKey("report_revisions.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("channel", sa.String(length=30), nullable=False),
            sa.Column("destination", sa.Text(), nullable=True),
            sa.Column("subject", sa.String(length=255), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("content_snapshot", sa.Text(), nullable=False),
            sa.Column("content_hash", sa.String(length=64), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("actor_name", sa.String(length=150), nullable=True),
            sa.Column("status", sa.String(length=30), nullable=False),
            sa.Column("result_details", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
        )
        for name in (
            "report_id", "revision_id", "channel", "content_hash", "actor_user_id",
            "actor_name", "status", "created_at", "completed_at",
        ):
            op.create_index(f"ix_report_deliveries_{name}", "report_deliveries", [name], unique=False)
    else:
        _add_columns("report_deliveries", {
            "content_snapshot": sa.Column("content_snapshot", sa.Text(), nullable=True),
        })
        op.execute(sa.text(
            "UPDATE report_deliveries SET content_snapshot = '' "
            "WHERE content_snapshot IS NULL"
        ))

    if "history_search_tokens" not in tables:
        op.create_table(
            "history_search_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("entity_type", sa.String(length=30), nullable=False),
            sa.Column("entity_id", sa.String(length=64), nullable=False),
            sa.Column("field", sa.String(length=30), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint(
                "entity_type", "entity_id", "field", "token_hash",
                name="uq_history_search_token",
            ),
        )
        op.create_index(
            "ix_history_search_token_lookup", "history_search_tokens",
            ["token_hash", "entity_type", "field", "entity_id"], unique=False,
        )
        op.create_index(
            "ix_history_search_token_entity", "history_search_tokens",
            ["entity_type", "entity_id"], unique=False,
        )


def downgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for table_name in ("history_search_tokens", "report_deliveries", "report_revisions"):
        if table_name in tables:
            op.drop_table(table_name)
