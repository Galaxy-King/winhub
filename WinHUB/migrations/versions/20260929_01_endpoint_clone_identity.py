"""Add endpoint clone detection and identity split state.

Revision ID: 20260929_01
Revises: 20260922_01
"""

from alembic import op
import sqlalchemy as sa


revision = "20260929_01"
down_revision = "20260922_01"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    op.create_table(
        "endpoint_instances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=100), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("boot_id", sa.String(length=128), nullable=True),
        sa.Column("instance_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=100), nullable=True),
        sa.Column("connection_ip", sa.String(length=64), nullable=True),
        sa.Column("agent_version", sa.String(length=50), nullable=True),
        sa.Column("capabilities", sa.String(length=255), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id", "session_id", name="uq_endpoint_instance_session"),
    )
    op.create_index("ix_endpoint_instances_endpoint_id", "endpoint_instances", ["endpoint_id"])
    op.create_index("ix_endpoint_instances_instance_fingerprint", "endpoint_instances", ["instance_fingerprint"])
    op.create_index("ix_endpoint_instances_connection_ip", "endpoint_instances", ["connection_ip"])
    op.create_index("ix_endpoint_instances_last_seen", "endpoint_instances", ["last_seen"])

    op.create_table(
        "endpoint_identity_conflicts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution", sa.String(length=50), nullable=True),
        sa.Column("resolved_by", sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_endpoint_identity_conflicts_endpoint_id", "endpoint_identity_conflicts", ["endpoint_id"])
    op.create_index("ix_endpoint_identity_conflicts_status", "endpoint_identity_conflicts", ["status"])
    op.create_index("ix_endpoint_identity_conflicts_detected_at", "endpoint_identity_conflicts", ["detected_at"])

    op.create_table(
        "endpoint_identity_commands",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("conflict_id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=100), nullable=False),
        sa.Column("target_session_id", sa.String(length=64), nullable=False),
        sa.Column("new_endpoint_id", sa.String(length=100), nullable=False),
        sa.Column("new_auth_token", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["conflict_id"], ["endpoint_identity_conflicts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["new_endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("new_endpoint_id"),
    )
    op.create_index("ix_endpoint_identity_commands_conflict_id", "endpoint_identity_commands", ["conflict_id"])
    op.create_index("ix_endpoint_identity_commands_endpoint_id", "endpoint_identity_commands", ["endpoint_id"])
    op.create_index("ix_endpoint_identity_commands_target_session_id", "endpoint_identity_commands", ["target_session_id"])
    op.create_index("ix_endpoint_identity_commands_status", "endpoint_identity_commands", ["status"])
    op.create_index("ix_endpoint_identity_commands_expires_at", "endpoint_identity_commands", ["expires_at"])

    if inspector.has_table("agent_tasks"):
        with op.batch_alter_table("agent_tasks") as batch_op:
            batch_op.add_column(sa.Column("instance_session_id", sa.String(length=64), nullable=True))
            batch_op.create_index("ix_agent_tasks_instance_session_id", ["instance_session_id"])
    if inspector.has_table("telemetry_history"):
        with op.batch_alter_table("telemetry_history") as batch_op:
            batch_op.add_column(sa.Column("instance_session_id", sa.String(length=64), nullable=True))
            batch_op.create_index("ix_telemetry_history_instance_session_id", ["instance_session_id"])
    if inspector.has_table("connection_ip_history"):
        with op.batch_alter_table("connection_ip_history") as batch_op:
            batch_op.add_column(sa.Column("instance_session_id", sa.String(length=64), nullable=True))
            batch_op.create_index("ix_connection_ip_history_instance_session_id", ["instance_session_id"])


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("connection_ip_history") and "instance_session_id" in {column["name"] for column in inspector.get_columns("connection_ip_history")}:
        with op.batch_alter_table("connection_ip_history") as batch_op:
            batch_op.drop_index("ix_connection_ip_history_instance_session_id")
            batch_op.drop_column("instance_session_id")
    if inspector.has_table("telemetry_history") and "instance_session_id" in {column["name"] for column in inspector.get_columns("telemetry_history")}:
        with op.batch_alter_table("telemetry_history") as batch_op:
            batch_op.drop_index("ix_telemetry_history_instance_session_id")
            batch_op.drop_column("instance_session_id")
    if inspector.has_table("agent_tasks") and "instance_session_id" in {column["name"] for column in inspector.get_columns("agent_tasks")}:
        with op.batch_alter_table("agent_tasks") as batch_op:
            batch_op.drop_index("ix_agent_tasks_instance_session_id")
            batch_op.drop_column("instance_session_id")
    op.drop_table("endpoint_identity_commands")
    op.drop_table("endpoint_identity_conflicts")
    op.drop_table("endpoint_instances")
