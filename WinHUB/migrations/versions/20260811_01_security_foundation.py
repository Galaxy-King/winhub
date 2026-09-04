"""security foundation

Revision ID: 20260811_01
Revises:
Create Date: 2026-08-11
"""

from alembic import op
import sqlalchemy as sa


revision = "20260811_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "endpoints" in tables:
        columns = {column["name"] for column in inspector.get_columns("endpoints")}
        additions = {
            "task_signing_private_key": sa.Column("task_signing_private_key", sa.Text(), nullable=True),
            "task_signing_public_key": sa.Column("task_signing_public_key", sa.Text(), nullable=True),
            "task_signing_key_id": sa.Column("task_signing_key_id", sa.String(length=64), nullable=True),
            "task_signing_sequence": sa.Column("task_signing_sequence", sa.BigInteger(), server_default="0", nullable=True),
            "task_signature_v2_seen_at": sa.Column("task_signature_v2_seen_at", sa.DateTime(), nullable=True),
        }
        for name, column in additions.items():
            if name not in columns:
                op.add_column("endpoints", column)
        indexes = {index["name"] for index in inspector.get_indexes("endpoints")}
        if "ix_endpoints_task_signing_key_id" not in indexes:
            op.create_index("ix_endpoints_task_signing_key_id", "endpoints", ["task_signing_key_id"], unique=False)

    if "task_templates" in tables:
        columns = {column["name"] for column in inspector.get_columns("task_templates")}
        additions = {
            "approved_content_hash": sa.Column("approved_content_hash", sa.String(length=64), nullable=True),
            "approved_at": sa.Column("approved_at", sa.DateTime(), nullable=True),
            "approved_by": sa.Column("approved_by", sa.String(length=100), nullable=True),
        }
        for name, column in additions.items():
            if name not in columns:
                op.add_column("task_templates", column)
        indexes = {index["name"] for index in inspector.get_indexes("task_templates")}
        if "ix_task_templates_approved_content_hash" not in indexes:
            op.create_index("ix_task_templates_approved_content_hash", "task_templates", ["approved_content_hash"], unique=False)


def downgrade():
    op.drop_index("ix_task_templates_approved_content_hash", table_name="task_templates")
    op.drop_column("task_templates", "approved_by")
    op.drop_column("task_templates", "approved_at")
    op.drop_column("task_templates", "approved_content_hash")
    op.drop_index("ix_endpoints_task_signing_key_id", table_name="endpoints")
    op.drop_column("endpoints", "task_signature_v2_seen_at")
    op.drop_column("endpoints", "task_signing_sequence")
    op.drop_column("endpoints", "task_signing_key_id")
    op.drop_column("endpoints", "task_signing_public_key")
    op.drop_column("endpoints", "task_signing_private_key")
