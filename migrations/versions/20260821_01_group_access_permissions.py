"""per-group infrastructure permissions

Revision ID: 20260821_01
Revises: 20260811_01
Create Date: 2026-08-21
"""

from alembic import op
import sqlalchemy as sa


revision = "20260821_01"
down_revision = "20260811_01"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "user_group_access" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("user_group_access")}
    if "permissions" not in columns:
        op.add_column(
            "user_group_access",
            sa.Column(
                "permissions",
                sa.Text(),
                nullable=False,
                server_default='["*"]',
            ),
        )


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if "user_group_access" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("user_group_access")}
    if "permissions" in columns:
        op.drop_column("user_group_access", "permissions")
