"""durable AI report requests

Revision ID: 20260901_01
Revises: 20260831_01
Create Date: 2026-09-01
"""

from alembic import op
import sqlalchemy as sa


revision = "20260901_01"
down_revision = "20260831_01"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_report_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("report_id", sa.String(length=36), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_name", sa.String(length=150), nullable=True),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=150), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="WaitingForTasks"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input_hash", sa.String(length=64), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("output_revision_id", sa.String(length=36), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["report_id"], ["aggregated_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("job_id", "report_id", "actor_user_id", "status", "input_hash", "prompt_hash", "output_revision_id", "created_at", "completed_at"):
        op.create_index(f"ix_ai_report_requests_{column}", "ai_report_requests", [column], unique=False)


def downgrade():
    op.drop_table("ai_report_requests")
