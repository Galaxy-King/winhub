"""Persist launch reasons without inventing reasons for historical tasks."""
from alembic import op
import sqlalchemy as sa

revision = '20260904_02'
down_revision = '20260904_01'
branch_labels = None
depends_on = None

TABLES = ('agent_tasks', 'scheduled_tasks', 'trigger_rules', 'agent_update_rollouts')


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for table in TABLES:
        # EncryptedText stores ciphertext in a text column. NULL denotes legacy data.
        if table in tables and 'launch_reason' not in {c['name'] for c in inspector.get_columns(table)}:
            op.add_column(table, sa.Column('launch_reason', sa.Text(), nullable=True))


def downgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for table in reversed(TABLES):
        if table in tables and 'launch_reason' in {c['name'] for c in inspector.get_columns(table)}:
            op.drop_column(table, 'launch_reason')
