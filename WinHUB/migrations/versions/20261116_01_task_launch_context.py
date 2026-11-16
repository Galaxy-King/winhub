"""Keep encrypted input values for editable task re-runs."""
from alembic import op
import sqlalchemy as sa

revision = '20261116_01'
down_revision = '20261028_01'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'agent_tasks' in inspector.get_table_names() and 'launch_context' not in {c['name'] for c in inspector.get_columns('agent_tasks')}:
        op.add_column('agent_tasks', sa.Column('launch_context', sa.Text(), nullable=True))


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if 'agent_tasks' in inspector.get_table_names() and 'launch_context' in {c['name'] for c in inspector.get_columns('agent_tasks')}:
        op.drop_column('agent_tasks', 'launch_context')
