"""Scoped package delivery and enrollment for Proxmox-created Windows VMs."""
from alembic import op
import sqlalchemy as sa

revision = '20261124_01'
down_revision = '20261120_01'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('agent_bootstrap_grants',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('parent_task_id', sa.String(36), nullable=False),
        sa.Column('snapshot', sa.Text(), nullable=False),
        sa.Column('download_hash', sa.String(64), nullable=False),
        sa.Column('enrollment_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('expected_hostname', sa.String(100), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('enrolled_endpoint_id', sa.String(100)),
        sa.Column('enrolled_key_fingerprint', sa.String(64)),
        sa.Column('download_until', sa.DateTime()))
    op.create_index('ix_agent_bootstrap_grants_parent_task_id', 'agent_bootstrap_grants', ['parent_task_id'])


def downgrade():
    op.drop_table('agent_bootstrap_grants')
