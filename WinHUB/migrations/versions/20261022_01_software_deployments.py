"""Durable Software catalogue, queue and shared control row.

Encrypted payloads use TEXT columns. Existing JSON catalogue is imported lazily,
without deleting original files or automatically approving legacy recipes.
"""
from alembic import op
import sqlalchemy as sa

revision = '20261022_01'
down_revision = '20260929_01'
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if 'software_control' not in tables:
        op.create_table('software_control', sa.Column('id', sa.Integer(), primary_key=True),
                        sa.Column('settings', sa.Text(), nullable=False))
    if 'software_catalog' not in tables:
        op.create_table('software_catalog', sa.Column('id', sa.String(36), primary_key=True),
                        sa.Column('record', sa.Text(), nullable=False))
    if 'software_deployments' not in tables:
        op.create_table('software_deployments',
                        sa.Column('id', sa.String(36), primary_key=True),
                        sa.Column('actor_user_id', sa.Integer(), nullable=False),
                        sa.Column('created_by', sa.String(100), nullable=False),
                        sa.Column('launch_reason', sa.Text(), nullable=False),
                        sa.Column('status', sa.String(20), nullable=False),
                        sa.Column('parallelism', sa.Integer(), nullable=False),
                        sa.Column('created_at', sa.DateTime(), nullable=False),
                        sa.Column('expires_at', sa.DateTime(), nullable=False))
    if 'software_steps' not in tables:
        op.create_table('software_steps',
                        sa.Column('id', sa.String(36), primary_key=True),
                        sa.Column('deployment_id', sa.String(36), sa.ForeignKey('software_deployments.id'), nullable=False),
                        sa.Column('endpoint_id', sa.String(100), nullable=False),
                        sa.Column('position', sa.Integer(), nullable=False),
                        sa.Column('package_name', sa.String(160), nullable=False),
                        sa.Column('snapshot', sa.Text(), nullable=False),
                        sa.Column('status', sa.String(20), nullable=False),
                        sa.Column('task_id', sa.String(36)),
                        sa.Column('started_at', sa.DateTime()),
                        sa.Column('token_hash', sa.String(64)),
                        sa.Column('token_until', sa.DateTime()),
                        sa.Column('download_lease', sa.String(36)),
                        sa.Column('download_until', sa.DateTime()),
                        sa.Column('message', sa.String(255)))
        for column in ('deployment_id', 'endpoint_id', 'status', 'task_id'):
            op.create_index('ix_software_steps_' + column, 'software_steps', [column])


def downgrade():
    for table in ('software_steps', 'software_deployments', 'software_catalog', 'software_control'):
        op.drop_table(table)
