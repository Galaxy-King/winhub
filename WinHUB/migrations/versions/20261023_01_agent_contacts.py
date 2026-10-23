"""Server-observed contact windows; no agent performance telemetry."""
from alembic import op
import sqlalchemy as sa
revision = '20261023_01'
down_revision = '20261022_01'
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    has_endpoints = 'endpoints' in sa.inspect(bind).get_table_names()
    columns = {c['name'] for c in sa.inspect(bind).get_columns('endpoints')} if has_endpoints else set()
    for name in ('last_poll_at', 'next_contact_min', 'next_contact_max'):
        if has_endpoints and name not in columns:
            op.add_column('endpoints', sa.Column(name, sa.DateTime(), nullable=True))
    if 'agent_contact_hours' not in sa.inspect(bind).get_table_names():
        op.create_table('agent_contact_hours',
            sa.Column('endpoint_id', sa.String(100), sa.ForeignKey('endpoints.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('hour', sa.DateTime(), primary_key=True),
            sa.Column('contacts', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('late_contacts', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('max_gap_seconds', sa.Integer(), nullable=False, server_default='0'))

def downgrade():
    op.drop_table('agent_contact_hours')
    for name in ('last_poll_at', 'next_contact_min', 'next_contact_max'):
        op.drop_column('endpoints', name)
