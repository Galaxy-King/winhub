"""Durable scheduler occurrences and separate delivery/execution outcomes."""
from alembic import op
import sqlalchemy as sa

revision = '20261028_01'
down_revision = '20261023_01'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = sa.inspect(bind).get_table_names()
    additions = {
        'scheduled_tasks': [('schedule_spec', sa.Text()), ('execution_policy', sa.Text())],
        'agent_tasks': [('schedule_run_id', sa.String(36)), ('picked_up_at', sa.DateTime()),
                        ('delivery_deadline', sa.DateTime()), ('retry_after', sa.DateTime()), ('result_deadline', sa.DateTime()),
                        ('exit_code', sa.Integer()), ('outcome', sa.String(32)),
                        ('retry_count', sa.Integer())],
    }
    for table, columns in additions.items():
        if table not in tables:
            continue
        existing = {c['name'] for c in sa.inspect(bind).get_columns(table)}
        for name, kind in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, kind, nullable=name != 'retry_count', server_default='0' if name == 'retry_count' else None))
    if 'schedule_runs' not in tables and 'scheduled_tasks' in tables:
        op.create_table('schedule_runs',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('schedule_id', sa.String(36), sa.ForeignKey('scheduled_tasks.id', ondelete='SET NULL')),
            sa.Column('occurrence_key', sa.String(80), nullable=False),
            sa.Column('name', sa.String(150), nullable=False),
            sa.Column('category', sa.String(100), nullable=False),
            sa.Column('source', sa.String(20), nullable=False),
            sa.Column('scheduled_at', sa.DateTime(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('finished_at', sa.DateTime()),
            sa.Column('status', sa.String(32), nullable=False),
            sa.Column('message', sa.Text()),
            sa.Column('job_id', sa.String(36)),
            sa.Column('policy_snapshot', sa.Text(), nullable=False),
            sa.Column('actor_user_id', sa.Integer()),
            sa.Column('actor_name', sa.String(100)),
            sa.Column('launch_reason', sa.Text()),
            sa.UniqueConstraint('schedule_id', 'occurrence_key', name='uq_schedule_occurrence'))
    for table, column in [('agent_tasks', 'schedule_run_id')] + [('schedule_runs', c) for c in ('schedule_id', 'scheduled_at', 'status', 'job_id')]:
        if table not in sa.inspect(bind).get_table_names():
            continue
        name = 'ix_' + table + '_' + column
        if name not in {i['name'] for i in sa.inspect(bind).get_indexes(table)}:
            op.create_index(name, table, [column])


def downgrade():
    op.drop_table('schedule_runs')
    op.drop_index('ix_agent_tasks_schedule_run_id', table_name='agent_tasks')
    for name in ('schedule_run_id', 'picked_up_at', 'delivery_deadline', 'retry_after', 'result_deadline', 'exit_code', 'outcome', 'retry_count'):
        op.drop_column('agent_tasks', name)
    for name in ('schedule_spec', 'execution_policy'):
        op.drop_column('scheduled_tasks', name)
