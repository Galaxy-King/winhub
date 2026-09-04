"""Private AI template drafts, separate from executable templates."""
from alembic import op
import sqlalchemy as sa

revision = '20260904_01'
down_revision = '20260901_01'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('ai_template_drafts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('actor_user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('prompt', sa.Text(), nullable=False),
        sa.Column('source_code', sa.Text()),
        sa.Column('language', sa.String(20), nullable=False),
        sa.Column('include_report', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('model', sa.String(150), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='Queued'),
        sa.Column('result_json', sa.Text()), sa.Column('validation_json', sa.Text()),
        sa.Column('error', sa.String(300)), sa.Column('saved_template_ids', sa.Text()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime()), sa.Column('completed_at', sa.DateTime()))
    for column in ('actor_user_id', 'status', 'created_at'):
        op.create_index(f'ix_ai_template_drafts_{column}', 'ai_template_drafts', [column])


def downgrade():
    op.drop_table('ai_template_drafts')
