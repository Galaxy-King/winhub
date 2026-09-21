"""Add durable Newsletter campaigns and recipient delivery state."""
from alembic import op
import sqlalchemy as sa


revision = '20260921_01'
down_revision = '20260904_02'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'newsletter_campaigns',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('task_id', sa.String(length=36), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=False, server_default='manual'),
        sa.Column('source_message_id_hash', sa.String(length=64), nullable=True),
        sa.Column('sender_email', sa.String(length=320), nullable=False),
        sa.Column('keyserver_override', sa.String(length=1000), nullable=True),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('attachments_json', sa.Text(), nullable=True),
        sa.Column('selected_lists_json', sa.Text(), nullable=True),
        sa.Column('use_gpg', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='Queued'),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('total_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sent_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('skipped_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['task_id'], ['tasks.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('task_id'),
        sa.UniqueConstraint('source_message_id_hash'),
    )
    op.create_index('ix_newsletter_campaigns_task_id', 'newsletter_campaigns', ['task_id'])
    op.create_index('ix_newsletter_campaigns_user_id', 'newsletter_campaigns', ['user_id'])
    op.create_index('ix_newsletter_campaigns_source', 'newsletter_campaigns', ['source'])
    op.create_index('ix_newsletter_campaigns_source_message_id_hash', 'newsletter_campaigns', ['source_message_id_hash'])
    op.create_index('ix_newsletter_campaigns_status', 'newsletter_campaigns', ['status'])
    op.create_index('ix_newsletter_campaigns_created_at', 'newsletter_campaigns', ['created_at'])

    op.create_table(
        'newsletter_deliveries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('campaign_id', sa.String(length=36), nullable=False),
        sa.Column('recipient', sa.Text(), nullable=False),
        sa.Column('recipient_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='Pending'),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('message_id', sa.String(length=255), nullable=True),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['campaign_id'], ['newsletter_campaigns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('campaign_id', 'recipient_hash', name='uq_newsletter_delivery_recipient'),
    )
    op.create_index('ix_newsletter_deliveries_campaign_id', 'newsletter_deliveries', ['campaign_id'])
    op.create_index('ix_newsletter_deliveries_recipient_hash', 'newsletter_deliveries', ['recipient_hash'])
    op.create_index('ix_newsletter_deliveries_status', 'newsletter_deliveries', ['status'])


def downgrade():
    op.drop_table('newsletter_deliveries')
    op.drop_table('newsletter_campaigns')
