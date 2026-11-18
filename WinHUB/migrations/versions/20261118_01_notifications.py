"""Notification inbox, Web Push delivery and remembered device sessions."""
from alembic import op
import sqlalchemy as sa

revision = '20261118_01'
down_revision = '20261116_02'
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'notification_signals' not in existing:
        op.create_table('notification_signals',
            sa.Column('id', sa.String(36), nullable=False, primary_key=True),
            sa.Column('kind', sa.String(30), nullable=False),
            sa.Column('source_id', sa.String(100), nullable=False),
            sa.Column('state', sa.String(100), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_notification_signals_created_at', 'notification_signals', ['created_at'], unique=False)
    if 'notifications' not in existing:
        op.create_table('notifications',
            sa.Column('id', sa.String(36), nullable=False, primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('event_key', sa.String(200), nullable=False),
            sa.Column('kind', sa.String(30), nullable=False),
            sa.Column('source_id', sa.String(100), nullable=False),
            sa.Column('category', sa.String(30), nullable=False),
            sa.Column('severity', sa.String(16), nullable=False),
            sa.Column('title', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('read_at', sa.DateTime(), nullable=True),
            sa.Column('dismissed_at', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('user_id', 'event_key', name='uq_notification_recipient_event'),
        )
        op.create_index('ix_notifications_user_id', 'notifications', ['user_id'], unique=False)
        op.create_index('ix_notifications_created_at', 'notifications', ['created_at'], unique=False)
        op.create_index('ix_notification_inbox', 'notifications', ['user_id', 'dismissed_at', 'created_at'], unique=False)
    if 'notification_preferences' not in existing:
        op.create_table('notification_preferences',
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, primary_key=True),
            sa.Column('settings', sa.Text(), nullable=False),
        )
    if 'notification_push_subscriptions' not in existing:
        op.create_table('notification_push_subscriptions',
            sa.Column('id', sa.String(36), nullable=False, primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('endpoint_hash', sa.String(64), nullable=False),
            sa.Column('subscription', sa.Text(), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('active', sa.Boolean(), nullable=False),
            sa.UniqueConstraint('endpoint_hash', name=None),
        )
        op.create_index('ix_notification_push_subscriptions_user_id', 'notification_push_subscriptions', ['user_id'], unique=False)
    if 'notification_push_deliveries' not in existing:
        op.create_table('notification_push_deliveries',
            sa.Column('id', sa.String(36), nullable=False, primary_key=True),
            sa.Column('notification_id', sa.String(36), sa.ForeignKey('notifications.id', ondelete='CASCADE'), nullable=False),
            sa.Column('subscription_id', sa.String(36), sa.ForeignKey('notification_push_subscriptions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('attempts', sa.Integer(), nullable=False),
            sa.Column('next_attempt', sa.DateTime(), nullable=False),
            sa.Column('done', sa.Boolean(), nullable=False),
            sa.UniqueConstraint('notification_id', 'subscription_id', name='uq_notification_push_delivery'),
        )
        op.create_index('ix_notification_push_deliveries_next_attempt', 'notification_push_deliveries', ['next_attempt'], unique=False)
        op.create_index('ix_push_delivery_pending', 'notification_push_deliveries', ['done', 'next_attempt'], unique=False)
    if 'notification_push_identity' not in existing:
        op.create_table('notification_push_identity',
            sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
            sa.Column('private_key', sa.Text(), nullable=False),
            sa.Column('public_key', sa.Text(), nullable=False),
            sa.Column('subject', sa.String(250), nullable=False),
        )
    if 'remembered_devices' not in existing:
        op.create_table('remembered_devices',
            sa.Column('id', sa.String(36), nullable=False, primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('credential_stamp', sa.String(64), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('revoked', sa.Boolean(), nullable=False),
        )
        op.create_index('ix_remembered_devices_user_id', 'remembered_devices', ['user_id'], unique=False)


def downgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'remembered_devices' in existing:
        op.drop_table('remembered_devices')
    if 'notification_push_identity' in existing:
        op.drop_table('notification_push_identity')
    if 'notification_push_deliveries' in existing:
        op.drop_table('notification_push_deliveries')
    if 'notification_push_subscriptions' in existing:
        op.drop_table('notification_push_subscriptions')
    if 'notification_preferences' in existing:
        op.drop_table('notification_preferences')
    if 'notifications' in existing:
        op.drop_table('notifications')
    if 'notification_signals' in existing:
        op.drop_table('notification_signals')
