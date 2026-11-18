"""Durable notification inbox and transactional delivery signals."""
from datetime import datetime
import uuid
from core.database import db, EncryptedText


class NotificationSignal(db.Model):
    __tablename__ = 'notification_signals'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kind = db.Column(db.String(30), nullable=False)
    source_id = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    event_key = db.Column(db.String(200), nullable=False)
    kind = db.Column(db.String(30), nullable=False)
    source_id = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    title = db.Column(EncryptedText, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime)
    dismissed_at = db.Column(db.DateTime)
    __table_args__ = (db.UniqueConstraint('user_id', 'event_key', name='uq_notification_recipient_event'),
                     db.Index('ix_notification_inbox', 'user_id', 'dismissed_at', 'created_at'))


class NotificationPreference(db.Model):
    __tablename__ = 'notification_preferences'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    settings = db.Column(db.Text, nullable=False, default='{}')


class PushSubscription(db.Model):
    __tablename__ = 'notification_push_subscriptions'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    endpoint_hash = db.Column(db.String(64), nullable=False, unique=True)
    subscription = db.Column(EncryptedText, nullable=False)
    name = db.Column(db.String(100), nullable=False, default='Browser')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    active = db.Column(db.Boolean, nullable=False, default=True)


class PushDelivery(db.Model):
    __tablename__ = 'notification_push_deliveries'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    notification_id = db.Column(db.String(36), db.ForeignKey('notifications.id', ondelete='CASCADE'), nullable=False)
    subscription_id = db.Column(db.String(36), db.ForeignKey('notification_push_subscriptions.id', ondelete='CASCADE'), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    next_attempt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    done = db.Column(db.Boolean, nullable=False, default=False)
    __table_args__ = (db.UniqueConstraint('notification_id', 'subscription_id', name='uq_notification_push_delivery'),
                     db.Index('ix_push_delivery_pending', 'done', 'next_attempt'))


class PushIdentity(db.Model):
    __tablename__ = 'notification_push_identity'
    id = db.Column(db.Integer, primary_key=True)
    private_key = db.Column(EncryptedText, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(250), nullable=False)


class RememberedDevice(db.Model):
    __tablename__ = 'remembered_devices'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    credential_stamp = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
