"""Explicit, revocable remembered sessions; password/2FA changes invalidate them."""
import hashlib
from datetime import datetime, timedelta
from flask import request, session, jsonify
from core.database import db, User
from core.notification_models import RememberedDevice, PushSubscription
from core.notifications import bp, current_user


def stamp(user):
    return hashlib.sha256((str(user.password_hash) + '\0' + str(user.totp_secret)).encode()).hexdigest()


def remember(user):
    row = RememberedDevice(user_id=user.id, name=request.user_agent.browser or 'Browser',
        credential_stamp=stamp(user), expires_at=datetime.utcnow() + timedelta(days=30))
    db.session.add(row); db.session.flush()
    session['remembered_device_id'] = row.id
    db.session.commit()


def remembered_valid():
    device_id = session.get('remembered_device_id')
    if not device_id:
        return False
    row = db.session.get(RememberedDevice, device_id)
    user = db.session.get(User, session.get('user_id'))
    return bool(row and user and user.is_active and row.user_id == user.id and not row.revoked
                and row.expires_at > datetime.utcnow() and row.credential_stamp == stamp(user))


def revoke_current():
    row = db.session.get(RememberedDevice, session.get('remembered_device_id')) if session.get('remembered_device_id') else None
    if row and row.user_id == session.get('user_id'):
        row.revoked = True
    device = db.session.get(PushSubscription, session.get('push_device_id')) if session.get('push_device_id') else None
    if device and device.user_id == session.get('user_id'):
        device.active = False
    db.session.commit()


@bp.get('/api/notifications/sessions')
def sessions():
    user = current_user()
    return jsonify(devices=[dict(id=r.id, name=r.name, expires_at=r.expires_at.isoformat()+'Z',
        current=r.id == session.get('remembered_device_id')) for r in RememberedDevice.query.filter_by(user_id=user.id, revoked=False).filter(RememberedDevice.expires_at > datetime.utcnow())])


@bp.delete('/api/notifications/sessions/<device_id>')
def revoke_session(device_id):
    user = current_user()
    row = RememberedDevice.query.filter_by(user_id=user.id, id=device_id).first_or_404()
    row.revoked = True; db.session.commit()
    return jsonify(success=True)
