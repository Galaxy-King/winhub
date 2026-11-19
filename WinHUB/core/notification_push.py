"""Web Push transport: encrypted payloads, pinned public destinations, bounded retries."""
import base64
import hashlib
import ipaddress
import json
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import certifi
import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import abort, jsonify, request, session, send_from_directory, current_app
from sqlalchemy.exc import IntegrityError

from core.database import db, User
from core import limiter
from core.notification_models import PushIdentity, PushSubscription, PushDelivery, Notification
from core.notifications import bp, current_user, permitted, settings, json_body, serialize
from core.outbound_security import validate_outbound_host


def endpoint_url(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError('Invalid push endpoint')
    parsed = urlsplit(url)
    host = parsed.hostname or ''
    allowed = host in ('fcm.googleapis.com', 'updates.push.services.mozilla.com', 'push.services.mozilla.com', 'web.push.apple.com') or any(
        host.endswith('.' + suffix) for suffix in ('push.apple.com', 'notify.windows.com', 'push.services.mozilla.com'))
    if parsed.scheme != 'https' or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment or not allowed:
        raise ValueError('Unsupported push service. Use Chrome, Edge, Firefox or Safari.')
    return parsed


def validate_subscription(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid subscription')
    endpoint_url(value.get('endpoint'))
    keys = value.get('keys')
    if not isinstance(keys, dict):
        raise ValueError('Missing encryption keys')
    decoded = {}
    for key, length in (('p256dh', 65), ('auth', 16)):
        raw = keys.get(key)
        if not isinstance(raw, str) or len(raw) > 120:
            raise ValueError('Invalid encryption key')
        decoded[key] = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True)
        if len(decoded[key]) != length:
            raise ValueError('Invalid encryption key length')
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded['p256dh'])
    return dict(endpoint=value['endpoint'], keys={k: keys[k] for k in ('p256dh', 'auth')})


class PinnedPushTransport:
    def post(self, url, data=None, headers=None, timeout=None, **kwargs):
        parsed = endpoint_url(url)
        addresses = validate_outbound_host(parsed.hostname, 443, 'Web Push')
        if not addresses or any(not ipaddress.ip_address(str(a)).is_global for a in addresses):
            raise ValueError('Push services must resolve to public addresses')
        # Prefer IPv4; allow one connection-only fallback to the other address family.
        ordered = sorted(addresses, key=lambda a: (ipaddress.ip_address(str(a)).version, str(a)))
        candidates = [ordered[0]]
        alternate = next((a for a in ordered if a.version != ordered[0].version), None)
        if alternate is not None:
            candidates.append(alternate)
        for index, address in enumerate(candidates):
            pool = urllib3.HTTPSConnectionPool(str(address), port=443,
                server_hostname=parsed.hostname, assert_hostname=parsed.hostname,
                cert_reqs='CERT_REQUIRED', ca_certs=certifi.where(), timeout=urllib3.Timeout(connect=5, read=8, total=12))
            try:
                result = pool.urlopen('POST', parsed.path + ('?' + parsed.query if parsed.query else ''),
                    body=data, headers={**(headers or {}), 'Host': parsed.hostname},
                    redirect=False, retries=False, preload_content=False)
                try:
                    response = requests.Response()
                    response.status_code = result.status
                    response.headers.update(result.headers)
                    response._content = result.read(4096)
                    return response
                finally:
                    result.close()
            except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError):
                if index == len(candidates) - 1:
                    raise
            finally:
                pool.close()



@bp.post('/api/notifications/push/key')
def public_key():
    current_user()
    if not request.is_secure:
        return jsonify(message='Web Push requires trusted HTTPS.'), 400
    identity = db.session.get(PushIdentity, 1)
    if not identity:
        private = ec.generate_private_key(ec.SECP256R1())
        identity = PushIdentity(id=1, private_key=base64.urlsafe_b64encode(private.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
            public_key=base64.urlsafe_b64encode(private.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode().rstrip('='),
            subject=request.host_url.rstrip('/'))
        db.session.add(identity)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            identity = db.session.get(PushIdentity, 1)
    return jsonify(public_key=identity.public_key)


@bp.route('/api/notifications/push/devices', methods=['GET', 'POST'])
def devices():
    user = current_user()
    if request.method == 'POST':
        if not request.is_secure:
            abort(400)
        data = json_body()
        try:
            subscription = validate_subscription(data.get('subscription'))
        except (ValueError, TypeError):
            return jsonify(message='Invalid or unsupported browser subscription.'), 400
        digest = hashlib.sha256(subscription['endpoint'].encode()).hexdigest()
        row = PushSubscription.query.filter_by(endpoint_hash=digest).first()
        # Explicit subscription on a shared browser transfers this endpoint to its current user.
        if not row and PushSubscription.query.filter_by(user_id=user.id, active=True).count() >= 10:
            return jsonify(message='Remove an old device before adding another (limit: 10).'), 400
        row = row or PushSubscription(endpoint_hash=digest)
        row.user_id, row.subscription, row.active = user.id, json.dumps(subscription), True
        row.name = str(data.get('name') or 'Browser')[:100]
        db.session.add(row); db.session.commit()
        session['push_device_id'] = row.id
    return jsonify(devices=[dict(id=r.id, name=r.name, current=r.id == session.get('push_device_id'))
        for r in PushSubscription.query.filter_by(user_id=user.id, active=True)])


@bp.delete('/api/notifications/push/devices/<device_id>')
def remove_device(device_id):
    user = current_user()
    row = PushSubscription.query.filter_by(id=device_id, user_id=user.id).first_or_404()
    row.active = False; db.session.commit()
    return jsonify(success=True)


@bp.post('/api/notifications/push/bind')
def bind_existing_browser():
    """Restore logout binding after re-login; never subscribe a different account silently."""
    user = current_user()
    endpoint = json_body().get('endpoint')
    try:
        endpoint_url(endpoint)
    except (ValueError, TypeError):
        abort(400)
    digest = hashlib.sha256(endpoint.encode()).hexdigest()
    row = PushSubscription.query.filter_by(endpoint_hash=digest, active=True).first()
    if row and row.user_id == user.id:
        session['push_device_id'] = row.id
    elif row:
        row.active = False
        db.session.commit()
    return jsonify(success=True)


def quiet_now(preferences, now):
    start, end = preferences.get('quiet_start'), preferences.get('quiet_end')
    if start is None or end is None or start == end:
        return False
    return start <= now.hour < end if start < end else now.hour >= start or now.hour < end


@bp.post('/api/notifications/push/test')
@limiter.limit('3 per minute', key_func=lambda: str(session.get('user_id') or request.remote_addr))
def test_push():
    """Explicit diagnostic to the caller's current subscription, never arbitrary targets."""
    from pywebpush import webpush
    from core.outbound_security import OutboundPolicyError
    user = current_user()
    if not request.is_secure:
        return jsonify(message='Trusted HTTPS is required.'), 400
    device = PushSubscription.query.filter_by(id=session.get('push_device_id'), user_id=user.id, active=True).first()
    identity = db.session.get(PushIdentity, 1)
    if not device or not identity:
        return jsonify(message='Enable push on this device first.'), 409
    try:
        webpush(json.loads(device.subscription), data=json.dumps({'test': True}),
            vapid_private_key=identity.private_key, vapid_claims={'sub': identity.subject},
            ttl=60, timeout=12, requests_session=PinnedPushTransport())
    except Exception as exc:
        status = getattr(getattr(exc, 'response', None), 'status_code', None)
        if status in (404, 410):
            device.active = False
            db.session.commit()
            message = 'This subscription has expired. Enable push on this device again.'
        elif status in (400, 401, 403):
            message = 'Push provider rejected the request. Check server VAPID identity and browser subscription.'
        elif isinstance(exc, OutboundPolicyError):
            message = 'Server outbound policy or DNS blocked the push provider. Check OUTBOUND_ALLOWED_HOSTS and DNS.'
        elif isinstance(exc, (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError)):
            message = 'Cannot connect to the push provider. Check server IPv4/IPv6 routing and outbound TCP 443.'
        elif isinstance(exc, urllib3.exceptions.SSLError):
            message = 'Server TLS verification failed for the push provider. Check server time and CA certificates.'
        elif isinstance(exc, urllib3.exceptions.ReadTimeoutError):
            message = 'The push provider did not respond before the timeout.'
        else:
            message = 'Push delivery failed. Check server outbound HTTPS connectivity, TLS and push configuration.'
        # Never expose capability URLs, encryption keys or provider response bodies.
        return jsonify(success=False, message=message, provider_status=status if isinstance(status, int) else None), 502
    return jsonify(success=True, message='Push provider accepted the test. Check this deviceâ€™s system notifications. Acceptance does not confirm display on the phone.')


def deliver_pending():
    from pywebpush import webpush, WebPushException
    identity = db.session.get(PushIdentity, 1)
    if not identity:
        return
    now = datetime.utcnow()
    ids = [r.id for r in PushDelivery.query.filter_by(done=False).filter(PushDelivery.next_attempt <= now).order_by(PushDelivery.next_attempt).limit(10)]
    for delivery_id in ids:
        delivery = PushDelivery.query.filter_by(id=delivery_id, done=False).filter(
            PushDelivery.next_attempt <= now).with_for_update(skip_locked=True).first()
        if not delivery:
            continue
        # A lease prevents other web processes delivering the same item concurrently.
        delivery.next_attempt = now + timedelta(minutes=5)
        db.session.commit()
        notification = db.session.get(Notification, delivery.notification_id)
        device = db.session.get(PushSubscription, delivery.subscription_id)
        user = db.session.get(User, notification.user_id) if notification else None
        valid = (notification and device and device.active and device.user_id == notification.user_id
                 and not notification.dismissed_at and not notification.read_at and permitted(user, notification))
        if valid and notification.category == 'approvals' and serialize(notification)['resolved']:
            valid = False
        pref = settings(user.id) if valid else {}
        if (not valid or notification.created_at < now - timedelta(days=1)
                or notification.category not in pref.get('push_categories', [])
                or pref.get('errors_only') and notification.severity not in ('warning', 'error')):
            delivery.done = True; db.session.commit(); continue
        if quiet_now(pref, now):
            delivery.next_attempt = now + timedelta(minutes=15); db.session.commit(); continue
        try:
            webpush(json.loads(device.subscription), data=json.dumps(dict(id=notification.id,
                title='WinHUB', body='You have a new notification. Open WinHUB to review.',
                url='/notifications/' + notification.id)), vapid_private_key=identity.private_key,
                vapid_claims={'sub': identity.subject}, ttl=3600, timeout=12, requests_session=PinnedPushTransport())
            delivery.done = True
        except Exception as exc:
            # Do not log provider response bodies or capability endpoint URLs.
            status = getattr(getattr(exc, 'response', None), 'status_code', None)
            delivery.attempts += 1
            if status in (404, 410):
                device.active = False
            delivery.done = status in (400, 401, 403, 404, 410) or delivery.attempts >= 5
            delivery.next_attempt = now + timedelta(seconds=min(3600, 30 * 2 ** delivery.attempts))
        db.session.commit()


@bp.get('/winhub-sw.js')
def service_worker():
    response = send_from_directory(current_app.static_folder, 'js/notification_sw.js', mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@bp.get('/manifest.webmanifest')
def manifest():
    response = jsonify(name='WinHUB', short_name='WinHUB', id='/', start_url='/mobile', scope='/',
        display='standalone', background_color='#07111f', theme_color='#07111f',
        icons=[dict(src=f'/static/pwa-{size}.png', sizes=f'{size}x{size}', type='image/png', purpose='any maskable') for size in (192, 512)])
    response.mimetype = 'application/manifest+json'
    return response
