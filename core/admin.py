import logging
import secrets
import string
import json
import os
import smtplib
import subprocess
import tempfile
import uuid
import threading
import keyring
import csv
import io
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, Response
from core.database import db, User, EndpointGroup, ApiKey, AuditLog
from core.security import sec_manager
from core.config import Config
from core.module_registry import get_module_registry
from core.permissions import MODULE_PERMISSION_CATALOG, parse_allowed_modules
from core.sdk import WinHubCore
from core.gpg import gpg_env, import_public_key, fetch_public_key, list_public_keys, delete_public_key, validate_gpg

log = logging.getLogger("winhub.admin")
admin_bp = Blueprint('admin', __name__)
GPG_KEYSERVERS_FILE = os.path.join(Config.DATA_DIR, "gpg_keyservers.json")
DEFAULT_GPG_KEYSERVERS = [
    "hkps://keys.openpgp.org",
    "hkps://keyserver.ubuntu.com",
]


def load_gpg_keyservers():
    try:
        with open(GPG_KEYSERVERS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                values = [str(item).strip() for item in data if str(item).strip()]
                return list(dict.fromkeys(DEFAULT_GPG_KEYSERVERS + values))
    except FileNotFoundError:
        pass
    except Exception:
        log.exception("Failed to load GPG keyservers")
    return list(DEFAULT_GPG_KEYSERVERS)


def save_gpg_keyserver(keyserver):
    value = str(keyserver or "").strip()
    if not value:
        return load_gpg_keyservers()
    values = load_gpg_keyservers()
    if value not in values:
        values.append(value)
    os.makedirs(os.path.dirname(GPG_KEYSERVERS_FILE), exist_ok=True)
    with open(GPG_KEYSERVERS_FILE, "w", encoding="utf-8") as handle:
        json.dump(values, handle, indent=2)
    return values


def sanitize_allowed_modules(raw_items):
    if not isinstance(raw_items, list):
        return []

    valid_modules = set()
    registry = get_module_registry()
    if registry:
        valid_modules.update(registry.keys())
    elif os.path.exists(Config.MODULES_DIR):
        valid_modules.update(
            item for item in os.listdir(Config.MODULES_DIR)
            if os.path.isdir(os.path.join(Config.MODULES_DIR, item))
        )
    valid_modules.update(MODULE_PERMISSION_CATALOG.keys())

    valid_tokens = {
        f"{module_id}:{permission['id']}"
        for module_id, permissions in MODULE_PERMISSION_CATALOG.items()
        for permission in permissions
    }
    cleaned = []
    for item in raw_items:
        if not isinstance(item, str):
            continue
        if item in valid_modules or item in valid_tokens:
            if item not in cleaned:
                cleaned.append(item)
    return cleaned


def sanitize_api_group_scope(raw_group_ids):
    if not isinstance(raw_group_ids, list):
        return []
    group_ids = [str(item) for item in raw_group_ids if item]
    valid_ids = {
        group.id
        for group in EndpointGroup.query.filter(EndpointGroup.id.in_(group_ids)).all()
    }
    cleaned = []
    for group_id in group_ids:
        if group_id in valid_ids and group_id not in cleaned:
            cleaned.append(group_id)
    return cleaned


def api_scope_tokens(group_ids):
    return [f"scope:group:{group_id}" for group_id in group_ids]


def parse_api_key_permissions(raw):
    items = parse_allowed_modules(raw)
    groups = []
    permissions = []
    for item in items:
        if isinstance(item, str) and item.startswith("scope:group:"):
            group_id = item.split(":", 2)[2]
            if group_id not in groups:
                groups.append(group_id)
        elif item not in permissions:
            permissions.append(item)
    return permissions, groups


def parse_expiration(days):
    if days == "__keep":
        return "__keep"
    if days in (None, "", "never", "Never"):
        return None
    try:
        days_int = int(days)
    except (TypeError, ValueError):
        raise ValueError("Expiration days must be a number")
    if days_int <= 0:
        return None
    if days_int > 3650:
        raise ValueError("Expiration cannot exceed 3650 days")
    return datetime.utcnow() + timedelta(days=days_int)

def hidden_subprocess_kwargs():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}

def get_notification_smtp_password(sender_email):
    if getattr(Config, 'SMTP_PASSWORD', None):
        return Config.SMTP_PASSWORD
    try:
        return keyring.get_password(sender_email, sender_email)
    except Exception:
        log.warning("Could not read SMTP password from keyring. Set SMTP_PASSWORD in the environment on Linux.")
        return None

def send_notification_email(subject, recipient, body_content, encrypt=True):
    sender_email = getattr(Config, 'SENDER_EMAIL', os.environ.get('SENDER_EMAIL', 'admin@localhost'))
    smtp_server = getattr(Config, 'SMTP_SERVER', os.environ.get('SMTP_SERVER', 'localhost'))
    smtp_port = int(getattr(Config, 'SMTP_PORT', os.environ.get('SMTP_PORT', 587)))
    gpg_path = getattr(Config, 'GPG_PATH', os.environ.get('GPG_PATH', 'gpg'))
    
    smtp_password = get_notification_smtp_password(sender_email)
    if not smtp_password: return False

    final_body = body_content
    if encrypt:
        unique_id = str(uuid.uuid4())
        tmp_in = os.path.join(tempfile.gettempdir(), f"mail_{unique_id}.txt")
        tmp_out = tmp_in + ".asc"
        try:
            with open(tmp_in, 'w', encoding='utf-8') as f: f.write(body_content)
            cmd = [gpg_path, "--batch", "--yes", "--trust-model", "always",
                   "--encrypt", "--armor", "-r", recipient, "-r", sender_email, "-o", tmp_out, tmp_in]
            subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=gpg_env(), **hidden_subprocess_kwargs())
            if os.path.exists(tmp_out):
                with open(tmp_out, 'r', encoding='utf-8') as f: final_body = f.read()
        except Exception: return False
        finally:
            for f in [tmp_in, tmp_out]:
                if os.path.exists(f): os.remove(f)

    try:
        msg = MIMEText(final_body, 'plain', 'utf-8')
        msg['Subject'] = f"WinHUB: {subject}" + (" [SECURE]" if encrypt else "")
        msg['From'] = sender_email
        msg['To'] = recipient
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, smtp_password)
            server.send_message(msg)
            return True
    except Exception: return False

def iso_or_none(value):
    return value.isoformat() if value else None

def parse_datetime_filter(value, end_of_day=False):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    if end_of_day and len(value) == 10:
        parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed

def audit_to_dict(item):
    return {
        "id": item.id,
        "timestamp": item.timestamp.isoformat() if item.timestamp else None,
        "user": item.user,
        "actor_type": item.actor_type or "user",
        "actor_name": item.actor_name or item.user,
        "module": item.module,
        "action": item.action,
        "target_type": item.target_type,
        "target_id": item.target_id,
        "ip_address": item.ip_address,
        "request_id": item.request_id,
        "details": item.details or "",
        "status": item.status or "",
    }

def build_audit_query():
    query = AuditLog.query
    module = request.args.get("module", "").strip()
    status = request.args.get("status", "").strip()
    actor = request.args.get("actor", "").strip()
    q = request.args.get("q", "").strip()
    date_from = parse_datetime_filter(request.args.get("date_from", "").strip() or None)
    date_to = parse_datetime_filter(request.args.get("date_to", "").strip() or None, end_of_day=True)
    if module:
        query = query.filter(AuditLog.module == module)
    if status:
        query = query.filter(AuditLog.status == status)
    if actor:
        like = f"%{actor}%"
        query = query.filter((AuditLog.user.ilike(like)) | (AuditLog.actor_name.ilike(like)))
    if q:
        like = f"%{q}%"
        query = query.filter(
            (AuditLog.action.ilike(like)) |
            (AuditLog.target_id.ilike(like)) |
            (AuditLog.request_id.ilike(like))
        )
    if date_from:
        query = query.filter(AuditLog.timestamp >= date_from)
    if date_to:
        query = query.filter(AuditLog.timestamp <= date_to)
    return query.order_by(AuditLog.timestamp.desc())

def allowed_system_logs():
    base = os.path.abspath(Config.BASE_DIR)
    data_logs = os.path.abspath(os.path.join(Config.DATA_DIR, "logs"))
    server_log_file = os.path.abspath(getattr(Config, "SERVER_LOG_FILE", os.path.join(base, "winhub_prod.log")))
    candidates = {
        "production": server_log_file,
        "app": os.path.join(base, "winhub.log"),
    }
    try:
        if os.path.isdir(data_logs):
            for name in os.listdir(data_logs):
                if name.lower().endswith(".log"):
                    key = f"data/{name}"
                    candidates[key] = os.path.join(data_logs, name)
    except OSError:
        pass
    safe = {}
    for key, path in candidates.items():
        abs_path = os.path.abspath(path)
        allowed_prefixes = (base, os.path.abspath(Config.DATA_DIR), os.path.dirname(server_log_file))
        if any(abs_path.startswith(prefix) for prefix in allowed_prefixes) and abs_path.lower().endswith(".log"):
            safe[key] = abs_path
    return safe

def tail_file(path, lines=200):
    lines = max(1, min(int(lines or 200), 2000))
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        data = handle.readlines()
    return [line.rstrip("\r\n") for line in data[-lines:]]

@admin_bp.before_request
def check_admin():
    if not session.get('logged_in') or not session.get('is_admin'):
        if request.path.startswith('/api/'): return jsonify({"success": False, "message": "Admin access required."}), 403
        return redirect(url_for('auth.login_page'))

@admin_bp.route('/admin/users')
def users_page():
    return render_template('admin_users.html', username=session.get('username'), is_admin=session.get('is_admin'))

@admin_bp.route('/api/admin/modules', methods=['GET'])
def get_modules():
    modules = []
    registry = get_module_registry()
    if registry:
        for item in registry.values():
            modules.append({
                "id": item.get("id"),
                "name": item.get("name") or item.get("id"),
                "status": item.get("status", "disabled"),
                "required": bool(item.get("required")),
                "optional": bool(item.get("optional")),
                "error_message": item.get("error_message"),
                "permissions": MODULE_PERMISSION_CATALOG.get(item.get("id"), []),
            })
    elif os.path.exists(Config.MODULES_DIR):
        for item in os.listdir(Config.MODULES_DIR):
            if os.path.isdir(os.path.join(Config.MODULES_DIR, item)) and not item.startswith('__'):
                if os.path.exists(os.path.join(Config.MODULES_DIR, item, 'manifest.json')):
                    modules.append({
                        "id": item,
                        "name": item.replace('_', ' '),
                        "status": "loaded",
                        "required": False,
                        "optional": True,
                        "error_message": None,
                        "permissions": MODULE_PERMISSION_CATALOG.get(item, []),
                    })
    return jsonify({"success": True, "modules": modules})

@admin_bp.route('/api/admin/groups', methods=['GET'])
def get_host_groups():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    pagination = EndpointGroup.query.order_by(EndpointGroup.name).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "success": True, 
        "groups": [{"id": g.id, "name": g.name} for g in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    })

@admin_bp.route('/api/admin/users', methods=['GET'])
def get_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    pagination = User.query.order_by(User.id).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "success": True, 
        "users": [{
            "id": u.id, "username": u.username, "email": u.email,
            "is_admin": u.is_admin, "is_active": u.is_active,
            "allowed_modules": parse_allowed_modules(u.allowed_modules),
            "allowed_groups": [g.id for g in u.allowed_host_groups]
        } for u in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    })

@admin_bp.route('/api/admin/users', methods=['POST'])
def create_user():
    data = request.json or {}
    username, email = data.get('username', '').strip(), data.get('email', '').strip().lower()
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "User or Email already exists."}), 400

    raw_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14))
    raw_totp = sec_manager.generate_totp_secret()
    new_user = User(
        username=username, email=email, is_admin=bool(data.get('is_admin')),
        password_hash=sec_manager.hash_password(raw_password),
        totp_secret=sec_manager.encrypt_data(raw_totp),
        allowed_modules=json.dumps(sanitize_allowed_modules(data.get('allowed_modules', [])))
    )
    db.session.add(new_user); db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Create User",
        target_type="user",
        target_id=new_user.id,
        details={"username": username, "email": email, "is_admin": bool(new_user.is_admin)},
        status="Success"
    )
    return jsonify({"success": True, "credentials": {"username": username, "password": raw_password, "totp_secret": raw_totp}})

@admin_bp.route('/api/admin/users/<int:user_id>/toggle', methods=['POST'])
def toggle_user(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"success": False, "message": "Not found"}), 404
    if user.id == session.get('user_id'): return jsonify({"success": False, "message": "Cannot lock yourself."}), 403
    user.is_active = not user.is_active
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Toggle User",
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "is_active": bool(user.is_active)},
        status="Success"
    )
    return jsonify({"success": True, "message": "Status updated."})

@admin_bp.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
def manage_user(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"success": False, "message": "Not found"}), 404
    
    if request.method == 'DELETE':
        if user.username == 'admin' or user.id == session.get('user_id'):
            return jsonify({"success": False, "message": "Protection active."}), 403
        audit_details = {"username": user.username, "email": user.email}
        db.session.delete(user); db.session.commit()
        WinHubCore.audit(
            user_id=session.get('user_id'),
            module="Admin",
            action="Delete User",
            target_type="user",
            target_id=user_id,
            details=audit_details,
            status="Success"
        )
        return jsonify({"success": True})

    data = request.json or {}
    if 'email' in data: user.email = data['email'].strip().lower()
    if 'password' in data and data['password'].strip():
        user.password_hash = sec_manager.hash_password(data['password'].strip())
    if 'is_admin' in data: user.is_admin = bool(data['is_admin'])
    if 'allowed_modules' in data: user.allowed_modules = json.dumps(sanitize_allowed_modules(data['allowed_modules']))
    
    if 'allowed_groups' in data:
        group_ids = data['allowed_groups']
        user.allowed_host_groups = EndpointGroup.query.filter(EndpointGroup.id.in_(group_ids)).all()
        
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Update User",
        target_type="user",
        target_id=user.id,
        details={
            "username": user.username,
            "changed_fields": sorted([key for key in data.keys() if key != "password"]),
            "password_changed": bool(data.get("password")),
            "allowed_groups_count": len(data.get("allowed_groups", [])) if "allowed_groups" in data else None,
            "allowed_modules_count": len(data.get("allowed_modules", [])) if "allowed_modules" in data else None,
        },
        status="Success"
    )
    return jsonify({"success": True})

@admin_bp.route('/api/admin/users/<int:user_id>/reset_credentials', methods=['POST'])
def reset_credentials(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({"success": False}), 404
    data = request.json or {}
    raw_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14))
    raw_totp = sec_manager.generate_totp_secret()
    user.password_hash = sec_manager.hash_password(raw_pass)
    user.totp_secret = sec_manager.encrypt_data(raw_totp)
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Reset User Credentials",
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "send_email": bool(data.get('send_email'))},
        status="Success"
    )
    if data.get('send_email') and "localhost" not in user.email:
        body = f"New credentials for WinHUB:\nPass: {raw_pass}\n2FA: {raw_totp}"
        threading.Thread(target=send_notification_email, args=("Reset", user.email, body)).start()
    return jsonify({"success": True, "credentials": {"username": user.username, "password": raw_pass, "totp_secret": raw_totp}})

# ---------------------------------------------------------
# СИСТЕМА API КЛЮЧІВ
# ---------------------------------------------------------
@admin_bp.route('/api/admin/apikeys', methods=['GET'])
def get_api_keys():
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    result = []
    for k in keys:
        permissions, group_scope = parse_api_key_permissions(k.permissions)
        result.append({
            "id": k.id, "name": k.name, "prefix": k.prefix, "user": k.user.username if k.user else "Unknown",
            "expires": k.expires_at.strftime('%Y-%m-%d') if k.expires_at else "Never Expires",
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created": k.created_at.strftime('%Y-%m-%d'),
            "is_active": k.is_active,
            "permissions": permissions,
            "group_scope": group_scope,
        })
    return jsonify({"success": True, "keys": result})

@admin_bp.route('/api/admin/apikeys', methods=['POST'])
def create_api_key():
    data = request.json or {}
    name = data.get('name')
    if not name: return jsonify({"success": False, "message": "Key name is required"}), 400
    
    raw_key = f"wh_{secrets.token_urlsafe(40)}"
    key_hash = sec_manager.hash_password(raw_key)
    
    try:
        expires = parse_expiration(data.get('days'))
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    permissions = sanitize_allowed_modules(data.get('permissions', []))
    group_scope = sanitize_api_group_scope(data.get('group_scope', []))
    
    new_key = ApiKey(
        user_id=session.get('user_id'), 
        name=name, 
        key_hash=key_hash, 
        prefix=raw_key[:8], 
        expires_at=expires,
        permissions=json.dumps(permissions + api_scope_tokens(group_scope))
    )
    db.session.add(new_key)
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Create API Key",
        details={
            "key_id": new_key.id,
            "name": new_key.name,
            "prefix": new_key.prefix,
            "permissions_count": len(permissions),
            "group_scope_count": len(group_scope),
            "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
        },
        status="Success"
    )
    
    # Повертаємо raw_key ТІЛЬКИ ОДИН РАЗ
    return jsonify({"success": True, "raw_key": raw_key}) 

@admin_bp.route('/api/admin/apikeys/<int:kid>', methods=['DELETE'])
def delete_api_key(kid):
    k = ApiKey.query.get(kid)
    if k:
        audit_details = {"key_id": k.id, "name": k.name, "prefix": k.prefix}
        db.session.delete(k)
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get('user_id'),
            module="Admin",
            action="Delete API Key",
            details=audit_details,
            status="Success"
        )
    return jsonify({"success": True})


@admin_bp.route('/api/admin/apikeys/<int:kid>/permissions', methods=['PUT'])
def update_api_key_permissions(kid):
    key = ApiKey.query.get(kid)
    if not key:
        return jsonify({"success": False, "message": "API key not found"}), 404
    data = request.json or {}
    permissions = sanitize_allowed_modules(data.get('permissions', []))
    group_scope = sanitize_api_group_scope(data.get('group_scope', []))
    key.permissions = json.dumps(permissions + api_scope_tokens(group_scope))
    if 'days' in data:
        try:
            expires = parse_expiration(data.get('days'))
            if expires != "__keep":
                key.expires_at = expires
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Update API Key",
        details={
            "key_id": key.id,
            "name": key.name,
            "prefix": key.prefix,
            "permissions_count": len(permissions),
            "group_scope_count": len(group_scope),
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        },
        status="Success"
    )
    return jsonify({"success": True})


@admin_bp.route('/api/admin/audit-logs', methods=['GET'])
def get_audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)
    query = build_audit_query()
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    modules = [
        row[0] for row in db.session.query(AuditLog.module)
        .filter(AuditLog.module.isnot(None))
        .distinct()
        .order_by(AuditLog.module)
        .all()
        if row[0]
    ]
    statuses = [
        row[0] for row in db.session.query(AuditLog.status)
        .filter(AuditLog.status.isnot(None))
        .distinct()
        .order_by(AuditLog.status)
        .all()
        if row[0]
    ]
    return jsonify({
        "success": True,
        "logs": [audit_to_dict(item) for item in pagination.items],
        "modules": modules,
        "statuses": statuses,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page,
    })


@admin_bp.route('/api/admin/audit-logs/export', methods=['GET'])
def export_audit_logs():
    query = build_audit_query().limit(5000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "timestamp", "actor_type", "actor_name", "module", "action",
        "target_type", "target_id", "status", "ip_address", "request_id", "details"
    ])
    writer.writeheader()
    for item in query.all():
        data = audit_to_dict(item)
        writer.writerow({key: data.get(key, "") for key in writer.fieldnames})
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=winhub_audit_logs.csv"}
    )


@admin_bp.route('/api/admin/system-logs', methods=['GET'])
def get_system_logs():
    logs = allowed_system_logs()
    selected = request.args.get("file", "production")
    level = request.args.get("level", "").strip().upper()
    lines = request.args.get("lines", 200, type=int)
    if selected not in logs:
        selected = next(iter(logs), None)
    if not selected:
        return jsonify({"success": True, "files": [], "selected": None, "lines": []})
    output_lines = tail_file(logs[selected], lines=lines)
    if level:
        output_lines = [line for line in output_lines if f"[{level}]" in line or level in line]
    return jsonify({
        "success": True,
        "files": [{"id": key, "name": key, "exists": os.path.exists(path)} for key, path in logs.items()],
        "selected": selected,
        "lines": output_lines,
    })


@admin_bp.route('/api/admin/gpg/keys', methods=['GET'])
def get_gpg_keys():
    ok, message = validate_gpg()
    if not ok:
        return jsonify({"success": False, "message": message, "keys": []}), 500
    listed, list_message, keys = list_public_keys()
    return jsonify({"success": listed, "message": list_message, "keys": keys, "keyservers": load_gpg_keyservers()})


@admin_bp.route('/api/admin/gpg/keyservers', methods=['GET'])
def get_gpg_keyservers():
    return jsonify({"success": True, "keyservers": load_gpg_keyservers()})


@admin_bp.route('/api/admin/gpg/import', methods=['POST'])
def import_gpg_key():
    data = request.json or {}
    ok, message = import_public_key(data.get("key") or "")
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Import GPG Key",
        details={"success": bool(ok), "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message}), 200 if ok else 400


@admin_bp.route('/api/admin/gpg/fetch', methods=['POST'])
def fetch_gpg_key_route():
    data = request.json or {}
    keyserver = data.get("keyserver")
    ok, message = fetch_public_key(keyserver, data.get("search"))
    keyservers = save_gpg_keyserver(keyserver) if ok else load_gpg_keyservers()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Fetch GPG Key",
        details={"success": bool(ok), "search": data.get("search"), "keyserver": keyserver, "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message, "keyservers": keyservers}), 200 if ok else 400


@admin_bp.route('/api/admin/gpg/keys/<fingerprint>', methods=['DELETE'])
def delete_gpg_key_route(fingerprint):
    ok, message = delete_public_key(fingerprint)
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Delete GPG Key",
        details={"success": bool(ok), "fingerprint": fingerprint, "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message}), 200 if ok else 400
