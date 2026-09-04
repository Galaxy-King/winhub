import logging
import secrets
import string
import json
import os
import smtplib
import ssl
import subprocess
import tempfile
import uuid
import threading
import keyring
import csv
import io
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, Response
from core.database import db, User, Endpoint, EndpointGroup, ApiKey, AuditLog, TaskTemplate
from core.security import sec_manager
from core.config import Config
from core.module_registry import get_module_registry
from core.permissions import (
    MODULE_PERMISSION_CATALOG,
    all_permission_tokens_for_module,
    granular_permission_catalog,
    has_permission,
    parse_allowed_modules,
)
from core.group_access import (
    GROUP_ACTION_CATALOG,
    GROUP_ACTION_IDS,
    group_permissions_for_users,
    replace_user_group_permissions,
)
from core.api_access import (
    api_key_group_permissions_for_keys,
    api_key_template_ids_for_keys,
    approved_action_templates,
    normalize_allowed_networks,
    normalize_max_targets,
    replace_api_key_group_permissions,
    replace_api_key_template_ids,
    stored_allowed_networks,
)
from core.sdk import WinHubCore
from core.gpg import gpg_env, import_public_key, fetch_public_key, list_public_keys, delete_public_key, validate_gpg
from core.outbound_security import pinned_outbound_host
from core.production_readiness import build_production_readiness

log = logging.getLogger("winhub.admin")
admin_bp = Blueprint('admin', __name__)
GPG_KEYSERVERS_FILE = os.path.join(Config.DATA_DIR, "gpg_keyservers.json")
DEFAULT_GPG_KEYSERVERS = []
LEGACY_GPG_KEYSERVERS = {
    "hkps://keys.openpgp.org",
    "hkps://keyserver.ubuntu.com",
}

try:
    KYIV_TZ = ZoneInfo("Europe/Kyiv")
except Exception:
    KYIV_TZ = ZoneInfo("Europe/Kiev")


def load_gpg_keyservers():
    try:
        with open(GPG_KEYSERVERS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                values = [
                    str(item).strip()
                    for item in data
                    if str(item).strip() and str(item).strip() not in LEGACY_GPG_KEYSERVERS
                ]
                return list(dict.fromkeys(DEFAULT_GPG_KEYSERVERS + values))
    except FileNotFoundError:
        pass
    except Exception:
        log.exception("Failed to load GPG keyservers")
    return list(DEFAULT_GPG_KEYSERVERS)


def load_custom_gpg_keyservers():
    try:
        with open(GPG_KEYSERVERS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                return [
                    str(item).strip()
                    for item in data
                    if (
                        str(item).strip()
                        and str(item).strip() not in DEFAULT_GPG_KEYSERVERS
                        and str(item).strip() not in LEGACY_GPG_KEYSERVERS
                    )
                ]
    except FileNotFoundError:
        pass
    except Exception:
        log.exception("Failed to load custom GPG keyservers")
    return []


def save_custom_gpg_keyservers(values):
    cleaned = [
        str(item).strip()
        for item in values
        if (
            str(item).strip()
            and str(item).strip() not in DEFAULT_GPG_KEYSERVERS
            and str(item).strip() not in LEGACY_GPG_KEYSERVERS
        )
    ]
    cleaned = list(dict.fromkeys(cleaned))
    os.makedirs(os.path.dirname(GPG_KEYSERVERS_FILE), exist_ok=True)
    with open(GPG_KEYSERVERS_FILE, "w", encoding="utf-8") as handle:
        json.dump(cleaned, handle, indent=2)
    return load_gpg_keyservers()


def save_gpg_keyserver(keyserver):
    value = str(keyserver or "").strip()
    if not value:
        return load_gpg_keyservers()
    values = load_custom_gpg_keyservers()
    if value not in DEFAULT_GPG_KEYSERVERS and value not in values:
        values.append(value)
    return save_custom_gpg_keyservers(values)


def update_gpg_keyserver(old_keyserver, new_keyserver):
    old_value = str(old_keyserver or "").strip()
    new_value = str(new_keyserver or "").strip()
    if not old_value or not new_value:
        return False, "Both old and new keyserver values are required.", gpg_keyserver_payload()
    if old_value in DEFAULT_GPG_KEYSERVERS:
        return False, "Built-in keyservers cannot be edited.", gpg_keyserver_payload()
    values = load_custom_gpg_keyservers()
    if old_value not in values:
        return False, "Custom keyserver not found.", gpg_keyserver_payload()
    values = [new_value if item == old_value else item for item in values]
    save_custom_gpg_keyservers(values)
    return True, "Keyserver updated.", gpg_keyserver_payload()


def gpg_keyserver_payload():
    custom = load_custom_gpg_keyservers()
    return {
        "keyservers": load_gpg_keyservers(),
        "built_in": list(DEFAULT_GPG_KEYSERVERS),
        "custom": custom,
    }


def delete_gpg_keyserver(keyserver):
    value = str(keyserver or "").strip()
    if not value:
        return False, "Keyserver value is required.", gpg_keyserver_payload()
    if value in DEFAULT_GPG_KEYSERVERS:
        return False, "Built-in keyservers cannot be removed.", gpg_keyserver_payload()
    values = [item for item in load_custom_gpg_keyservers() if item != value]
    save_custom_gpg_keyservers(values)
    return True, "Keyserver removed.", gpg_keyserver_payload()


def current_admin_user():
    user_id = session.get("user_id")
    return User.query.get(user_id) if user_id else None


def can_manage_gpg_keys():
    user = current_admin_user()
    return bool(user and (user.is_admin or has_permission(user, "Administration", "manage_gpg_keys")))


def require_gpg_access():
    if can_manage_gpg_keys():
        return None
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "message": "GPG key management access required."}), 403
    return redirect(url_for('auth.login_page'))


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

    valid_tokens = set()
    for module_id in MODULE_PERMISSION_CATALOG:
        valid_tokens.update(all_permission_tokens_for_module(module_id))
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


def _api_group_entries(data):
    entries = data.get("group_access")
    if entries is not None:
        if not isinstance(entries, list):
            raise ValueError("Group access must be a list")
        return entries
    # Compatibility with older clients that only sent a group checkbox list.
    return [
        {"group_id": group_id, "permissions": list(GROUP_ACTION_IDS)}
        for group_id in sanitize_api_group_scope(data.get("group_scope", []))
    ]


def _api_policy_values(data, existing_key=None):
    permissions = sanitize_allowed_modules(data.get("permissions", []))
    group_entries = _api_group_entries(data)
    template_ids = data.get("allowed_template_ids", [])
    if not isinstance(template_ids, list):
        raise ValueError("Allowed templates must be a list")
    template_ids = list(dict.fromkeys(str(item) for item in template_ids if item))

    if "Infrastructure:view_sensitive_reports" in permissions:
        raise ValueError("API keys cannot be granted permission to reveal passwords or secrets")
    if any(
        isinstance(entry, dict) and "view_sensitive_reports" in (entry.get("permissions") or [])
        for entry in group_entries
    ):
        raise ValueError("API keys cannot reveal sensitive task or report output")

    existing_networks = stored_allowed_networks(existing_key) if existing_key else []
    networks = normalize_allowed_networks(data.get("allowed_networks", existing_networks))
    # New and edited keys always use the strict policy; the migration also
    # blocks pre-existing keys until this policy is configured.
    ip_enforced = True
    template_enforced = True
    max_targets = normalize_max_targets(
        data.get("max_targets_per_run", getattr(existing_key, "max_targets_per_run", 1) if existing_key else 1)
    )

    if ip_enforced and not networks:
        raise ValueError("At least one allowed source IP or CIDR is required")

    grants_run_tasks = "Infrastructure" in permissions or "Infrastructure:run_tasks" in permissions
    if grants_run_tasks and template_enforced and not template_ids:
        raise ValueError("Select at least one approved action template for a key that can run tasks")
    if grants_run_tasks and not any(
        isinstance(entry, dict) and "run_tasks" in (entry.get("permissions") or [])
        for entry in group_entries
    ):
        raise ValueError("Grant run_tasks in at least one host group")

    return {
        "permissions": permissions,
        "group_entries": group_entries,
        "template_ids": template_ids,
        "networks": networks,
        "ip_enforced": ip_enforced,
        "template_enforced": template_enforced,
        "max_targets": max_targets,
    }

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
        with pinned_outbound_host(smtp_server, smtp_port, "administration notification SMTP"):
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if Config.OUTBOUND_POLICY_MODE == "enforce":
                    server.starttls(context=ssl.create_default_context())
                else:
                    server.starttls()
                server.login(sender_email, smtp_password)
                server.send_message(msg)
                return True
    except Exception: return False

def _as_utc(value):
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _as_kyiv(value):
    utc_value = _as_utc(value)
    return utc_value.astimezone(KYIV_TZ) if utc_value else None


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
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=KYIV_TZ)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)

def audit_to_dict(item):
    return {
        "id": item.id,
        "timestamp": iso_or_none(_as_kyiv(item.timestamp)),
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
    if not session.get('logged_in'):
        if request.path.startswith('/api/'): return jsonify({"success": False, "message": "Authentication required."}), 403
        return redirect(url_for('auth.login_page'))

    if request.path == "/admin/gpg" or request.path.startswith("/api/admin/gpg/"):
        denied = require_gpg_access()
        if denied:
            return denied
        return None

    if not session.get('is_admin'):
        if request.path.startswith('/api/'): return jsonify({"success": False, "message": "Admin access required."}), 403
        return redirect(url_for('auth.login_page'))

@admin_bp.route('/admin/users')
def users_page():
    return render_template('admin_users.html', username=session.get('username'), is_admin=session.get('is_admin'))


@admin_bp.route('/admin/gpg')
def gpg_keys_page():
    denied = require_gpg_access()
    if denied:
        return denied
    return render_template('admin_gpg_keys.html', username=session.get('username'), is_admin=session.get('is_admin'))

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
                "permissions": granular_permission_catalog(item.get("id")),
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
                        "permissions": granular_permission_catalog(item),
                    })
    if not any(item.get("id") == "Administration" for item in modules):
        modules.append({
            "id": "Administration",
            "name": "Administration",
            "status": "loaded",
            "required": True,
            "optional": False,
            "error_message": None,
            "permissions": granular_permission_catalog("Administration"),
        })
    action_templates = approved_action_templates()
    return jsonify({
        "success": True,
        "modules": modules,
        "group_permissions": GROUP_ACTION_CATALOG,
        "action_templates": [{
            "id": template.id,
            "name": template.name,
            "category": template.category or "General",
            "action_type": template.action_type,
        } for template in action_templates],
    })

@admin_bp.route('/api/admin/groups', methods=['GET'])
def get_host_groups():
    page = request.args.get('page', 1, type=int)
    # Keep each response bounded; the access editor walks the pages and only
    # requests lightweight id/name records instead of loading group members.
    per_page = max(1, min(request.args.get('per_page', 250, type=int), 500))
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

    group_access_by_user = group_permissions_for_users([user.id for user in pagination.items])
    return jsonify({
        "success": True,
        "users": [{
            "id": u.id, "username": u.username, "email": u.email,
            "is_admin": u.is_admin, "is_active": u.is_active,
            "allowed_modules": parse_allowed_modules(u.allowed_modules),
            "allowed_groups": list(group_access_by_user.get(u.id, {})),
            "group_access": group_access_by_user.get(u.id, {}),
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

    updated_group_ids = None
    if 'group_access' in data:
        updated_group_ids = replace_user_group_permissions(user.id, data.get('group_access'))
    elif 'allowed_groups' in data:
        # Compatibility with older clients: a selected group inherits all
        # group-level actions, while global permissions remain the first gate.
        updated_group_ids = replace_user_group_permissions(user.id, [
            {"group_id": group_id, "permissions": list(GROUP_ACTION_IDS)}
            for group_id in (data.get('allowed_groups') or [])
        ])

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
            "allowed_groups_count": len(updated_group_ids) if updated_group_ids is not None else None,
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
    key_ids = [key.id for key in keys]
    group_maps = api_key_group_permissions_for_keys(key_ids)
    template_maps = api_key_template_ids_for_keys(key_ids)
    template_names = {
        str(template.id): template.name
        for template in TaskTemplate.query.filter(
            TaskTemplate.id.in_(set().union(*template_maps.values()) if template_maps else set())
        ).all()
    } if any(template_maps.values()) else {}
    result = []
    for k in keys:
        permissions, legacy_group_scope = parse_api_key_permissions(k.permissions)
        group_access = group_maps.get(k.id) or {}
        if not group_access and legacy_group_scope:
            group_access = {
                group_id: list(GROUP_ACTION_IDS)
                for group_id in legacy_group_scope
            }
        template_ids = sorted(template_maps.get(k.id, set()))
        result.append({
            "id": k.id, "name": k.name, "prefix": k.prefix, "user": k.user.username if k.user else "Unknown",
            "expires": k.expires_at.strftime('%Y-%m-%d') if k.expires_at else "Never Expires",
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created": k.created_at.strftime('%Y-%m-%d'),
            "is_active": k.is_active,
            "permissions": permissions,
            "group_scope": list(group_access.keys()),
            "group_access": group_access,
            "allowed_networks": stored_allowed_networks(k),
            "ip_allowlist_enforced": bool(k.ip_allowlist_enforced),
            "template_scope_enforced": bool(k.template_scope_enforced),
            "allowed_template_ids": template_ids,
            "allowed_templates": [
                {"id": template_id, "name": template_names.get(template_id, template_id)}
                for template_id in template_ids
            ],
            "max_targets_per_run": int(k.max_targets_per_run or 1),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "last_used_ip": k.last_used_ip or None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
            "policy_mode": "enforced" if k.ip_allowlist_enforced and k.template_scope_enforced else "legacy",
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

    try:
        policy = _api_policy_values(data)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    new_key = ApiKey(
        user_id=session.get('user_id'),
        name=name,
        key_hash=key_hash,
        prefix=raw_key[:8],
        expires_at=expires,
        permissions=json.dumps(policy["permissions"]),
        allowed_networks=json.dumps(policy["networks"]),
        ip_allowlist_enforced=policy["ip_enforced"],
        template_scope_enforced=policy["template_enforced"],
        max_targets_per_run=policy["max_targets"],
    )
    try:
        db.session.add(new_key)
        db.session.flush()
        groups = replace_api_key_group_permissions(new_key.id, policy["group_entries"])
        templates = replace_api_key_template_ids(new_key.id, policy["template_ids"])
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception:
        db.session.rollback()
        log.exception("Failed to create API key")
        return jsonify({"success": False, "message": "Failed to create API key"}), 500
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Create API Key",
        details={
            "key_id": new_key.id,
            "name": new_key.name,
            "prefix": new_key.prefix,
            "permissions_count": len(policy["permissions"]),
            "group_scope_count": len(groups),
            "template_scope_count": len(templates),
            "allowed_networks": policy["networks"],
            "max_targets_per_run": policy["max_targets"],
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
        k.is_active = False
        k.revoked_at = datetime.utcnow()
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get('user_id'),
            module="Admin",
            action="Revoke API Key",
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
    try:
        policy = _api_policy_values(data, existing_key=key)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    key.permissions = json.dumps(policy["permissions"])
    key.allowed_networks = json.dumps(policy["networks"])
    key.ip_allowlist_enforced = policy["ip_enforced"]
    key.template_scope_enforced = policy["template_enforced"]
    key.max_targets_per_run = policy["max_targets"]
    if 'days' in data:
        try:
            expires = parse_expiration(data.get('days'))
            if expires != "__keep":
                key.expires_at = expires
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
    try:
        groups = replace_api_key_group_permissions(key.id, policy["group_entries"])
        templates = replace_api_key_template_ids(key.id, policy["template_ids"])
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception:
        db.session.rollback()
        log.exception("Failed to update API key")
        return jsonify({"success": False, "message": "Failed to update API key"}), 500
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Update API Key",
        details={
            "key_id": key.id,
            "name": key.name,
            "prefix": key.prefix,
            "permissions_count": len(policy["permissions"]),
            "group_scope_count": len(groups),
            "template_scope_count": len(templates),
            "allowed_networks": policy["networks"],
            "max_targets_per_run": policy["max_targets"],
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        },
        status="Success"
    )
    return jsonify({"success": True})


@admin_bp.route('/api/admin/apikeys/<int:kid>/rotate', methods=['POST'])
def rotate_api_key(kid):
    key = ApiKey.query.get(kid)
    if not key:
        return jsonify({"success": False, "message": "API key not found"}), 404
    raw_key = f"wh_{secrets.token_urlsafe(40)}"
    key.key_hash = sec_manager.hash_password(raw_key)
    key.prefix = raw_key[:8]
    key.is_active = True
    key.revoked_at = None
    key.last_used_at = None
    key.last_used_ip = None
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Rotate API Key",
        details={"key_id": key.id, "name": key.name, "prefix": key.prefix},
        status="Success"
    )
    return jsonify({"success": True, "raw_key": raw_key})


@admin_bp.route('/api/admin/apikeys/<int:kid>/toggle', methods=['POST'])
def toggle_api_key(kid):
    key = ApiKey.query.get(kid)
    if not key:
        return jsonify({"success": False, "message": "API key not found"}), 404
    key.is_active = not bool(key.is_active)
    key.revoked_at = None if key.is_active else datetime.utcnow()
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Enable API Key" if key.is_active else "Revoke API Key",
        details={"key_id": key.id, "name": key.name, "prefix": key.prefix},
        status="Success"
    )
    return jsonify({"success": True, "is_active": key.is_active})


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


@admin_bp.route('/api/admin/production-readiness', methods=['GET'])
def get_production_readiness():
    return jsonify({"success": True, **build_production_readiness(db=db, User=User, Endpoint=Endpoint)})


@admin_bp.route('/api/admin/gpg/keys', methods=['GET'])
def get_gpg_keys():
    ok, message = validate_gpg()
    if not ok:
        return jsonify({"success": False, "message": message, "keys": []}), 500
    listed, list_message, keys = list_public_keys()
    return jsonify({"success": listed, "message": list_message, "keys": keys, **gpg_keyserver_payload()})


@admin_bp.route('/api/admin/gpg/keyservers', methods=['GET'])
def get_gpg_keyservers():
    return jsonify({"success": True, **gpg_keyserver_payload()})


@admin_bp.route('/api/admin/gpg/keyservers', methods=['POST'])
def add_gpg_keyserver_route():
    data = request.json or {}
    keyserver = str(data.get("keyserver") or "").strip()
    if not keyserver:
        return jsonify({"success": False, "message": "Keyserver value is required.", **gpg_keyserver_payload()}), 400
    save_gpg_keyserver(keyserver)
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Add GPG Keyserver",
        details={"keyserver": keyserver},
        status="Success"
    )
    return jsonify({"success": True, "message": "Keyserver added.", **gpg_keyserver_payload()})


@admin_bp.route('/api/admin/gpg/keyservers', methods=['PUT'])
def update_gpg_keyserver_route():
    data = request.json or {}
    old_keyserver = data.get("old_keyserver")
    new_keyserver = data.get("new_keyserver")
    ok, message, payload = update_gpg_keyserver(old_keyserver, new_keyserver)
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Update GPG Keyserver",
        details={"success": bool(ok), "old_keyserver": old_keyserver, "new_keyserver": new_keyserver, "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message, **payload}), 200 if ok else 400


@admin_bp.route('/api/admin/gpg/keyservers', methods=['DELETE'])
def delete_gpg_keyserver_route():
    data = request.json or {}
    ok, message, payload = delete_gpg_keyserver(data.get("keyserver"))
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Delete GPG Keyserver",
        details={"success": bool(ok), "keyserver": data.get("keyserver"), "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message, **payload}), 200 if ok else 400


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
    WinHubCore.audit(
        user_id=session.get('user_id'),
        module="Admin",
        action="Fetch GPG Key",
        details={"success": bool(ok), "search": data.get("search"), "keyserver": keyserver, "message": message[:300]},
        status="Success" if ok else "Error"
    )
    return jsonify({"success": ok, "message": message, **gpg_keyserver_payload()}), 200 if ok else 400


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
