import os
import json
import uuid
import hashlib
import base64
import logging
import threading
import smtplib
import ast
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.utils import parseaddr
from zoneinfo import ZoneInfo
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, current_app, Response, send_from_directory
from sqlalchemy import func, or_
from werkzeug.utils import secure_filename

from core.database import db, User, Endpoint, EndpointGroup, AgentTask, TaskTemplate, TelemetryHistory, ConnectionIpHistory, ScheduledTask, EndpointMetric, AgentUpdateRollout, TriggerRule, AggregatedJob, ApiKey, RegistrationHistory, AuditLog
from core.sdk import WinHubCore
from core.admin import send_notification_email
from core.security import sec_manager
from core.config import Config
from core.permissions import has_module_access, has_permission, user_permissions
from core.gpg import gpg_env

infrastructure_bp = Blueprint('infrastructure', __name__, template_folder='templates')
kyiv_tz = ZoneInfo("Europe/Kyiv")

SMTP_FILE = os.path.join(Config.DATA_DIR, "infra_smtp_profiles.json")
SCHEDULED_REPORTS_FILE = os.path.join(Config.DATA_DIR, "infra_scheduled_reports.json")
SECRETS_FILE = os.path.join(Config.DATA_DIR, "infra_template_secrets.json")
AGENT_PACKAGES_FILE = os.path.join(Config.DATA_DIR, "infra_agent_packages.json")
AGENT_PACKAGES_DIR = os.path.join(Config.DATA_DIR, "agent_packages")
SOFTWARE_PACKAGES_FILE = os.path.join(Config.DATA_DIR, "infra_software_packages.json")
SOFTWARE_PACKAGES_DIR = os.path.join(Config.DATA_DIR, "software_packages")

# Глобальні змінні для фонового потоку автовідправки
auto_thread_started = False
auto_thread_lock = threading.Lock()

def load_smtp_profiles():
    if not os.path.exists(SMTP_FILE): return {}
    try:
        with open(SMTP_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_smtp_profiles(data):
    with open(SMTP_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def load_scheduled_reports():
    if not os.path.exists(SCHEDULED_REPORTS_FILE):
        return []
    try:
        with open(SCHEDULED_REPORTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        logging.getLogger("winhub").exception("Failed to load scheduled reports")
        return []

def save_scheduled_reports(reports):
    os.makedirs(os.path.dirname(SCHEDULED_REPORTS_FILE), exist_ok=True)
    with open(SCHEDULED_REPORTS_FILE, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)

def load_agent_packages():
    if not os.path.exists(AGENT_PACKAGES_FILE):
        return []
    try:
        with open(AGENT_PACKAGES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        logging.getLogger("winhub").exception("Failed to load agent package registry")
        return []

def save_agent_packages(packages):
    os.makedirs(os.path.dirname(AGENT_PACKAGES_FILE), exist_ok=True)
    with open(AGENT_PACKAGES_FILE, "w", encoding="utf-8") as f:
        json.dump(packages, f, indent=2, ensure_ascii=False)

def find_agent_package(package_id):
    for package in load_agent_packages():
        if package.get("id") == package_id:
            return package
    return None

def agent_package_public_url(package_id):
    path = url_for("infrastructure.download_agent_package_public", package_id=package_id)
    if getattr(Config, "AGENT_PUBLIC_BASE_URL", ""):
        return f"{Config.AGENT_PUBLIC_BASE_URL}{path}"
    return url_for("infrastructure.download_agent_package_public", package_id=package_id, _external=True)

def latest_agent_package_version():
    packages = load_agent_packages()
    return packages[0].get("version", "") if packages else Config.LATEST_AGENT_VERSION

def load_software_packages():
    if not os.path.exists(SOFTWARE_PACKAGES_FILE):
        return []
    try:
        with open(SOFTWARE_PACKAGES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        logging.getLogger("winhub").exception("Failed to load software package registry")
        return []

def save_software_packages(packages):
    os.makedirs(os.path.dirname(SOFTWARE_PACKAGES_FILE), exist_ok=True)
    with open(SOFTWARE_PACKAGES_FILE, "w", encoding="utf-8") as f:
        json.dump(packages, f, indent=2, ensure_ascii=False)

def find_software_package(package_id):
    for package in load_software_packages():
        if package.get("id") == package_id:
            return package
    return None

def software_package_public_url(package_id):
    return url_for("infrastructure.download_software_package_public", package_id=package_id, _external=True)

def to_kyiv_time(dt):
    if not dt: return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(kyiv_tz).strftime('%Y-%m-%d %H:%M:%S')

def to_kyiv_time_short(dt):
    if not dt: return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(kyiv_tz).strftime('%H:%M %d.%m')

def can_access_report(report_id):
    if session.get('is_admin'):
        return True
    allowed_hosts = [h.id for h in WinHubCore.get_allowed_hosts(session.get('user_id'))]
    if not allowed_hosts:
        return False
    source_job_id = report_id
    split_match = re.match(r"^([0-9a-fA-F]{32})\.(\d{3})$", str(report_id or ""))
    if split_match:
        try:
            source_job_id = str(uuid.UUID(hex=split_match.group(1)))
        except ValueError:
            source_job_id = report_id
    return AgentTask.query.filter(
        ((AgentTask.job_id == source_job_id) | (AgentTask.id == report_id)),
        AgentTask.endpoint_id.in_(allowed_hosts)
    ).first() is not None

def load_template_payload(template):
    try:
        parsed = json.loads(template.payload) if template.payload else {}
        if isinstance(parsed, dict):
            return parsed
        return {"script": str(parsed)}
    except Exception:
        return {"script": str(template.payload or "")}


TEMPLATE_POLICY_KEY = "__template_policy"


def template_policy(template_or_payload):
    payload = template_or_payload if isinstance(template_or_payload, dict) else load_template_payload(template_or_payload)
    policy = payload.get(TEMPLATE_POLICY_KEY, {}) if isinstance(payload, dict) else {}
    return policy if isinstance(policy, dict) else {}


def template_variable_names(template):
    payload = load_template_payload(template)
    values = []
    if isinstance(payload, dict):
        values = [str(value) for key, value in payload.items() if isinstance(value, str) and not str(key).startswith("__")]
    else:
        values = [str(payload or "")]
    names = set()
    for value in values:
        names.update(VARIABLE_PATTERN.findall(value))
    return sorted(names)


def can_view_template_code(template):
    if session.get("is_admin"):
        return True
    return not bool(template_policy(template).get("hide_code"))


def can_edit_template(template):
    if session.get("is_admin"):
        return True
    return can("manage_templates") and not bool(template_policy(template).get("lock_edit"))


def can_delete_template(template):
    if session.get("is_admin"):
        return True
    return can("manage_templates") and not bool(template_policy(template).get("lock_delete"))


def load_template_secrets():
    if not os.path.exists(SECRETS_FILE):
        return {}
    try:
        with open(SECRETS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        logging.getLogger("winhub").exception("Failed to load Infrastructure template secrets")
        return {}


def save_template_secrets(data):
    os.makedirs(os.path.dirname(SECRETS_FILE), exist_ok=True)
    with open(SECRETS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def valid_secret_name(name):
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.-]{1,80}$", str(name or "")))


VARIABLE_PATTERN = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}")
SECRET_PATTERN = re.compile(r"{{\s*secret:([^}]+)}}", re.IGNORECASE)
SENSITIVE_NAME_PARTS = ("password", "passwd", "secret", "token", "key", "credential", "pass")
SENSITIVE_TEXT_PATTERNS = [
    re.compile(r'("?(?:temporary_)?password"?\s*[:=]\s*)("[^"]*"|[^\s,;}\]]+)', re.IGNORECASE),
    re.compile(r'("?(?:secret|token|api_key|apikey|credential)"?\s*[:=]\s*)("[^"]*"|[^\s,;}\]]+)', re.IGNORECASE),
    re.compile(r'(\bPass\s*:\s*)([^\s|]+)', re.IGNORECASE),
    re.compile(r'(\bPASSWORD\s*[-:]\s*)([^\r\n]+)', re.IGNORECASE),
]


def is_sensitive_name(name):
    lowered = str(name or "").lower()
    return any(part in lowered for part in SENSITIVE_NAME_PARTS)


def mask_sensitive_value(name, value):
    if is_sensitive_name(name):
        return "***"
    return value


def masked_variables(variables):
    return {
        key: mask_sensitive_value(key, value)
        for key, value in (variables or {}).items()
    }


def mask_sensitive_text(text):
    masked = str(text or "")
    for pattern in SENSITIVE_TEXT_PATTERNS:
        masked = pattern.sub(r"\1***", masked)
    return masked


def can_view_sensitive_reports():
    return can("view_sensitive_reports")


def report_body_for_current_user(report_body):
    if can_view_sensitive_reports():
        return report_body
    return mask_sensitive_text(report_body)


def apply_template_variables(payload, variables):
    payload_dict = dict(payload or {})
    string_fields = {
        key: str(value)
        for key, value in payload_dict.items()
        if isinstance(value, str) and not str(key).startswith("__")
    }
    if not string_fields:
        return payload_dict, []

    secrets_store = load_template_secrets()

    def replace_secret(match):
        secret_name = match.group(1).strip()
        encrypted_value = secrets_store.get(secret_name)
        if not encrypted_value:
            raise ValueError(f"Missing template secret: {secret_name}")
        try:
            return sec_manager.decrypt_data(encrypted_value)
        except Exception:
            raise ValueError(f"Cannot decrypt template secret: {secret_name}")

    rendered_fields = {
        key: SECRET_PATTERN.sub(replace_secret, value)
        for key, value in string_fields.items()
    }

    provided = variables or {}
    required_variables = set()
    for value in rendered_fields.values():
        required_variables.update(VARIABLE_PATTERN.findall(value))
    unresolved = sorted(required_variables - set(provided.keys()))
    for key, value in provided.items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(key)):
            raise ValueError(f"Invalid variable name: {key}")
        if isinstance(value, (dict, list)):
            raise ValueError(f"Variable '{key}' must be a scalar value")
        value = "" if value is None else str(value)
        if len(value) > 2048:
            raise ValueError(f"Variable '{key}' is too long")
        if any(ch in value for ch in ("\x00", "\r")):
            raise ValueError(f"Variable '{key}' contains unsupported control characters")
        for field_name, field_value in rendered_fields.items():
            rendered_fields[field_name] = re.sub(r"{{\s*" + re.escape(str(key)) + r"\s*}}", value, field_value)

    payload_dict.update(rendered_fields)
    return payload_dict, unresolved


def resolve_endpoint_identifier(identifier):
    raw_identifier = str(identifier or "").strip()
    if not raw_identifier:
        return None
    endpoint = Endpoint.query.get(raw_identifier)
    if endpoint:
        return endpoint.id
    endpoint = Endpoint.query.filter(Endpoint.hostname.ilike(raw_identifier)).first()
    return endpoint.id if endpoint else None


def resolve_target_ids(data):
    target_type = data.get("target_type")
    missing = []
    if target_type in ("host", "hosts"):
        requested = [data.get("target_id")] if data.get("target_id") else (data.get("target_ids", []) or [])
        resolved = []
        for item in requested:
            endpoint_id = resolve_endpoint_identifier(item)
            if endpoint_id:
                resolved.append(endpoint_id)
            else:
                missing.append(str(item))
        return list(dict.fromkeys(resolved)), missing
    if target_type == "group":
        group = EndpointGroup.query.get(data.get("target_id"))
        if not group:
            return [], [str(data.get("target_id"))]
        return [a.id for a in group.endpoints], []
    return [], []


def current_actor_label():
    if session.get("api_key_auth"):
        key = ApiKey.query.get(session.get("api_key_id"))
        if key:
            return f"API: {key.name} ({key.prefix})"
        return "API Key"
    return session.get("username") or "System"

def write_infra_audit(action, target_type="", target_id="", details=None, status="Success"):
    try:
        db.session.add(AuditLog(
            user=session.get("username") or "System",
            actor_type="api_key" if session.get("api_key_auth") else "user",
            actor_name=current_actor_label(),
            module="Infrastructure",
            action=action,
            target_type=target_type,
            target_id=str(target_id or ""),
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
            details=json.dumps(details or {}, ensure_ascii=False),
            status=status,
        ))
    except Exception:
        logging.getLogger("winhub").exception("Failed to write Infrastructure audit")


def dispatch_infrastructure_task(user_id, action_type, target_ids, payload, title, created_by=None):
    user = User.query.get(user_id)
    if not user:
        raise PermissionError("Invalid user")

    payload_json = json.dumps(payload, ensure_ascii=False)
    job_id = str(uuid.uuid4())
    task_ids = []

    for host_id in target_ids:
        host = Endpoint.query.get(host_id)
        if not host:
            raise ValueError(f"Unknown endpoint: {host_id}")
        if getattr(host, "approval_status", "Approved") != "Approved":
            raise PermissionError(f"Endpoint is not approved: {host.hostname or host.id}")
        if not WinHubCore.can_manage_host(user_id, host_id):
            continue
        task_id = str(uuid.uuid4())
        task = AgentTask(
            id=task_id,
            job_id=job_id,
            endpoint_id=host_id,
            title=title,
            module_source="Infrastructure",
            action_type=action_type,
            payload=payload_json,
            created_by=created_by or user.username
        )
        db.session.add(task)
        task_ids.append(task_id)

    if not task_ids:
        raise PermissionError("No authorized targets selected")

    db.session.commit()
    return job_id, task_ids

def current_user():
    return User.query.get(session.get('user_id'))

def can(permission_id):
    return has_permission(current_user(), "Infrastructure", permission_id)

def endpoint_health_score(endpoint, latest_version=None):
    now = datetime.utcnow()
    latest_version = latest_version if latest_version is not None else latest_agent_package_version()
    last_seen = endpoint.last_seen
    if last_seen and getattr(last_seen, "tzinfo", None):
        last_seen = last_seen.replace(tzinfo=None)
    online = bool(last_seen and last_seen >= now - timedelta(minutes=5))
    outdated = bool(latest_version and (getattr(endpoint, "agent_version", "") or "") != latest_version)

    score = 100
    reasons = []
    if not online:
        score -= 35
        reasons.append("offline")
    if outdated:
        score -= 20
        reasons.append("agent_outdated")
    if getattr(endpoint, "is_blocked", False):
        score -= 30
        reasons.append("blocked")
    if getattr(endpoint, "approval_status", "Approved") != "Approved":
        score -= 25
        reasons.append("not_approved")
    if getattr(endpoint, "identity_warning", None):
        score -= 15
        reasons.append("identity_warning")

    try:
        host_info = json.loads(endpoint.host_info or "{}")
        if host_info.get("pending_reboot") or host_info.get("pendingReboot"):
            score -= 10
            reasons.append("pending_reboot")
    except Exception:
        pass

    score = max(0, min(100, score))
    if score >= 80:
        status = "Healthy"
    elif score >= 50:
        status = "Warning"
    else:
        status = "Critical"
    return {
        "score": score,
        "status": status,
        "reasons": reasons,
        "online": online,
        "outdated": outdated,
    }

def encryption_status_from_host_info(host_info):
    security = {}
    if isinstance(host_info, dict):
        security = host_info.get("security") or {}
    bitlocker = security.get("bitlocker") or {}
    bitlocker_status = str(bitlocker.get("status") or "").lower()
    bitlocker_text = str(security.get("bitlocker_summary") or "")
    bitlocker_lower = bitlocker_text.lower()
    bitlocker_on = (
        bitlocker_status == "encrypted"
        or "protection on" in bitlocker_lower
        or "fully encrypted" in bitlocker_lower
        or "percentage encrypted: 100" in bitlocker_lower
    )
    bitlocker_partial = (
        bitlocker_status == "partial"
        or "encryption in progress" in bitlocker_lower
        or "percentage encrypted:" in bitlocker_lower and "percentage encrypted: 0" not in bitlocker_lower
    )
    veracrypt = bool(security.get("veracrypt_detected"))
    truecrypt = bool(security.get("truecrypt_detected"))
    if bitlocker_on or veracrypt or truecrypt:
        status = "Encrypted"
        level = "encrypted"
    elif bitlocker_partial:
        status = "Partial"
        level = "partial"
    elif bitlocker_status == "not_encrypted" or (bitlocker_text and bitlocker_text not in ("unavailable", "timeout")):
        status = "Not encrypted"
        level = "none"
    else:
        status = "Unknown"
        level = "unknown"
    methods = []
    if bitlocker_on or bitlocker_partial:
        methods.append("BitLocker")
    if veracrypt:
        methods.append("VeraCrypt")
    if truecrypt:
        methods.append("TrueCrypt")
    return {"status": status, "level": level, "methods": methods}

def annotate_endpoint_duplicates(agents):
    def normalized_hostname(agent):
        return str(getattr(agent, "hostname", "") or "").strip().upper()

    def stable_identity_fingerprint(agent):
        try:
            network_interfaces = json.loads(agent.network_info or "[]")
            if not isinstance(network_interfaces, list):
                network_interfaces = []
        except Exception:
            network_interfaces = []
        macs = []
        for item in network_interfaces:
            if isinstance(item, dict):
                mac = str(item.get("mac") or "").strip().upper()
                if mac:
                    macs.append(mac)
        source = json.dumps({
            "hostname": str(agent.hostname or "").strip().upper(),
            "os_type": getattr(agent, "os_type", None) or "Windows",
            "macs": sorted(set(macs)),
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def endpoint_signals(agent):
        fingerprints = {
            getattr(agent, "identity_fingerprint", None),
            stable_identity_fingerprint(agent),
        }
        fingerprints.discard(None)
        fingerprints.discard("")
        return {
            "fingerprints": fingerprints,
            "hostname": normalized_hostname(agent),
            "connection_ip": getattr(agent, "ip_address", None) or "",
        }

    approved = [
        agent for agent in agents
        if getattr(agent, "approval_status", "Approved") == "Approved"
    ]
    signals_by_id = {agent.id: endpoint_signals(agent) for agent in agents}
    approved_by_fingerprint = {}
    approved_by_hostname = {}
    approved_by_id = {agent.id: agent for agent in approved}
    for approved_agent in approved:
        signals = signals_by_id.get(approved_agent.id, {})
        for fingerprint in signals.get("fingerprints", set()):
            approved_by_fingerprint.setdefault(fingerprint, []).append(approved_agent)
        hostname = signals.get("hostname")
        if hostname:
            approved_by_hostname.setdefault(hostname, []).append(approved_agent)

    for agent in agents:
        agent_signals = signals_by_id.get(agent.id, {})
        agent_fingerprints = agent_signals.get("fingerprints", set())
        candidate_ids = set()
        candidates = []
        for fingerprint in agent_fingerprints:
            for candidate in approved_by_fingerprint.get(fingerprint, []):
                if candidate.id not in candidate_ids and candidate.id != agent.id:
                    candidates.append(candidate)
                    candidate_ids.add(candidate.id)
        hostname = agent_signals.get("hostname")
        if hostname:
            for candidate in approved_by_hostname.get(hostname, []):
                if candidate.id not in candidate_ids and candidate.id != agent.id:
                    candidates.append(candidate)
                    candidate_ids.add(candidate.id)

        matches = []
        for approved_agent in candidates:
            approved_signals = signals_by_id.get(approved_agent.id, {})
            approved_fingerprints = approved_signals.get("fingerprints", set())
            reasons = []
            if hostname and hostname == approved_signals.get("hostname"):
                reasons.append("hostname")
            if agent_signals.get("connection_ip") and agent_signals.get("connection_ip") == approved_signals.get("connection_ip"):
                reasons.append("connection_ip")
            if agent_fingerprints and approved_fingerprints and agent_fingerprints.intersection(approved_fingerprints):
                reasons.append("identity")
            if reasons:
                strong_match = "identity" in reasons or "hostname" in reasons
                matches.append({
                    "id": approved_agent.id,
                    "hostname": approved_agent.hostname or approved_agent.id,
                    "agent_version": getattr(approved_agent, "agent_version", "") or "unknown",
                    "reasons": reasons,
                    "strong_match": strong_match,
                })
        agent.duplicate_matches = matches
        agent.possible_duplicate = any(match.get("strong_match") for match in matches)

def can_use_template(template):
    if session.get("is_admin"):
        return True
    if not template:
        return False
    if bool(template_policy(template).get("disable_run")):
        return False
    if getattr(template, "created_by", None) == session.get("username") and can("manage_templates"):
        return True
    return True

def require_permission(permission_id):
    if not can(permission_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None

def require_superadmin():
    if not session.get("is_admin"):
        return jsonify({"success": False, "message": "Superadmin access required"}), 403
    return None

def require_any_permission(*permission_ids):
    if not any(can(permission_id) for permission_id in permission_ids):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None

# ==========================================
# BACKGROUND AUTO-EMAIL THREAD
# ==========================================
def get_task_payload(task):
    for attr in ['payload', 'payload_raw', 'parameters', 'args', 'data']:
        if hasattr(task, attr):
            val = getattr(task, attr)
            if val:
                if isinstance(val, str):
                    try: return json.loads(val)
                    except: pass
                elif isinstance(val, dict): return val
    return {}

def parse_recipients(recipient_list):
    if isinstance(recipient_list, list):
        raw_items = recipient_list
    else:
        raw_items = str(recipient_list or '').replace(';', ',').split(',')
    recipients = []
    for item in raw_items:
        email = parseaddr(str(item).strip())[1]
        if email and '@' in email and email not in recipients:
            recipients.append(email)
    return recipients

def hidden_subprocess_kwargs():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}

def encrypt_report_body(body, recipient, sender_email):
    gpg_path = getattr(Config, 'GPG_PATH', os.environ.get('GPG_PATH', 'gpg'))
    if not os.path.exists(gpg_path):
        return False, body, f"GPG executable not found: {gpg_path}"

    unique_id = str(uuid.uuid4())
    tmp_in = os.path.join(tempfile.gettempdir(), f"winhub_report_{unique_id}.txt")
    tmp_out = tmp_in + ".asc"
    try:
        with open(tmp_in, 'w', encoding='utf-8') as f:
            f.write(body)
        cmd = [
            gpg_path, "--batch", "--yes", "--trust-model", "always",
            "--encrypt", "--armor", "-r", recipient,
            "-o", tmp_out, tmp_in
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=gpg_env(), **hidden_subprocess_kwargs())
        if result.returncode != 0 or not os.path.exists(tmp_out):
            error_text = (result.stderr or result.stdout or "GPG encryption failed").strip()
            return False, body, error_text
        with open(tmp_out, 'r', encoding='utf-8') as f:
            return True, f.read(), None
    except Exception as e:
        return False, body, str(e)
    finally:
        for path in [tmp_in, tmp_out]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass

def send_report_email(title, report_body, sender_email, recipient_list, custom_message='', use_gpg=True):
    try:
        profiles = load_smtp_profiles()
        if sender_email not in profiles:
            return False, f"SMTP profile for {sender_email} not found.", 0

        recipients = parse_recipients(recipient_list)
        if not recipients:
            return False, "No valid recipient email addresses.", 0

        smtp_conf = profiles[sender_email]
        host = smtp_conf.get('host')
        port = int(smtp_conf.get('port') or 587)
        if not host:
            return False, "SMTP host is empty.", 0

        final_body = report_body or ''
        if custom_message:
            final_body = f"{custom_message}\n\n{'=' * 50}\n\n{final_body}"

        sent_count = 0
        server_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        with server_class(host, port, timeout=20) as server:
            if port != 465:
                server.starttls()
            dec_pass = sec_manager.decrypt_data(smtp_conf['password'])
            server.login(sender_email, dec_pass)

            for rec in recipients:
                body_to_send = final_body
                if use_gpg:
                    encrypted, encrypted_body, error_text = encrypt_report_body(final_body, rec, sender_email)
                    if not encrypted:
                        return False, f"GPG encryption failed for {rec}: {error_text}", sent_count
                    body_to_send = encrypted_body

                msg = MIMEText(body_to_send, 'plain', 'utf-8')
                msg['Subject'] = f"WinHUB Report: {title}" + (" [SECURE]" if use_gpg else "")
                msg['From'] = sender_email
                msg['To'] = rec
                server.send_message(msg)
                sent_count += 1

        return True, f"Report sent to {sent_count} recipient(s).", sent_count
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check the saved password for this sender profile.", 0
    except smtplib.SMTPRecipientsRefused as e:
        return False, f"SMTP rejected recipients: {e.recipients}", 0
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}", 0
    except Exception as e:
        logging.getLogger("winhub").exception("[Report Email] Failed to send email")
        return False, str(e), 0

def perform_auto_email_send(report_id, title, report_body, sender_email, recipient_list, use_gpg=True):
    success, message, sent_count = send_report_email(
        title=title,
        report_body=report_body,
        sender_email=sender_email,
        recipient_list=recipient_list,
        use_gpg=use_gpg
    )
    if not success:
        logging.getLogger("winhub").error(f"[Auto-Email] {message}")
    return success, message, sent_count

def scheduled_report_period(period):
    now = datetime.now(kyiv_tz)
    if period == "week":
        start = now - timedelta(days=7)
    else:
        start = now - timedelta(days=1)
    return (
        start.astimezone(timezone.utc).replace(tzinfo=None),
        now.astimezone(timezone.utc).replace(tzinfo=None),
    )

def scheduled_report_label(period):
    return "Last 7 days" if period == "week" else "Last 24 hours"

def compact_details(value, max_len=260):
    if value is None:
        return ""
    text = str(value).replace("\n", " ").strip()
    return text if len(text) <= max_len else text[:max_len - 3] + "..."

def build_scheduled_report_body(report_types, since, until):
    selected = set(report_types or [])
    if not selected:
        selected = {"summary", "tasks", "audit", "enrollments", "agent_updates"}
    since_kyiv = since.replace(tzinfo=timezone.utc).astimezone(kyiv_tz)
    until_kyiv = until.replace(tzinfo=timezone.utc).astimezone(kyiv_tz)

    lines = [
        "WinHUB Regular Report",
        f"Period: {since_kyiv.strftime('%Y-%m-%d %H:%M')} - {until_kyiv.strftime('%Y-%m-%d %H:%M')} Kyiv",
        f"Generated: {datetime.now(kyiv_tz).strftime('%Y-%m-%d %H:%M:%S')} Kyiv",
        "",
    ]

    if "summary" in selected:
        total = Endpoint.query.count()
        approved = Endpoint.query.filter_by(approval_status="Approved").count()
        pending = Endpoint.query.filter_by(approval_status="Pending").count()
        rejected = Endpoint.query.filter_by(approval_status="Rejected").count()
        signed = Endpoint.query.filter(Endpoint.public_key_pem.isnot(None), Endpoint.public_key_pem != "").count()
        latest = latest_agent_package_version()
        outdated = Endpoint.query.filter(Endpoint.approval_status == "Approved", Endpoint.agent_version != latest).count() if latest else 0
        online_since = datetime.utcnow() - timedelta(minutes=5)
        online = Endpoint.query.filter(Endpoint.last_seen >= online_since).count()
        lines += [
            "== Endpoint Summary ==",
            f"Total endpoints: {total}",
            f"Approved: {approved} | Pending: {pending} | Rejected: {rejected}",
            f"Online now: {online}",
            f"Signed identity keys: {signed}",
            f"Latest agent: {latest or 'unknown'} | Outdated approved agents: {outdated}",
            "",
        ]

    if "tasks" in selected:
        tasks = AgentTask.query.filter(AgentTask.created_at >= since, AgentTask.created_at <= until).order_by(AgentTask.created_at.desc()).limit(200).all()
        status_counts = {}
        for task in tasks:
            status_counts[task.status or "Unknown"] = status_counts.get(task.status or "Unknown", 0) + 1
        lines += [
            "== Execution Tasks ==",
            f"Tasks in period: {len(tasks)}",
            "Status counts: " + (", ".join(f"{k}: {v}" for k, v in sorted(status_counts.items())) or "none"),
        ]
        for task in tasks[:60]:
            endpoint_name = task.endpoint.hostname if task.endpoint else task.endpoint_id
            lines.append(f"- {task.created_at} | {task.status} | {endpoint_name} | {task.title} | by {task.created_by or 'System'}")
        if len(tasks) > 60:
            lines.append(f"... {len(tasks) - 60} more tasks omitted.")
        lines.append("")

    if "agent_updates" in selected:
        updates = AgentTask.query.filter(
            AgentTask.created_at >= since,
            AgentTask.created_at <= until,
            AgentTask.action_type == "agent_update",
        ).order_by(AgentTask.created_at.desc()).limit(120).all()
        lines += ["== Agent Updates ==", f"Update tasks in period: {len(updates)}"]
        for task in updates[:60]:
            endpoint_name = task.endpoint.hostname if task.endpoint else task.endpoint_id
            lines.append(f"- {task.created_at} | {task.status} | {endpoint_name} | {task.title}")
        if len(updates) > 60:
            lines.append(f"... {len(updates) - 60} more update tasks omitted.")
        lines.append("")

    if "enrollments" in selected:
        events = RegistrationHistory.query.filter(
            RegistrationHistory.timestamp >= since,
            RegistrationHistory.timestamp <= until,
        ).order_by(RegistrationHistory.timestamp.desc()).limit(120).all()
        lines += ["== Enrollment Events ==", f"Events in period: {len(events)}"]
        for event in events[:80]:
            lines.append(f"- {event.timestamp} | {event.hostname} | {event.event_type} | {event.ip_address or '-'}")
        if len(events) > 80:
            lines.append(f"... {len(events) - 80} more enrollment events omitted.")
        lines.append("")

    if "audit" in selected:
        audit_logs = AuditLog.query.filter(
            AuditLog.timestamp >= since,
            AuditLog.timestamp <= until,
        ).order_by(AuditLog.timestamp.desc()).limit(160).all()
        lines += ["== Audit Logs ==", f"Audit records in period: {len(audit_logs)}"]
        for item in audit_logs[:100]:
            actor = item.actor_name or item.user or "System"
            lines.append(f"- {item.timestamp} | {item.status or '-'} | {actor} | {item.module or '-'} | {item.action or '-'} | {item.target_type or '-'}:{item.target_id or '-'} | {compact_details(item.details)}")
        if len(audit_logs) > 100:
            lines.append(f"... {len(audit_logs) - 100} more audit records omitted.")
        lines.append("")

    return "\n".join(lines).strip() + "\n"

def normalize_scheduled_report(data, existing=None):
    existing = existing or {}
    report_types = data.get("report_types") or data.get("types") or existing.get("report_types") or []
    if not isinstance(report_types, list):
        report_types = []
    allowed_types = {"summary", "tasks", "audit", "enrollments", "agent_updates"}
    report_types = [item for item in report_types if item in allowed_types] or ["summary", "tasks", "audit"]

    frequency = data.get("frequency") or existing.get("frequency") or "daily"
    if frequency not in ("daily", "weekly"):
        frequency = "daily"
    period = data.get("period") or existing.get("period") or ("week" if frequency == "weekly" else "day")
    if period not in ("day", "week"):
        period = "day"
    try:
        hour = int(data.get("hour", existing.get("hour", 8)))
    except Exception:
        hour = 8
    hour = max(0, min(23, hour))
    try:
        weekday = int(data.get("weekday", existing.get("weekday", 0)))
    except Exception:
        weekday = 0
    weekday = max(0, min(6, weekday))

    return {
        "id": existing.get("id") or data.get("id") or str(uuid.uuid4()),
        "name": str(data.get("name") or existing.get("name") or "Infrastructure Regular Report").strip()[:120],
        "enabled": bool(data.get("enabled", existing.get("enabled", True))),
        "frequency": frequency,
        "period": period,
        "hour": hour,
        "weekday": weekday,
        "sender": str(data.get("sender") or existing.get("sender") or "").strip(),
        "recipients": ", ".join(parse_recipients(data.get("recipients", existing.get("recipients", "")))),
        "use_gpg": bool(data.get("use_gpg", existing.get("use_gpg", False))),
        "report_types": report_types,
        "last_run_key": existing.get("last_run_key"),
        "last_run_at": existing.get("last_run_at"),
        "last_status": existing.get("last_status"),
    }

def scheduled_report_due(report, now):
    if not report.get("enabled"):
        return False, None
    if int(report.get("hour", 8)) > now.hour:
        return False, None
    if report.get("frequency") == "weekly":
        if int(report.get("weekday", 0)) != now.weekday():
            return False, None
        run_key = f"{now.strftime('%G')}-W{now.strftime('%V')}"
    else:
        run_key = now.strftime("%Y-%m-%d")
    return report.get("last_run_key") != run_key, run_key

def send_scheduled_report(report):
    since, until = scheduled_report_period(report.get("period"))
    body = build_scheduled_report_body(report.get("report_types"), since, until)
    title = f"{report.get('name') or 'Infrastructure Report'} ({scheduled_report_label(report.get('period'))})"
    return send_report_email(
        title=title,
        report_body=body,
        sender_email=report.get("sender"),
        recipient_list=report.get("recipients"),
        use_gpg=bool(report.get("use_gpg")),
    )

def process_due_scheduled_reports():
    reports = load_scheduled_reports()
    if not reports:
        return
    changed = False
    now = datetime.now(kyiv_tz)
    for report in reports:
        due, run_key = scheduled_report_due(report, now)
        if not due:
            continue
        success, message, sent_count = send_scheduled_report(report)
        report["last_run_key"] = run_key
        report["last_run_at"] = now.isoformat()
        report["last_status"] = f"Sent to {sent_count}" if success else f"Error: {message}"
        changed = True
        if not success:
            logging.getLogger("winhub").error("[Scheduled Reports] %s", message)
    if changed:
        save_scheduled_reports(reports)

def auto_email_checker_thread(app):
    import time
    with app.app_context():
        while True:
            try:
                db.session.commit()
                jobs = AggregatedJob.query.filter_by(status='Waiting Review').all()
                for job in jobs:
                    source_job_id = job.id
                    split_match = re.match(r"^([0-9a-fA-F]{32})\.(\d{3})$", str(job.id or ""))
                    if split_match:
                        try:
                            source_job_id = str(uuid.UUID(hex=split_match.group(1)))
                        except ValueError:
                            source_job_id = job.id
                    task = AgentTask.query.filter((AgentTask.job_id == source_job_id) | (AgentTask.id == job.id)).first()
                    if task:
                        payload = get_task_payload(task)
                        if payload.get('__auto_email_toggle') or payload.get('auto_email_toggle'):
                            sender = payload.get('__auto_email_sender') or payload.get('auto_email_sender')
                            recipients = payload.get('__auto_email_recipients') or payload.get('auto_email_recipients')
                            use_gpg = payload.get('__auto_email_use_gpg', payload.get('auto_email_use_gpg', True))
                            
                            if sender and recipients:
                                job.status = 'Sending...'
                                db.session.commit()
                                
                                success, message, sent_count = perform_auto_email_send(job.id, job.title, job.report_data, sender, recipients, use_gpg)
                                
                                if success:
                                    time_str = datetime.now(kyiv_tz).strftime("%H:%M")
                                    job.status = f'Sent ({sent_count}) {time_str}'
                                else:
                                    job.status = 'Send Error'
                db.session.commit()
            except Exception as e:
                pass
            try:
                process_due_agent_update_rollouts()
            except Exception:
                db.session.rollback()
                logging.getLogger("winhub").exception("Agent update rollout checker failed")
            try:
                process_due_scheduled_reports()
            except Exception:
                db.session.rollback()
                logging.getLogger("winhub").exception("Scheduled report checker failed")
            time.sleep(5)

@infrastructure_bp.before_request
def check_access_and_start_thread():
    global auto_thread_started
    if request.path.startswith("/api/public/agent-packages/") or request.path.startswith("/api/public/software-packages/"):
        return None
    if not auto_thread_started:
        with auto_thread_lock:
            if not auto_thread_started:
                app = current_app._get_current_object()
                t = threading.Thread(target=auto_email_checker_thread, args=(app,), daemon=True)
                t.start()
                auto_thread_started = True

    user_id = session.get('user_id')
    if not user_id: return redirect(url_for('auth.login_page'))
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for('auth.login_page'))
    
    if not has_module_access(user, 'Infrastructure'):
        return "Access Denied", 403

# ==========================================
# UI ROUTES
# ==========================================
@infrastructure_bp.route('/module/infrastructure')
def index():
    user_id = session.get('user_id')
    now = datetime.utcnow()
    online_threshold = now - timedelta(minutes=5)
    
    agents = WinHubCore.get_allowed_hosts(user_id)
    groups = WinHubCore.get_allowed_groups(user_id)
    
    stats = {
        'total': len(agents),
        'online': sum(1 for a in agents if a.last_seen and a.last_seen >= online_threshold),
        'offline': len(agents) - sum(1 for a in agents if a.last_seen and a.last_seen >= online_threshold),
        'blocked': sum(1 for a in agents if a.is_blocked),
        'pending': sum(1 for a in agents if getattr(a, "approval_status", "Approved") == "Pending"),
        'rejected': sum(1 for a in agents if getattr(a, "approval_status", "Approved") == "Rejected"),
        'current': sum(1 for a in agents if Config.LATEST_AGENT_VERSION and (a.agent_version or "") == Config.LATEST_AGENT_VERSION),
        'signed': sum(1 for a in agents if bool(getattr(a, "public_key_pem", None))),
    }
    
    for a in agents: 
        a.is_online = (a.last_seen and a.last_seen >= online_threshold)
        a.last_seen_str = to_kyiv_time(a.last_seen)
        a.last_enrollment_str = to_kyiv_time(getattr(a, "last_enrollment_at", None))
        a.agent_outdated = bool(Config.LATEST_AGENT_VERSION and (a.agent_version or "") != Config.LATEST_AGENT_VERSION)
        try:
            a.encryption = encryption_status_from_host_info(json.loads(a.host_info or "{}"))
        except Exception:
            a.encryption = {"status": "Unknown", "level": "unknown", "methods": []}
    annotate_endpoint_duplicates(agents)

    available_hosts = [{
        "id": a.id,
        "name": a.hostname or a.id,
        "ip": a.ip_address or "",
        "os_type": getattr(a, 'os_type', 'Windows'),
        "is_blocked": bool(a.is_blocked),
        "approval_status": getattr(a, 'approval_status', 'Approved'),
        "agent_version": getattr(a, 'agent_version', '') or '',
        "agent_outdated": bool(Config.LATEST_AGENT_VERSION and (getattr(a, 'agent_version', '') or '') != Config.LATEST_AGENT_VERSION),
        "agent_identity_key_enrolled": bool(getattr(a, "public_key_pem", None)),
        "is_online": bool(a.last_seen and a.last_seen >= online_threshold),
        "last_seen": to_kyiv_time_short(a.last_seen),
        "encryption": getattr(a, "encryption", {"status": "Unknown", "level": "unknown", "methods": []}),
    } for a in agents]
    pending_agents = [
        a for a in agents
        if getattr(a, "approval_status", "Approved") == "Pending"
    ]
    rejected_agents = [
        a for a in agents
        if getattr(a, "approval_status", "Approved") == "Rejected"
    ]
    agent_by_id = {a.id: a for a in agents}
    approved_duplicate_pairs = []
    seen_duplicate_pairs = set()
    for agent in agents:
        if getattr(agent, "approval_status", "Approved") != "Approved":
            continue
        for duplicate in getattr(agent, "duplicate_matches", []):
            if not duplicate.get("strong_match"):
                continue
            duplicate_id = duplicate.get("id")
            duplicate_agent = agent_by_id.get(duplicate_id)
            if not duplicate_agent or getattr(duplicate_agent, "approval_status", "Approved") != "Approved":
                continue
            pair_key = tuple(sorted([agent.id, duplicate_id]))
            if pair_key in seen_duplicate_pairs:
                continue
            seen_duplicate_pairs.add(pair_key)
            approved_duplicate_pairs.append({
                "left": agent,
                "right": duplicate_agent,
                "reasons": duplicate.get("reasons", []),
            })
    stats["review"] = len(pending_agents) + len(rejected_agents) + len(approved_duplicate_pairs)
        
    is_admin = session.get('is_admin')
    permissions = user_permissions(User.query.get(user_id), "Infrastructure")
    if is_admin:
        templates_raw = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
        scheduled_raw = ScheduledTask.query.order_by(ScheduledTask.category, ScheduledTask.name).all()
        triggers_raw = TriggerRule.query.order_by(TriggerRule.name).all()
    else:
        templates_raw = TaskTemplate.query.filter(
            (TaskTemplate.is_approved == True) | (TaskTemplate.created_by == session.get("username"))
        ).order_by(TaskTemplate.category, TaskTemplate.name).all()
        templates_raw = [t for t in templates_raw if can_use_template(t)]
        scheduled_raw = []
        triggers_raw = []

    templates_raw = [
        t for t in templates_raw
        if not (t.name == "Agent Self Update" and t.action_type == "agent_update" and t.created_by == "System")
    ]
            
    templates = [{
        "id": t.id, "name": t.name, "category": getattr(t, 'category', 'General'), 
        "action_type": t.action_type,
        "type": getattr(t, 'type', 'action'),
        "is_approved": t.is_approved,
        "payload": t.payload if (t.payload and can_view_template_code(t)) else "{}",
        "policy": template_policy(t),
        "can_view_code": can_view_template_code(t),
        "can_edit": can_edit_template(t),
        "can_delete": can_delete_template(t),
        "can_run": can_use_template(t),
        "variables": template_variable_names(t),
    } for t in templates_raw]
    template_categories = sorted({
        (template.get("category") or "General").strip() or "General"
        for template in templates
    })

    scheduled_tasks = [{
        "id": st.id, "name": st.name, "category": st.category, "cron": st.cron_expr, "is_active": st.is_active,
        "target_type": st.target_type,
        "target_name": Endpoint.query.get(st.target_id).hostname if st.target_type == 'host' and Endpoint.query.get(st.target_id) else (EndpointGroup.query.get(st.target_id).name if EndpointGroup.query.get(st.target_id) else "Unknown Target"),
        "template_name": st.template.name if st.template else "Deleted Template",
        "last_run": to_kyiv_time_short(st.last_run)
    } for st in scheduled_raw]

    trigger_rules = []
    for tr in triggers_raw:
        action_tpl = TaskTemplate.query.get(tr.action_template_id)
        trigger_rules.append({
            "id": tr.id, "name": tr.name, "metric_name": tr.metric_name,
            "operator": tr.operator, "threshold_value": tr.threshold_value,
            "action_template_id": tr.action_template_id,
            "action_name": action_tpl.name if action_tpl else "Deleted Template",
            "is_active": tr.is_active
        })

    return render_template('infrastructure_index.html', agents=agents, groups=groups, templates=templates,
                           template_categories=template_categories,
                           available_hosts=available_hosts,
                           pending_agents=pending_agents,
                           rejected_agents=rejected_agents,
                           approved_duplicate_pairs=approved_duplicate_pairs,
                           scheduled_tasks=scheduled_tasks, trigger_rules=trigger_rules, stats=stats,
                           username=session.get('username'), is_admin=is_admin, permissions=permissions)


@infrastructure_bp.route('/api/infrastructure/hosts', methods=['GET'])
def list_hosts():
    denied = require_permission("view_hosts")
    if denied:
        return denied

    now = datetime.utcnow()
    online_threshold = now - timedelta(minutes=5)
    hosts = WinHubCore.get_allowed_hosts(session.get("user_id"))
    return jsonify({
        "success": True,
        "hosts": [{
            "id": host.id,
            "hostname": host.hostname,
            "ip": host.ip_address,
            "os": host.os_version,
            "os_type": getattr(host, "os_type", "Windows"),
            "last_seen": to_kyiv_time(host.last_seen),
            "is_online": bool(host.last_seen and host.last_seen >= online_threshold),
            "is_blocked": bool(host.is_blocked),
	            "approval_status": getattr(host, "approval_status", "Approved"),
            "agent_version": getattr(host, "agent_version", None),
            "agent_outdated": bool(Config.LATEST_AGENT_VERSION and (getattr(host, "agent_version", "") or "") != Config.LATEST_AGENT_VERSION),
            "agent_identity_key_enrolled": bool(getattr(host, "public_key_pem", None)),
            "groups": [{"id": group.id, "name": group.name} for group in host.groups],
	        } for host in hosts]
	    })


@infrastructure_bp.route('/api/infrastructure/releases/current', methods=['GET'])
def current_release_info():
    denied = require_permission("view_hosts")
    if denied:
        return denied
    version_file = os.path.join(Config.BASE_DIR, "VERSION")
    try:
        server_version = open(version_file, "r", encoding="utf-8").read().strip()
    except OSError:
        server_version = "unknown"
    return jsonify({
        "success": True,
        "server_version": server_version,
        "latest_agent_version": Config.LATEST_AGENT_VERSION,
    })


@infrastructure_bp.route('/api/infrastructure/groups', methods=['GET'])
def list_groups():
    denied = require_permission("view_groups")
    if denied:
        return denied

    groups = WinHubCore.get_allowed_groups(session.get("user_id"))
    return jsonify({
        "success": True,
        "groups": [{
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "hosts_count": len(group.endpoints),
        } for group in groups]
    })

# ==========================================
# API: SMTP CONFIG
# ==========================================
@infrastructure_bp.route('/api/infrastructure/smtp', methods=['GET', 'POST', 'DELETE'])
def manage_smtp():
    profiles = load_smtp_profiles()

    if request.method == 'GET':
        if not (can("send_reports") or can("manage_smtp")):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        safe_profiles = [{"email": k, "host": v.get("host"), "port": v.get("port")} for k, v in profiles.items()]
        return jsonify({"success": True, "profiles": safe_profiles})
        
    denied = require_permission("manage_smtp")
    if denied: return denied
        
    if request.method == 'POST':
        data = request.json
        email = data.get("email", "").strip()
        host = data.get("host", "").strip()
        port = data.get("port", 587)
        password = data.get("password", "")
        
        if not email or not host or not password:
            return jsonify({"success": False, "message": "Email, Host, and Password are required."}), 400
            
        profiles[email] = {
            "host": host, "port": int(port),
            "password": sec_manager.encrypt_data(password)
        }
        save_smtp_profiles(profiles)
        return jsonify({"success": True})
        
    if request.method == 'DELETE':
        email = request.json.get("email")
        if email in profiles:
            del profiles[email]
            save_smtp_profiles(profiles)
        return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/scheduled-reports', methods=['GET', 'POST'])
def manage_scheduled_reports():
    if request.method == 'GET':
        if not (can("send_reports") or can("manage_smtp")):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        return jsonify({"success": True, "reports": load_scheduled_reports()})

    denied = require_permission("manage_smtp")
    if denied:
        return denied

    data = request.json or {}
    reports = load_scheduled_reports()
    report_id = data.get("id")
    existing = None
    if report_id:
        existing = next((item for item in reports if item.get("id") == report_id), None)
    report = normalize_scheduled_report(data, existing)
    if not report.get("sender"):
        return jsonify({"success": False, "message": "Sender SMTP profile is required."}), 400
    if report.get("sender") not in load_smtp_profiles():
        return jsonify({"success": False, "message": "Selected SMTP profile was not found."}), 400
    if not parse_recipients(report.get("recipients")):
        return jsonify({"success": False, "message": "At least one valid recipient email is required."}), 400

    if existing:
        reports = [report if item.get("id") == report["id"] else item for item in reports]
    else:
        reports.append(report)
    save_scheduled_reports(reports)
    write_infra_audit("scheduled_report_saved", "scheduled_report", report["id"], {"name": report["name"], "frequency": report["frequency"]})
    db.session.commit()
    return jsonify({"success": True, "report": report})


@infrastructure_bp.route('/api/infrastructure/scheduled-reports/<report_id>', methods=['DELETE'])
def delete_scheduled_report(report_id):
    denied = require_permission("manage_smtp")
    if denied:
        return denied
    reports = load_scheduled_reports()
    next_reports = [item for item in reports if item.get("id") != report_id]
    save_scheduled_reports(next_reports)
    write_infra_audit("scheduled_report_deleted", "scheduled_report", report_id)
    db.session.commit()
    return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/scheduled-reports/<report_id>/send-now', methods=['POST'])
def send_scheduled_report_now(report_id):
    denied = require_permission("manage_smtp")
    if denied:
        return denied
    reports = load_scheduled_reports()
    report = next((item for item in reports if item.get("id") == report_id), None)
    if not report:
        return jsonify({"success": False, "message": "Scheduled report was not found."}), 404
    data = request.json or {}
    if data:
        report = normalize_scheduled_report({**report, **data}, report)
    success, message, sent_count = send_scheduled_report(report)
    report["last_run_at"] = datetime.now(kyiv_tz).isoformat()
    report["last_status"] = f"Manual sent to {sent_count}" if success else f"Manual error: {message}"
    reports = [report if item.get("id") == report_id else item for item in reports]
    save_scheduled_reports(reports)
    write_infra_audit("scheduled_report_send_now", "scheduled_report", report_id, {"success": success, "message": message})
    db.session.commit()
    return jsonify({"success": success, "message": message, "sent_count": sent_count})


@infrastructure_bp.route('/api/infrastructure/secrets', methods=['GET', 'POST'])
def manage_template_secrets():
    denied = require_permission("manage_templates")
    if denied:
        return denied

    secrets_store = load_template_secrets()
    if request.method == 'GET':
        return jsonify({
            "success": True,
            "secrets": [{
                "name": name,
                "placeholder": f"{{{{secret:{name}}}}}"
            } for name in sorted(secrets_store.keys())]
        })

    data = request.json or {}
    name = str(data.get("name", "")).strip()
    value = str(data.get("value", ""))
    if not valid_secret_name(name):
        return jsonify({"success": False, "message": "Secret name must start with a letter/underscore and contain only letters, numbers, dot, dash, underscore."}), 400
    if not value:
        return jsonify({"success": False, "message": "Secret value is required."}), 400
    if len(value) > 8192:
        return jsonify({"success": False, "message": "Secret value is too long."}), 400

    secrets_store[name] = sec_manager.encrypt_data(value)
    save_template_secrets(secrets_store)
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Save Template Secret",
        details={"secret": name},
        status="Success"
    )
    return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/secrets/<name>', methods=['DELETE'])
def delete_template_secret(name):
    denied = require_permission("manage_templates")
    if denied:
        return denied

    secrets_store = load_template_secrets()
    if name in secrets_store:
        del secrets_store[name]
        save_template_secrets(secrets_store)
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Delete Template Secret",
            details={"secret": name},
            status="Success"
        )
    return jsonify({"success": True})

# ==========================================
# API: REPORTS
# ==========================================
@infrastructure_bp.route('/api/infrastructure/reports/all', methods=['GET'])
def get_reports():
    denied = require_permission("view_reports")
    if denied: return denied
    reports = AggregatedJob.query.order_by(AggregatedJob.created_at.desc()).limit(100).all()
    if not session.get('is_admin'):
        reports = [r for r in reports if can_access_report(r.id)]
    data = [{
        "id": r.id, "title": r.title, "status": r.status,
        "total": r.total_count, "success": r.success_count, "error": r.error_count,
        "created_at": to_kyiv_time(r.created_at), "report_data": report_body_for_current_user(r.report_data)
    } for r in reports]
    return jsonify({"success": True, "data": data})

@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/action', methods=['POST'])
def action_report(report_id):
    r = AggregatedJob.query.get(report_id)
    if not r: return jsonify({"success": False}), 404
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403
    
    action = request.json.get('action')
    
    if action == 'save':
        denied = require_permission("edit_reports")
        if denied: return denied
        if not can_view_sensitive_reports():
            return jsonify({
                "success": False,
                "message": "This report contains masked sensitive data. Users without sensitive report access cannot save report text."
            }), 403
        r.report_data = request.json.get('report_data', '')
        db.session.commit()
        return jsonify({"success": True})
        
    elif action == 'dismiss':
        denied = require_permission("dismiss_reports")
        if denied: return denied
        r.status = 'Dismissed'
        db.session.commit()
        return jsonify({"success": True})
        
    elif action == 'send':
        denied = require_permission("send_reports")
        if denied: return denied
        sender = request.json.get('sender')
        emails = request.json.get('email')
        subject = request.json.get('subject') or f"Report: {r.title}"
        custom_message = request.json.get('custom_message', '').strip()
        use_gpg = request.json.get('use_gpg', False)
        
        r.status = 'Sending...'
        db.session.commit()
        success, message, sent_count = send_report_email(
            title=subject,
            report_body=r.report_data,
            sender_email=sender,
            recipient_list=emails,
            custom_message=custom_message,
            use_gpg=use_gpg
        )
        if success:
            time_str = datetime.now(kyiv_tz).strftime("%H:%M")
            r.status = f'Sent ({sent_count}) {time_str}'
            db.session.commit()
            return jsonify({"success": True, "message": message, "sent": sent_count})

        r.status = 'Send Error'
        db.session.commit()
        return jsonify({"success": False, "message": message}), 400
        
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    denied = require_permission("delete_reports")
    if denied: return denied
    r = AggregatedJob.query.get(report_id)
    if r:
        db.session.delete(r)
        db.session.commit()
    return jsonify({"success": True})

# ==========================================
# API: TRIGGERS & SCHEDULER
# ==========================================
@infrastructure_bp.route('/api/infrastructure/triggers', methods=['POST'])
def manage_trigger():
    denied = require_permission("manage_triggers")
    if denied: return denied
    data = request.json
    tid = data.get('id')
    if tid:
        tr = TriggerRule.query.get(tid)
        if tr:
            tr.name = data.get('name'); tr.metric_name = data.get('metric_name'); tr.operator = data.get('operator')
            tr.threshold_value = data.get('threshold_value'); tr.action_template_id = data.get('action_template_id'); tr.is_active = data.get('is_active', True)
    else:
        db.session.add(TriggerRule(name=data.get('name'), metric_name=data.get('metric_name'), operator=data.get('operator'), threshold_value=data.get('threshold_value'), action_template_id=data.get('action_template_id'), is_active=data.get('is_active', True)))
    db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/triggers/<tid>', methods=['DELETE'])
def delete_trigger(tid):
    denied = require_permission("manage_triggers")
    if denied: return denied
    tr = TriggerRule.query.get(tid)
    if tr: db.session.delete(tr); db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/schedule', methods=['POST'])
def manage_schedule():
    denied = require_permission("manage_scheduler")
    if denied: return denied
    data = request.json
    tid = data.get('id')
    if tid:
        st = ScheduledTask.query.get(tid)
        if st:
            st.name = data.get('name'); st.category = data.get('category', 'Scheduled'); st.template_id = data.get('template_id')
            st.target_type = data.get('target_type'); st.target_id = data.get('target_id'); st.cron_expr = data.get('cron'); st.is_active = data.get('is_active', True)
    else:
        db.session.add(ScheduledTask(name=data.get('name'), category=data.get('category', 'Scheduled'), template_id=data.get('template_id'), target_type=data.get('target_type'), target_id=data.get('target_id'), cron_expr=data.get('cron'), is_active=data.get('is_active', True), created_by=session.get('username')))
    db.session.commit()
    from core import reload_scheduler_jobs
    reload_scheduler_jobs(current_app)
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/schedule/<tid>', methods=['DELETE'])
def delete_schedule(tid):
    denied = require_permission("manage_scheduler")
    if denied: return denied
    st = ScheduledTask.query.get(tid)
    if st:
        db.session.delete(st); db.session.commit()
        from core import reload_scheduler_jobs
        reload_scheduler_jobs(current_app)
    return jsonify({"success": True})

# ==========================================
# API: TEMPLATES & TASKS
# ==========================================
@infrastructure_bp.route('/api/infrastructure/templates', methods=['GET'])
def list_templates():
    denied = require_permission("run_tasks")
    if denied:
        return denied

    templates = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
    if not session.get("is_admin"):
        templates = [
            t for t in templates
            if (t.is_approved or (getattr(t, "created_by", None) == session.get("username") and can("manage_templates")))
            and getattr(t, "type", "action") != "report"
            and can_use_template(t)
        ]

    return jsonify({
        "success": True,
        "templates": [{
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "action_type": t.action_type,
            "type": getattr(t, "type", "action"),
            "is_approved": bool(t.is_approved),
            "created_by": t.created_by,
            "created_at": to_kyiv_time(t.created_at),
            "policy": template_policy(t),
            "can_view_code": can_view_template_code(t),
            "can_edit": can_edit_template(t),
            "can_delete": can_delete_template(t),
            "can_run": can_use_template(t),
        } for t in templates]
    })


@infrastructure_bp.route('/api/infrastructure/templates/export', methods=['GET'])
def export_templates():
    denied = require_permission("manage_templates")
    if denied: return denied

    templates = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
    payload = {
        "format": "winhub-template-library",
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "templates": [{
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "action_type": t.action_type,
            "type": getattr(t, "type", "action"),
            "payload": load_template_payload(t) if can_view_template_code(t) else {},
            "is_approved": bool(t.is_approved),
            "created_by": t.created_by,
            "created_at": t.created_at.isoformat() + "Z" if t.created_at else None,
        } for t in templates]
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    filename = f"winhub_templates_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@infrastructure_bp.route('/api/infrastructure/templates/<tid>/export', methods=['GET'])
def export_single_template(tid):
    denied = require_superadmin()
    if denied: return denied

    t = TaskTemplate.query.get(tid)
    if not t:
        return jsonify({"success": False, "message": "Template not found"}), 404

    payload = {
        "format": "winhub-template-library",
        "version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "templates": [{
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "action_type": t.action_type,
            "type": getattr(t, "type", "action"),
            "payload": load_template_payload(t),
            "is_approved": bool(t.is_approved),
            "created_by": t.created_by,
            "created_at": t.created_at.isoformat() + "Z" if t.created_at else None,
        }]
    }
    safe_name = secure_filename(t.name or "template") or "template"
    filename = f"winhub_template_{safe_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@infrastructure_bp.route('/api/infrastructure/templates/import', methods=['POST'])
def import_templates():
    denied = require_permission("manage_templates")
    if denied: return denied

    try:
        if request.files.get("file"):
            raw = request.files["file"].read().decode("utf-8-sig")
            data = json.loads(raw)
        else:
            data = request.get_json(force=True)

        templates = data.get("templates") if isinstance(data, dict) else data
        if not isinstance(templates, list):
            return jsonify({"success": False, "message": "Import file must contain a templates list"}), 400

        imported = 0
        updated = 0
        for item in templates:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            category = str(item.get("category") or "Imported").strip() or "Imported"
            t_type = str(item.get("type") or "action").strip() or "action"
            action_type = str(item.get("action_type") or item.get("action") or "run_script").strip() or "run_script"
            incoming_payload = item.get("payload") or {}
            if isinstance(incoming_payload, str):
                try:
                    incoming_payload = json.loads(incoming_payload)
                except Exception:
                    incoming_payload = {"script": incoming_payload}
            payload_raw = json.dumps(incoming_payload, ensure_ascii=False)
            is_approved = bool(item.get("is_approved", False))

            template_id = str(item.get("id") or "").strip()
            template = TaskTemplate.query.get(template_id) if template_id else None
            if not template:
                template = TaskTemplate.query.filter_by(name=name, category=category, type=t_type).first()

            if template:
                template.name = name
                template.category = category
                template.action_type = action_type
                template.type = t_type
                template.payload = payload_raw
                template.is_approved = is_approved
                updated += 1
            else:
                db.session.add(TaskTemplate(
                    id=template_id or str(uuid.uuid4()),
                    name=name,
                    category=category,
                    action_type=action_type,
                    type=t_type,
                    payload=payload_raw,
                    is_approved=is_approved,
                    created_by=session.get('username')
                ))
                imported += 1

        db.session.commit()
        write_infra_audit("Template Import", "template", "bulk", {"imported": imported, "updated": updated})
        db.session.commit()
        return jsonify({"success": True, "imported": imported, "updated": updated})
    except Exception as e:
        db.session.rollback()
        logging.getLogger("winhub").exception("Template import failed")
        return jsonify({"success": False, "message": f"Template import failed: {e}"}), 400


@infrastructure_bp.route('/api/public/agent-packages/<package_id>/download', methods=['GET'])
def download_agent_package_public(package_id):
    package = find_agent_package(package_id)
    if not package:
        return jsonify({"success": False, "message": "Package not found"}), 404
    filename = package.get("filename")
    if not filename:
        return jsonify({"success": False, "message": "Package file missing"}), 404
    return send_from_directory(AGENT_PACKAGES_DIR, filename, as_attachment=True)


@infrastructure_bp.route('/api/infrastructure/agent-packages', methods=['GET', 'POST'])
def agent_packages():
    if request.method == "GET":
        denied = require_permission("view_hosts")
        if denied: return denied
        packages = load_agent_packages()
        for package in packages:
            package["download_url"] = agent_package_public_url(package["id"])
        return jsonify({"success": True, "packages": packages})

    denied = require_superadmin()
    if denied: return denied
    try:
        upload = request.files.get("file")
        version = str(request.form.get("version") or "").strip()
        if not upload or not upload.filename:
            return jsonify({"success": False, "message": "Package file is required"}), 400
        if not version:
            return jsonify({"success": False, "message": "Version is required"}), 400

        os.makedirs(AGENT_PACKAGES_DIR, exist_ok=True)
        package_id = str(uuid.uuid4())
        base_name = secure_filename(upload.filename) or f"WinHUBAgent-{version}.zip"
        filename = f"{package_id}_{base_name}"
        path = os.path.join(AGENT_PACKAGES_DIR, filename)

        sha256 = hashlib.sha256()
        size = 0
        with open(path, "wb") as f:
            while True:
                chunk = upload.stream.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                size += len(chunk)
                f.write(chunk)

        packages = load_agent_packages()
        record = {
            "id": package_id,
            "version": version,
            "original_filename": base_name,
            "filename": filename,
            "sha256": sha256.hexdigest(),
            "size": size,
            "notes": str(request.form.get("notes") or "").strip(),
            "uploaded_by": session.get("username"),
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
        }
        packages.insert(0, record)
        save_agent_packages(packages[:50])
        record["download_url"] = agent_package_public_url(package_id)
        write_infra_audit("Agent Package Upload", "agent_package", package_id, {"version": version, "sha256": record["sha256"], "size": size})
        db.session.commit()
        return jsonify({"success": True, "package": record})
    except Exception as e:
        db.session.rollback()
        logging.getLogger("winhub").exception("Agent package upload failed")
        return jsonify({"success": False, "message": f"Package upload failed: {e}"}), 500


@infrastructure_bp.route('/api/infrastructure/agent-packages/<package_id>', methods=['DELETE'])
def delete_agent_package(package_id):
    denied = require_superadmin()
    if denied: return denied

    packages = load_agent_packages()
    package = next((item for item in packages if item.get("id") == package_id), None)
    if not package:
        return jsonify({"success": False, "message": "Package not found"}), 404

    filename = os.path.basename(str(package.get("filename") or ""))
    if filename:
        path = os.path.abspath(os.path.join(AGENT_PACKAGES_DIR, filename))
        packages_dir = os.path.abspath(AGENT_PACKAGES_DIR)
        if path.startswith(packages_dir + os.sep) and os.path.exists(path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    packages = [item for item in packages if item.get("id") != package_id]
    save_agent_packages(packages)
    write_infra_audit("Agent Package Delete", "agent_package", package_id, {
        "version": package.get("version"),
        "filename": package.get("original_filename") or package.get("filename"),
        "sha256": package.get("sha256"),
    })
    db.session.commit()
    return jsonify({"success": True})


def agent_updater_bootstrap_script():
    updater_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "WinHUBAgent",
        "update-service.ps1"
    ))
    with open(updater_path, "rb") as f:
        updater_b64 = base64.b64encode(f.read()).decode("ascii")
    return f"""$ErrorActionPreference = 'Stop'
$InstallDir = "C:\\Program Files\\WinHUBAgent"
$UpdaterPath = Join-Path $InstallDir "update-service.ps1"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$bytes = [Convert]::FromBase64String("{updater_b64}")
$content = [System.Text.Encoding]::UTF8.GetString($bytes)
[System.IO.File]::WriteAllText($UpdaterPath, $content, (New-Object System.Text.UTF8Encoding($false)))
Unblock-File -LiteralPath $UpdaterPath -ErrorAction SilentlyContinue
Write-Output "[WinHUB] update-service.ps1 prepared at $UpdaterPath"
"""


def is_agent_updater_prepare_task(task):
    return task.action_type == "run_script" and (task.title or "").startswith("Prepare Agent Updater")


def existing_endpoint_id_set(host_ids):
    cleaned = [str(item) for item in (host_ids or []) if str(item or "").strip()]
    if not cleaned:
        return set()
    return {row[0] for row in db.session.query(Endpoint.id).filter(Endpoint.id.in_(cleaned)).all()}


def create_agent_update_wave(host_ids, package, created_by, wave_index, wave_total):
    job_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    updater_script = agent_updater_bootstrap_script()
    payload = {
        "package_url": package.get("download_url") or agent_package_public_url(package["id"]),
        "package_sha256": package.get("sha256"),
        "target_version": package.get("version"),
    }
    title = f"Agent Update {package.get('version')} - Wave {wave_index}/{wave_total}"
    for host_id in host_ids:
        db.session.add(AgentTask(
            id=str(uuid.uuid4()),
            job_id=job_id,
            endpoint_id=host_id,
            title=f"Prepare Agent Updater - Wave {wave_index}/{wave_total}",
            module_source="Infrastructure",
            action_type="run_script",
            payload=json.dumps({"script": updater_script}, ensure_ascii=False),
            created_by=created_by,
            created_at=created_at,
        ))
        db.session.add(AgentTask(
            id=str(uuid.uuid4()),
            job_id=job_id,
            endpoint_id=host_id,
            title=title,
            module_source="Infrastructure",
            action_type="agent_update",
            payload=json.dumps(payload, ensure_ascii=False),
            created_by=created_by,
            created_at=created_at + timedelta(seconds=1),
        ))
    db.session.commit()
    return job_id


def process_due_agent_update_rollouts():
    now = datetime.utcnow()
    rollouts = AgentUpdateRollout.query.filter(
        AgentUpdateRollout.status == "Running",
        AgentUpdateRollout.next_run_at <= now
    ).order_by(AgentUpdateRollout.created_at.asc()).all()
    for rollout in rollouts:
        try:
            target_ids = json.loads(rollout.target_ids or "[]")
            target_ids = list(dict.fromkeys([str(item) for item in target_ids if str(item or "").strip()])) if isinstance(target_ids, list) else []
            if not isinstance(target_ids, list) or not target_ids:
                rollout.status = "Completed"
                rollout.updated_at = now
                continue

            package = find_agent_package(rollout.package_id)
            if not package:
                package = {
                    "id": rollout.package_id,
                    "version": rollout.package_version,
                    "download_url": rollout.package_url,
                    "sha256": None,
                }
            package["download_url"] = rollout.package_url or package.get("download_url") or agent_package_public_url(package["id"])

            wave_size = max(1, int(rollout.wave_size or 50))
            existing_ids = existing_endpoint_id_set(target_ids)
            missing_ids = [host_id for host_id in target_ids if host_id not in existing_ids]
            if missing_ids:
                logging.getLogger("winhub").warning(
                    "Skipping %s missing endpoint(s) from agent update rollout %s: %s",
                    len(missing_ids),
                    rollout.id,
                    ", ".join(missing_ids[:8]) + ("..." if len(missing_ids) > 8 else "")
                )
                target_ids = [host_id for host_id in target_ids if host_id in existing_ids]
                rollout.target_ids = json.dumps(target_ids, ensure_ascii=False)
            if not target_ids:
                rollout.status = "Completed"
                rollout.updated_at = now
                continue

            recalculated_total_waves = max(1, (len(target_ids) + wave_size - 1) // wave_size)
            rollout.total_waves = recalculated_total_waves
            index = max(1, int(rollout.next_wave_index or 1))
            if index > recalculated_total_waves:
                rollout.status = "Completed"
                rollout.updated_at = now
                continue
            start = (index - 1) * wave_size
            host_ids = target_ids[start:start + wave_size]
            if not host_ids:
                rollout.status = "Completed"
                rollout.updated_at = now
                continue

            create_agent_update_wave(host_ids, package, rollout.created_by or "System", index, recalculated_total_waves)
            rollout.next_wave_index = index + 1
            rollout.updated_at = datetime.utcnow()
            if rollout.next_wave_index > recalculated_total_waves:
                rollout.status = "Completed"
            else:
                rollout.next_run_at = datetime.utcnow() + timedelta(seconds=max(0, int(rollout.wave_delay_seconds or 0)))
        except Exception:
            db.session.rollback()
            logging.getLogger("winhub").exception("Failed to process agent update rollout %s", rollout.id)
    if rollouts:
        db.session.commit()


@infrastructure_bp.route('/api/public/software-packages/<package_id>/download', methods=['GET'])
def download_software_package_public(package_id):
    package = find_software_package(package_id)
    if not package:
        return jsonify({"success": False, "message": "Software package not found"}), 404
    filename = package.get("filename")
    if not filename:
        return jsonify({"success": False, "message": "Software package file missing"}), 404
    return send_from_directory(SOFTWARE_PACKAGES_DIR, filename, as_attachment=True)


def package_form_text(name, limit=4096):
    return str(request.form.get(name) or "").strip()[:limit]


def write_uploaded_software_file(upload, package_id, fallback_name):
    os.makedirs(SOFTWARE_PACKAGES_DIR, exist_ok=True)
    original_filename = secure_filename(upload.filename) or fallback_name
    filename = f"{package_id}_{original_filename}"
    path = os.path.join(SOFTWARE_PACKAGES_DIR, filename)
    sha256 = hashlib.sha256()
    size = 0
    with open(path, "wb") as f:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            size += len(chunk)
            f.write(chunk)
    return {
        "source": "upload",
        "original_filename": original_filename,
        "filename": filename,
        "sha256": sha256.hexdigest(),
        "size": size,
    }


def software_package_form_record(package_id, existing=None):
    existing = existing or {}
    upload = request.files.get("file")
    external_url = package_form_text("external_url", 2048)
    name = package_form_text("name", 160)
    version = package_form_text("version", 80)
    package_type = package_form_text("package_type", 32).lower() or "exe"
    install_command = package_form_text("install_command", 12000)
    if package_type not in ("msi", "exe", "zip", "ps1", "bat", "custom"):
        raise ValueError("Unsupported package type")
    if not name:
        raise ValueError("Package name is required")
    if not version:
        raise ValueError("Version is required")
    if not install_command:
        raise ValueError("Install command for all users is required")

    file_data = {}
    sha256_value = package_form_text("sha256", 128).lower()
    remove_file = package_form_text("remove_file", 16).lower() in ("1", "true", "yes")
    if upload and upload.filename:
        old_filename = existing.get("filename")
        file_data = write_uploaded_software_file(upload, package_id, f"{name}-{version}")
        if old_filename and old_filename != file_data.get("filename"):
            try:
                os.remove(os.path.join(SOFTWARE_PACKAGES_DIR, old_filename))
            except OSError:
                pass
    elif external_url:
        if sha256_value and not re.fullmatch(r"[A-Fa-f0-9]{64}", sha256_value):
            raise ValueError("External URL SHA256 must be 64 hex characters")
        if remove_file and existing.get("filename"):
            try:
                os.remove(os.path.join(SOFTWARE_PACKAGES_DIR, existing.get("filename")))
            except OSError:
                pass
        file_data = {
            "source": "external_url",
            "external_url": external_url,
            "original_filename": "",
            "filename": "",
            "sha256": sha256_value,
            "size": 0,
        }
    elif existing.get("external_url") and not remove_file:
        file_data = {
            "source": "external_url",
            "external_url": existing.get("external_url", ""),
            "original_filename": "",
            "filename": "",
            "sha256": existing.get("sha256", ""),
            "size": 0,
        }
    elif existing.get("filename") and not remove_file:
        file_data = {
            "source": "upload",
            "external_url": "",
            "original_filename": existing.get("original_filename", ""),
            "filename": existing.get("filename", ""),
            "sha256": existing.get("sha256", ""),
            "size": int(existing.get("size") or 0),
        }
    elif remove_file:
        if not external_url:
            raise ValueError("Select a replacement file or provide external URL before removing the current file")
        if existing.get("filename"):
            try:
                os.remove(os.path.join(SOFTWARE_PACKAGES_DIR, existing.get("filename")))
            except OSError:
                pass
        file_data = {
            "source": "external_url" if external_url else "",
            "external_url": external_url,
            "original_filename": "",
            "filename": "",
            "sha256": sha256_value,
            "size": 0,
        }
    else:
        raise ValueError("Upload a file or provide external URL")

    record = dict(existing)
    record.update({
        "id": package_id,
        "name": name,
        "version": version,
        "vendor": package_form_text("vendor", 160),
        "category": package_form_text("category", 120) or "General",
        "package_type": package_type,
        "architecture": package_form_text("architecture", 32) or "any",
        "external_url": file_data.get("external_url", external_url),
        "original_filename": file_data.get("original_filename", ""),
        "filename": file_data.get("filename", ""),
        "sha256": file_data.get("sha256", ""),
        "size": file_data.get("size", 0),
        "source": file_data.get("source", "upload" if file_data.get("filename") else "external_url"),
        "install_command": install_command,
        "user_install_command": package_form_text("user_install_command", 12000),
        "uninstall_command": package_form_text("uninstall_command", 12000),
        "detection_type": package_form_text("detection_type", 40) or "none",
        "detection_value": package_form_text("detection_value", 4096),
        "expected_exit_codes": package_form_text("expected_exit_codes", 120) or "0,3010",
        "timeout_seconds": max(30, min(86400, int(request.form.get("timeout_seconds") or existing.get("timeout_seconds") or 1800))),
        "notes": package_form_text("notes", 4096),
        "updated_by": session.get("username"),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    })
    if not record.get("uploaded_at"):
        record["uploaded_by"] = session.get("username")
        record["uploaded_at"] = record["updated_at"]
    return record


@infrastructure_bp.route('/api/infrastructure/software-packages', methods=['GET', 'POST'])
def software_packages():
    if request.method == "GET":
        denied = require_any_permission("run_tasks", "manage_software")
        if denied: return denied
        packages = load_software_packages()
        for package in packages:
            if package.get("filename"):
                package["download_url"] = software_package_public_url(package["id"])
        return jsonify({"success": True, "packages": packages})

    denied = require_permission("manage_software")
    if denied: return denied
    try:
        package_id = str(uuid.uuid4())
        packages = load_software_packages()
        record = software_package_form_record(package_id)
        packages.insert(0, record)
        save_software_packages(packages[:200])
        if record.get("filename"):
            record["download_url"] = software_package_public_url(package_id)
        write_infra_audit("Software Package Upload", "software_package", package_id, {"name": record.get("name"), "version": record.get("version"), "sha256": record.get("sha256"), "size": record.get("size")})
        db.session.commit()
        return jsonify({"success": True, "package": record})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logging.getLogger("winhub").exception("Software package upload failed")
        return jsonify({"success": False, "message": f"Software package upload failed: {e}"}), 500


@infrastructure_bp.route('/api/infrastructure/software-packages/<package_id>', methods=['PUT', 'DELETE'])
def software_package_detail(package_id):
    denied = require_permission("manage_software")
    if denied: return denied
    packages = load_software_packages()
    index = next((i for i, package in enumerate(packages) if package.get("id") == package_id), None)
    if index is None:
        return jsonify({"success": False, "message": "Software package not found"}), 404

    if request.method == "DELETE":
        filename = packages[index].get("filename")
        if filename:
            try:
                os.remove(os.path.join(SOFTWARE_PACKAGES_DIR, filename))
            except OSError:
                pass
        removed = packages.pop(index)
        save_software_packages(packages)
        write_infra_audit("Software Package Delete", "software_package", package_id, {"name": removed.get("name"), "version": removed.get("version")})
        db.session.commit()
        return jsonify({"success": True})

    try:
        record = software_package_form_record(package_id, packages[index])
        packages[index] = record
        save_software_packages(packages)
        if record.get("filename"):
            record["download_url"] = software_package_public_url(package_id)
        write_infra_audit("Software Package Update", "software_package", package_id, {"name": record.get("name"), "version": record.get("version"), "sha256": record.get("sha256"), "size": record.get("size")})
        db.session.commit()
        return jsonify({"success": True, "package": record})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logging.getLogger("winhub").exception("Software package update failed")
        return jsonify({"success": False, "message": f"Software package update failed: {e}"}), 500


def ps_single(value):
    return str(value or "").replace("'", "''")


def build_software_install_script(package, install_scope="all", user_logins=None, operation="install"):
    package_url = package.get("external_url") or software_package_public_url(package["id"])
    operation = operation if operation in ("install", "uninstall") else "install"
    user_logins = [
        str(item).strip()
        for item in (user_logins or [])
        if str(item).strip()
    ][:100]
    user_csv = ",".join(user_logins)
    selected_command = package.get("install_command") or ""
    if operation == "uninstall":
        selected_command = package.get("uninstall_command") or ""
    elif install_scope == "users" and package.get("user_install_command"):
        selected_command = package.get("user_install_command") or selected_command
    placeholders = {
        "{file}": "$PackageFile",
        "{extract_dir}": "$ExtractDir",
        "{package_dir}": "$WorkDir",
        "{name}": package.get("name", ""),
        "{version}": package.get("version", ""),
        "{users}": user_csv,
        "{user_list}": user_csv,
        "{user_logins}": user_csv,
    }
    install_command = selected_command
    for token, value in placeholders.items():
        install_command = install_command.replace(token, value)
    expected_codes = [
        int(item.strip())
        for item in str(package.get("expected_exit_codes") or "0,3010").split(",")
        if item.strip().lstrip("-").isdigit()
    ] or [0, 3010]
    return f"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PackageName = '{ps_single(package.get("name"))}'
$PackageVersion = '{ps_single(package.get("version"))}'
$PackageUrl = '{ps_single(package_url)}'
$PackageOriginalFilename = '{ps_single(package.get("original_filename") or "")}'
$ExpectedSha256 = '{ps_single(package.get("sha256"))}'.ToLowerInvariant()
$PackageType = '{ps_single(package.get("package_type"))}'.ToLowerInvariant()
$SoftwareOperation = '{ps_single(operation)}'.ToLowerInvariant()
$InstallScope = '{ps_single(install_scope)}'.ToLowerInvariant()
$TargetUsersCsv = '{ps_single(user_csv)}'
$TargetUsers = @($TargetUsersCsv -split ',' | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }})
$DetectionType = '{ps_single(package.get("detection_type"))}'.ToLowerInvariant()
$DetectionValue = @'
{package.get("detection_value") or ""}
'@.Trim()
$InstallCommand = @'
{install_command}
'@.Trim()
$ExpectedExitCodes = @({','.join(str(code) for code in expected_codes)})
$WorkDir = Join-Path $env:ProgramData ("WinHUB\\software\\" + [guid]::NewGuid().ToString("N"))
$ExtractDir = Join-Path $WorkDir "extracted"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

function Test-WinHUBDetection {{
    param([string]$Type, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Type) -or $Type -eq 'none') {{ return $false }}
    if ($Type -eq 'file_exists') {{ return Test-Path -LiteralPath $Value -PathType Leaf }}
    if ($Type -eq 'folder_exists') {{ return Test-Path -LiteralPath $Value -PathType Container }}
    if ($Type -eq 'registry_key_exists') {{ return Test-Path -LiteralPath $Value }}
    if ($Type -eq 'command') {{
        $DetectionScript = Join-Path $env:TEMP ("winhub_detection_" + [guid]::NewGuid().ToString("N") + ".ps1")
        try {{
            Set-Content -LiteralPath $DetectionScript -Value $Value -Encoding UTF8
            $Process = Start-Process -FilePath "powershell.exe" -ArgumentList @("-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-File", $DetectionScript) -Wait -PassThru -WindowStyle Hidden
            return $Process.ExitCode -eq 0
        }} catch {{
            return $false
        }} finally {{
            try {{ Remove-Item -LiteralPath $DetectionScript -Force -ErrorAction SilentlyContinue }} catch {{ }}
        }}
    }}
    return $false
}}

try {{
    Write-Host "[WinHUB] Software operation: $SoftwareOperation"
    Write-Host "[WinHUB] Package: $PackageName $PackageVersion"
    Write-Host "[WinHUB] Scope: $InstallScope"
    if ($InstallScope -eq 'users') {{
        if ($TargetUsers.Count -eq 0) {{ throw "Specific users scope requires at least one user login." }}
        Write-Host "[WinHUB] Target users: $($TargetUsers -join ', ')"
    }}
    if ($SoftwareOperation -eq 'uninstall') {{
        if ([string]::IsNullOrWhiteSpace($InstallCommand)) {{ throw "Uninstall command is empty." }}
        Write-Host "[WinHUB] Running uninstall command"
        Invoke-Expression $InstallCommand
        $ExitCode = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} else {{ 0 }}
        Write-Host "[WinHUB] Uninstaller exit code: $ExitCode"
        if ($ExpectedExitCodes -notcontains $ExitCode) {{
            throw "Uninstaller returned unexpected exit code $ExitCode. Expected: $($ExpectedExitCodes -join ', ')"
        }}
        Write-Host "[WinHUB] Software uninstall completed."
        exit 0
    }}
    if (Test-WinHUBDetection -Type $DetectionType -Value $DetectionValue) {{
        Write-Host "[WinHUB] Detection rule already matches. Nothing to install."
        exit 0
    }}

    $FileName = [IO.Path]::GetFileName(([Uri]$PackageUrl).AbsolutePath)
    if (-not [string]::IsNullOrWhiteSpace($PackageOriginalFilename)) {{ $FileName = $PackageOriginalFilename }}
    if ([string]::IsNullOrWhiteSpace($FileName)) {{ $FileName = "package.bin" }}
    $PackageFile = Join-Path $WorkDir $FileName
    Write-Host "[WinHUB] Downloading $PackageUrl"
    try {{
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        [Net.ServicePointManager]::Expect100Continue = $false
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {{
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}
            Write-Host "[WinHUB] TLS certificate validation relaxed for this package download; SHA256 verification remains enforced."
        }}
    }} catch {{ }}

    $Downloaded = $false
    $DownloadErrors = New-Object System.Collections.Generic.List[string]

    $Curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($Curl) {{
        try {{
            Write-Host "[WinHUB] Download method: curl.exe"
            $curlArgs = @("-L", "--fail", "--silent", "--show-error")
            if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {{ $curlArgs += "-k" }}
            $curlArgs += @("-o", $PackageFile, $PackageUrl)
            $curlOutput = & $Curl.Source @curlArgs 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $PackageFile)) {{
                $Downloaded = $true
            }} else {{
                $DownloadErrors.Add("curl.exe exit $LASTEXITCODE $curlOutput")
            }}
        }} catch {{
            $DownloadErrors.Add("curl.exe: $($_.Exception.Message)")
        }}
    }}

    if (-not $Downloaded) {{
        try {{
            Write-Host "[WinHUB] Download method: WebClient"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($PackageUrl, $PackageFile)
            if (Test-Path -LiteralPath $PackageFile) {{ $Downloaded = $true }}
        }} catch {{
            $inner = if ($_.Exception.InnerException) {{ $_.Exception.InnerException.Message }} else {{ "" }}
            $DownloadErrors.Add("WebClient: $($_.Exception.Message) $inner")
        }} finally {{
            if ($wc) {{ $wc.Dispose() }}
        }}
    }}

    if (-not $Downloaded) {{
        try {{
            Write-Host "[WinHUB] Download method: Invoke-WebRequest"
            Invoke-WebRequest -Uri $PackageUrl -OutFile $PackageFile -UseBasicParsing
            if (Test-Path -LiteralPath $PackageFile) {{ $Downloaded = $true }}
        }} catch {{
            $inner = if ($_.Exception.InnerException) {{ $_.Exception.InnerException.Message }} else {{ "" }}
            $DownloadErrors.Add("Invoke-WebRequest: $($_.Exception.Message) $inner")
        }}
    }}

    if (-not $Downloaded) {{
        throw "Package download failed. $($DownloadErrors -join ' | ')"
    }}

    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {{
        $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PackageFile).Hash.ToLowerInvariant()
        if ($ActualSha256 -ne $ExpectedSha256) {{
            throw "SHA256 mismatch. Expected $ExpectedSha256, got $ActualSha256"
        }}
        Write-Host "[WinHUB] SHA256 verified: $ActualSha256"
    }}

    if ($PackageType -eq 'zip') {{
        New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
        Expand-Archive -LiteralPath $PackageFile -DestinationPath $ExtractDir -Force
        Write-Host "[WinHUB] Extracted to $ExtractDir"
    }}

    if ([string]::IsNullOrWhiteSpace($InstallCommand)) {{ throw "Install command is empty." }}
    Write-Host "[WinHUB] Running install command"
    Invoke-Expression $InstallCommand
    $ExitCode = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} else {{ 0 }}
    Write-Host "[WinHUB] Installer exit code: $ExitCode"
    if ($ExpectedExitCodes -notcontains $ExitCode) {{
        throw "Installer returned unexpected exit code $ExitCode. Expected: $($ExpectedExitCodes -join ', ')"
    }}

    if ($DetectionType -ne 'none' -and -not (Test-WinHUBDetection -Type $DetectionType -Value $DetectionValue)) {{
        throw "Installation command completed, but detection rule does not match."
    }}
    Write-Host "[WinHUB] Software installation completed."
    exit 0
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    try {{ Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }} catch {{ }}
}}
"""


@infrastructure_bp.route('/api/infrastructure/software/install', methods=['POST'])
def run_software_install():
    denied = require_permission("run_tasks")
    if denied: return denied
    data = request.get_json(force=True) or {}
    package = find_software_package(str(data.get("package_id") or ""))
    if not package:
        return jsonify({"success": False, "message": "Software package not found"}), 404

    allowed = [h for h in WinHubCore.get_allowed_hosts(session.get("user_id")) if getattr(h, "approval_status", "Approved") == "Approved"]
    allowed_by_id = {h.id: h for h in allowed if WinHubCore.can_manage_host(session.get("user_id"), h.id)}
    target_mode = str(data.get("target_mode") or "selected")
    if target_mode == "group":
        group = EndpointGroup.query.get(data.get("group_id"))
        group_ids = {h.id for h in group.endpoints} if group else set()
        target_ids = [host_id for host_id in allowed_by_id if host_id in group_ids]
    else:
        target_ids = [str(item) for item in (data.get("target_ids") or []) if str(item) in allowed_by_id]

    target_ids = list(dict.fromkeys(target_ids))
    if not target_ids:
        return jsonify({"success": False, "message": "No eligible targets selected"}), 400

    install_scope = str(data.get("install_scope") or "all").strip().lower()
    if install_scope not in ("all", "users"):
        return jsonify({"success": False, "message": "Unsupported install scope"}), 400
    operation = str(data.get("operation") or "install").strip().lower()
    if operation not in ("install", "uninstall"):
        return jsonify({"success": False, "message": "Unsupported software operation"}), 400
    if operation == "uninstall" and not package.get("uninstall_command"):
        return jsonify({"success": False, "message": "This software package has no uninstall command"}), 400
    if operation == "install" and install_scope == "users" and not package.get("user_install_command"):
        return jsonify({"success": False, "message": "This software package has no specific-user install recipe"}), 400
    raw_user_logins = data.get("user_logins") or []
    if isinstance(raw_user_logins, str):
        raw_user_logins = re.split(r"[\n,;]+", raw_user_logins)
    user_logins = [
        str(item).strip()
        for item in raw_user_logins
        if str(item).strip()
    ][:100]
    if install_scope == "users" and not user_logins:
        return jsonify({"success": False, "message": "Specify at least one user login"}), 400

    script = build_software_install_script(package, install_scope=install_scope, user_logins=user_logins, operation=operation)
    payload = {"script": script}
    scope_title = "users" if install_scope == "users" else "all users"
    verb = "Uninstall" if operation == "uninstall" else "Install"
    title = f"{verb} Software: {package.get('name')} {package.get('version')} ({scope_title})"
    job_id, task_ids = dispatch_infrastructure_task(
        session.get("user_id"),
        "run_script",
        target_ids,
        payload,
        title,
        created_by=current_actor_label(),
    )
    write_infra_audit("Software Dispatch", "software_package", package["id"], {"operation": operation, "targets": len(target_ids), "target_mode": target_mode, "install_scope": install_scope, "user_logins": user_logins})
    db.session.commit()
    return jsonify({"success": True, "job_id": job_id, "tasks": len(task_ids), "targets": len(target_ids)})


@infrastructure_bp.route('/api/infrastructure/fleet', methods=['GET'])
def fleet_center():
    denied = require_permission("view_hosts")
    if denied: return denied

    latest_version = latest_agent_package_version()
    hosts = []
    allowed_hosts = [
        endpoint for endpoint in WinHubCore.get_allowed_hosts(session.get("user_id"))
        if getattr(endpoint, "approval_status", "Approved") == "Approved"
    ]
    annotate_endpoint_duplicates(allowed_hosts)
    allowed_hosts.sort(key=lambda endpoint: ((endpoint.hostname or endpoint.id or "").lower()))
    for endpoint in allowed_hosts:
        health = endpoint_health_score(endpoint, latest_version)
        try:
            encryption = encryption_status_from_host_info(json.loads(endpoint.host_info or "{}"))
        except Exception:
            encryption = {"status": "Unknown", "level": "unknown", "methods": []}
        hosts.append({
            "id": endpoint.id,
            "hostname": endpoint.hostname or endpoint.id,
            "ip": endpoint.ip_address or "",
            "os": endpoint.os_version or getattr(endpoint, "os_type", "Windows"),
            "agent_version": getattr(endpoint, "agent_version", "") or "",
            "agent_identity_key_enrolled": bool(getattr(endpoint, "public_key_pem", None)),
            "identity_fingerprint": getattr(endpoint, "identity_fingerprint", "") or "",
            "possible_duplicate": bool(getattr(endpoint, "possible_duplicate", False)),
            "duplicate_matches": getattr(endpoint, "duplicate_matches", []),
            "last_seen": to_kyiv_time_short(endpoint.last_seen),
            "groups": [{"id": group.id, "name": group.name} for group in endpoint.groups],
            "health": health,
            "encryption": encryption,
        })

    packages = load_agent_packages()
    for package in packages:
        package["download_url"] = agent_package_public_url(package["id"])

    return jsonify({
        "success": True,
        "latest_version": latest_version,
        "hosts": hosts,
        "packages": packages,
    })


@infrastructure_bp.route('/api/infrastructure/fleet/update', methods=['POST'])
def run_fleet_update():
    denied = require_permission("run_tasks")
    if denied: return denied
    data = request.get_json(force=True) or {}
    package = find_agent_package(str(data.get("package_id") or ""))
    if not package:
        return jsonify({"success": False, "message": "Agent package not found"}), 404
    package["download_url"] = agent_package_public_url(package["id"])

    target_mode = str(data.get("target_mode") or "outdated")
    allowed = [h for h in WinHubCore.get_allowed_hosts(session.get("user_id")) if getattr(h, "approval_status", "Approved") == "Approved"]
    allowed_by_id = {h.id: h for h in allowed if WinHubCore.can_manage_host(session.get("user_id"), h.id)}
    latest_version = package.get("version")

    if target_mode == "selected":
        target_ids = [str(item) for item in (data.get("target_ids") or []) if str(item) in allowed_by_id]
    elif target_mode == "group":
        group = EndpointGroup.query.get(data.get("group_id"))
        group_ids = {h.id for h in group.endpoints} if group else set()
        target_ids = [host_id for host_id in allowed_by_id if host_id in group_ids]
    else:
        target_ids = [
            host_id for host_id, host in allowed_by_id.items()
            if latest_version and (getattr(host, "agent_version", "") or "") != latest_version
        ]

    target_ids = list(dict.fromkeys(target_ids))
    if not target_ids:
        return jsonify({"success": False, "message": "No eligible targets selected"}), 400

    wave_size = max(1, int(data.get("wave_size") or 50))
    wave_delay_seconds = max(0, int(data.get("wave_delay_seconds") or 0))
    waves = [target_ids[i:i + wave_size] for i in range(0, len(target_ids), wave_size)]
    created_by = current_actor_label()

    rollout = AgentUpdateRollout(
        package_id=package["id"],
        package_url=package["download_url"],
        package_version=package.get("version"),
        target_ids=json.dumps(target_ids, ensure_ascii=False),
        wave_size=wave_size,
        wave_delay_seconds=wave_delay_seconds,
        next_wave_index=1,
        total_waves=len(waves),
        status="Running",
        created_by=created_by,
        next_run_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(rollout)
    db.session.flush()
    process_due_agent_update_rollouts()
    job_id = rollout.id

    write_infra_audit("Fleet Agent Update", "agent_package", package["id"], {
        "version": package.get("version"),
        "targets": len(target_ids),
        "waves": len(waves),
        "wave_size": wave_size,
        "wave_delay_seconds": wave_delay_seconds,
        "target_mode": target_mode,
        "rollout_id": rollout.id,
    })
    db.session.commit()
    return jsonify({
        "success": True,
        "job_id": job_id,
        "targets": len(target_ids),
        "waves": len(waves),
        "wave_size": wave_size,
        "wave_delay_seconds": wave_delay_seconds,
    })


@infrastructure_bp.route('/api/infrastructure/templates', methods=['POST'])
def create_template():
    denied = require_permission("manage_templates")
    if denied: return denied
    data = request.json
    payload_dict = data.get('payload', {})
    
    if 'report_template_id' in data and data['report_template_id']:
        payload_dict['__report_template_id'] = data['report_template_id']
        
    payload_raw = json.dumps(payload_dict)
    is_approved = bool(data.get('is_approved', False))
    category = data.get('category', 'General').strip() or 'General'
    t_type = data.get('type', 'action') 
    
    tid = data.get('id')
    if tid:
        t = TaskTemplate.query.get(tid)
        if t:
            if not can_edit_template(t):
                return jsonify({"success": False, "message": "Template editing is locked by superadmin policy"}), 403
            if not session.get("is_admin"):
                payload_dict[TEMPLATE_POLICY_KEY] = template_policy(t)
                payload_raw = json.dumps(payload_dict)
            t.name = data.get('name'); t.category = category; t.action_type = data.get('action')
            t.type = t_type; t.payload = payload_raw; t.is_approved = is_approved
    else:
        db.session.add(TaskTemplate(name=data.get('name'), category=category, action_type=data.get('action'), type=t_type, payload=payload_raw, is_approved=is_approved, created_by=session.get('username')))
    db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/templates/<tid>', methods=['DELETE'])
def delete_template(tid):
    denied = require_permission("manage_templates")
    if denied: return denied
    t = TaskTemplate.query.get(tid)
    if not t:
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_delete_template(t):
        return jsonify({"success": False, "message": "Template deletion is locked by superadmin policy"}), 403

    try:
        ScheduledTask.query.filter_by(template_id=tid).delete(synchronize_session=False)
        TriggerRule.query.filter_by(action_template_id=tid).update(
            {"action_template_id": None},
            synchronize_session=False
        )
        db.session.delete(t)
        db.session.commit()
        return jsonify({"success": True})
    except Exception:
        db.session.rollback()
        logging.getLogger("winhub").exception("Template delete failed")
        return jsonify({"success": False, "message": "Template delete failed"}), 500

@infrastructure_bp.route('/api/infrastructure/tasks/create', methods=['POST'])
def create_task():
    denied = require_permission("run_tasks")
    if denied: return denied
    data = request.json
    target_type = data.get('target_type') 
    action = data.get('action')
    is_admin = session.get('is_admin', False)
    
    action_type = 'run_script'
    payload_dict = {}
    template = TaskTemplate.query.get(data.get('template_id')) if data.get('template_id') else None

    # ТЕПЕР ДЛЯ ВСІХ КОРИСТУВАЧІВ (І АДМІНІВ І ЗВИЧАЙНИХ) МИ ПРИЙМАЄМО СКРИПТ З ФРОНТЕНДУ
    if not is_admin:
        own_runnable = bool(template and getattr(template, "created_by", None) == session.get("username") and can("manage_templates"))
        if not template or (not template.is_approved and not own_runnable) or getattr(template, 'type', 'action') == 'report' or not can_use_template(template):
            return jsonify({"success": False, "message": "Template denied or not found"}), 403
        action_type = template.action_type or 'run_script'
        payload_dict = load_template_payload(template)
        if 'script' not in payload_dict and 'command' in payload_dict:
            payload_dict['script'] = payload_dict['command']
        if getattr(template, 'type', 'action') == 'metric':
            payload_dict['__is_metric'] = True
            payload_dict['__metric_name'] = template.name

    elif action == 'run_script':
        action_type = 'run_script'
        payload_dict = dict(data.get('payload', {}))
        
        # Перевірка на випадок порожнього тексту
        if not payload_dict.get('script') or str(payload_dict.get('script')).strip() == "":
            return jsonify({"success": False, "message": "Скрипт порожній. Якщо це шаблон, переконайтеся що адміністратор зберіг його правильно."}), 400
            
        if data.get('template_type') == 'metric':
            payload_dict['__is_metric'] = True
            payload_dict['__metric_name'] = data.get('title', 'Manual Item')
            
    elif action == 'run_template':
        # Залишаємо як фолбек, якщо раптом фронтенд відішле це
        t = template
        own_runnable = bool(t and getattr(t, "created_by", None) == session.get("username") and can("manage_templates"))
        if not t or (not is_admin and ((not t.is_approved and not own_runnable) or not can_use_template(t))): 
            return jsonify({"success": False, "message": "Template denied or not found"}), 403
        action_type = t.action_type or 'run_script'
        payload_dict = load_template_payload(t)
        if 'script' not in payload_dict and 'command' in payload_dict: payload_dict['script'] = payload_dict['command']
        if getattr(t, 'type', 'action') == 'metric':
            payload_dict['__is_metric'] = True
            payload_dict['__metric_name'] = t.name
            
    elif action == 'reboot': 
        action_type = 'reboot'
        payload_dict = {"command": "restart"}

    elif action == 'agent_update':
        if not is_admin and not template:
            return jsonify({"success": False, "message": "Template denied or not found"}), 403
        action_type = 'agent_update'
        payload_dict = load_template_payload(template) if template else dict(data.get('payload', {}))

    # Метадані для звітності та автовідправки
    if data.get('report_template_id'): 
        payload_dict['__report_template_id'] = data.get('report_template_id')
    if data.get('auto_email_toggle'):
        payload_dict['__auto_email_toggle'] = True
        payload_dict['__auto_email_sender'] = data.get('auto_email_sender')
        payload_dict['__auto_email_recipients'] = data.get('auto_email_recipients')
        payload_dict['__auto_email_use_gpg'] = data.get('auto_email_use_gpg', True)

    # ЗАМІНА ДИНАМІЧНИХ ЗМІННИХ (VARIABLES) У СКРИПТІ
    tpl_vars = data.get('variables', {})
    if 'script' in payload_dict and data.get('template_type') != 'report':
        try:
            payload_dict, unresolved = apply_template_variables(
                payload_dict,
                tpl_vars if isinstance(tpl_vars, dict) else {}
            )
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
        if unresolved:
            return jsonify({
                "success": False,
                "message": "Missing template variables",
                "missing_variables": unresolved
            }), 400

    if action_type == 'agent_update':
        try:
            payload_dict, unresolved = apply_template_variables(
                payload_dict,
                tpl_vars if isinstance(tpl_vars, dict) else {}
            )
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
        unresolved_required = [item for item in unresolved if item != 'sha256']
        if unresolved_required:
            return jsonify({
                "success": False,
                "message": "Missing template variables",
                "missing_variables": unresolved_required
            }), 400
        if not str(payload_dict.get('package_url') or '').strip() or '{{' in str(payload_dict.get('package_url') or ''):
            return jsonify({"success": False, "message": "Agent update requires package_url"}), 400

        sha256_value = str(payload_dict.get('sha256') or '').strip()
        if sha256_value:
            sha256_match = re.search(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])", sha256_value)
            if sha256_match:
                payload_dict['sha256'] = sha256_match.group(0).upper()
            else:
                payload_dict.pop('sha256', None)
        else:
            payload_dict.pop('sha256', None)

    # Розбір цілей
    agent_ids = []
    if target_type == "hosts": 
        agent_ids = data.get('target_ids', [])
    elif target_type == "group":
        group = EndpointGroup.query.get(data.get('target_id'))
        if group: agent_ids = [a.id for a in group.endpoints]

    if not agent_ids: 
        return jsonify({"success": False, "message": "No targets selected"}), 400
    
    try:
        WinHubCore.dispatch_task(session.get('user_id'), "Infrastructure", action_type, agent_ids, payload_dict, data.get('title', 'Task'))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@infrastructure_bp.route('/api/infrastructure/templates/<template_id>/run', methods=['POST'])
def run_template_api(template_id):
    denied = require_permission("run_tasks")
    if denied:
        return denied

    data = request.json or {}
    template = TaskTemplate.query.get(template_id)
    own_runnable = bool(template and getattr(template, "created_by", None) == session.get("username") and can("manage_templates"))
    if not template or (not template.is_approved and not own_runnable) or getattr(template, "type", "action") == "report":
        return jsonify({"success": False, "message": "Approved action template not found"}), 404
    if not can_use_template(template):
        return jsonify({"success": False, "message": "Template denied"}), 403

    target_ids, missing_targets = resolve_target_ids(data)
    if missing_targets:
        return jsonify({
            "success": False,
            "message": "Unknown target endpoints",
            "missing_targets": missing_targets
        }), 400
    if not target_ids:
        return jsonify({"success": False, "message": "No targets selected"}), 400

    variables = data.get("variables", {}) or {}
    if not isinstance(variables, dict):
        return jsonify({"success": False, "message": "Variables must be an object"}), 400

    try:
        payload_dict = load_template_payload(template)
        if "script" not in payload_dict and "command" in payload_dict:
            payload_dict["script"] = payload_dict["command"]
        payload_dict, unresolved = apply_template_variables(payload_dict, variables)
        if unresolved:
            return jsonify({
                "success": False,
                "message": "Missing template variables",
                "missing_variables": unresolved
            }), 400

        if getattr(template, "type", "action") == "metric":
            payload_dict["__is_metric"] = True
            payload_dict["__metric_name"] = template.name

        if data.get("report_template_id"):
            payload_dict["__report_template_id"] = data.get("report_template_id")
        if data.get("auto_email_toggle"):
            denied = require_permission("send_reports")
            if denied:
                return denied
            if not data.get("auto_email_sender") or not data.get("auto_email_recipients"):
                return jsonify({"success": False, "message": "Auto-email sender and recipients are required"}), 400
            payload_dict["__auto_email_toggle"] = True
            payload_dict["__auto_email_sender"] = data.get("auto_email_sender")
            payload_dict["__auto_email_recipients"] = data.get("auto_email_recipients")
            payload_dict["__auto_email_use_gpg"] = data.get("auto_email_use_gpg", True)

        title = data.get("title") or template.name or "API Template Run"
        job_id, task_ids = dispatch_infrastructure_task(
            session.get("user_id"),
            template.action_type or "run_script",
            target_ids,
            payload_dict,
            title,
            created_by=current_actor_label()
        )

        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="API Run Template",
            details={
                "template_id": template.id,
                "template_name": template.name,
                "job_id": job_id,
                "target_type": data.get("target_type"),
                "requested_targets": len(target_ids),
                "created_tasks": len(task_ids),
                "variables": masked_variables(variables),
                "api_key_auth": bool(session.get("api_key_auth")),
                "api_key_id": session.get("api_key_id"),
            },
            status="Success"
        )

        return jsonify({
            "success": True,
            "job_id": job_id,
            "task_ids": task_ids,
            "created_tasks": len(task_ids)
        })
    except (PermissionError, ValueError) as e:
        db.session.rollback()
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="API Run Template",
            details={
                "template_id": template_id,
                "error": str(e),
                "variables": masked_variables(variables),
                "api_key_auth": bool(session.get("api_key_auth")),
                "api_key_id": session.get("api_key_id"),
            },
            status="Error"
        )
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logging.getLogger("winhub").exception("API template run failed")
        try:
            WinHubCore.audit(
                user_id=session.get("user_id"),
                module="Infrastructure",
                action="API Run Template",
                details={
                    "template_id": template_id,
                    "error": str(e),
                    "variables": masked_variables(variables),
                    "api_key_auth": bool(session.get("api_key_auth")),
                    "api_key_id": session.get("api_key_id"),
                },
                status="Error"
            )
        except Exception:
            logging.getLogger("winhub").exception("Failed to write API template failure audit")
        return jsonify({"success": False, "message": "Template run failed. Check server logs for details."}), 500

@infrastructure_bp.route('/api/infrastructure/tasks/all')
def get_tasks():
    denied = require_permission("view_queue")
    if denied: return denied
    user_id = session.get('user_id')
    allowed_hosts = [h.id for h in WinHubCore.get_allowed_hosts(user_id)]
    if not allowed_hosts: return jsonify({"success": True, "jobs": []})

    last_created_at = func.max(AgentTask.created_at).label("last_created_at")
    recent_jobs = db.session.query(
        AgentTask.job_id,
        last_created_at
    ).filter(
        AgentTask.endpoint_id.in_(allowed_hosts),
        AgentTask.job_id.isnot(None)
    ).group_by(
        AgentTask.job_id
    ).order_by(last_created_at.desc()).limit(25).all()

    job_ids = [job_id for job_id, _ in recent_jobs if job_id]
    if not job_ids:
        return jsonify({"success": True, "jobs": []})

    tasks = db.session.query(AgentTask, Endpoint.hostname).join(Endpoint).filter(
        AgentTask.endpoint_id.in_(allowed_hosts),
        AgentTask.job_id.in_(job_ids)
    ).order_by(AgentTask.created_at.desc()).all()
    
    jobs = {}
    for t, hostname in tasks:
        jid = t.job_id or t.id
        if jid not in jobs:
            jobs[jid] = {"job_id": jid, "title": t.title or "Untitled Task", "action": t.action_type, "created_at": to_kyiv_time(t.created_at), "created_by": t.created_by, "tasks": [], "total": 0, "success": 0, "error": 0, "pending": 0, "running": 0, "cancelled": 0}
        if is_agent_updater_prepare_task(t):
            continue
        jobs[jid]["tasks"].append({"task_id": t.id, "endpoint_id": t.endpoint_id, "hostname": hostname, "status": t.status or "Pending"})
        jobs[jid]["total"] += 1
        
        status_norm = (t.status or "Pending").capitalize()
        if status_norm == "Success": jobs[jid]["success"] += 1
        elif status_norm == "Error": jobs[jid]["error"] += 1
        elif status_norm in ["Pending", "Pickedup"]: jobs[jid]["pending"] += 1
        elif status_norm == "Cancelled": jobs[jid]["cancelled"] += 1
        else: jobs[jid]["running"] += 1

    result = []
    for jid in job_ids:
        data = jobs.get(jid)
        if not data:
            continue
        if data["total"] == 0:
            continue
        data["target_summary"] = data["tasks"][0]["hostname"] if data["total"] == 1 else f"Group Deployment ({data['total']} hosts)"
        if data["error"] > 0: data["status"] = "Error"
        elif data["cancelled"] == data["total"]: data["status"] = "Cancelled"
        elif data["pending"] > 0 or data["running"] > 0: data["status"] = "Pending"
        else: data["status"] = "Success"
        result.append(data)
        
    return jsonify({"success": True, "jobs": result})

@infrastructure_bp.route('/api/infrastructure/task/<task_id>', methods=['GET'])
def get_single_task(task_id):
    denied = require_permission("view_queue")
    if denied: return denied
    task = AgentTask.query.get(task_id)
    if not task: return jsonify({"success": False}), 404
    if not WinHubCore.can_manage_host(session.get('user_id'), task.endpoint_id): return jsonify({"success": False}), 403
    task_log = task.result_log if task.result_log else "Waiting..."
    return jsonify({"success": True, "data": {"id": task.id, "title": task.title or "Untitled", "status": task.status or "Pending", "log": report_body_for_current_user(task_log), "hostname": task.endpoint.hostname if task.endpoint else "Unknown"}})

@infrastructure_bp.route('/api/infrastructure/tasks/cleanup', methods=['POST'])
def cleanup_tasks():
    denied = require_permission("cleanup_tasks")
    if denied: return denied
    days = int(request.json.get('days', 30))
    AgentTask.query.filter(AgentTask.created_at < (datetime.utcnow() - timedelta(days=days))).delete(synchronize_session=False); db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    denied = require_permission("cleanup_tasks")
    if denied: return denied
    AgentTask.query.filter_by(job_id=job_id).delete(synchronize_session=False); AgentTask.query.filter_by(id=job_id).delete(synchronize_session=False); db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>/cancel-pending', methods=['POST'])
def cancel_pending_job(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if not can_access_report(job_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    tasks = AgentTask.query.filter_by(job_id=job_id).filter(or_(AgentTask.status.is_(None), AgentTask.status == "Pending")).all()
    for task in tasks:
        if WinHubCore.can_manage_host(session.get("user_id"), task.endpoint_id):
            task.status = "Cancelled"
            task.result_log = "Cancelled before pickup."
            task.finished_at = datetime.utcnow()
    write_infra_audit("Cancel Pending Job Tasks", "job", job_id, {"cancelled": len(tasks)})
    db.session.commit()
    return jsonify({"success": True, "cancelled": len(tasks)})


@infrastructure_bp.route('/api/infrastructure/job/<job_id>/finalize-report', methods=['POST'])
def finalize_job_report(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if not can_access_report(job_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403

    completed_count = AgentTask.query.filter_by(job_id=job_id).filter(AgentTask.status.in_(["Success", "Error"])).count()
    if completed_count == 0:
        return jsonify({"success": False, "message": "No successful or failed tasks are available for report"}), 400

    pending_tasks = AgentTask.query.filter_by(job_id=job_id).filter(
        or_(
            AgentTask.status.is_(None),
            AgentTask.status.in_(["Pending", "PickedUp", "Running"])
        )
    ).all()
    cancelled = 0
    for task in pending_tasks:
        if WinHubCore.can_manage_host(session.get("user_id"), task.endpoint_id):
            task.status = "Cancelled"
            task.result_log = "Excluded from finalized report before completion."
            task.finished_at = datetime.utcnow()
            cancelled += 1

    db.session.commit()

    WinHubCore.process_job_completion(job_id, include_statuses=["Success", "Error"], force=True)
    write_infra_audit("Finalize Job Report", "job", job_id, {"cancelled_pending": cancelled, "included_completed": completed_count})
    return jsonify({"success": True, "cancelled": cancelled, "included": completed_count})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>/retry-failed', methods=['POST'])
def retry_failed_job(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if not can_access_report(job_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403

    failed_tasks = AgentTask.query.filter_by(job_id=job_id).filter(AgentTask.status.in_(["Error", "Cancelled"])).all()
    new_job_id = str(uuid.uuid4())
    created = 0
    for task in failed_tasks:
        if not WinHubCore.can_manage_host(session.get("user_id"), task.endpoint_id):
            continue
        db.session.add(AgentTask(
            id=str(uuid.uuid4()),
            job_id=new_job_id,
            endpoint_id=task.endpoint_id,
            title=f"[Retry] {task.title or 'Untitled Task'}",
            module_source=task.module_source or "Infrastructure",
            action_type=task.action_type,
            payload=task.payload,
            created_by=current_actor_label(),
        ))
        created += 1
    if not created:
        return jsonify({"success": False, "message": "No failed tasks available to retry"}), 400
    write_infra_audit("Retry Failed Job Tasks", "job", job_id, {"new_job_id": new_job_id, "created": created})
    db.session.commit()
    return jsonify({"success": True, "job_id": new_job_id, "created": created})

# ==========================================
# API: GROUPS & HOSTS
# ==========================================
@infrastructure_bp.route('/api/infrastructure/host/<host_id>', methods=['GET', 'DELETE'])
def host_operations(host_id):
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    agent = Endpoint.query.get(host_id)
    if request.method == 'DELETE':
        denied = require_permission("manage_hosts")
        if denied: return denied
        db.session.delete(agent); db.session.commit()
        return jsonify({"success": True})
    denied = require_permission("view_hosts")
    if denied: return denied
    history = AgentTask.query.filter_by(endpoint_id=host_id).order_by(AgentTask.created_at.desc()).limit(20).all()
    try:
        network_info = json.loads(agent.network_info or "[]")
    except Exception:
        network_info = []
    try:
        host_info = json.loads(agent.host_info or "{}")
    except Exception:
        host_info = {}
    annotate_endpoint_duplicates(WinHubCore.get_allowed_hosts(session.get("user_id")))
    return jsonify({"success": True, "data": {"id": agent.id, "hostname": agent.hostname, "os": agent.os_version, "ip": agent.ip_address, "os_type": getattr(agent, 'os_type', 'Windows'), "last_seen": to_kyiv_time(agent.last_seen), "first_seen": to_kyiv_time(getattr(agent, "first_seen", None)), "last_enrollment_at": to_kyiv_time(getattr(agent, "last_enrollment_at", None)), "last_enrollment_ip": getattr(agent, "last_enrollment_ip", None), "enrollment_attempts": int(getattr(agent, "enrollment_attempts", 0) or 0), "identity_fingerprint": getattr(agent, "identity_fingerprint", None), "agent_identity_key_enrolled": bool(getattr(agent, "public_key_pem", None)), "duplicate_matches": getattr(agent, "duplicate_matches", []), "identity_warning": getattr(agent, "identity_warning", None), "is_blocked": agent.is_blocked, "approval_status": getattr(agent, "approval_status", "Approved"), "agent_version": getattr(agent, "agent_version", None), "network_info": network_info, "host_info": host_info, "encryption": encryption_status_from_host_info(host_info), "groups": [{"id": g.id, "name": g.name} for g in agent.groups], "history": [{"id": h.id, "title": h.title, "status": h.status or "Pending", "date": to_kyiv_time_short(h.created_at), "by": h.created_by} for h in history]}})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/telemetry', methods=['GET'])
def get_host_telemetry(host_id):
    denied = require_permission("view_hosts")
    if denied: return denied
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    days = int(request.args.get('days', 1))
    threshold = datetime.utcnow() - timedelta(days=days)
    records = TelemetryHistory.query.filter(TelemetryHistory.endpoint_id == host_id, TelemetryHistory.timestamp >= threshold).order_by(TelemetryHistory.timestamp.asc()).all()
    if len(records) > 100: records = records[::max(1, len(records) // 100)]
    return jsonify({"success": True, "data": [{
        "time": to_kyiv_time_short(r.timestamp),
        "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else None,
        "cpu": r.cpu_usage,
        "ram": r.ram_usage,
        "disk": r.disk_c_free
    } for r in records]})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/ip-history', methods=['GET'])
def get_host_ip_history(host_id):
    denied = require_permission("view_hosts")
    if denied: return denied
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    days = int(request.args.get('days', 30))
    threshold = datetime.utcnow() - timedelta(days=days)
    records = ConnectionIpHistory.query.filter(
        ConnectionIpHistory.endpoint_id == host_id,
        ConnectionIpHistory.timestamp >= threshold
    ).order_by(ConnectionIpHistory.timestamp.desc()).limit(200).all()
    return jsonify({"success": True, "data": [{
        "time": to_kyiv_time_short(r.timestamp),
        "ip": r.ip_address,
        "source": r.source or "agent",
    } for r in records]})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/metrics', methods=['GET'])
def get_host_metrics(host_id):
    denied = require_permission("view_hosts")
    if denied: return denied
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    metrics = EndpointMetric.query.filter_by(endpoint_id=host_id).order_by(EndpointMetric.item_name.asc()).all()
    return jsonify({"success": True, "data": [{"id": m.id, "item_name": m.item_name, "last_value": m.last_value, "last_updated": to_kyiv_time_short(m.last_updated)} for m in metrics]})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/block', methods=['POST'])
def toggle_block_host(host_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    agent = Endpoint.query.get(host_id)
    if agent:
        agent.is_blocked = not agent.is_blocked
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Toggle Host Block",
            details={"host_id": agent.id, "hostname": agent.hostname, "is_blocked": bool(agent.is_blocked)},
            status="Success"
        )
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/approval', methods=['POST'])
def update_host_approval(host_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    agent = Endpoint.query.get(host_id)
    if not agent:
        return jsonify({"success": False, "message": "Host not found"}), 404
    status = (request.json or {}).get("status")
    if status not in ("Pending", "Approved", "Rejected"):
        return jsonify({"success": False, "message": "Invalid approval status"}), 400
    agent.approval_status = status
    agent.identity_warning = None if status == "Approved" else agent.identity_warning
    if status == "Rejected":
        agent.is_blocked = True
    elif status == "Approved":
        agent.is_blocked = False
        from core.agent_gateway import ensure_default_groups_and_assign
        ensure_default_groups_and_assign(agent, getattr(agent, "os_type", "Windows") or "Windows")
    db.session.add(RegistrationHistory(
        hw_id=agent.id,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        event_type=f"Approval {status}"
    ))
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Host Approval",
        details={"host_id": agent.id, "hostname": agent.hostname, "status": status},
        status="Success"
    )
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/hosts/approval', methods=['POST'])
def bulk_update_host_approval():
    denied = require_permission("manage_hosts")
    if denied: return denied
    payload = request.json or {}
    status = payload.get("status")
    if status not in ("Pending", "Approved", "Rejected"):
        return jsonify({"success": False, "message": "Invalid approval status"}), 400

    if payload.get("all_pending"):
        agents = Endpoint.query.filter(Endpoint.approval_status == "Pending").all()
    else:
        host_ids = payload.get("host_ids") or []
        if not isinstance(host_ids, list) or not host_ids:
            return jsonify({"success": False, "message": "No hosts selected"}), 400
        agents = Endpoint.query.filter(Endpoint.id.in_(host_ids)).all()

    if not agents:
        return jsonify({"success": False, "message": "No matching hosts found"}), 404

    ensure_default_groups_and_assign = None
    if status == "Approved":
        from core.agent_gateway import ensure_default_groups_and_assign as assign_defaults
        ensure_default_groups_and_assign = assign_defaults

    for agent in agents:
        agent.approval_status = status
        agent.identity_warning = None if status == "Approved" else agent.identity_warning
        if status == "Rejected":
            agent.is_blocked = True
        elif status == "Approved":
            agent.is_blocked = False
            ensure_default_groups_and_assign(agent, getattr(agent, "os_type", "Windows") or "Windows")
        db.session.add(RegistrationHistory(
            hw_id=agent.id,
            hostname=agent.hostname,
            ip_address=agent.ip_address,
            event_type=f"Bulk Approval {status}"
        ))

    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Bulk Host Approval",
        details={"status": status, "count": len(agents), "all_pending": bool(payload.get("all_pending"))},
        status="Success"
    )
    return jsonify({"success": True, "count": len(agents)})

@infrastructure_bp.route('/api/infrastructure/host/merge-duplicate', methods=['POST'])
def merge_duplicate_host():
    denied = require_permission("manage_hosts")
    if denied: return denied
    payload = request.json or {}
    keep_id = str(payload.get("keep_id") or "").strip()
    remove_id = str(payload.get("remove_id") or "").strip()
    if not keep_id or not remove_id or keep_id == remove_id:
        return jsonify({"success": False, "message": "Select two different endpoint records"}), 400

    keep = Endpoint.query.get(keep_id)
    remove = Endpoint.query.get(remove_id)
    if not keep or not remove:
        return jsonify({"success": False, "message": "Endpoint record not found"}), 404
    if not WinHubCore.can_manage_host(session.get("user_id"), keep_id) or not WinHubCore.can_manage_host(session.get("user_id"), remove_id):
        return jsonify({"success": False, "message": "Access denied"}), 403

    allowed_hosts = WinHubCore.get_allowed_hosts(session.get("user_id"))
    annotate_endpoint_duplicates(allowed_hosts)
    keep_matches = getattr(keep, "duplicate_matches", [])
    if not any(match.get("id") == remove_id and match.get("strong_match") for match in keep_matches):
        return jsonify({"success": False, "message": "These endpoint records are not marked as a strong duplicate"}), 400

    for group in list(remove.groups):
        if group not in keep.groups:
            keep.groups.append(group)

    moved_tasks = AgentTask.query.filter_by(endpoint_id=remove_id).update({"endpoint_id": keep_id}, synchronize_session=False)
    moved_telemetry = TelemetryHistory.query.filter_by(endpoint_id=remove_id).update({"endpoint_id": keep_id}, synchronize_session=False)
    moved_metrics = EndpointMetric.query.filter_by(endpoint_id=remove_id).update({"endpoint_id": keep_id}, synchronize_session=False)
    moved_ips = ConnectionIpHistory.query.filter_by(endpoint_id=remove_id).update({"endpoint_id": keep_id}, synchronize_session=False)
    moved_registration = RegistrationHistory.query.filter_by(hw_id=remove_id).update({"hw_id": keep_id}, synchronize_session=False)

    if remove.first_seen and (not keep.first_seen or remove.first_seen < keep.first_seen):
        keep.first_seen = remove.first_seen
    keep.enrollment_attempts = max(int(keep.enrollment_attempts or 0), int(remove.enrollment_attempts or 0))
    keep.identity_warning = None
    keep.approval_status = "Approved"
    keep.is_blocked = False

    db.session.add(RegistrationHistory(
        hw_id=keep.id,
        hostname=keep.hostname,
        ip_address=keep.ip_address,
        event_type="Merged Duplicate"
    ))
    removed_summary = {
        "id": remove.id,
        "hostname": remove.hostname,
        "agent_version": remove.agent_version,
        "last_seen": remove.last_seen.isoformat() if remove.last_seen else None,
    }
    db.session.delete(remove)
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Merge Endpoint Duplicate",
        details={
            "keep_id": keep_id,
            "remove_id": remove_id,
            "removed": removed_summary,
            "moved_tasks": moved_tasks,
            "moved_telemetry": moved_telemetry,
            "moved_metrics": moved_metrics,
            "moved_connection_ips": moved_ips,
            "moved_registration": moved_registration,
        },
        status="Success"
    )
    return jsonify({"success": True, "keep_id": keep_id, "removed_id": remove_id})

@infrastructure_bp.route('/api/infrastructure/group', methods=['POST'])
def create_group():
    denied = require_permission("manage_groups")
    if denied: return denied
    db.session.add(EndpointGroup(name=request.json.get('name', 'Untitled'), description=request.json.get('description', ''))); db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/group/<group_id>', methods=['GET', 'DELETE'])
def manage_group(group_id):
    group = EndpointGroup.query.get(group_id)
    if not group:
        return jsonify({"success": False}), 404
    if request.method == 'DELETE':
        denied = require_permission("manage_groups")
        if denied: return denied
        db.session.delete(group); db.session.commit()
        return jsonify({"success": True})

    denied = require_permission("view_groups")
    if denied: return denied
    if not session.get('is_admin'):
        allowed_group_ids = {g.id for g in WinHubCore.get_allowed_groups(session.get('user_id'))}
        if group.id not in allowed_group_ids:
            return jsonify({"success": False}), 403
        allowed_host_ids = {h.id for h in WinHubCore.get_allowed_hosts(session.get('user_id'))}
        members_source = [a for a in group.endpoints if a.id in allowed_host_ids]
        group_endpoint_ids = {a.id for a in group.endpoints}
        if can("manage_groups"):
            non_member_query = Endpoint.query.filter(
                db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None)),
                ~Endpoint.id.in_(group_endpoint_ids)
            ).order_by(Endpoint.hostname, Endpoint.id)
            non_members = [{"id": a.id, "hostname": a.hostname or a.id} for a in non_member_query.all()]
        else:
            non_members = []
    else:
        group_endpoint_ids = [a.id for a in group.endpoints]
        members_source = group.endpoints
        non_members = [
            {"id": a.id, "hostname": a.hostname or a.id}
            for a in Endpoint.query.filter(
                db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None))
            ).order_by(Endpoint.hostname, Endpoint.id).all()
            if a.id not in group_endpoint_ids
        ]

    members = [{"id": a.id, "hostname": a.hostname, "ip": a.ip_address, "os_type": getattr(a, 'os_type', 'Windows')} for a in members_source]
    return jsonify({"success": True, "data": {"id": group.id, "name": group.name, "description": group.description, "members": members, "non_members": non_members}})

@infrastructure_bp.route('/api/infrastructure/group/<group_id>/members', methods=['POST'])
def update_group_members(group_id):
    denied = require_permission("manage_groups")
    if denied: return denied
    group = EndpointGroup.query.get(group_id)
    agent = Endpoint.query.get(request.json.get('agent_id'))
    if not group or not agent:
        return jsonify({"success": False, "message": "Group or host not found"}), 404
    if not session.get('is_admin'):
        allowed_group_ids = {g.id for g in WinHubCore.get_allowed_groups(session.get('user_id'))}
        if group.id not in allowed_group_ids:
            return jsonify({"success": False, "message": "Group denied"}), 403
        if (getattr(agent, "approval_status", "Approved") or "Approved") != "Approved":
            return jsonify({"success": False, "message": "Only approved hosts can be added to groups"}), 403
    if request.json.get('action') == 'add' and agent not in group.endpoints: group.endpoints.append(agent)
    elif request.json.get('action') == 'remove' and agent in group.endpoints: group.endpoints.remove(agent)
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Group Membership",
        details={"group_id": group.id, "group": group.name, "host_id": agent.id, "hostname": agent.hostname, "action": request.json.get('action')},
        status="Success"
    )
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/group/<group_id>/block', methods=['POST'])
def block_group_hosts(group_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    group = EndpointGroup.query.get(group_id)
    action = request.json.get('action')
    for agent in group.endpoints: agent.is_blocked = (action == 'block')
    db.session.commit()
    return jsonify({"success": True})
