import os
import json
import uuid
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
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, current_app

from core.database import db, User, Endpoint, EndpointGroup, AgentTask, TaskTemplate, TelemetryHistory, ScheduledTask, EndpointMetric, TriggerRule, AggregatedJob, ApiKey, RegistrationHistory
from core.sdk import WinHubCore
from core.admin import send_notification_email
from core.security import sec_manager
from core.config import Config
from core.permissions import has_module_access, has_permission, user_permissions

infrastructure_bp = Blueprint('infrastructure', __name__, template_folder='templates')
kyiv_tz = ZoneInfo("Europe/Kyiv")

SMTP_FILE = os.path.join(Config.DATA_DIR, "infra_smtp_profiles.json")
SECRETS_FILE = os.path.join(Config.DATA_DIR, "infra_template_secrets.json")

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
    return AgentTask.query.filter(
        ((AgentTask.job_id == report_id) | (AgentTask.id == report_id)),
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

def can_use_template(template):
    if session.get("is_admin"):
        return True
    if not template:
        return False
    if getattr(template, "created_by", None) == session.get("username") and can("manage_templates"):
        return True
    return True

def require_permission(permission_id):
    if not can(permission_id):
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, **hidden_subprocess_kwargs())
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

def auto_email_checker_thread(app):
    import time
    with app.app_context():
        while True:
            try:
                db.session.commit()
                jobs = AggregatedJob.query.filter_by(status='Waiting Review').all()
                for job in jobs:
                    task = AgentTask.query.filter((AgentTask.job_id == job.id) | (AgentTask.id == job.id)).first()
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
            time.sleep(5)

@infrastructure_bp.before_request
def check_access_and_start_thread():
    global auto_thread_started
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
    }
    
    for a in agents: 
        a.is_online = (a.last_seen and a.last_seen >= online_threshold)
        a.last_seen_str = to_kyiv_time(a.last_seen)
        a.agent_outdated = bool(Config.LATEST_AGENT_VERSION and (a.agent_version or "") != Config.LATEST_AGENT_VERSION)

    available_hosts = [{
        "id": a.id,
        "name": a.hostname or a.id,
        "ip": a.ip_address or "",
        "os_type": getattr(a, 'os_type', 'Windows'),
        "is_blocked": bool(a.is_blocked),
        "approval_status": getattr(a, 'approval_status', 'Approved'),
        "agent_version": getattr(a, 'agent_version', '') or '',
        "agent_outdated": bool(Config.LATEST_AGENT_VERSION and (getattr(a, 'agent_version', '') or '') != Config.LATEST_AGENT_VERSION),
    } for a in agents]
    pending_agents = [
        a for a in agents
        if getattr(a, "approval_status", "Approved") == "Pending"
    ]
        
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
            
    templates = [{
        "id": t.id, "name": t.name, "category": getattr(t, 'category', 'General'), 
        "action_type": t.action_type, "type": getattr(t, 'type', 'action'), "is_approved": t.is_approved, "payload": t.payload if t.payload else "{}"
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
        denied = require_permission("manage_reports")
        if denied: return denied
        r.report_data = request.json.get('report_data', '')
        db.session.commit()
        return jsonify({"success": True})
        
    elif action == 'dismiss':
        denied = require_permission("manage_reports")
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
            report_body=report_body_for_current_user(r.report_data),
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
    denied = require_permission("manage_reports")
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
        } for t in templates]
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
    if t: db.session.delete(t); db.session.commit()
    return jsonify({"success": True})

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
        if not payload_dict.get('package_url'):
            return jsonify({"success": False, "message": "Agent update requires package_url"}), 400

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
        sha256_value = str(payload_dict.get('sha256') or '').strip()
        if sha256_value and not re.match(r"^[A-Fa-f0-9:\-\s]{64,95}$", sha256_value):
            return jsonify({"success": False, "message": "Invalid package SHA256 format"}), 400

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

    tasks = db.session.query(AgentTask, Endpoint.hostname).join(Endpoint).filter(AgentTask.endpoint_id.in_(allowed_hosts)).order_by(AgentTask.created_at.desc()).limit(200).all()
    
    jobs = {}
    for t, hostname in tasks:
        jid = t.job_id or t.id
        if jid not in jobs:
            jobs[jid] = {"job_id": jid, "title": t.title or "Untitled Task", "action": t.action_type, "created_at": to_kyiv_time(t.created_at), "created_by": t.created_by, "tasks": [], "total": 0, "success": 0, "error": 0, "pending": 0, "running": 0}
        jobs[jid]["tasks"].append({"task_id": t.id, "hostname": hostname, "status": t.status or "Pending"})
        jobs[jid]["total"] += 1
        
        status_norm = (t.status or "Pending").capitalize()
        if status_norm == "Success": jobs[jid]["success"] += 1
        elif status_norm == "Error": jobs[jid]["error"] += 1
        elif status_norm in ["Pending", "Pickedup"]: jobs[jid]["pending"] += 1
        else: jobs[jid]["running"] += 1

    result = []
    for jid, data in jobs.items():
        data["target_summary"] = data["tasks"][0]["hostname"] if data["total"] == 1 else f"Group Deployment ({data['total']} hosts)"
        if data["error"] > 0: data["status"] = "Error"
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
    return jsonify({"success": True, "data": {"id": agent.id, "hostname": agent.hostname, "os": agent.os_version, "ip": agent.ip_address, "os_type": getattr(agent, 'os_type', 'Windows'), "last_seen": to_kyiv_time(agent.last_seen), "first_seen": to_kyiv_time(getattr(agent, "first_seen", None)), "last_enrollment_at": to_kyiv_time(getattr(agent, "last_enrollment_at", None)), "last_enrollment_ip": getattr(agent, "last_enrollment_ip", None), "enrollment_attempts": int(getattr(agent, "enrollment_attempts", 0) or 0), "identity_warning": getattr(agent, "identity_warning", None), "is_blocked": agent.is_blocked, "approval_status": getattr(agent, "approval_status", "Approved"), "agent_version": getattr(agent, "agent_version", None), "network_info": network_info, "host_info": host_info, "groups": [{"id": g.id, "name": g.name} for g in agent.groups], "history": [{"id": h.id, "title": h.title, "status": h.status or "Pending", "date": to_kyiv_time_short(h.created_at), "by": h.created_by} for h in history]}})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/telemetry', methods=['GET'])
def get_host_telemetry(host_id):
    denied = require_permission("view_hosts")
    if denied: return denied
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    days = int(request.args.get('days', 1))
    threshold = datetime.utcnow() - timedelta(days=days)
    records = TelemetryHistory.query.filter(TelemetryHistory.endpoint_id == host_id, TelemetryHistory.timestamp >= threshold).order_by(TelemetryHistory.timestamp.asc()).all()
    if len(records) > 100: records = records[::max(1, len(records) // 100)]
    return jsonify({"success": True, "data": [{"time": to_kyiv_time_short(r.timestamp), "cpu": r.cpu_usage, "ram": r.ram_usage, "disk": r.disk_c_free} for r in records]})

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
