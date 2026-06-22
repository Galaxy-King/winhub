import os
import json
import logging
import traceback
import threading
import imaplib
import re
import urllib.request
import urllib.parse
import subprocess
import tempfile
import time
import base64
import mimetypes
import smtplib
import ssl
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Blueprint, request, jsonify, session, render_template, current_app
from flask_socketio import join_room
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from core.database import db, User, Task
from core import socketio
from core.sdk import WinHubCore
from core.config import Config
from core.permissions import has_module_access, has_permission, user_permissions
from core.gpg import gpg_env

log = logging.getLogger("winhub.newsletter")

newsletter_bp = Blueprint('newsletter', __name__, template_folder='templates')

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("NEWSLETTER_DATA_DIR") or os.path.join(Config.DATA_DIR, "newsletter")
LISTS_DIR = os.path.join(DATA_DIR, "lists")
SMTP_FILE = os.path.join(DATA_DIR, "smtp_profiles.json")
INBOUND_FILE = os.path.join(DATA_DIR, "inbound_relay.json")
DEFAULT_RECIPIENT_DOMAIN = os.environ.get("NEWSLETTER_RECIPIENT_DOMAIN", "@syneforge.com")
MAX_ATTACHMENTS = int(os.environ.get("NEWSLETTER_MAX_ATTACHMENTS", "8"))
MAX_ATTACHMENT_BYTES = int(os.environ.get("NEWSLETTER_MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024)))
MAX_TOTAL_ATTACHMENT_BYTES = int(os.environ.get("NEWSLETTER_MAX_TOTAL_ATTACHMENT_BYTES", str(25 * 1024 * 1024)))
INBOUND_SUBJECT_RE = re.compile(r"^\s*\[(list|ldap):([A-Za-z0-9_.-]+)\]\s*(.*)$", re.IGNORECASE)
_inbound_worker_started = False
_inbound_worker_lock = threading.Lock()

try:
    KYIV_TZ = ZoneInfo("Europe/Kyiv")
except Exception:
    KYIV_TZ = ZoneInfo("Europe/Kiev")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LISTS_DIR, exist_ok=True)

@socketio.on('join_newsletter_logs')
def join_newsletter_logs():
    user_id = session.get('user_id')
    if user_id:
        join_room(str(user_id))

def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

def hidden_subprocess_kwargs():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}

def kyiv_log_timestamp():
    return datetime.now(KYIV_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")

def normalize_recipient(value):
    recipient = str(value or "").strip()
    if not recipient:
        return ""
    if "@" in recipient:
        return recipient
    domain = DEFAULT_RECIPIENT_DOMAIN.strip()
    if domain and not domain.startswith("@"):
        domain = f"@{domain}"
    return f"{recipient}{domain}"

def html_to_text(html):
    import re
    text = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", str(html or ""))
    text = re.sub(r"(?i)</\s*(p|div|h[1-6]|li|tr)\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return "\n".join(line.rstrip() for line in text.splitlines()).strip()

def normalize_attachments(raw_attachments):
    if not isinstance(raw_attachments, list):
        return []
    if len(raw_attachments) > MAX_ATTACHMENTS:
        raise ValueError(f"Too many attachments. Maximum is {MAX_ATTACHMENTS}.")

    attachments = []
    total_size = 0
    for item in raw_attachments:
        if not isinstance(item, dict):
            continue
        filename = secure_filename(str(item.get("name") or "attachment"))
        if not filename:
            filename = "attachment"
        content_type = str(item.get("type") or "").strip() or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        data_url = str(item.get("data") or "")
        if "," in data_url:
            data_url = data_url.split(",", 1)[1]
        try:
            content = base64.b64decode(data_url, validate=True)
        except Exception:
            raise ValueError(f"Attachment '{filename}' is not valid base64.")
        if len(content) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"Attachment '{filename}' is too large.")
        total_size += len(content)
        if total_size > MAX_TOTAL_ATTACHMENT_BYTES:
            raise ValueError("Total attachment size is too large.")
        attachments.append({"filename": filename, "content_type": content_type, "content": content})
    return attachments

def build_clear_message(sender_email, recipient, subject, body_text, body_html=None, attachments=None):
    msg = EmailMessage(policy=policy.SMTP)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient

    body_text = body_text or html_to_text(body_html) or " "
    if body_html:
        msg.set_content(body_text, subtype="plain", charset="utf-8")
        msg.add_alternative(body_html, subtype="html", charset="utf-8")
    else:
        msg.set_content(body_text, subtype="plain", charset="utf-8")

    for att in attachments or []:
        if "/" in att["content_type"]:
            maintype, subtype = att["content_type"].split("/", 1)
        else:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(att["content"], maintype=maintype, subtype=subtype, filename=att["filename"])
    return msg

def build_encrypted_message(sender_email, recipient, subject, encrypted_payload):
    msg = EmailMessage(policy=policy.SMTP)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient
    msg.set_type("multipart/encrypted")
    msg.set_param("protocol", "application/pgp-encrypted")

    version_part = EmailMessage(policy=policy.SMTP)
    version_part.set_content("Version: 1\n", subtype="pgp-encrypted", charset="us-ascii")
    version_part.replace_header("Content-Type", "application/pgp-encrypted")

    encrypted_part = EmailMessage(policy=policy.SMTP)
    encrypted_part.set_content(encrypted_payload, subtype="octet-stream", charset="us-ascii")
    encrypted_part.replace_header("Content-Type", 'application/octet-stream; name="encrypted.asc"')
    encrypted_part["Content-Disposition"] = 'inline; filename="encrypted.asc"'

    msg.attach(version_part)
    msg.attach(encrypted_part)
    return msg

def env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "enabled"}

def env_int(name, default, minimum=None):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value

def inbound_allowed_senders():
    settings = load_inbound_settings()
    configured = settings.get("allowed_senders")
    if isinstance(configured, list):
        return {str(item).strip().lower() for item in configured if str(item).strip()}
    raw = os.environ.get("NEWSLETTER_INBOUND_ALLOWED_SENDERS", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}

def inbound_sender_profile_setting():
    settings = load_inbound_settings()
    return str(settings.get("sender_profile") or os.environ.get("NEWSLETTER_INBOUND_SENDER_PROFILE", "")).strip()

def inbound_gpg_passphrase():
    settings = load_inbound_settings()
    encrypted = settings.get("gpg_passphrase")
    if encrypted:
        return decrypt_pass(encrypted)
    return os.environ.get("NEWSLETTER_INBOUND_GPG_PASSPHRASE", "")

def parse_inbound_subject(subject):
    match = INBOUND_SUBJECT_RE.match(str(subject or ""))
    if not match:
        return None, None, None
    target_type = match.group(1).strip().lower()
    target_name = match.group(2).strip()
    clean_subject = match.group(3).strip() or "Newsletter"
    return target_type, target_name, clean_subject

def env_csv_set(name):
    raw = os.environ.get(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}

def csv_set_from_value(value):
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").split(",")
    return {str(item).strip().lower() for item in items if str(item).strip()}

def inbound_plain_setting(key, env_name=None, default=""):
    settings = load_inbound_settings()
    value = settings.get(key)
    if value is None or value == "":
        value = os.environ.get(env_name or key.upper(), default)
    return str(value or "").strip()

def inbound_secret_setting(key, env_name):
    settings = load_inbound_settings()
    encrypted = settings.get(key)
    if encrypted:
        return decrypt_pass(encrypted)
    return os.environ.get(env_name, "")

def inbound_bool_setting(key, env_name, default=False):
    settings = load_inbound_settings()
    if key in settings:
        return bool(settings.get(key))
    return env_bool(env_name, default)

def ldap_enabled():
    return inbound_bool_setting("ldap_enabled", "NEWSLETTER_LDAP_ENABLED", False)

def ldap_allowed_group(group_name):
    configured = inbound_plain_setting("ldap_allowed_groups", "NEWSLETTER_LDAP_ALLOWED_GROUPS", "")
    allowed = csv_set_from_value(configured)
    return not allowed or "*" in allowed or str(group_name or "").strip().lower() in allowed

def freeipa_api_base_url():
    value = inbound_plain_setting("freeipa_api_url", "NEWSLETTER_FREEIPA_API_URL", "")
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value.rstrip("/")

def freeipa_api_recipients_from_group(group_name):
    base_url = freeipa_api_base_url()
    if not base_url:
        return None

    try:
        import requests
    except ImportError as e:
        raise RuntimeError("Python package 'requests' is not installed.") from e

    username = inbound_plain_setting("freeipa_api_user", "NEWSLETTER_FREEIPA_API_USER", "")
    password = inbound_secret_setting("freeipa_api_password", "NEWSLETTER_FREEIPA_API_PASSWORD")
    if not username:
        bind_dn = inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", "")
        match = re.search(r"uid=([^,]+)", bind_dn, re.IGNORECASE)
        username = match.group(1) if match else ""
    if not password:
        password = inbound_secret_setting("ldap_bind_password", "NEWSLETTER_LDAP_BIND_PASSWORD")
    if not username or not password:
        raise ValueError("FreeIPA API settings are incomplete. Check NEWSLETTER_FREEIPA_API_USER/PASSWORD or LDAP bind settings.")

    verify_tls = inbound_bool_setting("freeipa_api_verify_tls", "NEWSLETTER_FREEIPA_API_VERIFY_TLS", True)
    session = requests.Session()
    session.verify = verify_tls
    login_url = f"{base_url}/ipa/session/login_password"
    api_url = f"{base_url}/ipa/session/json"
    referer = f"{base_url}/ipa"

    login = session.post(
        login_url,
        data={"user": username, "password": password},
        headers={
            "Referer": referer,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/plain",
        },
        timeout=20,
    )
    login.raise_for_status()

    group_payload = {
        "method": "group_show",
        "params": [[group_name], {"all": True, "rights": False}],
        "id": 0,
    }
    group_response = session.post(
        api_url,
        json=group_payload,
        headers={"Referer": referer, "Content-Type": "application/json", "Accept": "application/json"},
        timeout=20,
    )
    group_response.raise_for_status()
    group_data = group_response.json()
    if group_data.get("error"):
        raise ValueError(f"FreeIPA group lookup failed: {group_data['error']}")
    members = group_data.get("result", {}).get("result", {}).get("member_user", []) or []
    if not members:
        raise ValueError(f"FreeIPA group '{group_name}' has no user members.")

    user_email_attr = inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail") or "mail"
    recipients = []
    skipped_without_email = 0
    for uid in members:
        user_payload = {
            "method": "user_show",
            "params": [[uid], {"all": True, "rights": False}],
            "id": 0,
        }
        user_response = session.post(
            api_url,
            json=user_payload,
            headers={"Referer": referer, "Content-Type": "application/json", "Accept": "application/json"},
            timeout=20,
        )
        user_response.raise_for_status()
        user_data = user_response.json()
        if user_data.get("error"):
            skipped_without_email += 1
            continue
        raw_mail = user_data.get("result", {}).get("result", {}).get(user_email_attr)
        if isinstance(raw_mail, list):
            email_value = raw_mail[0] if raw_mail else ""
        else:
            email_value = raw_mail or ""
        email_value = str(email_value).strip()
        if email_value:
            recipients.append(email_value)
        else:
            skipped_without_email += 1

    unique_recipients = sorted({normalize_recipient(item) for item in recipients if normalize_recipient(item)})
    if not unique_recipients:
        raise ValueError(f"FreeIPA group '{group_name}' has no members with email attribute '{user_email_attr}'.")
    return unique_recipients, {
        "resolver": "freeipa_api",
        "members_count": len(members),
        "skipped_without_email": skipped_without_email,
    }

def ldap_recipients_from_group(group_name):
    if not ldap_enabled():
        raise ValueError("LDAP group targets are disabled. Set NEWSLETTER_LDAP_ENABLED=true.")
    if not ldap_allowed_group(group_name):
        raise PermissionError(f"LDAP group '{group_name}' is not allowed for inbound newsletter relay.")

    api_result = freeipa_api_recipients_from_group(group_name)
    if api_result is not None:
        return api_result

    try:
        from ldap3 import ALL, BASE, SUBTREE, Connection, Server
        from ldap3.utils.conv import escape_filter_chars
    except ImportError as e:
        raise RuntimeError("Python package 'ldap3' is not installed.") from e

    uri = inbound_plain_setting("ldap_uri", "NEWSLETTER_LDAP_URI", "")
    bind_dn = inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", "")
    bind_password = inbound_secret_setting("ldap_bind_password", "NEWSLETTER_LDAP_BIND_PASSWORD")
    base_dn = inbound_plain_setting("ldap_base_dn", "NEWSLETTER_LDAP_BASE_DN", "")
    group_base_dn = inbound_plain_setting("ldap_group_base_dn", "NEWSLETTER_LDAP_GROUP_BASE_DN", base_dn)
    group_name_attr = inbound_plain_setting("ldap_group_name_attr", "NEWSLETTER_LDAP_GROUP_NAME_ATTR", "cn") or "cn"
    group_member_attr = inbound_plain_setting("ldap_group_member_attr", "NEWSLETTER_LDAP_GROUP_MEMBER_ATTR", "member") or "member"
    user_email_attr = inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail") or "mail"

    if not uri or not bind_dn or not bind_password or not group_base_dn:
        raise ValueError("LDAP settings are incomplete. Check NEWSLETTER_LDAP_URI, BIND_DN, BIND_PASSWORD and BASE_DN.")

    server = Server(uri, get_info=ALL)
    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=15)
    try:
        group_filter = f"({group_name_attr}={escape_filter_chars(group_name)})"
        if not conn.search(group_base_dn, group_filter, search_scope=SUBTREE, attributes=[group_member_attr]):
            raise ValueError(f"LDAP group '{group_name}' was not found.")
        if not conn.entries:
            raise ValueError(f"LDAP group '{group_name}' was not found.")

        group_entry = conn.entries[0]
        member_dns = []
        if hasattr(group_entry, group_member_attr):
            member_dns = [str(value) for value in getattr(group_entry, group_member_attr).values if str(value).strip()]
        if not member_dns:
            raise ValueError(f"LDAP group '{group_name}' has no members.")

        recipients = []
        skipped_without_email = 0
        for member_dn in member_dns:
            if not conn.search(member_dn, "(objectClass=*)", search_scope=BASE, attributes=[user_email_attr]):
                skipped_without_email += 1
                continue
            if not conn.entries or not hasattr(conn.entries[0], user_email_attr):
                skipped_without_email += 1
                continue
            values = [str(value).strip() for value in getattr(conn.entries[0], user_email_attr).values if str(value).strip()]
            if values:
                recipients.append(values[0])
            else:
                skipped_without_email += 1

        unique_recipients = sorted({normalize_recipient(item) for item in recipients if normalize_recipient(item)})
        if not unique_recipients:
            raise ValueError(f"LDAP group '{group_name}' has no members with email attribute '{user_email_attr}'.")
        return unique_recipients, {"skipped_without_email": skipped_without_email, "members_count": len(member_dns)}
    finally:
        conn.unbind()

def extract_pgp_encrypted_payload(msg):
    content_type = msg.get_content_type()
    protocol = (msg.get_param("protocol") or "").lower()
    if content_type == "multipart/encrypted" and protocol == "application/pgp-encrypted":
        for part in msg.iter_parts():
            if part.get_content_type() == "application/octet-stream":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload
            filename = (part.get_filename() or "").lower()
            if filename.endswith((".asc", ".pgp", ".gpg")):
                payload = part.get_payload(decode=True)
                if payload:
                    return payload

    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        begin = text.find("-----BEGIN PGP MESSAGE-----")
        end = text.find("-----END PGP MESSAGE-----")
        if begin >= 0 and end >= begin:
            end += len("-----END PGP MESSAGE-----")
            return text[begin:end].encode("utf-8")
    return None

def decrypt_with_gpg(gpg_path, encrypted_payload, passphrase):
    fd, tmp_path = tempfile.mkstemp(suffix=".asc")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encrypted_payload if isinstance(encrypted_payload, (bytes, bytearray)) else str(encrypted_payload).encode("utf-8"))

        cmd = [
            gpg_path,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--decrypt",
            tmp_path,
        ]
        stdin = ((passphrase or "") + "\n").encode("utf-8")
        proc = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=False,
            timeout=30,
            env=gpg_env(),
            **hidden_subprocess_kwargs(),
        )
        if proc.returncode != 0:
            error_text = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
            return False, error_text or f"GPG decrypt failed with exit code {proc.returncode}"
        return True, proc.stdout
    except subprocess.TimeoutExpired:
        return False, "GPG decrypt timed out after 30 seconds"
    except Exception as e:
        return False, str(e)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

def parse_decrypted_message(decrypted_payload):
    try:
        return BytesParser(policy=policy.default).parsebytes(decrypted_payload)
    except Exception:
        msg = EmailMessage(policy=policy.default)
        msg.set_content(decrypted_payload.decode("utf-8", errors="replace"))
        return msg

def extract_body_and_attachments(msg):
    body_text_parts = []
    body_html_parts = []
    attachments = []
    total_size = 0

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        if disposition == "attachment" or part.get_filename():
            if len(attachments) >= MAX_ATTACHMENTS:
                raise ValueError(f"Too many attachments. Maximum is {MAX_ATTACHMENTS}.")
            filename = secure_filename(part.get_filename() or "attachment")
            if not filename:
                filename = "attachment"
            if len(payload) > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"Attachment '{filename}' is too large.")
            total_size += len(payload)
            if total_size > MAX_TOTAL_ATTACHMENT_BYTES:
                raise ValueError("Total attachment size is too large.")
            attachments.append({"filename": filename, "content_type": content_type, "content": payload})
        elif content_type == "text/plain":
            body_text_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
        elif content_type == "text/html":
            body_html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))

    body_text = "\n\n".join(part.strip() for part in body_text_parts if part.strip())
    body_html = "\n\n".join(part.strip() for part in body_html_parts if part.strip())
    if not body_text and body_html:
        body_text = html_to_text(body_html)
    return body_text, body_html, attachments

def resolve_inbound_sender_profile(profiles, mailbox_user):
    configured = inbound_sender_profile_setting()
    if configured and configured in profiles:
        return configured, profiles[configured]
    mailbox_user = (mailbox_user or "").strip()
    if mailbox_user and mailbox_user in profiles:
        return mailbox_user, profiles[mailbox_user]
    if profiles:
        first_sender = sorted(profiles.keys())[0]
        return first_sender, profiles[first_sender]
    return None, None

def move_imap_message(imap, uid, folder):
    folder = (folder or "").strip()
    if not folder:
        return
    try:
        imap.create(folder)
    except Exception:
        pass
    typ, _ = imap.uid("COPY", uid, folder)
    if typ == "OK":
        imap.uid("STORE", uid, "+FLAGS", r"(\Deleted)")

def system_user_id():
    admin = User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()
    if admin:
        return admin.id
    user = User.query.order_by(User.id.asc()).first()
    return user.id if user else 1

def resolve_inbound_recipients(target_type, target_name):
    if target_type == "list":
        lists = load_lists()
        if target_name not in lists:
            raise ValueError(f"Mailing list '{target_name}' not found.")
        recipients = sorted({
            normalize_recipient(item)
            for item in lists.get(target_name, [])
            if normalize_recipient(item)
        })
        meta = {"source": "list", "target": target_name}
    elif target_type == "ldap":
        recipients, ldap_meta = ldap_recipients_from_group(target_name)
        meta = {"source": "ldap", "target": target_name, **ldap_meta}
    else:
        raise ValueError("Subject must start with [list:<name>] or [ldap:<group>].")

    if not recipients:
        raise ValueError(f"Inbound target '{target_name}' has no recipients.")
    return recipients, meta

def dispatch_inbound_newsletter(app, source_msg, decrypted_msg, target_type, target_name, subject):
    with app.app_context():
        target_users, target_meta = resolve_inbound_recipients(target_type, target_name)
        log.info(
            "Newsletter inbound relay resolved %s:%s to %s recipients via %s.",
            target_type,
            target_name,
            len(target_users),
            target_meta.get("resolver") or target_meta.get("source") or target_type,
        )

        profiles = load_smtp_profiles()
        mailbox_user = os.environ.get("NEWSLETTER_INBOUND_IMAP_USER", "")
        sender_email, smtp_config = resolve_inbound_sender_profile(profiles, mailbox_user)
        if not sender_email:
            raise ValueError("No SMTP profile available for inbound newsletter relay.")

        body_text, body_html, attachments = extract_body_and_attachments(decrypted_msg)
        if not (body_text or html_to_text(body_html)):
            raise ValueError("Decrypted message body is empty.")

        user_id = system_user_id()
        task_id = str(uuid.uuid4())
        log_file = os.path.join(app.config["DATA_DIR"], "logs", f"task_{task_id}.log")
        ensure_parent_dir(log_file)
        from_email = parseaddr(source_msg.get("From", ""))[1].lower()
        message_id = str(source_msg.get("Message-ID") or "").strip()

        task = Task(
            id=task_id,
            user_id=user_id,
            module_name="Newsletter",
            action="Inbound Mailing",
            targets=f"{target_type}:{target_name}"[:50],
            status="Running",
            log_file=log_file,
        )
        db.session.add(task)
        db.session.commit()

        WinHubCore.audit(
            user_id=user_id,
            username="Newsletter Inbound",
            module="Newsletter",
            action="Inbound Mailing",
            details={
                "from": from_email,
                "target_type": target_type,
                "target": target_name,
                "subject": subject,
                "recipients_count": len(target_users),
                "message_id": message_id,
                "use_gpg": True,
                "attachments_count": len(attachments),
                **target_meta,
            },
            status="Success",
        )

        thread = threading.Thread(
            target=bg_send_execution,
            args=(
                app,
                task_id,
                sender_email,
                smtp_config,
                list(target_users),
                subject,
                body_text,
                body_html,
                attachments,
                True,
                log_file,
                None,
                True,
            ),
            daemon=True,
        )
        thread.start()
        return task_id

def process_inbound_message(app, imap, uid, raw_message):
    msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    from_email = parseaddr(msg.get("From", ""))[1].lower()
    allowed = inbound_allowed_senders()
    if "*" not in allowed and from_email not in allowed:
        raise PermissionError(f"Sender '{from_email}' is not allowed.")

    target_type, target_name, subject = parse_inbound_subject(msg.get("Subject", ""))
    if not target_type or not target_name:
        raise ValueError("Subject must start with [list:<list-name>] or [ldap:<group-name>].")

    encrypted_payload = extract_pgp_encrypted_payload(msg)
    if not encrypted_payload:
        raise ValueError("Inbound message is not PGP encrypted.")

    passphrase = inbound_gpg_passphrase()
    gpg_path = app.config.get("GPG_PATH") or os.environ.get("GPG_PATH", "gpg")
    ok, decrypted = decrypt_with_gpg(gpg_path, encrypted_payload, passphrase)
    if not ok:
        raise ValueError(f"Could not decrypt inbound message: {decrypted}")

    decrypted_msg = parse_decrypted_message(decrypted)
    task_id = dispatch_inbound_newsletter(app, msg, decrypted_msg, target_type, target_name, subject)
    imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
    return task_id

def poll_inbound_mailbox(app):
    host = os.environ.get("NEWSLETTER_INBOUND_IMAP_HOST", "").strip()
    user = os.environ.get("NEWSLETTER_INBOUND_IMAP_USER", "").strip()
    password = os.environ.get("NEWSLETTER_INBOUND_IMAP_PASSWORD", "")
    if not host or not user or not password:
        log.warning("Newsletter inbound relay is enabled but IMAP host/user/password is incomplete.")
        return

    port = env_int("NEWSLETTER_INBOUND_IMAP_PORT", 993, 1)
    use_ssl = env_bool("NEWSLETTER_INBOUND_IMAP_SSL", True)
    folder = os.environ.get("NEWSLETTER_INBOUND_IMAP_FOLDER", "INBOX")
    processed_folder = os.environ.get("NEWSLETTER_INBOUND_PROCESSED_FOLDER", "Processed")
    failed_folder = os.environ.get("NEWSLETTER_INBOUND_FAILED_FOLDER", "Failed")

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
        imap.login(user, password)
        imap.select(folder)
        typ, data = imap.uid("SEARCH", None, "UNSEEN")
        if typ != "OK":
            raise RuntimeError("IMAP search failed.")
        for uid in (data[0] or b"").split():
            try:
                typ, fetched = imap.uid("FETCH", uid, "(RFC822)")
                if typ != "OK" or not fetched:
                    raise RuntimeError("IMAP fetch failed.")
                raw = None
                for item in fetched:
                    if isinstance(item, tuple):
                        raw = item[1]
                        break
                if not raw:
                    raise RuntimeError("IMAP message body is empty.")
                task_id = process_inbound_message(app, imap, uid, raw)
                log.info("Newsletter inbound relay accepted UID %s as task %s", uid.decode(errors="replace"), task_id)
                move_imap_message(imap, uid, processed_folder)
            except Exception as e:
                log.error("Newsletter inbound relay rejected UID %s: %s", uid.decode(errors="replace"), e)
                try:
                    imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
                    move_imap_message(imap, uid, failed_folder)
                except Exception:
                    log.error("Newsletter inbound relay could not move failed UID %s", uid.decode(errors="replace"))
        try:
            imap.expunge()
        except Exception:
            pass
    finally:
        if imap:
            try:
                imap.logout()
            except Exception:
                pass

def inbound_worker(app):
    startup_delay = env_int("NEWSLETTER_INBOUND_STARTUP_DELAY_SECONDS", 5, 0)
    poll_seconds = env_int("NEWSLETTER_INBOUND_POLL_SECONDS", 60, 10)
    time.sleep(startup_delay)
    log.info("Newsletter inbound relay worker started; polling every %s seconds.", poll_seconds)
    while True:
        try:
            with app.app_context():
                poll_inbound_mailbox(app)
        except Exception:
            log.error("Newsletter inbound relay poll failed: %s", traceback.format_exc())
        time.sleep(poll_seconds)

def start_module(app):
    global _inbound_worker_started
    if not env_bool("NEWSLETTER_INBOUND_ENABLED", False):
        return
    with _inbound_worker_lock:
        if _inbound_worker_started:
            return
        _inbound_worker_started = True
        thread = threading.Thread(target=inbound_worker, args=(app,), daemon=True)
        thread.start()

# --- Encryption Helper for SMTP Passwords ---
def get_cipher():
    """Generates a Fernet cipher based on the app's SECRET_KEY"""
    secret = current_app.config['SECRET_KEY']
    key = base64.urlsafe_b64encode(secret.encode('utf-8')[:32].ljust(32, b'='))
    return Fernet(key)

def encrypt_pass(password):
    return get_cipher().encrypt(password.encode('utf-8')).decode('utf-8')

def decrypt_pass(encrypted_password):
    try:
        return get_cipher().decrypt(encrypted_password.encode('utf-8')).decode('utf-8')
    except:
        return ""

# --- Helper Functions ---
def load_smtp_profiles():
    if not os.path.exists(SMTP_FILE): return {}
    try:
        with open(SMTP_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_smtp_profiles(data):
    ensure_parent_dir(SMTP_FILE)
    with open(SMTP_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def load_inbound_settings():
    if not os.path.exists(INBOUND_FILE):
        return {}
    try:
        with open(INBOUND_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_inbound_settings(data):
    ensure_parent_dir(INBOUND_FILE)
    with open(INBOUND_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def safe_inbound_settings():
    settings = load_inbound_settings()
    allowed = settings.get("allowed_senders")
    if not isinstance(allowed, list):
        allowed = sorted(inbound_allowed_senders())
    return {
        "allowed_senders": allowed,
        "sender_profile": inbound_sender_profile_setting(),
        "passphrase_saved": bool(settings.get("gpg_passphrase") or os.environ.get("NEWSLETTER_INBOUND_GPG_PASSPHRASE")),
        "env_enabled": env_bool("NEWSLETTER_INBOUND_ENABLED", False),
        "imap_user": os.environ.get("NEWSLETTER_INBOUND_IMAP_USER", ""),
        "ldap": {
            "enabled": inbound_bool_setting("ldap_enabled", "NEWSLETTER_LDAP_ENABLED", False),
            "uri": inbound_plain_setting("ldap_uri", "NEWSLETTER_LDAP_URI", ""),
            "bind_dn": inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", ""),
            "bind_password_saved": bool(settings.get("ldap_bind_password") or os.environ.get("NEWSLETTER_LDAP_BIND_PASSWORD")),
            "base_dn": inbound_plain_setting("ldap_base_dn", "NEWSLETTER_LDAP_BASE_DN", ""),
            "group_base_dn": inbound_plain_setting("ldap_group_base_dn", "NEWSLETTER_LDAP_GROUP_BASE_DN", ""),
            "group_name_attr": inbound_plain_setting("ldap_group_name_attr", "NEWSLETTER_LDAP_GROUP_NAME_ATTR", "cn"),
            "group_member_attr": inbound_plain_setting("ldap_group_member_attr", "NEWSLETTER_LDAP_GROUP_MEMBER_ATTR", "member"),
            "user_email_attr": inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail"),
            "allowed_groups": inbound_plain_setting("ldap_allowed_groups", "NEWSLETTER_LDAP_ALLOWED_GROUPS", ""),
            "freeipa_api_url": inbound_plain_setting("freeipa_api_url", "NEWSLETTER_FREEIPA_API_URL", ""),
            "freeipa_api_user": inbound_plain_setting("freeipa_api_user", "NEWSLETTER_FREEIPA_API_USER", ""),
            "freeipa_api_password_saved": bool(settings.get("freeipa_api_password") or os.environ.get("NEWSLETTER_FREEIPA_API_PASSWORD")),
            "freeipa_api_verify_tls": inbound_bool_setting("freeipa_api_verify_tls", "NEWSLETTER_FREEIPA_API_VERIFY_TLS", True),
        },
    }

def normalize_email_list(raw):
    if isinstance(raw, str):
        items = raw.splitlines()
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    clean = []
    seen = set()
    for item in items:
        value = str(item or "").strip().lower()
        if not value:
            continue
        if value != "*" and "@" not in value:
            raise ValueError(f"Invalid sender email: {value}")
        if value not in seen:
            seen.add(value)
            clean.append(value)
    return clean

def load_lists():
    lists = {}
    for filename in os.listdir(LISTS_DIR):
        if filename.endswith(".json"):
            list_name = filename[:-5]
            filepath = os.path.join(LISTS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lists[list_name] = json.load(f)
            except:
                lists[list_name] = []
    return lists

# --- Access Protection ---
@newsletter_bp.before_request
def check_access():
    user = User.query.get(session.get('user_id'))
    if not user: return jsonify({"success": False}), 401
    if not has_module_access(user, 'Newsletter'):
        return "Access Denied", 403

def current_user():
    return User.query.get(session.get('user_id'))

def require_permission(permission_id):
    if not has_permission(current_user(), "Newsletter", permission_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None

# --- Routes ---
@newsletter_bp.route("/module/newsletter")
def index():
    permissions = user_permissions(current_user(), "Newsletter")
    return render_template('newsletter_index.html', username=session.get('username'), is_admin=session.get('is_admin'), permissions=permissions)

@newsletter_bp.route("/api/newsletter/config", methods=["GET"])
def get_config():
    can_manage_smtp = has_permission(current_user(), "Newsletter", "manage_smtp")
    can_manage_lists = has_permission(current_user(), "Newsletter", "manage_lists")
    profiles = load_smtp_profiles()
    
    senders = []
    for email, conf in profiles.items():
        if can_manage_smtp:
            senders.append({
                "email": email, 
                "host": conf.get("host", ""), 
                "port": conf.get("port", 587),
                "keyserver": conf.get("keyserver", "")
            })
        else:
            senders.append({"email": email})
            
    all_lists = load_lists()
    
    # Маскуємо дані списків для звичайних користувачів
    if not can_manage_lists:
        all_lists = {k: [] for k in all_lists.keys()}
            
    payload = {"success": True, "senders": senders, "lists": all_lists}
    if can_manage_smtp:
        payload["inbound"] = safe_inbound_settings()
    return jsonify(payload)

@newsletter_bp.route("/api/newsletter/smtp", methods=["POST"])
def manage_smtp():
    denied = require_permission("manage_smtp")
    if denied: return denied
        
    data = request.json or {}
    action = data.get("action")
    email = data.get("email", "").strip()
    
    if not email: return jsonify({"success": False, "message": "Email is required."}), 400
    
    profiles = load_smtp_profiles()
    
    if action == "add":
        host = data.get("host", "").strip()
        port = data.get("port", 587)
        password = data.get("password", "")
        keyserver = data.get("keyserver", "").strip()
        
        if not host or not password:
            return jsonify({"success": False, "message": "Host and Password are required."}), 400
            
        profiles[email] = {
            "host": host,
            "port": int(port),
            "password": encrypt_pass(password),
            "keyserver": keyserver
        }
        save_smtp_profiles(profiles)
        
    elif action == "delete":
        if email in profiles:
            del profiles[email]
            save_smtp_profiles(profiles)
            
    return jsonify({"success": True, "message": "SMTP configuration updated."})

@newsletter_bp.route("/api/newsletter/inbound", methods=["GET", "POST"])
def manage_inbound_relay():
    denied = require_permission("manage_smtp")
    if denied:
        return denied

    if request.method == "GET":
        return jsonify({"success": True, "inbound": safe_inbound_settings()})

    data = request.json or {}
    settings = load_inbound_settings()

    try:
        settings["allowed_senders"] = normalize_email_list(data.get("allowed_senders", []))
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    sender_profile = str(data.get("sender_profile") or "").strip()
    profiles = load_smtp_profiles()
    if sender_profile and sender_profile not in profiles:
        return jsonify({"success": False, "message": "Sender profile not found."}), 400
    settings["sender_profile"] = sender_profile

    passphrase = str(data.get("gpg_passphrase") or "")
    if passphrase:
        settings["gpg_passphrase"] = encrypt_pass(passphrase)
    if bool(data.get("clear_gpg_passphrase")):
        settings.pop("gpg_passphrase", None)

    ldap_data = data.get("ldap") if isinstance(data.get("ldap"), dict) else {}
    settings["ldap_enabled"] = bool(ldap_data.get("enabled"))
    for key in (
        "ldap_uri",
        "ldap_bind_dn",
        "ldap_base_dn",
        "ldap_group_base_dn",
        "ldap_group_name_attr",
        "ldap_group_member_attr",
        "ldap_user_email_attr",
        "ldap_allowed_groups",
        "freeipa_api_url",
        "freeipa_api_user",
    ):
        settings[key] = str(ldap_data.get(key) or "").strip()
    settings["freeipa_api_verify_tls"] = bool(ldap_data.get("freeipa_api_verify_tls", True))

    ldap_bind_password = str(ldap_data.get("ldap_bind_password") or "")
    if ldap_bind_password:
        settings["ldap_bind_password"] = encrypt_pass(ldap_bind_password)
    if bool(ldap_data.get("clear_ldap_bind_password")):
        settings.pop("ldap_bind_password", None)

    freeipa_api_password = str(ldap_data.get("freeipa_api_password") or "")
    if freeipa_api_password:
        settings["freeipa_api_password"] = encrypt_pass(freeipa_api_password)
    if bool(ldap_data.get("clear_freeipa_api_password")):
        settings.pop("freeipa_api_password", None)

    save_inbound_settings(settings)
    try:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            username=session.get("username"),
            module="Newsletter",
            action="Inbound Relay Settings Updated",
            details={
                "allowed_senders_count": len(settings.get("allowed_senders", [])),
                "sender_profile": settings.get("sender_profile", ""),
                "passphrase_saved": bool(settings.get("gpg_passphrase")),
                "ldap_enabled": bool(settings.get("ldap_enabled")),
                "ldap_bind_password_saved": bool(settings.get("ldap_bind_password")),
                "freeipa_api_password_saved": bool(settings.get("freeipa_api_password")),
            },
            status="Success",
        )
    except Exception as e:
        log.error(f"Failed to audit Newsletter inbound settings update: {e}")

    return jsonify({"success": True, "inbound": safe_inbound_settings()})

@newsletter_bp.route("/api/newsletter/lists", methods=["POST"])
def save_list():
    denied = require_permission("manage_lists")
    if denied: return denied

    data = request.json or {}
    list_name = data.get("list_name", "").strip()
    users = data.get("users", [])
    
    if not list_name: return jsonify({"success": False, "message": "List name is required."}), 400
    
    clean_users = [u.strip() for u in users if u.strip()]
    filepath = os.path.join(LISTS_DIR, f"{list_name}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(clean_users, f, indent=4)
        
    return jsonify({"success": True, "message": "List saved successfully."})

@newsletter_bp.route("/api/newsletter/lists/<list_name>", methods=["DELETE"])
def delete_list(list_name):
    denied = require_permission("manage_lists")
    if denied: return denied

    filepath = os.path.join(LISTS_DIR, f"{list_name}.json")
    if os.path.exists(filepath): os.remove(filepath)
    return jsonify({"success": True})

@newsletter_bp.route("/api/newsletter/send", methods=["POST"])
def send_newsletter():
    denied = require_permission("send_campaigns")
    if denied: return denied
    data = request.json or {}
    sender_email = data.get("sender", "").strip()
    selected_lists = data.get("lists", [])
    subject = data.get("subject", "Newsletter").strip()
    body = data.get("body", "").strip()
    body_html = data.get("body_html", "").strip()
    use_gpg = bool(data.get("use_gpg", True))
    try:
        attachments = normalize_attachments(data.get("attachments", []))
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    
    user_id = session.get('user_id')
    room_id = str(user_id)
    is_admin = session.get('is_admin', False)
    
    if not sender_email or not selected_lists or not (body or html_to_text(body_html)):
        return jsonify({"success": False, "message": "Please fill in all required fields."}), 400

    profiles = load_smtp_profiles()
    if sender_email not in profiles:
        return jsonify({"success": False, "message": "Sender profile not found."}), 404
        
    all_lists = load_lists()
    target_users = set()
    for lname in selected_lists:
        if lname in all_lists:
            for item in all_lists[lname]:
                recipient = normalize_recipient(item)
                if recipient:
                    target_users.add(recipient)
            
    if not target_users:
        return jsonify({"success": False, "message": "No recipients found in the selected lists."}), 400

    # Create Task in DB
    task_id = str(uuid.uuid4())
    log_file = os.path.join(current_app.config['DATA_DIR'], 'logs', f"task_{task_id}.log")
    ensure_parent_dir(log_file)
    
    targets_db = ", ".join(selected_lists)
    if len(targets_db) > 50: targets_db = targets_db[:47] + "..."
    
    new_task = Task(
        id=task_id, user_id=user_id, module_name="Newsletter",
        action="Send Mailing", targets=targets_db, status="Running", log_file=log_file
    )
    db.session.add(new_task)
    db.session.commit()

    try:
        WinHubCore.audit(
            user_id=user_id,
            username=session.get('username'),
            module="Newsletter",
            action="Send Mailing",
            details={
                "sender": sender_email,
                "lists": selected_lists,
                "recipients_count": len(target_users),
                "use_gpg": use_gpg,
                "attachments_count": len(attachments),
            },
            status="Success"
        )
    except Exception as e:
        log.error(f"Failed to audit Newsletter mailing start: {e}")

    # Background Execution
    app_context = current_app._get_current_object()
    thread = threading.Thread(target=bg_send_execution, args=(
        app_context, task_id, sender_email, profiles[sender_email], list(target_users), subject, body, body_html, attachments, use_gpg, log_file, room_id, is_admin
    ))
    thread.daemon = True
    thread.start()

    return jsonify({"success": True})


# --- GPG Functions ---
def get_gpg_key_status(gpg_path, email):
    cmd = [gpg_path, "--batch", "--with-colons", "--list-keys", email]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, env=gpg_env(), **hidden_subprocess_kwargs())
    except Exception as e:
        return {"exists": False, "usable": False, "reason": f"GPG key check failed: {e}"}

    if proc.returncode != 0:
        return {"exists": False, "usable": False, "reason": "Missing public key"}

    now_ts = int(time.time())
    saw_public_key = False
    unusable_reasons = []
    validity_reasons = {
        "e": "Public key is expired",
        "r": "Public key is revoked",
        "d": "Public key is disabled",
    }

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if not parts or parts[0] != "pub":
            continue
        saw_public_key = True
        validity = parts[1] if len(parts) > 1 else ""
        expires_raw = parts[6] if len(parts) > 6 else ""

        reason = validity_reasons.get(validity)
        if not reason and expires_raw:
            try:
                expires_ts = int(expires_raw)
                if expires_ts > 0 and expires_ts < now_ts:
                    reason = "Public key is expired"
            except ValueError:
                pass

        if reason:
            unusable_reasons.append(reason)
            continue
        return {"exists": True, "usable": True, "reason": "Public key is usable"}

    if not saw_public_key:
        return {"exists": False, "usable": False, "reason": "Missing public key"}

    reason = unusable_reasons[0] if unusable_reasons else "No usable public key"
    return {"exists": True, "usable": False, "reason": reason}


def check_gpg_key_exists(gpg_path, email):
    return get_gpg_key_status(gpg_path, email)["usable"]


def ensure_gpg_key_ready(gpg_path, keyserver, email, emit_and_write=None, progress_prefix=""):
    status = get_gpg_key_status(gpg_path, email)
    if status["usable"]:
        return True, status["reason"]

    keyserver = (keyserver or "").strip()
    if not keyserver:
        return False, status["reason"]

    if emit_and_write:
        emit_and_write(
            f"{progress_prefix} ⚠️ {status['reason']} for {email}. Fetching from keyserver {keyserver}...",
            "__HIDE__",
        )

    fetch_success, fetch_msg = fetch_gpg_key(gpg_path, keyserver, email)
    if not fetch_success:
        return False, f"{status['reason']}; keyserver fetch failed: {fetch_msg}"

    refreshed_status = get_gpg_key_status(gpg_path, email)
    if refreshed_status["usable"]:
        if emit_and_write:
            emit_and_write(f"{progress_prefix} 🔑 Public key refreshed successfully.", "__HIDE__")
        return True, "Public key refreshed successfully"

    return False, f"{refreshed_status['reason']} after keyserver refresh"

def validate_gpg(gpg_path):
    if not gpg_path or not os.path.exists(gpg_path):
        return False, f"GPG executable not found at '{gpg_path}'"
    try:
        proc = subprocess.run([gpg_path, "--version"], capture_output=True, text=True, timeout=5, env=gpg_env(), **hidden_subprocess_kwargs())
        if proc.returncode != 0:
            return False, proc.stderr.strip() or "GPG version check failed"
        return True, "GPG is available"
    except Exception as e:
        return False, str(e)

def fetch_gpg_key(gpg_path, keyserver, email):
    """Миттєве завантаження ключа через стандартний HTTPS API сервера SKS (Обхід багів dirmngr)"""
    try:
        base_url = keyserver.replace("hkps://", "https://").replace("hkp://", "http://")
        api_url = f"{base_url}/pks/lookup?op=get&options=mr&search={urllib.parse.quote(email)}"
        
        # ІГНОРУВАННЯ ПОМИЛОК SSL (Для самопідписаних сертифікатів)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Намагаємося завантажити ключ з HTTP/HTTPS
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0 (WinHUB)'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                key_data = response.read().decode('utf-8')
        except Exception as e:
            return False, f"HTTP Fetch Error: {str(e)}"

        # Перевіряємо, чи отримали ми саме ключ
        if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in key_data:
            return False, "Invalid response: No PGP public key block found in server reply."

        # Зберігаємо у тимчасовий файл
        fd, tmp_path = tempfile.mkstemp(suffix=".asc")
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(key_data)

        # Спокійно імпортуємо локально в GPG
        try:
            cmd_import = [gpg_path, "--batch", "--yes", "--import", tmp_path]
            proc = subprocess.run(cmd_import, capture_output=True, text=True, timeout=10, env=gpg_env(), **hidden_subprocess_kwargs())
        except FileNotFoundError:
            os.remove(tmp_path)
            return False, f"GPG executable not found at '{gpg_path}'"

        # Видаляємо тимчасовий файл
        try: os.remove(tmp_path)
        except: pass

        if proc.returncode == 0:
            return True, "Key imported successfully"
        else:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown import error"
            return False, f"GPG Import returned exit code {proc.returncode}: {err_msg}"
    except Exception as e:
        log.error(f"GPG HTTP Fetch Error: {str(e)}")
        return False, f"System Error: {str(e)}"

def encrypt_with_gpg(gpg_path, recipient_email, payload):
    unique_id = str(time.time()).replace(".", "")
    tmp_in = os.path.join(tempfile.gettempdir(), f"nl_{unique_id}.eml")
    tmp_out = tmp_in + ".asc"
    
    try:
        mode = "wb" if isinstance(payload, (bytes, bytearray)) else "w"
        kwargs = {} if mode == "wb" else {"encoding": "utf-8"}
        with open(tmp_in, mode, **kwargs) as f:
            f.write(payload)
            
        # УВАГА: Видалено шифрування для відправника (-r sender_email), 
        # оскільки відсутність його ключа блокує розсилку та викликає таймаути
        cmd = [gpg_path, "--batch", "--yes", "--trust-model", "always",
               "--encrypt", "--armor", "-r", recipient_email,
               "-o", tmp_out, tmp_in]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL, env=gpg_env(), **hidden_subprocess_kwargs())
                              
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown GPG Error"
            return False, f"GPG Exit {proc.returncode}: {err_msg}"
            
        if not os.path.exists(tmp_out): 
            return False, "Encryption file not generated"
            
        with open(tmp_out, 'r', encoding='utf-8') as f: encrypted_body = f.read()
        return True, encrypted_body
        
    except subprocess.TimeoutExpired:
        return False, "GPG encryption timed out after 15 seconds"
    except Exception as e:
        return False, f"Exception: {str(e)}"
    finally:
        for f in [tmp_in, tmp_out]:
            if os.path.exists(f): 
                try: os.remove(f)
                except: pass

# --- Background Worker ---
def bg_send_execution(app, task_id, sender_email, smtp_config, target_users, subject, body, body_html, attachments, use_gpg, log_file, room_id, is_admin):
    timestamp = kyiv_log_timestamp()
    ensure_parent_dir(log_file)
    
    def emit_and_write(full_line, public_line=None):
        ensure_parent_dir(log_file)
        with open(log_file, "a", encoding="utf-8") as f: 
            f.write(full_line + "\n")
            
        display_line = public_line if public_line is not None else full_line
        
        if display_line != "__HIDE__":
            public_log_file = log_file.replace(".log", "_public.log")
            ensure_parent_dir(public_log_file)
            with open(public_log_file, "a", encoding="utf-8") as f:
                f.write(display_line + "\n")
        
        actual_emit = full_line if is_admin else display_line
        if room_id and actual_emit != "__HIDE__":
            socketio.emit('log_update', {'data': actual_emit}, to=room_id)

    with app.app_context():
        server = None
        try:
            keyserver = smtp_config.get('keyserver', '').strip()
            use_gpg = bool(use_gpg)
            
            emit_and_write(f"========== [ {timestamp} ] NEWSLETTER MAILING ==========")
            emit_and_write(f"--- 📤 Sender: {sender_email}")
            emit_and_write(f"--- 👥 Recipients: {len(target_users)}", "__HIDE__")
            emit_and_write(f"--- 📎 Attachments: {len(attachments or [])}", "__HIDE__")
            emit_and_write(f"--- 🔒 GPG Encryption: {'ENABLED' if use_gpg else 'DISABLED'}")
            
            if keyserver:
                emit_and_write(f"--- 🌐 Keyserver Fallback: {keyserver}", "__HIDE__")
                
            emit_and_write(f"----------------------------------------------------------\n")
            
            # Строге зчитування з .env напряму (бо Flask config може не містити цього ключа)
            gpg_path = app.config.get('GPG_PATH') or os.environ.get('GPG_PATH', 'gpg')
            if use_gpg:
                gpg_ok, gpg_message = validate_gpg(gpg_path)
                if not gpg_ok:
                    emit_and_write(f"❌ [CRITICAL ERROR] GPG unavailable: {gpg_message}", "❌ [CRITICAL ERROR] GPG is unavailable. Sending stopped.")
                    raise Exception("GPG unavailable")
            
            success_count = 0
            error_count = 0
            failure_reasons = {}

            emit_and_write(f"⏳ Connecting to SMTP server ({smtp_config['host']}:{smtp_config['port']})...", "⏳ Connecting to mail server...")
            try:
                server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
                server.starttls()
                decrypted_pass = decrypt_pass(smtp_config['password'])
                server.login(sender_email, decrypted_pass)
                emit_and_write(f"✅ SMTP Authentication Successful.\n", "✅ Mail server connection established.\n")
            except Exception as e:
                emit_and_write(f"❌ [CRITICAL ERROR] SMTP Connection Failed: {str(e)}", "❌ [CRITICAL ERROR] Mail server connection failed. Contact an administrator.")
                raise Exception("SMTP Authentication failed")

            emit_and_write(f"🚀 Starting dispatch to {len(target_users)} recipients...", "⏳ Sending emails...\n")

            # Sending loop
            for idx, recipient in enumerate(sorted(target_users), 1):
                clear_msg = build_clear_message(sender_email, recipient, subject, body, body_html, attachments)
                final_msg = clear_msg
                if use_gpg:
                    key_ready, key_message = ensure_gpg_key_ready(
                        gpg_path,
                        keyserver,
                        recipient,
                        emit_and_write=emit_and_write,
                        progress_prefix=f"[{idx}/{len(target_users)}]",
                    )

                    if not key_ready:
                        emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (Encryption Error: {key_message})", "__HIDE__")
                        error_count += 1
                        failure_reasons["Missing/Invalid GPG Key"] = failure_reasons.get("Missing/Invalid GPG Key", 0) + 1
                        continue
                        
                    is_encrypted, encrypted_payload = encrypt_with_gpg(gpg_path, recipient, clear_msg.as_bytes())
                    
                    if not is_encrypted:
                        emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (Encryption Error: {encrypted_payload})", "__HIDE__")
                        error_count += 1
                        failure_reasons["GPG Encryption Error"] = failure_reasons.get("GPG Encryption Error", 0) + 1
                        continue
                    final_msg = build_encrypted_message(sender_email, recipient, subject, encrypted_payload)
                else:
                    emit_and_write(f"[{idx}/{len(target_users)}] ⚠️ Sending without GPG encryption: {recipient}", "__HIDE__")
                
                try:
                    server.send_message(final_msg)
                    emit_and_write(f"[{idx}/{len(target_users)}] ✅ Sent: {recipient}", "__HIDE__")
                    success_count += 1
                except Exception as e:
                    emit_and_write(f"[{idx}/{len(target_users)}] ❌ Failed: {recipient} (SMTP Send Error)", "__HIDE__")
                    error_count += 1
                    failure_reasons["SMTP Connection/Send Error"] = failure_reasons.get("SMTP Connection/Send Error", 0) + 1
                
                time.sleep(0.01)

            if server:
                server.quit()
                server = None
            
            # --- FINAL NEWSLETTER SUMMARY ---
            emit_and_write(f"\n==================================================", "__HIDE__")
            emit_and_write(f"📊 NEWSLETTER SENDING SUMMARY", "__HIDE__")
            emit_and_write(f"==================================================", "__HIDE__")
            
            emit_and_write(f"✅ Total Successfully Sent: {success_count}", "__HIDE__")
            emit_and_write(f"❌ Total Failed: {error_count}", "__HIDE__")
            
            if error_count == 0:
                emit_and_write("✅ Newsletter completed successfully.", "✅ Newsletter completed successfully.")
            else:
                emit_and_write("⚠️ Newsletter completed with errors.", "⚠️ Newsletter completed with errors. Contact an administrator.")

            if error_count > 0:
                emit_and_write(f"\nFailure Breakdown:", "__HIDE__")
                for reason, count in failure_reasons.items():
                    emit_and_write(f"   - {reason}: {count}", "__HIDE__")
            emit_and_write(f"==================================================", "__HIDE__")
            
            task = Task.query.get(task_id)
            if task:
                task.status = "Success" if error_count == 0 else "Warning"
                task.ended_at = datetime.utcnow()
                db.session.commit()
            try:
                WinHubCore.audit(
                    module="Newsletter",
                    action="Mailing Finished",
                    details={
                        "sender": sender_email,
                        "recipients_count": len(target_users),
                        "success_count": success_count,
                        "error_count": error_count,
                        "use_gpg": use_gpg,
                        "attachments_count": len(attachments or []),
                    },
                    status="Success" if error_count == 0 else "Warning"
                )
            except Exception as audit_error:
                log.error(f"Failed to audit Newsletter mailing finish: {audit_error}")
                
        except Exception as e:
            log.error(f"Newsletter Script Error: {traceback.format_exc()}")
            try:
                emit_and_write(f"\n❌ [CRITICAL ERROR] {str(e)}", f"\n❌ [CRITICAL ERROR] Sending was interrupted. Contact an administrator.")
            except Exception as log_error:
                log.error(f"Failed to write Newsletter error log: {log_error}")
            task = Task.query.get(task_id)
            if task:
                task.status = "Error"
                task.ended_at = datetime.utcnow()
                db.session.commit()
            try:
                WinHubCore.audit(
                    module="Newsletter",
                    action="Mailing Failed",
                    details={
                        "sender": sender_email,
                        "recipients_count": len(target_users),
                        "error": str(e),
                        "use_gpg": use_gpg,
                        "attachments_count": len(attachments or []),
                    },
                    status="Error"
                )
            except Exception as audit_error:
                log.error(f"Failed to audit Newsletter mailing failure: {audit_error}")
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
