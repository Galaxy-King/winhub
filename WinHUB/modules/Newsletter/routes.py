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
import html as html_lib
import smtplib
import ssl
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
import uuid
import hashlib
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Blueprint, request, jsonify, session, render_template, current_app
from flask_socketio import join_room
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from core.database import db, User, Task, NewsletterCampaign, NewsletterDelivery
from core import socketio
from core.sdk import WinHubCore
from core.config import Config
from core.permissions import has_module_access, has_permission, user_permissions
from core.gpg import gpg_env
from core.outbound_security import normalized_origin, pinned_outbound_host, pinned_outbound_url

log = logging.getLogger("winhub.newsletter")

newsletter_bp = Blueprint('newsletter', __name__, template_folder='templates')

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("NEWSLETTER_DATA_DIR") or os.path.join(Config.DATA_DIR, "newsletter")
LISTS_DIR = os.path.join(DATA_DIR, "lists")
SMTP_FILE = os.path.join(DATA_DIR, "smtp_profiles.json")
INBOUND_FILE = os.path.join(DATA_DIR, "inbound_relay.json")
WORKER_HEARTBEAT_FILE = os.path.join(DATA_DIR, "worker_heartbeat.json")
MAX_ATTACHMENTS = int(os.environ.get("NEWSLETTER_MAX_ATTACHMENTS", "8"))
MAX_ATTACHMENT_BYTES = int(os.environ.get("NEWSLETTER_MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024)))
MAX_TOTAL_ATTACHMENT_BYTES = int(os.environ.get("NEWSLETTER_MAX_TOTAL_ATTACHMENT_BYTES", str(25 * 1024 * 1024)))
_inbound_worker_started = False
_inbound_worker_lock = threading.Lock()
LIST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")
NEWSLETTER_HTML_TAGS = {"a", "b", "br", "div", "em", "font", "h1", "h2", "h3", "hr", "i", "li", "ol", "p", "span", "strong", "u", "ul"}


class _NewsletterHtmlSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.open_tags = []
        self.suppressed_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = str(tag or "").lower()
        if tag in {"script", "style", "template", "object", "iframe"}:
            self.suppressed_depth += 1
            return
        if self.suppressed_depth or tag not in NEWSLETTER_HTML_TAGS:
            return
        safe_attrs = []
        for name, value in attrs:
            name, value = str(name or "").lower(), str(value or "")
            if tag == "a" and name == "href" and re.match(r"^(https?:|mailto:)", value.strip(), re.I):
                safe_attrs.append(("href", value.strip()))
            elif tag == "a" and name == "title":
                safe_attrs.append(("title", value[:200]))
            elif tag == "font" and name == "face" and re.fullmatch(r"[A-Za-z0-9 ,'-]{1,80}", value):
                safe_attrs.append(("face", value))
            elif tag == "font" and name == "size" and re.fullmatch(r"[1-7]", value):
                safe_attrs.append(("size", value))
            elif tag == "font" and name == "color" and re.fullmatch(r"#[A-Fa-f0-9]{3,8}|[A-Za-z]{1,20}", value):
                safe_attrs.append(("color", value))
            elif name == "style" and re.fullmatch(r"\s*text-align\s*:\s*(left|center|right|justify)\s*;?\s*", value, re.I):
                safe_attrs.append(("style", value.strip()))
        if tag == "a":
            safe_attrs.append(("rel", "noopener noreferrer"))
        attrs_html = "".join(f' {name}="{html_lib.escape(value, quote=True)}"' for name, value in safe_attrs)
        if tag in {"br", "hr"}:
            self.output.append(f"<{tag}{attrs_html}>")
        else:
            self.output.append(f"<{tag}{attrs_html}>")
            self.open_tags.append(tag)

    def handle_endtag(self, tag):
        tag = str(tag or "").lower()
        if self.suppressed_depth:
            self.suppressed_depth -= 1
            return
        if tag not in self.open_tags:
            return
        while self.open_tags:
            current = self.open_tags.pop()
            self.output.append(f"</{current}>")
            if current == tag:
                break

    def handle_data(self, data):
        if not self.suppressed_depth:
            self.output.append(html_lib.escape(str(data or ""), quote=False))

    def close(self):
        super().close()
        while self.open_tags:
            self.output.append(f"</{self.open_tags.pop()}>")


def sanitize_newsletter_html(value):
    parser = _NewsletterHtmlSanitizer()
    parser.feed(str(value or ""))
    parser.close()
    return "".join(parser.output).strip()


def outbound_policy_enforced():
    return str(getattr(Config, "OUTBOUND_POLICY_MODE", "audit") or "audit").lower() == "enforce"


def open_smtp_connection(host, port, purpose, timeout=15):
    port = int(port or 587)
    tls_context = ssl.create_default_context() if outbound_policy_enforced() else None
    with pinned_outbound_host(host, port, purpose):
        if port == 465:
            if tls_context is not None:
                return smtplib.SMTP_SSL(host, port, timeout=timeout, context=tls_context)
            return smtplib.SMTP_SSL(host, port, timeout=timeout)
        connection = smtplib.SMTP(host, port, timeout=timeout)
        if tls_context is not None:
            connection.starttls(context=tls_context)
        else:
            connection.starttls()
        return connection


def open_imap_connection(host, port, use_ssl, purpose):
    port = int(port or (993 if use_ssl else 143))
    if not use_ssl:
        if outbound_policy_enforced():
            raise ValueError(f"Blocked {purpose}: IMAP without TLS is not allowed in enforce mode")
        with pinned_outbound_host(host, port, purpose):
            return imaplib.IMAP4(host, port)
    with pinned_outbound_host(host, port, purpose):
        if outbound_policy_enforced():
            return imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        return imaplib.IMAP4_SSL(host, port)

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

def normalize_domain_suffix(value):
    domain = str(value or "").strip()
    if not domain:
        return ""
    return domain if domain.startswith("@") else f"@{domain}"

def normalize_recipient(value, domain=None):
    recipient = str(value or "").strip()
    if not recipient:
        return ""
    if "@" in recipient:
        return recipient.lower()
    suffix = normalize_domain_suffix(domain)
    return f"{recipient}{suffix}".lower() if suffix else recipient.lower()


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(str(value or "").strip()))


def normalize_list_name(value):
    name = str(value or "").strip()
    if not LIST_NAME_RE.fullmatch(name) or name in {".", ".."}:
        raise ValueError("List name must be 1-80 characters and contain only letters, numbers, dot, underscore or hyphen.")
    return name


def list_file_path(list_name):
    name = normalize_list_name(list_name)
    base = Path(LISTS_DIR).resolve()
    candidate = (base / f"{name}.json").resolve()
    if candidate.parent != base:
        raise ValueError("Invalid list path.")
    return str(candidate)


def atomic_json_write(path, data):
    ensure_parent_dir(path)
    target = Path(path)
    fd, temporary_path = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=4, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)

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

def env_csv_set(name):
    raw = os.environ.get(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}

def csv_set_from_value(value):
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").split(",")
    return {str(item).strip().lower() for item in items if str(item).strip()}

def split_config_values(value):
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r"[\n,]+", str(value or ""))
    clean = []
    seen = set()
    for item in raw_items:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        clean.append(text)
    return clean


def normalize_fingerprints(value):
    fingerprints = []
    for raw in split_config_values(value):
        fingerprint = re.sub(r"\s+", "", raw).upper()
        if not re.fullmatch(r"[A-F0-9]{40,64}", fingerprint):
            raise ValueError(f"Invalid GPG fingerprint: {raw}")
        if fingerprint not in fingerprints:
            fingerprints.append(fingerprint)
    return fingerprints

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

def decrypt_optional_secret(value):
    if not value:
        return ""
    return decrypt_pass(value)

def profile_secret(value):
    if not value:
        return ""
    decrypted = decrypt_optional_secret(value)
    return decrypted or str(value)

def normalize_mail_profile(email, raw, existing=None, for_save=False):
    existing = existing or {}
    email = str(email or raw.get("email") or existing.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("Valid email is required.")

    profile = {
        "email": email,
        "host": str(raw.get("host") or raw.get("smtp_host") or existing.get("host") or "").strip(),
        "port": int(raw.get("port") or raw.get("smtp_port") or existing.get("port") or 587),
        "keyserver": str(raw.get("keyserver") or existing.get("keyserver") or "").strip(),
        "imap_host": str(raw.get("imap_host") or existing.get("imap_host") or "").strip(),
        "imap_port": int(raw.get("imap_port") or existing.get("imap_port") or 993),
        "imap_ssl": bool(raw.get("imap_ssl", existing.get("imap_ssl", True))),
        "imap_user": str(raw.get("imap_user") or existing.get("imap_user") or email).strip(),
        "imap_folder": str(raw.get("imap_folder") or existing.get("imap_folder") or "INBOX").strip() or "INBOX",
        "processed_folder": str(raw.get("processed_folder") or existing.get("processed_folder") or "Processed").strip(),
        "failed_folder": str(raw.get("failed_folder") or existing.get("failed_folder") or "Failed").strip(),
    }

    smtp_origin_unchanged = (
        not existing
        or (
            str(existing.get("host") or "").strip().lower() == profile["host"].lower()
            and int(existing.get("port") or 587) == profile["port"]
            and str(existing.get("email") or email).strip().lower() == email
        )
    )
    imap_origin_unchanged = (
        not existing
        or (
            str(existing.get("imap_host") or "").strip().lower() == profile["imap_host"].lower()
            and int(existing.get("imap_port") or 993) == profile["imap_port"]
            and str(existing.get("imap_user") or email).strip().lower() == profile["imap_user"].lower()
        )
    )

    smtp_password = str(raw.get("password") or raw.get("smtp_password") or "")
    if smtp_password:
        profile["password"] = encrypt_pass(smtp_password) if for_save else smtp_password
    elif existing.get("password") and not raw.get("clear_smtp_password") and smtp_origin_unchanged:
        profile["password"] = existing.get("password")
    if raw.get("clear_smtp_password"):
        profile.pop("password", None)

    imap_password = str(raw.get("imap_password") or "")
    if imap_password:
        profile["imap_password"] = encrypt_pass(imap_password) if for_save else imap_password
    elif existing.get("imap_password") and not raw.get("clear_imap_password") and imap_origin_unchanged:
        profile["imap_password"] = existing.get("imap_password")
    if raw.get("clear_imap_password"):
        profile.pop("imap_password", None)

    gpg_passphrase = str(raw.get("gpg_passphrase") or "")
    if gpg_passphrase:
        profile["gpg_passphrase"] = encrypt_pass(gpg_passphrase) if for_save else gpg_passphrase
    elif existing.get("gpg_passphrase") and not raw.get("clear_gpg_passphrase"):
        profile["gpg_passphrase"] = existing.get("gpg_passphrase")
    if raw.get("clear_gpg_passphrase"):
        profile.pop("gpg_passphrase", None)

    return profile

def safe_mail_profile(email, profile):
    item = {
        "email": email,
        "host": profile.get("host", ""),
        "port": profile.get("port", 587),
        "keyserver": profile.get("keyserver", ""),
        "imap_host": profile.get("imap_host", ""),
        "imap_port": profile.get("imap_port", 993),
        "imap_ssl": profile.get("imap_ssl", True),
        "imap_user": profile.get("imap_user", email),
        "imap_folder": profile.get("imap_folder", "INBOX"),
        "processed_folder": profile.get("processed_folder", "Processed"),
        "failed_folder": profile.get("failed_folder", "Failed"),
        "smtp_password_saved": bool(profile.get("password")),
        "imap_password_saved": bool(profile.get("imap_password")),
        "gpg_passphrase_saved": bool(profile.get("gpg_passphrase")),
    }
    return item

def inbound_bool_setting(key, env_name, default=False):
    settings = load_inbound_settings()
    if key in settings:
        return bool(settings.get(key))
    return env_bool(env_name, default)

def legacy_env_mailbox():
    user = os.environ.get("NEWSLETTER_INBOUND_IMAP_USER", "").strip()
    host = os.environ.get("NEWSLETTER_INBOUND_IMAP_HOST", "").strip()
    if not user or not host:
        return None
    lists = split_config_values(os.environ.get("NEWSLETTER_INBOUND_LISTS", ""))
    ldap_groups = split_config_values(os.environ.get("NEWSLETTER_INBOUND_LDAP_GROUPS", ""))
    if env_bool("NEWSLETTER_INBOUND_ENABLED", False) and not lists and not ldap_groups:
        log.warning("NEWSLETTER_INBOUND_ENABLED is true, but no NEWSLETTER_INBOUND_LISTS or NEWSLETTER_INBOUND_LDAP_GROUPS are configured. Legacy inbound mailbox will be ignored.")
        return None
    return {
        "id": "env-default",
        "name": user,
        "enabled": env_bool("NEWSLETTER_INBOUND_ENABLED", False),
        "imap_host": host,
        "imap_port": env_int("NEWSLETTER_INBOUND_IMAP_PORT", 993, 1),
        "imap_ssl": env_bool("NEWSLETTER_INBOUND_IMAP_SSL", True),
        "imap_user": user,
        "imap_password_env": "NEWSLETTER_INBOUND_IMAP_PASSWORD",
        "imap_folder": os.environ.get("NEWSLETTER_INBOUND_IMAP_FOLDER", "INBOX"),
        "processed_folder": os.environ.get("NEWSLETTER_INBOUND_PROCESSED_FOLDER", "Processed"),
        "failed_folder": os.environ.get("NEWSLETTER_INBOUND_FAILED_FOLDER", "Failed"),
        "sender_profile": inbound_sender_profile_setting(),
        "allowed_senders": sorted(inbound_allowed_senders()),
        "allowed_signer_fingerprints": split_config_values(os.environ.get("NEWSLETTER_INBOUND_ALLOWED_FINGERPRINTS", "")),
        "lists": lists,
        "ldap_groups": ldap_groups,
        "legacy_env": True,
    }

def normalize_inbound_mailbox(raw, existing=None, for_save=False):
    existing = existing or {}
    mailbox_id = str(raw.get("id") or existing.get("id") or uuid.uuid4()).strip()
    if not mailbox_id:
        mailbox_id = str(uuid.uuid4())
    inbound_profile = str(raw.get("inbound_profile") or raw.get("inbound_profile_email") or existing.get("inbound_profile") or "").strip().lower()
    outbound_profile = str(raw.get("outbound_profile") or raw.get("sender_profile") or existing.get("outbound_profile") or existing.get("sender_profile") or "").strip().lower()
    ldap_profile = str(raw.get("ldap_profile") or existing.get("ldap_profile") or "").strip()
    imap_user = str(raw.get("imap_user") or existing.get("imap_user") or inbound_profile).strip()
    name = str(raw.get("name") or existing.get("name") or inbound_profile or imap_user).strip()

    mailbox = {
        "id": mailbox_id,
        "name": name or imap_user or mailbox_id,
        "enabled": bool(raw.get("enabled", existing.get("enabled", True))),
        "inbound_profile": inbound_profile,
        "outbound_profile": outbound_profile,
        "ldap_profile": ldap_profile,
        "recipient_keyserver": str(raw.get("recipient_keyserver") or existing.get("recipient_keyserver") or "").strip(),
        "imap_host": str(raw.get("imap_host") or existing.get("imap_host") or "").strip(),
        "imap_port": int(raw.get("imap_port") or existing.get("imap_port") or 993),
        "imap_ssl": bool(raw.get("imap_ssl", existing.get("imap_ssl", True))),
        "imap_user": imap_user,
        "imap_folder": str(raw.get("imap_folder") or existing.get("imap_folder") or "INBOX").strip() or "INBOX",
        "processed_folder": str(raw.get("processed_folder") or existing.get("processed_folder") or "Processed").strip(),
        "failed_folder": str(raw.get("failed_folder") or existing.get("failed_folder") or "Failed").strip(),
        "allowed_senders": normalize_email_list(raw.get("allowed_senders", existing.get("allowed_senders", []))),
        "allowed_signer_fingerprints": normalize_fingerprints(raw.get("allowed_signer_fingerprints", existing.get("allowed_signer_fingerprints", []))),
        "lists": split_config_values(raw.get("lists", existing.get("lists", []))),
        "ldap_groups": split_config_values(raw.get("ldap_groups", existing.get("ldap_groups", []))),
    }

    password = str(raw.get("imap_password") or "")
    if password:
        mailbox["imap_password"] = encrypt_pass(password) if for_save else password
    elif existing.get("imap_password") and not raw.get("clear_imap_password"):
        mailbox["imap_password"] = existing.get("imap_password")
    elif (raw.get("imap_password_env") or existing.get("imap_password_env")) and not raw.get("clear_imap_password"):
        mailbox["imap_password_env"] = raw.get("imap_password_env") or existing.get("imap_password_env")

    if raw.get("clear_imap_password"):
        mailbox.pop("imap_password", None)
        mailbox.pop("imap_password_env", None)

    passphrase = str(raw.get("gpg_passphrase") or "")
    if passphrase:
        mailbox["gpg_passphrase"] = encrypt_pass(passphrase) if for_save else passphrase
    elif existing.get("gpg_passphrase") and not raw.get("clear_gpg_passphrase"):
        mailbox["gpg_passphrase"] = existing.get("gpg_passphrase")

    if raw.get("clear_gpg_passphrase"):
        mailbox.pop("gpg_passphrase", None)

    return mailbox

def inbound_mailboxes(include_legacy=True):
    settings = load_inbound_settings()
    configured = settings.get("mailboxes")
    mailboxes = []
    if isinstance(configured, list):
        for raw in configured:
            if isinstance(raw, dict):
                try:
                    mailboxes.append(normalize_inbound_mailbox(raw))
                except Exception:
                    log.warning("Skipping invalid inbound mailbox configuration: %s", raw)
    elif include_legacy:
        legacy = legacy_env_mailbox()
        if legacy:
            mailboxes.append(normalize_inbound_mailbox(legacy))
    return mailboxes

def safe_inbound_mailboxes():
    safe = []
    for mailbox in inbound_mailboxes(include_legacy=True):
        item = dict(mailbox)
        item.pop("imap_password", None)
        item.pop("imap_password_env", None)
        item.pop("gpg_passphrase", None)
        item["imap_password_saved"] = bool(mailbox.get("imap_password") or mailbox.get("imap_password_env"))
        item["gpg_passphrase_saved"] = bool(mailbox.get("gpg_passphrase") or load_inbound_settings().get("gpg_passphrase") or os.environ.get("NEWSLETTER_INBOUND_GPG_PASSPHRASE"))
        safe.append(item)
    return safe

def mailbox_imap_password(mailbox):
    profile = load_smtp_profiles().get(str(mailbox.get("inbound_profile") or "").strip().lower())
    if profile and profile.get("imap_password"):
        return decrypt_optional_secret(profile.get("imap_password"))
    if mailbox.get("imap_password"):
        return decrypt_optional_secret(mailbox.get("imap_password"))
    env_name = mailbox.get("imap_password_env")
    if env_name:
        return os.environ.get(env_name, "")
    return ""

def mailbox_gpg_passphrase(mailbox):
    profile = load_smtp_profiles().get(str(mailbox.get("inbound_profile") or "").strip().lower())
    if profile and profile.get("gpg_passphrase"):
        return decrypt_optional_secret(profile.get("gpg_passphrase"))
    if mailbox.get("gpg_passphrase"):
        return decrypt_optional_secret(mailbox.get("gpg_passphrase"))
    return inbound_gpg_passphrase()

def inbound_relay_enabled():
    if env_bool("NEWSLETTER_INBOUND_ENABLED", False):
        return True
    return any(mailbox.get("enabled", True) for mailbox in inbound_mailboxes(include_legacy=False))

def normalize_ldap_profile(raw, existing=None, for_save=False):
    existing = existing or {}
    profile_id = str(raw.get("id") or existing.get("id") or uuid.uuid4()).strip()
    profile = {
        "id": profile_id,
        "name": str(raw.get("name") or existing.get("name") or raw.get("freeipa_api_user") or raw.get("ldap_bind_dn") or "LDAP Profile").strip(),
        "enabled": bool(raw.get("enabled", existing.get("enabled", True))),
        "freeipa_api_url": str(raw.get("freeipa_api_url") or existing.get("freeipa_api_url") or "").strip(),
        "freeipa_api_user": str(raw.get("freeipa_api_user") or existing.get("freeipa_api_user") or "").strip(),
        "freeipa_api_verify_tls": bool(raw.get("freeipa_api_verify_tls", existing.get("freeipa_api_verify_tls", True))),
        "ldap_uri": str(raw.get("ldap_uri") or existing.get("ldap_uri") or "").strip(),
        "ldap_bind_dn": str(raw.get("ldap_bind_dn") or existing.get("ldap_bind_dn") or "").strip(),
        "ldap_base_dn": str(raw.get("ldap_base_dn") or existing.get("ldap_base_dn") or "").strip(),
        "ldap_group_base_dn": str(raw.get("ldap_group_base_dn") or existing.get("ldap_group_base_dn") or "").strip(),
        "ldap_group_name_attr": str(raw.get("ldap_group_name_attr") or existing.get("ldap_group_name_attr") or "cn").strip() or "cn",
        "ldap_group_member_attr": str(raw.get("ldap_group_member_attr") or existing.get("ldap_group_member_attr") or "member").strip() or "member",
        "ldap_user_email_attr": str(raw.get("ldap_user_email_attr") or existing.get("ldap_user_email_attr") or "mail").strip() or "mail",
        "ldap_allowed_groups": str(raw.get("ldap_allowed_groups") or existing.get("ldap_allowed_groups") or "").strip(),
    }

    existing_freeipa_url = str(existing.get("freeipa_api_url") or "")
    current_freeipa_url = str(profile["freeipa_api_url"] or "")
    if existing_freeipa_url and "://" not in existing_freeipa_url:
        existing_freeipa_url = "https://" + existing_freeipa_url
    if current_freeipa_url and "://" not in current_freeipa_url:
        current_freeipa_url = "https://" + current_freeipa_url
    freeipa_origin_unchanged = (
        not existing
        or (
            normalized_origin(existing_freeipa_url) == normalized_origin(current_freeipa_url)
            and str(existing.get("freeipa_api_user") or "").strip() == profile["freeipa_api_user"]
        )
    )
    ldap_origin_unchanged = (
        not existing
        or (
            normalized_origin(existing.get("ldap_uri")) == normalized_origin(profile["ldap_uri"])
            and str(existing.get("ldap_bind_dn") or "").strip() == profile["ldap_bind_dn"]
        )
    )

    freeipa_password = str(raw.get("freeipa_api_password") or "")
    if freeipa_password:
        profile["freeipa_api_password"] = encrypt_pass(freeipa_password) if for_save else freeipa_password
    elif existing.get("freeipa_api_password") and not raw.get("clear_freeipa_api_password") and freeipa_origin_unchanged:
        profile["freeipa_api_password"] = existing.get("freeipa_api_password")
    if raw.get("clear_freeipa_api_password"):
        profile.pop("freeipa_api_password", None)

    ldap_password = str(raw.get("ldap_bind_password") or "")
    if ldap_password:
        profile["ldap_bind_password"] = encrypt_pass(ldap_password) if for_save else ldap_password
    elif existing.get("ldap_bind_password") and not raw.get("clear_ldap_bind_password") and ldap_origin_unchanged:
        profile["ldap_bind_password"] = existing.get("ldap_bind_password")
    if raw.get("clear_ldap_bind_password"):
        profile.pop("ldap_bind_password", None)

    return profile

def ldap_profiles():
    settings = load_inbound_settings()
    configured = settings.get("ldap_profiles")
    profiles = []
    if isinstance(configured, list):
        for raw in configured:
            if isinstance(raw, dict):
                profiles.append(normalize_ldap_profile(raw))
    if not profiles and (
        inbound_plain_setting("freeipa_api_url", "NEWSLETTER_FREEIPA_API_URL", "")
        or inbound_plain_setting("ldap_uri", "NEWSLETTER_LDAP_URI", "")
    ):
        profiles.append(normalize_ldap_profile({
            "id": "default",
            "name": "Default LDAP",
            "enabled": inbound_bool_setting("ldap_enabled", "NEWSLETTER_LDAP_ENABLED", False),
            "freeipa_api_url": inbound_plain_setting("freeipa_api_url", "NEWSLETTER_FREEIPA_API_URL", ""),
            "freeipa_api_user": inbound_plain_setting("freeipa_api_user", "NEWSLETTER_FREEIPA_API_USER", ""),
            "freeipa_api_password": inbound_secret_setting("freeipa_api_password", "NEWSLETTER_FREEIPA_API_PASSWORD"),
            "freeipa_api_verify_tls": inbound_bool_setting("freeipa_api_verify_tls", "NEWSLETTER_FREEIPA_API_VERIFY_TLS", True),
            "ldap_uri": inbound_plain_setting("ldap_uri", "NEWSLETTER_LDAP_URI", ""),
            "ldap_bind_dn": inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", ""),
            "ldap_bind_password": inbound_secret_setting("ldap_bind_password", "NEWSLETTER_LDAP_BIND_PASSWORD"),
            "ldap_base_dn": inbound_plain_setting("ldap_base_dn", "NEWSLETTER_LDAP_BASE_DN", ""),
            "ldap_group_base_dn": inbound_plain_setting("ldap_group_base_dn", "NEWSLETTER_LDAP_GROUP_BASE_DN", ""),
            "ldap_group_name_attr": inbound_plain_setting("ldap_group_name_attr", "NEWSLETTER_LDAP_GROUP_NAME_ATTR", "cn"),
            "ldap_group_member_attr": inbound_plain_setting("ldap_group_member_attr", "NEWSLETTER_LDAP_GROUP_MEMBER_ATTR", "member"),
            "ldap_user_email_attr": inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail"),
            "ldap_allowed_groups": inbound_plain_setting("ldap_allowed_groups", "NEWSLETTER_LDAP_ALLOWED_GROUPS", ""),
        }))
    return profiles

def ldap_profile_by_id(profile_id):
    profile_id = str(profile_id or "").strip()
    for profile in ldap_profiles():
        if profile.get("id") == profile_id:
            return profile
    return None

def safe_ldap_profiles():
    safe = []
    for profile in ldap_profiles():
        item = dict(profile)
        item.pop("freeipa_api_password", None)
        item.pop("ldap_bind_password", None)
        item["freeipa_api_password_saved"] = bool(profile.get("freeipa_api_password"))
        item["ldap_bind_password_saved"] = bool(profile.get("ldap_bind_password"))
        safe.append(item)
    return safe

def ldap_profile_groups(profile, limit=100):
    profile = profile or {}
    base_url = freeipa_api_base_url(profile)
    if base_url:
        web_schemes = ("https",) if Config.OUTBOUND_POLICY_MODE == "enforce" else ("https", "http")
        try:
            import requests
        except ImportError as e:
            raise RuntimeError("Python package 'requests' is not installed.") from e

        username = profile.get("freeipa_api_user") or ""
        password = profile_secret(profile.get("freeipa_api_password"))
        if not username or not password:
            raise ValueError("FreeIPA API user and password are required for this test.")

        with pinned_outbound_url(base_url, "FreeIPA API", allowed_schemes=web_schemes):
            session = requests.Session()
            session.verify = True if outbound_policy_enforced() else bool(profile.get("freeipa_api_verify_tls", True))
            if outbound_policy_enforced():
                session.trust_env = False
            referer = f"{base_url}/ipa"
            login = session.post(
                f"{base_url}/ipa/session/login_password",
                data={"user": username, "password": password},
                headers={"Referer": referer, "Content-Type": "application/x-www-form-urlencoded", "Accept": "text/plain"},
                timeout=20,
                allow_redirects=False,
            )
            login.raise_for_status()
            response = session.post(
                f"{base_url}/ipa/session/json",
                json={"method": "group_find", "params": [[], {"all": True, "sizelimit": int(limit)}], "id": 0},
                headers={"Referer": referer, "Content-Type": "application/json", "Accept": "application/json"},
                timeout=20,
                allow_redirects=False,
            )
            response.raise_for_status()
            payload = response.json()
        if payload.get("error"):
            raise ValueError(f"FreeIPA group lookup failed: {payload['error']}")
        results = payload.get("result", {}).get("result", []) or []
        groups = []
        for item in results:
            cn = item.get("cn")
            if isinstance(cn, list):
                cn = cn[0] if cn else ""
            if cn:
                groups.append(str(cn))
        return sorted(set(groups))

    try:
        from ldap3 import ALL, SUBTREE, Connection, Server, Tls
    except ImportError as e:
        raise RuntimeError("Python package 'ldap3' is not installed.") from e

    uri = profile.get("ldap_uri") or ""
    bind_dn = profile.get("ldap_bind_dn") or ""
    bind_password = profile_secret(profile.get("ldap_bind_password"))
    group_base_dn = profile.get("ldap_group_base_dn") or profile.get("ldap_base_dn") or ""
    group_name_attr = profile.get("ldap_group_name_attr") or "cn"
    if not uri or not bind_dn or not bind_password or not group_base_dn:
        raise ValueError("LDAP URI, bind DN, bind password and group base DN are required for this test.")

    ldap_schemes = ("ldaps",) if Config.OUTBOUND_POLICY_MODE == "enforce" else ("ldap", "ldaps")
    tls = Tls(validate=ssl.CERT_REQUIRED) if outbound_policy_enforced() else None
    with pinned_outbound_url(uri, "LDAP directory", allowed_schemes=ldap_schemes):
        conn = Connection(
            Server(uri, get_info=ALL, tls=tls),
            user=bind_dn,
            password=bind_password,
            auto_bind=True,
            auto_referrals=False,
            receive_timeout=15,
        )
    try:
        if not conn.search(group_base_dn, "(objectClass=*)", search_scope=SUBTREE, attributes=[group_name_attr], size_limit=int(limit)):
            return []
        groups = []
        for entry in conn.entries:
            if hasattr(entry, group_name_attr):
                values = [str(value) for value in getattr(entry, group_name_attr).values if str(value).strip()]
                groups.extend(values)
        return sorted(set(groups))
    finally:
        conn.unbind()

def ldap_enabled():
    return inbound_bool_setting("ldap_enabled", "NEWSLETTER_LDAP_ENABLED", False)

def ldap_allowed_group(group_name):
    configured = inbound_plain_setting("ldap_allowed_groups", "NEWSLETTER_LDAP_ALLOWED_GROUPS", "")
    allowed = csv_set_from_value(configured)
    return not allowed or "*" in allowed or str(group_name or "").strip().lower() in allowed

def freeipa_api_base_url(profile=None):
    value = (profile or {}).get("freeipa_api_url") or inbound_plain_setting("freeipa_api_url", "NEWSLETTER_FREEIPA_API_URL", "")
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value.rstrip("/")

def freeipa_api_recipients_from_group(group_name, profile=None):
    profile = profile or {}
    base_url = freeipa_api_base_url(profile)
    if not base_url:
        return None
    web_schemes = ("https",) if Config.OUTBOUND_POLICY_MODE == "enforce" else ("https", "http")

    try:
        import requests
    except ImportError as e:
        raise RuntimeError("Python package 'requests' is not installed.") from e

    username = profile.get("freeipa_api_user") or inbound_plain_setting("freeipa_api_user", "NEWSLETTER_FREEIPA_API_USER", "")
    password = profile_secret(profile.get("freeipa_api_password")) if profile.get("freeipa_api_password") else inbound_secret_setting("freeipa_api_password", "NEWSLETTER_FREEIPA_API_PASSWORD")
    if not username:
        bind_dn = profile.get("ldap_bind_dn") or inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", "")
        match = re.search(r"uid=([^,]+)", bind_dn, re.IGNORECASE)
        username = match.group(1) if match else ""
    if not password:
        password = profile_secret(profile.get("ldap_bind_password")) if profile.get("ldap_bind_password") else inbound_secret_setting("ldap_bind_password", "NEWSLETTER_LDAP_BIND_PASSWORD")
    if not username or not password:
        raise ValueError("FreeIPA API settings are incomplete. Check NEWSLETTER_FREEIPA_API_USER/PASSWORD or LDAP bind settings.")

    verify_tls = bool(profile.get("freeipa_api_verify_tls", inbound_bool_setting("freeipa_api_verify_tls", "NEWSLETTER_FREEIPA_API_VERIFY_TLS", True)))
    session = requests.Session()
    session.verify = True if outbound_policy_enforced() else verify_tls
    if outbound_policy_enforced():
        session.trust_env = False
    login_url = f"{base_url}/ipa/session/login_password"
    api_url = f"{base_url}/ipa/session/json"
    referer = f"{base_url}/ipa"

    with pinned_outbound_url(login_url, "FreeIPA API login", allowed_schemes=web_schemes):
        login = session.post(
            login_url,
            data={"user": username, "password": password},
            headers={
                "Referer": referer,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/plain",
            },
            timeout=20,
            allow_redirects=False,
        )
    login.raise_for_status()

    group_payload = {
        "method": "group_show",
        "params": [[group_name], {"all": True, "rights": False}],
        "id": 0,
    }
    with pinned_outbound_url(api_url, "FreeIPA API group lookup", allowed_schemes=web_schemes):
        group_response = session.post(
            api_url,
            json=group_payload,
            headers={"Referer": referer, "Content-Type": "application/json", "Accept": "application/json"},
            timeout=20,
            allow_redirects=False,
        )
    group_response.raise_for_status()
    group_data = group_response.json()
    if group_data.get("error"):
        raise ValueError(f"FreeIPA group lookup failed: {group_data['error']}")
    members = group_data.get("result", {}).get("result", {}).get("member_user", []) or []
    if not members:
        raise ValueError(f"FreeIPA group '{group_name}' has no user members.")

    user_email_attr = profile.get("ldap_user_email_attr") or inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail") or "mail"
    recipients = []
    skipped_without_email = 0
    for uid in members:
        user_payload = {
            "method": "user_show",
            "params": [[uid], {"all": True, "rights": False}],
            "id": 0,
        }
        with pinned_outbound_url(api_url, "FreeIPA API user lookup", allowed_schemes=web_schemes):
            user_response = session.post(
                api_url,
                json=user_payload,
                headers={"Referer": referer, "Content-Type": "application/json", "Accept": "application/json"},
                timeout=20,
                allow_redirects=False,
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

def ldap_recipients_from_group(group_name, profile=None):
    profile = profile or {}
    if profile and not profile.get("enabled", True):
        raise ValueError("Selected LDAP profile is disabled.")
    if not profile and not ldap_enabled():
        raise ValueError("LDAP group targets are disabled. Set NEWSLETTER_LDAP_ENABLED=true.")
    allowed = csv_set_from_value(profile.get("ldap_allowed_groups", "")) if profile else set()
    if profile and allowed and "*" not in allowed and str(group_name or "").strip().lower() not in allowed:
        raise PermissionError(f"LDAP group '{group_name}' is not allowed for selected LDAP profile.")
    if not profile and not ldap_allowed_group(group_name):
        raise PermissionError(f"LDAP group '{group_name}' is not allowed for inbound newsletter relay.")

    api_result = freeipa_api_recipients_from_group(group_name, profile)
    if api_result is not None:
        return api_result

    try:
        from ldap3 import ALL, BASE, SUBTREE, Connection, Server, Tls
        from ldap3.utils.conv import escape_filter_chars
    except ImportError as e:
        raise RuntimeError("Python package 'ldap3' is not installed.") from e

    uri = profile.get("ldap_uri") or inbound_plain_setting("ldap_uri", "NEWSLETTER_LDAP_URI", "")
    bind_dn = profile.get("ldap_bind_dn") or inbound_plain_setting("ldap_bind_dn", "NEWSLETTER_LDAP_BIND_DN", "")
    bind_password = profile_secret(profile.get("ldap_bind_password")) if profile.get("ldap_bind_password") else inbound_secret_setting("ldap_bind_password", "NEWSLETTER_LDAP_BIND_PASSWORD")
    base_dn = profile.get("ldap_base_dn") or inbound_plain_setting("ldap_base_dn", "NEWSLETTER_LDAP_BASE_DN", "")
    group_base_dn = profile.get("ldap_group_base_dn") or inbound_plain_setting("ldap_group_base_dn", "NEWSLETTER_LDAP_GROUP_BASE_DN", base_dn)
    group_name_attr = profile.get("ldap_group_name_attr") or inbound_plain_setting("ldap_group_name_attr", "NEWSLETTER_LDAP_GROUP_NAME_ATTR", "cn") or "cn"
    group_member_attr = profile.get("ldap_group_member_attr") or inbound_plain_setting("ldap_group_member_attr", "NEWSLETTER_LDAP_GROUP_MEMBER_ATTR", "member") or "member"
    user_email_attr = profile.get("ldap_user_email_attr") or inbound_plain_setting("ldap_user_email_attr", "NEWSLETTER_LDAP_USER_EMAIL_ATTR", "mail") or "mail"

    if not uri or not bind_dn or not bind_password or not group_base_dn:
        raise ValueError("LDAP settings are incomplete. Check NEWSLETTER_LDAP_URI, BIND_DN, BIND_PASSWORD and BASE_DN.")

    ldap_schemes = ("ldaps",) if Config.OUTBOUND_POLICY_MODE == "enforce" else ("ldap", "ldaps")
    tls = Tls(validate=ssl.CERT_REQUIRED) if outbound_policy_enforced() else None
    with pinned_outbound_url(uri, "LDAP directory", allowed_schemes=ldap_schemes):
        server = Server(uri, get_info=ALL, tls=tls)
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=True,
            auto_referrals=False,
            receive_timeout=15,
        )
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
            "--status-fd",
            "2",
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
        status_text = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        fingerprints = re.findall(r"\[GNUPG:\]\s+VALIDSIG\s+([A-Fa-f0-9]{40,64})\b", status_text)
        if proc.returncode != 0:
            return False, status_text or f"GPG decrypt failed with exit code {proc.returncode}", []
        return True, proc.stdout, [item.upper() for item in fingerprints]
    except subprocess.TimeoutExpired:
        return False, "GPG decrypt timed out after 30 seconds", []
    except Exception as e:
        return False, str(e), []
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
    body_html = sanitize_newsletter_html("\n\n".join(part.strip() for part in body_html_parts if part.strip()))
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
    return user.id if user else None

def resolve_mailbox_recipients(mailbox):
    configured_lists = split_config_values(mailbox.get("lists", []))
    configured_ldap_groups = split_config_values(mailbox.get("ldap_groups", []))
    if not configured_lists and not configured_ldap_groups:
        raise ValueError("Inbound mailbox has no mailing lists or LDAP groups configured.")

    recipients = set()
    list_counts = {}
    all_lists = load_list_records()
    for list_name in configured_lists:
        if list_name not in all_lists:
            raise ValueError(f"Mailing list '{list_name}' not found.")
        record = all_lists[list_name]
        resolved = set()
        invalid = []
        for item in record["entries"]:
            recipient = normalize_recipient(item, record["domain"])
            if not valid_email(recipient):
                invalid.append(str(item)[:200])
            else:
                resolved.add(recipient)
        if invalid:
            raise ValueError(
                f"Mailing list '{list_name}' contains aliases without a list domain or invalid addresses: "
                f"{', '.join(invalid[:5])}"
            )
        recipients.update(resolved)
        list_counts[list_name] = len(resolved)

    ldap_meta = {}
    selected_ldap_profile = ldap_profile_by_id(mailbox.get("ldap_profile")) if mailbox.get("ldap_profile") else None
    if configured_ldap_groups and mailbox.get("ldap_profile") and not selected_ldap_profile:
        raise ValueError(f"LDAP profile '{mailbox.get('ldap_profile')}' not found.")
    for group_name in configured_ldap_groups:
        group_recipients, group_meta = ldap_recipients_from_group(group_name, selected_ldap_profile)
        recipients.update(group_recipients)
        ldap_meta[group_name] = {
            "recipients_count": len(group_recipients),
            **group_meta,
        }

    clean_recipients = sorted(item for item in recipients if item)
    if not clean_recipients:
        raise ValueError("Inbound mailbox targets resolved to zero recipients.")
    return clean_recipients, {
        "source": "mailbox_rules",
        "mailbox": mailbox.get("name") or mailbox.get("imap_user"),
        "lists": configured_lists,
        "ldap_groups": configured_ldap_groups,
        "list_counts": list_counts,
        "ldap_meta": ldap_meta,
    }

def dispatch_inbound_newsletter(app, source_msg, decrypted_msg, mailbox, subject):
    with app.app_context():
        target_users, target_meta = resolve_mailbox_recipients(mailbox)
        log.info(
            "Newsletter inbound relay resolved mailbox %s to %s recipients.",
            mailbox.get("name") or mailbox.get("imap_user"),
            len(target_users),
        )

        profiles = load_smtp_profiles()
        configured_sender = str(mailbox.get("outbound_profile") or mailbox.get("sender_profile") or "").strip().lower()
        if configured_sender and configured_sender in profiles:
            sender_email, smtp_config = configured_sender, profiles[configured_sender]
        else:
            sender_email, smtp_config = resolve_inbound_sender_profile(profiles, mailbox.get("inbound_profile") or mailbox.get("imap_user", ""))
        if not sender_email:
            raise ValueError("No SMTP profile available for inbound newsletter relay.")
        route_keyserver = str(mailbox.get("recipient_keyserver") or "").strip()

        body_text, body_html, attachments = extract_body_and_attachments(decrypted_msg)
        if not (body_text or html_to_text(body_html)):
            raise ValueError("Decrypted message body is empty.")

        user_id = system_user_id()
        if user_id is None:
            raise ValueError("Inbound processing requires at least one WinHUB user account.")
        from_email = parseaddr(source_msg.get("From", ""))[1].lower()
        message_id = str(source_msg.get("Message-ID") or "").strip()
        if not message_id or len(message_id) > 998:
            raise ValueError("Inbound message requires a valid Message-ID header.")
        message_id_hash = hashlib.sha256(message_id.encode("utf-8")).hexdigest() if message_id else None
        existing_message = NewsletterCampaign.query.filter_by(source_message_id_hash=message_id_hash).first() if message_id_hash else None
        if existing_message:
            raise ValueError("Inbound message was already accepted.")

        campaign = enqueue_campaign(
            user_id=user_id,
            source="inbound",
            sender_email=sender_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
            recipients=target_users,
            selected_lists=target_meta.get("lists", []) + [f"ldap:{name}" for name in target_meta.get("ldap_groups", [])],
            use_gpg=True,
            source_message_id_hash=message_id_hash,
            keyserver_override=route_keyserver,
        )

        WinHubCore.audit(
            user_id=user_id,
            username="Newsletter Inbound",
            module="Newsletter",
            action="Inbound Mailing",
            details={
                "from": from_email,
                "mailbox": mailbox.get("name") or mailbox.get("imap_user"),
                "subject": subject,
                "recipients_count": len(target_users),
                "message_id": message_id,
                "campaign_id": campaign.id,
                "use_gpg": True,
                "attachments_count": len(attachments),
                **target_meta,
            },
            status="Success",
        )

        return campaign.task_id

def process_inbound_message(app, imap, uid, raw_message, mailbox):
    msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    subject = str(msg.get("Subject") or "Newsletter").strip() or "Newsletter"

    from_email = parseaddr(msg.get("From", ""))[1].lower()
    allowed = {str(item).strip().lower() for item in mailbox.get("allowed_senders", []) if str(item).strip()}
    if "*" not in allowed and from_email not in allowed:
        raise PermissionError(f"Sender '{from_email}' is not allowed.")

    encrypted_payload = extract_pgp_encrypted_payload(msg)
    if not encrypted_payload:
        raise ValueError("Inbound message is not PGP encrypted.")

    passphrase = mailbox_gpg_passphrase(mailbox)
    gpg_path = app.config.get("GPG_PATH") or os.environ.get("GPG_PATH", "gpg")
    ok, decrypted, signer_fingerprints = decrypt_with_gpg(gpg_path, encrypted_payload, passphrase)
    if not ok:
        raise ValueError(f"Could not decrypt inbound message: {decrypted}")
    allowed_fingerprints = {
        re.sub(r"\s+", "", str(item)).upper()
        for item in mailbox.get("allowed_signer_fingerprints", [])
        if str(item).strip()
    }
    if not allowed_fingerprints:
        raise PermissionError("Inbound route has no allowed GPG signer fingerprints configured.")
    if not allowed_fingerprints.intersection(signer_fingerprints):
        raise PermissionError("Inbound message does not have an approved valid GPG signature.")

    decrypted_msg = parse_decrypted_message(decrypted)
    task_id = dispatch_inbound_newsletter(app, msg, decrypted_msg, mailbox, subject)
    imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
    return task_id

def poll_inbound_mailbox(app, mailbox):
    if not mailbox.get("enabled", True):
        return
    profiles = load_smtp_profiles()
    inbound_profile = profiles.get(str(mailbox.get("inbound_profile") or "").strip().lower()) or {}
    host = str(inbound_profile.get("imap_host") or mailbox.get("imap_host") or "").strip()
    user = str(inbound_profile.get("imap_user") or mailbox.get("imap_user") or inbound_profile.get("email") or "").strip()
    password = mailbox_imap_password(mailbox)
    if not host or not user or not password:
        log.warning("Newsletter inbound mailbox '%s' is incomplete; IMAP host/user/password is required.", mailbox.get("name") or user or "unnamed")
        return

    port = int(inbound_profile.get("imap_port") or mailbox.get("imap_port") or 993)
    use_ssl = bool(inbound_profile.get("imap_ssl", mailbox.get("imap_ssl", True)))
    folder = inbound_profile.get("imap_folder") or mailbox.get("imap_folder") or "INBOX"
    processed_folder = inbound_profile.get("processed_folder") or mailbox.get("processed_folder") or "Processed"
    failed_folder = inbound_profile.get("failed_folder") or mailbox.get("failed_folder") or "Failed"
    mailbox_label = mailbox.get("name") or user

    imap = None
    try:
        imap = open_imap_connection(host, port, use_ssl, "newsletter IMAP")
        imap.login(user, password)
        imap.select(folder)
        typ, data = imap.uid("SEARCH", None, "UNSEEN")
        if typ != "OK":
            raise RuntimeError("IMAP search failed.")
        for uid in (data[0] or b"").split():
            try:
                typ, fetched = imap.uid("FETCH", uid, "(BODY.PEEK[])")
                if typ != "OK" or not fetched:
                    raise RuntimeError("IMAP fetch failed.")
                raw = None
                for item in fetched:
                    if isinstance(item, tuple):
                        raw = item[1]
                        break
                if not raw:
                    raise RuntimeError("IMAP message body is empty.")
                task_id = process_inbound_message(app, imap, uid, raw, mailbox)
                log.info("Newsletter inbound relay accepted mailbox %s UID %s as task %s", mailbox_label, uid.decode(errors="replace"), task_id)
                move_imap_message(imap, uid, processed_folder)
            except Exception as e:
                log.error("Newsletter inbound relay rejected mailbox %s UID %s: %s", mailbox_label, uid.decode(errors="replace"), e)
                try:
                    imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
                    move_imap_message(imap, uid, failed_folder)
                except Exception:
                    log.error("Newsletter inbound relay could not move failed mailbox %s UID %s", mailbox_label, uid.decode(errors="replace"))
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
                mailboxes = [mailbox for mailbox in inbound_mailboxes(include_legacy=True) if mailbox.get("enabled", True)]
                if not mailboxes:
                    log.debug("Newsletter inbound relay has no enabled mailboxes.")
                for mailbox in mailboxes:
                    poll_inbound_mailbox(app, mailbox)
        except Exception:
            log.error("Newsletter inbound relay poll failed: %s", traceback.format_exc())
        time.sleep(poll_seconds)

def start_module(app):
    global _inbound_worker_started
    # Production runs a single durable worker through winhub-newsletter.service.
    # Embedded mode is retained only for explicit local-development use.
    if not env_bool("NEWSLETTER_EMBEDDED_WORKER", False):
        return
    with _inbound_worker_lock:
        if _inbound_worker_started:
            return
        _inbound_worker_started = True
        thread = threading.Thread(target=run_newsletter_worker, args=(app,), daemon=True)
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
    atomic_json_write(SMTP_FILE, data)

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
    atomic_json_write(INBOUND_FILE, data)

def safe_inbound_settings():
    settings = load_inbound_settings()
    allowed = settings.get("allowed_senders")
    if not isinstance(allowed, list):
        allowed = sorted(inbound_allowed_senders())
    return {
        "allowed_senders": allowed,
        "sender_profile": inbound_sender_profile_setting(),
        "passphrase_saved": bool(settings.get("gpg_passphrase") or os.environ.get("NEWSLETTER_INBOUND_GPG_PASSPHRASE")),
        "env_enabled": inbound_relay_enabled(),
        "imap_user": os.environ.get("NEWSLETTER_INBOUND_IMAP_USER", ""),
        "mailboxes": safe_inbound_mailboxes(),
        "ldap_profiles": safe_ldap_profiles(),
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
        if value == "*" and outbound_policy_enforced():
            raise ValueError("Wildcard inbound senders are blocked in outbound enforce mode.")
        if value not in seen:
            seen.add(value)
            clean.append(value)
    return clean

def normalize_list_record(raw):
    if isinstance(raw, list):
        return {"schema": 1, "domain": "", "keyserver": "", "entries": raw}
    if not isinstance(raw, dict):
        return {"schema": 2, "domain": "", "keyserver": "", "entries": []}
    entries = raw.get("entries", raw.get("users", []))
    return {
        "schema": 2,
        "domain": normalize_domain_suffix(raw.get("domain")),
        "keyserver": str(raw.get("keyserver") or "").strip(),
        "entries": entries if isinstance(entries, list) else [],
    }


def load_list_records():
    lists = {}
    for filename in os.listdir(LISTS_DIR):
        if filename.endswith(".json"):
            list_name = filename[:-5]
            try:
                filepath = list_file_path(list_name)
            except ValueError:
                log.warning("Ignoring unsafe Newsletter list filename: %s", filename)
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lists[list_name] = normalize_list_record(json.load(f))
            except Exception:
                log.exception("Could not load Newsletter list %s", list_name)
                lists[list_name] = normalize_list_record([])
    return lists


def load_lists():
    return {name: record["entries"] for name, record in load_list_records().items()}


def resolve_campaign_recipients(selected_lists, domain=None):
    if not isinstance(selected_lists, list):
        raise ValueError("Target lists must be an array.")
    all_lists = load_list_records()
    unknown = sorted({str(name) for name in selected_lists if str(name) not in all_lists})
    if unknown:
        raise ValueError(f"Unknown mailing list: {', '.join(unknown)}")
    recipients = set()
    invalid = []
    per_list = {}
    for list_name in selected_lists:
        record = all_lists[list_name]
        resolved = []
        for raw in record["entries"]:
            recipient = normalize_recipient(raw, record["domain"])
            if not valid_email(recipient):
                invalid.append({"list": list_name, "value": str(raw)[:200]})
                continue
            recipients.add(recipient)
            resolved.append(recipient)
        per_list[list_name] = len(set(resolved))
    return sorted(recipients), invalid, per_list


def attachment_snapshot(attachments):
    return json.dumps([
        {
            "filename": item["filename"],
            "content_type": item["content_type"],
            "content": base64.b64encode(item["content"]).decode("ascii"),
        }
        for item in attachments or []
    ], ensure_ascii=False)


def attachment_restore(snapshot):
    restored = []
    for item in json.loads(snapshot or "[]"):
        restored.append({
            "filename": str(item.get("filename") or "attachment"),
            "content_type": str(item.get("content_type") or "application/octet-stream"),
            "content": base64.b64decode(str(item.get("content") or ""), validate=True),
        })
    return restored


def campaign_summary(campaign, include_subject=False, include_error=False):
    result = {
        "id": campaign.id,
        "task_id": campaign.task_id,
        "source": campaign.source,
        "sender": campaign.sender_email,
        "status": campaign.status,
        "use_gpg": bool(campaign.use_gpg),
        "total_count": campaign.total_count,
        "sent_count": campaign.sent_count,
        "failed_count": campaign.failed_count,
        "skipped_count": campaign.skipped_count,
        "cancel_requested": bool(campaign.cancel_requested),
        "created_at": campaign.created_at.isoformat() + "Z" if campaign.created_at else None,
        "started_at": campaign.started_at.isoformat() + "Z" if campaign.started_at else None,
        "ended_at": campaign.ended_at.isoformat() + "Z" if campaign.ended_at else None,
        "error_summary": (
            campaign.error_summary
            if include_error
            else ("Campaign processing failed. Contact an administrator." if campaign.error_summary else "")
        ),
    }
    if include_subject:
        result["subject"] = campaign.subject
        result["lists"] = json.loads(campaign.selected_lists_json or "[]")
    return result


def can_view_campaign(user, campaign):
    return bool(user and (
        campaign.user_id == user.id
        or has_permission(user, "Newsletter", "view_all_campaigns")
    ))


def enqueue_campaign(*, user_id, source, sender_email, subject, body_text, body_html, attachments, recipients, selected_lists, use_gpg, source_message_id_hash=None, keyserver_override=None):
    subject = str(subject or "").strip()
    if not subject:
        raise ValueError("Subject is required.")
    if "\r" in subject or "\n" in subject or len(subject) > 998:
        raise ValueError("Subject contains invalid characters or is too long.")
    if not recipients:
        raise ValueError("No valid recipients were resolved.")

    task_id = str(uuid.uuid4())
    campaign_id = str(uuid.uuid4())
    log_file = os.path.join(current_app.config['DATA_DIR'], 'logs', f"task_{task_id}.log")
    ensure_parent_dir(log_file)
    targets_db = ", ".join(selected_lists or []) or source.title()
    if len(targets_db) > 50:
        targets_db = targets_db[:47] + "..."

    task = Task(
        id=task_id, user_id=user_id, module_name="Newsletter",
        action="Inbound Mailing" if source == "inbound" else "Send Mailing",
        targets=targets_db, status="Queued", log_file=log_file,
    )
    campaign = NewsletterCampaign(
        id=campaign_id,
        task_id=task_id,
        user_id=user_id,
        source=source,
        source_message_id_hash=source_message_id_hash,
        sender_email=sender_email,
        keyserver_override=keyserver_override or None,
        subject=subject,
        body_text=body_text or "",
        body_html=body_html or "",
        attachments_json=attachment_snapshot(attachments),
        selected_lists_json=json.dumps(selected_lists or [], ensure_ascii=False),
        use_gpg=bool(use_gpg),
        status="Queued",
        total_count=len(recipients),
    )
    # NewsletterCampaign has a database FK to Task, but there is intentionally no
    # ORM relationship between the generic task log and campaign snapshot. Flush
    # the parent explicitly so PostgreSQL never receives the campaign INSERT first.
    db.session.add(task)
    db.session.flush()
    db.session.add(campaign)
    for recipient in sorted(set(recipients)):
        db.session.add(NewsletterDelivery(
            campaign_id=campaign_id,
            recipient=recipient,
            recipient_hash=hashlib.sha256(recipient.lower().encode("utf-8")).hexdigest(),
            status="Pending",
        ))
    db.session.commit()
    return campaign

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
    can_manage_inbound = has_permission(current_user(), "Newsletter", "manage_inbound_routes")
    can_manage_lists = has_permission(current_user(), "Newsletter", "manage_lists")
    profiles = load_smtp_profiles()

    senders = []
    for email, conf in profiles.items():
        if can_manage_smtp:
            senders.append(safe_mail_profile(email, conf))
        else:
            senders.append({"email": email})

    list_records = load_list_records()
    all_lists = {name: record["entries"] for name, record in list_records.items()}

    # Маскуємо дані списків для звичайних користувачів
    if not can_manage_lists:
        all_lists = {k: [] for k in all_lists.keys()}

    payload = {
        "success": True,
        "senders": senders,
        "lists": all_lists,
        "list_metadata": {
            name: {"domain": record["domain"], "keyserver": record["keyserver"]}
            for name, record in list_records.items()
        } if can_manage_lists else {},
        "limits": {
            "max_attachments": MAX_ATTACHMENTS,
            "max_attachment_bytes": MAX_ATTACHMENT_BYTES,
            "max_total_attachment_bytes": MAX_TOTAL_ATTACHMENT_BYTES,
        },
        "readiness": {
            "mail_profiles": len(profiles),
            "mailing_lists": len(all_lists),
            "worker_active": (
                os.path.exists(WORKER_HEARTBEAT_FILE)
                and time.time() - os.path.getmtime(WORKER_HEARTBEAT_FILE) < max(30, env_int("NEWSLETTER_WORKER_POLL_SECONDS", 5, 1) * 4)
            ),
        },
    }
    if can_manage_inbound:
        payload["inbound"] = safe_inbound_settings()
    return jsonify(payload)

@newsletter_bp.route("/api/newsletter/smtp", methods=["POST"])
def manage_smtp():
    denied = require_permission("manage_smtp")
    if denied: return denied

    data = request.json or {}
    action = data.get("action")
    email = str(data.get("email") or "").strip().lower()

    if not email: return jsonify({"success": False, "message": "Email is required."}), 400

    profiles = load_smtp_profiles()

    if action == "add":
        original_email = str(data.get("original_email") or email).strip().lower()
        existing = profiles.get(original_email, profiles.get(email, {}))
        try:
            profile = normalize_mail_profile(email, data, existing=existing, for_save=True)
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
        if not profile.get("host"):
            return jsonify({"success": False, "message": "SMTP host is required."}), 400
        if not profile.get("password"):
            return jsonify({"success": False, "message": "SMTP password is required."}), 400
        if original_email != email:
            if email in profiles:
                return jsonify({"success": False, "message": "A mail profile with this email already exists."}), 409
            profiles.pop(original_email, None)
            settings = load_inbound_settings()
            changed = False
            for mailbox in settings.get("mailboxes", []):
                if not isinstance(mailbox, dict):
                    continue
                for field in ("inbound_profile", "outbound_profile", "sender_profile"):
                    if str(mailbox.get(field) or "").strip().lower() == original_email:
                        mailbox[field] = email
                        changed = True
            if str(settings.get("sender_profile") or "").strip().lower() == original_email:
                settings["sender_profile"] = email
                changed = True
            if changed:
                save_inbound_settings(settings)
        profiles[email] = profile
        save_smtp_profiles(profiles)

    elif action == "delete":
        dependent_routes = [
            item.get("name") or item.get("id")
            for item in inbound_mailboxes(include_legacy=False)
            if item.get("inbound_profile") == email or item.get("outbound_profile") == email
        ]
        if dependent_routes:
            return jsonify({
                "success": False,
                "message": f"Profile is used by inbound routes: {', '.join(dependent_routes)}",
            }), 409
        if email in profiles:
            del profiles[email]
            save_smtp_profiles(profiles)

    else:
        return jsonify({"success": False, "message": "Unknown action."}), 400

    WinHubCore.audit(
        user_id=session.get("user_id"), username=session.get("username"), module="Newsletter",
        action="Mail Profile Updated" if action == "add" else "Mail Profile Deleted",
        details={"profile": email}, status="Success",
    )
    return jsonify({"success": True, "message": "SMTP configuration updated."})

@newsletter_bp.route("/api/newsletter/test/mail", methods=["POST"])
def test_mail_profile():
    denied = require_permission("manage_smtp")
    if denied: return denied

    data = request.json or {}
    profiles = load_smtp_profiles()
    email = str(data.get("email") or "").strip().lower()
    existing = profiles.get(email, {})
    try:
        profile = normalize_mail_profile(email, data, existing=existing, for_save=False)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    smtp_result = {"ok": False, "message": "SMTP not tested."}
    imap_result = {"ok": False, "message": "IMAP not tested."}

    if profile.get("host") and profile.get("password"):
        try:
            smtp_password = profile_secret(profile.get("password"))
            smtp = open_smtp_connection(profile["host"], int(profile.get("port") or 587), "newsletter SMTP test")
            smtp.login(profile["email"], smtp_password)
            test_message = EmailMessage(policy=policy.SMTP)
            test_message["Subject"] = "WinHUB Newsletter profile test"
            test_message["From"] = profile["email"]
            test_message["To"] = profile["email"]
            test_message.set_content("WinHUB successfully authenticated and sent this test message.")
            smtp.send_message(test_message)
            smtp.quit()
            smtp_result = {"ok": True, "message": f"SMTP login and test delivery to {profile['email']} succeeded."}
        except Exception as e:
            smtp_result = {"ok": False, "message": f"SMTP failed: {e}"}

    if profile.get("imap_host") and profile.get("imap_user") and profile.get("imap_password"):
        imap = None
        try:
            imap_password = profile_secret(profile.get("imap_password"))
            imap = open_imap_connection(
                profile["imap_host"],
                int(profile.get("imap_port") or 993),
                bool(profile.get("imap_ssl", True)),
                "newsletter IMAP test",
            )
            imap.login(profile["imap_user"], imap_password)
            typ, _ = imap.select(profile.get("imap_folder") or "INBOX", readonly=True)
            if typ != "OK":
                raise RuntimeError(f"Cannot select folder {profile.get('imap_folder') or 'INBOX'}")
            imap_result = {"ok": True, "message": "IMAP login and folder check OK."}
        except Exception as e:
            imap_result = {"ok": False, "message": f"IMAP failed: {e}"}
        finally:
            if imap:
                try:
                    imap.logout()
                except Exception:
                    pass

    imap_configured = bool(profile.get("imap_host") or profile.get("imap_password"))
    return jsonify({
        "success": smtp_result["ok"] and (not imap_configured or imap_result["ok"]),
        "smtp": smtp_result,
        "imap": imap_result,
    })

@newsletter_bp.route("/api/newsletter/test/ldap", methods=["POST"])
def test_ldap_profile():
    denied = require_permission("manage_inbound_routes")
    if denied: return denied

    data = request.json or {}
    profile_id = str(data.get("id") or "").strip()
    existing = ldap_profile_by_id(profile_id) if profile_id else None
    profile = normalize_ldap_profile(data, existing=existing, for_save=False)
    try:
        groups = ldap_profile_groups(profile)
        return jsonify({"success": True, "message": "LDAP profile test OK.", "groups": groups, "groups_count": len(groups)})
    except Exception as e:
        return jsonify({"success": False, "message": str(e), "groups": []}), 400

@newsletter_bp.route("/api/newsletter/inbound", methods=["GET", "POST"])
def manage_inbound_relay():
    denied = require_permission("manage_inbound_routes")
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

    incoming_ldap_profiles = data.get("ldap_profiles")
    if isinstance(incoming_ldap_profiles, list):
        existing_ldap_by_id = {
            str(item.get("id")): item
            for item in settings.get("ldap_profiles", [])
            if isinstance(item, dict) and item.get("id")
        }
        saved_ldap_profiles = []
        seen_ldap_ids = set()
        for raw_profile in incoming_ldap_profiles:
            if not isinstance(raw_profile, dict):
                continue
            existing = existing_ldap_by_id.get(str(raw_profile.get("id") or ""))
            profile = normalize_ldap_profile(raw_profile, existing=existing, for_save=True)
            if profile["id"] in seen_ldap_ids:
                return jsonify({"success": False, "message": "LDAP profile IDs must be unique."}), 400
            seen_ldap_ids.add(profile["id"])
            saved_ldap_profiles.append(profile)
        settings["ldap_profiles"] = saved_ldap_profiles

    incoming_mailboxes = data.get("mailboxes")
    if isinstance(incoming_mailboxes, list):
        existing_by_id = {
            str(item.get("id")): item
            for item in settings.get("mailboxes", [])
            if isinstance(item, dict) and item.get("id")
        }
        known_lists = load_list_records()
        saved_mailboxes = []
        seen_mailbox_ids = set()
        for raw_mailbox in incoming_mailboxes:
            if not isinstance(raw_mailbox, dict):
                continue
            existing = existing_by_id.get(str(raw_mailbox.get("id") or ""))
            try:
                mailbox = normalize_inbound_mailbox(raw_mailbox, existing=existing, for_save=True)
            except ValueError as e:
                return jsonify({"success": False, "message": str(e)}), 400
            if mailbox["id"] in seen_mailbox_ids:
                return jsonify({"success": False, "message": "Inbound mailbox IDs must be unique."}), 400
            seen_mailbox_ids.add(mailbox["id"])
            if mailbox.get("enabled"):
                if not mailbox.get("inbound_profile"):
                    return jsonify({"success": False, "message": f"Inbound mail profile is required for route '{mailbox.get('name')}'."}), 400
                if mailbox.get("inbound_profile") not in profiles:
                    return jsonify({"success": False, "message": f"Inbound mail profile '{mailbox.get('inbound_profile')}' not found."}), 400
                inbound_profile = profiles[mailbox.get("inbound_profile")]
                if not (inbound_profile.get("imap_host") and inbound_profile.get("imap_user") and inbound_profile.get("imap_password")):
                    return jsonify({"success": False, "message": f"Inbound mail profile '{mailbox.get('inbound_profile')}' needs IMAP host, user and password."}), 400
                if not mailbox.get("allowed_senders"):
                    return jsonify({"success": False, "message": f"Allowed senders are required for mailbox '{mailbox.get('name')}'."}), 400
                if not mailbox.get("allowed_signer_fingerprints"):
                    return jsonify({"success": False, "message": f"At least one approved GPG signer fingerprint is required for mailbox '{mailbox.get('name')}'."}), 400
                if not mailbox.get("lists") and not mailbox.get("ldap_groups"):
                    return jsonify({"success": False, "message": f"At least one mailing list or LDAP group is required for mailbox '{mailbox.get('name')}'."}), 400
            if mailbox.get("outbound_profile") and mailbox["outbound_profile"] not in profiles:
                return jsonify({"success": False, "message": f"Outbound mail profile '{mailbox['outbound_profile']}' not found."}), 400
            if mailbox.get("ldap_groups") and not mailbox.get("ldap_profile"):
                return jsonify({"success": False, "message": f"LDAP profile is required for route '{mailbox.get('name')}' because LDAP groups are configured."}), 400
            if mailbox.get("ldap_groups") and mailbox.get("ldap_profile") and not any(item.get("id") == mailbox.get("ldap_profile") for item in settings.get("ldap_profiles", [])):
                return jsonify({"success": False, "message": f"LDAP profile '{mailbox['ldap_profile']}' not found."}), 400
            missing_lists = [name for name in mailbox.get("lists", []) if name not in known_lists]
            if missing_lists:
                return jsonify({"success": False, "message": f"Unknown mailing list: {', '.join(missing_lists)}"}), 400
            saved_mailboxes.append(mailbox)
        settings["mailboxes"] = saved_mailboxes

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
                "mailboxes_count": len(settings.get("mailboxes", [])),
                "mailbox_passphrases_saved": sum(1 for item in settings.get("mailboxes", []) if isinstance(item, dict) and item.get("gpg_passphrase")),
                "ldap_enabled": bool(settings.get("ldap_enabled")),
                "ldap_bind_password_saved": bool(settings.get("ldap_bind_password")),
                "freeipa_api_password_saved": bool(settings.get("freeipa_api_password")),
            },
            status="Success",
        )
    except Exception as e:
        log.error(f"Failed to audit Newsletter inbound settings update: {e}")

    start_module(current_app._get_current_object())
    return jsonify({"success": True, "inbound": safe_inbound_settings()})

@newsletter_bp.route("/api/newsletter/lists", methods=["POST"])
def save_list():
    denied = require_permission("manage_lists")
    if denied: return denied

    data = request.json or {}
    try:
        list_name = normalize_list_name(data.get("list_name"))
        original_name = normalize_list_name(data.get("original_list_name")) if data.get("original_list_name") else list_name
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    users = data.get("users", [])
    domain = normalize_domain_suffix(data.get("domain"))
    keyserver = str(data.get("keyserver") or "").strip()

    if not isinstance(users, list):
        return jsonify({"success": False, "message": "Users must be an array."}), 400
    if len(users) > 10000:
        return jsonify({"success": False, "message": "A mailing list may contain at most 10,000 entries."}), 400

    clean_users = []
    seen = set()
    invalid = []
    for raw in users:
        value = str(raw or "").strip()
        if not value:
            continue
        normalized = normalize_recipient(value, domain)
        if not valid_email(normalized):
            invalid.append(value[:200])
            continue
        if normalized not in seen:
            seen.add(normalized)
            clean_users.append(value)
    if invalid:
        return jsonify({"success": False, "message": f"Invalid recipient addresses: {', '.join(invalid[:5])}"}), 400
    if not clean_users:
        return jsonify({"success": False, "message": "List cannot be empty."}), 400

    filepath = list_file_path(list_name)
    atomic_json_write(filepath, {
        "schema": 2,
        "domain": domain,
        "keyserver": keyserver,
        "entries": clean_users,
    })
    if original_name != list_name:
        settings = load_inbound_settings()
        changed = False
        for mailbox in settings.get("mailboxes", []):
            if not isinstance(mailbox, dict):
                continue
            lists = split_config_values(mailbox.get("lists", []))
            if original_name in lists:
                mailbox["lists"] = [list_name if item == original_name else item for item in lists]
                changed = True
        if changed:
            save_inbound_settings(settings)
        old_path = list_file_path(original_name)
        if old_path != filepath and os.path.exists(old_path):
            os.remove(old_path)

    WinHubCore.audit(
        user_id=session.get("user_id"), username=session.get("username"), module="Newsletter",
        action="Mailing List Saved", details={
            "list": list_name,
            "recipients_count": len(clean_users),
            "domain_configured": bool(domain),
            "keyserver_configured": bool(keyserver),
        }, status="Success",
    )

    return jsonify({"success": True, "message": "List saved successfully."})


@newsletter_bp.route("/api/newsletter/lists/<list_name>/gpg-check", methods=["POST"])
def check_list_gpg_keys(list_name):
    denied = require_permission("check_recipient_keys")
    if denied:
        return denied
    try:
        list_name = normalize_list_name(list_name)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    record = load_list_records().get(list_name)
    if not record:
        return jsonify({"success": False, "message": "Mailing list not found."}), 404
    refresh = bool((request.json or {}).get("refresh"))
    if refresh:
        denied = require_permission("refresh_recipient_keys")
        if denied:
            return denied
        if not record["keyserver"]:
            return jsonify({"success": False, "message": "Configure a keyserver for this list first."}), 400
        if not env_bool("NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT", False):
            return jsonify({
                "success": False,
                "message": "Key import is disabled. Set NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT=true after approving the keyserver trust policy.",
            }), 409

    try:
        recipients, invalid, _ = resolve_campaign_recipients([list_name])
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    if invalid:
        return jsonify({"success": False, "message": "Fix invalid list entries before checking keys.", "invalid_recipients": invalid}), 400

    gpg_path = current_app.config.get("GPG_PATH") or os.environ.get("GPG_PATH", "gpg")
    gpg_ok, gpg_message = validate_gpg(gpg_path)
    if not gpg_ok:
        return jsonify({"success": False, "message": f"GPG unavailable: {gpg_message}"}), 400

    results = []
    refreshed = 0
    for recipient in recipients:
        before = get_gpg_key_status(gpg_path, recipient)
        fetch_message = ""
        if refresh and not before["usable"]:
            fetch_ok, fetch_message = fetch_gpg_key(gpg_path, record["keyserver"], recipient)
            if fetch_ok:
                refreshed += 1
        after = get_gpg_key_status(gpg_path, recipient)
        results.append({"email": recipient, **after, "refresh_message": fetch_message})

    if refresh:
        WinHubCore.audit(
            user_id=session.get("user_id"), username=session.get("username"), module="Newsletter",
            action="Recipient GPG Keys Refreshed",
            details={"list": list_name, "requested": len(recipients), "refreshed": refreshed}, status="Success",
        )
    return jsonify({
        "success": True,
        "list": list_name,
        "results": results,
        "total": len(results),
        "usable": sum(1 for item in results if item["usable"]),
        "unusable": sum(1 for item in results if not item["usable"]),
        "refreshed": refreshed,
    })

@newsletter_bp.route("/api/newsletter/lists/<list_name>", methods=["DELETE"])
def delete_list(list_name):
    denied = require_permission("manage_lists")
    if denied: return denied

    try:
        list_name = normalize_list_name(list_name)
        filepath = list_file_path(list_name)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    dependent_routes = [
        item.get("name") or item.get("id")
        for item in inbound_mailboxes(include_legacy=False)
        if list_name in split_config_values(item.get("lists", []))
    ]
    if dependent_routes:
        return jsonify({"success": False, "message": f"List is used by inbound routes: {', '.join(dependent_routes)}"}), 409
    if os.path.exists(filepath): os.remove(filepath)
    WinHubCore.audit(
        user_id=session.get("user_id"), username=session.get("username"), module="Newsletter",
        action="Mailing List Deleted", details={"list": list_name}, status="Success",
    )
    return jsonify({"success": True})

@newsletter_bp.route("/api/newsletter/send", methods=["POST"])
def send_newsletter():
    denied = require_permission("send_campaigns")
    if denied: return denied
    data = request.json or {}
    sender_email = str(data.get("sender") or "").strip().lower()
    selected_lists = data.get("lists", [])
    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "").strip()
    body_html = sanitize_newsletter_html(data.get("body_html"))
    use_gpg = bool(data.get("use_gpg", True))
    try:
        attachments = normalize_attachments(data.get("attachments", []))
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    user_id = session.get('user_id')
    if not sender_email or not selected_lists or not subject or not (body or html_to_text(body_html)):
        return jsonify({"success": False, "message": "Please fill in all required fields."}), 400

    profiles = load_smtp_profiles()
    if sender_email not in profiles:
        return jsonify({"success": False, "message": "Sender profile not found."}), 404

    try:
        target_users, invalid, _ = resolve_campaign_recipients(selected_lists)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    if invalid:
        return jsonify({"success": False, "message": "Selected lists contain invalid recipient addresses. Edit the lists and run preflight again."}), 400
    try:
        campaign = enqueue_campaign(
            user_id=user_id,
            source="manual",
            sender_email=sender_email,
            subject=subject,
            body_text=body,
            body_html=body_html,
            attachments=attachments,
            recipients=target_users,
            selected_lists=selected_lists,
            use_gpg=use_gpg,
        )
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    try:
        WinHubCore.audit(
            user_id=user_id,
            username=session.get('username'),
            module="Newsletter",
            action="Send Mailing",
            details={
                "sender": sender_email,
                "lists": selected_lists,
                "campaign_id": campaign.id,
                "recipients_count": len(target_users),
                "use_gpg": use_gpg,
                "attachments_count": len(attachments),
            },
            status="Success"
        )
    except Exception as e:
        log.error(f"Failed to audit Newsletter mailing start: {e}")

    return jsonify({"success": True, "campaign": campaign_summary(campaign, include_subject=True)}), 202


@newsletter_bp.route("/api/newsletter/preflight", methods=["POST"])
def newsletter_preflight():
    denied = require_permission("send_campaigns")
    if denied:
        return denied
    data = request.json or {}
    sender_email = str(data.get("sender") or "").strip().lower()
    selected_lists = data.get("lists") or []
    profiles = load_smtp_profiles()
    if sender_email not in profiles:
        return jsonify({"success": False, "message": "Sender profile not found."}), 404
    try:
        recipients, invalid, per_list = resolve_campaign_recipients(selected_lists)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    use_gpg = bool(data.get("use_gpg", True))
    missing_keys = []
    if use_gpg:
        gpg_path = current_app.config.get('GPG_PATH') or os.environ.get('GPG_PATH', 'gpg')
        gpg_ok, gpg_message = validate_gpg(gpg_path)
        if not gpg_ok:
            return jsonify({"success": False, "message": f"GPG unavailable: {gpg_message}"}), 400
        for recipient in recipients:
            if not get_gpg_key_status(gpg_path, recipient).get("usable"):
                missing_keys.append(recipient)

    return jsonify({
        "success": not invalid and not missing_keys and bool(recipients),
        "message": "Ready to send." if recipients and not invalid and not missing_keys else "Resolve the reported issues before sending.",
        "recipients_count": len(recipients),
        "invalid_recipients": invalid[:50],
        "missing_gpg_keys": missing_keys[:50],
        "missing_gpg_keys_count": len(missing_keys),
        "per_list": per_list,
    })


@newsletter_bp.route("/api/newsletter/campaigns", methods=["GET"])
def list_newsletter_campaigns():
    denied = require_permission("view_newsletter")
    if denied:
        return denied
    user = current_user()
    query = NewsletterCampaign.query.order_by(NewsletterCampaign.created_at.desc())
    can_view_all = has_permission(user, "Newsletter", "view_all_campaigns")
    if not can_view_all:
        query = query.filter_by(user_id=user.id)
    campaigns = query.limit(50).all()
    return jsonify({
        "success": True,
        "campaigns": [
            campaign_summary(item, include_subject=True, include_error=can_view_all)
            for item in campaigns
        ],
    })


@newsletter_bp.route("/api/newsletter/campaigns/<campaign_id>", methods=["GET"])
def get_newsletter_campaign(campaign_id):
    denied = require_permission("view_newsletter")
    if denied:
        return denied
    campaign = db.session.get(NewsletterCampaign, campaign_id)
    if not campaign or not can_view_campaign(current_user(), campaign):
        return jsonify({"success": False, "message": "Campaign not found."}), 404
    user = current_user()
    return jsonify({
        "success": True,
        "campaign": campaign_summary(
            campaign,
            include_subject=True,
            include_error=has_permission(user, "Newsletter", "view_all_campaigns"),
        ),
    })


@newsletter_bp.route("/api/newsletter/campaigns/<campaign_id>/cancel", methods=["POST"])
def cancel_newsletter_campaign(campaign_id):
    denied = require_permission("send_campaigns")
    if denied:
        return denied
    campaign = db.session.get(NewsletterCampaign, campaign_id)
    if not campaign or not can_view_campaign(current_user(), campaign):
        return jsonify({"success": False, "message": "Campaign not found."}), 404
    if campaign.status in {"Completed", "Partial", "Failed", "Cancelled"}:
        return jsonify({"success": False, "message": "Campaign is already finished."}), 409
    campaign.cancel_requested = True
    db.session.commit()
    return jsonify({"success": True, "campaign": campaign_summary(campaign, include_subject=True)})


@newsletter_bp.route("/api/newsletter/campaigns/<campaign_id>/retry", methods=["POST"])
def retry_newsletter_campaign(campaign_id):
    denied = require_permission("send_campaigns")
    if denied:
        return denied
    campaign = db.session.get(NewsletterCampaign, campaign_id)
    if not campaign or not can_view_campaign(current_user(), campaign):
        return jsonify({"success": False, "message": "Campaign not found."}), 404
    retryable = NewsletterDelivery.query.filter_by(campaign_id=campaign.id).filter(NewsletterDelivery.status.in_(["Failed", "Skipped"])).all()
    if not retryable:
        return jsonify({"success": False, "message": "No failed deliveries are available for retry."}), 409
    for delivery in retryable:
        delivery.status = "Pending"
        delivery.error = None
        delivery.updated_at = datetime.utcnow()
    campaign.status = "Queued"
    campaign.cancel_requested = False
    campaign.ended_at = None
    campaign.error_summary = None
    if campaign.task_id:
        task = db.session.get(Task, campaign.task_id)
        if task:
            task.status = "Queued"
            task.ended_at = None
    db.session.commit()
    return jsonify({"success": True, "campaign": campaign_summary(campaign, include_subject=True)})


# --- GPG Functions ---
def get_gpg_key_status(gpg_path, email):
    cmd = [gpg_path, "--batch", "--with-colons", "--fingerprint", "--list-keys", email]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, env=gpg_env(), **hidden_subprocess_kwargs())
    except Exception as e:
        return {"exists": False, "usable": False, "reason": f"GPG key check failed: {e}"}

    if proc.returncode != 0:
        return {"exists": False, "usable": False, "reason": "Missing public key"}

    now_ts = int(time.time())
    public_keys = []
    current_key = None
    validity_reasons = {
        "e": "Public key is expired",
        "r": "Public key is revoked",
        "d": "Public key is disabled",
    }

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if not parts:
            continue
        if parts[0] == "pub":
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
            current_key = {"fingerprint": "", "reason": reason or "Public key is usable"}
            public_keys.append(current_key)
        elif parts[0] == "fpr" and current_key and not current_key["fingerprint"]:
            current_key["fingerprint"] = (parts[9] if len(parts) > 9 else "").upper()

    if not public_keys:
        return {"exists": False, "usable": False, "reason": "Missing public key"}
    usable = next((item for item in public_keys if item["reason"] == "Public key is usable"), None)
    if usable:
        return {"exists": True, "usable": True, **usable}
    first = public_keys[0]
    return {"exists": True, "usable": False, **first}


def check_gpg_key_exists(gpg_path, email):
    return get_gpg_key_status(gpg_path, email)["usable"]


def ensure_gpg_key_ready(gpg_path, keyserver, email, emit_and_write=None, progress_prefix=""):
    status = get_gpg_key_status(gpg_path, email)
    if status["usable"]:
        return True, status["reason"]

    keyserver = (keyserver or "").strip()
    if not keyserver:
        return False, status["reason"]
    fingerprint = status.get("fingerprint")
    if not fingerprint:
        return False, f"{status['reason']}; use the list key check to explicitly discover and import a key"

    if emit_and_write:
        emit_and_write(
            f"{progress_prefix} ⚠️ {status['reason']} for {email}. Fetching from keyserver {keyserver}...",
            "__HIDE__",
        )

    fetch_success, fetch_msg = fetch_gpg_key(gpg_path, keyserver, f"0x{fingerprint}")
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

class _NewsletterNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_gpg_key(gpg_path, keyserver, email):
    """Миттєве завантаження ключа через стандартний HTTPS API сервера SKS (Обхід багів dirmngr)"""
    try:
        base_url = keyserver.replace("hkps://", "https://").replace("hkp://", "http://")
        api_url = f"{base_url}/pks/lookup?op=get&options=mr&search={urllib.parse.quote(email)}"

        # ІГНОРУВАННЯ ПОМИЛОК SSL (Для самопідписаних сертифікатів)
        ctx = ssl.create_default_context()
        if not outbound_policy_enforced():
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Намагаємося завантажити ключ з HTTP/HTTPS
        try:
            web_schemes = ("https",) if outbound_policy_enforced() else ("https", "http")
            with pinned_outbound_url(api_url, "Newsletter GPG keyserver", allowed_schemes=web_schemes):
                req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0 (WinHUB)'})
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ctx),
                    _NewsletterNoRedirectHandler(),
                )
                with opener.open(req, timeout=10) as response:
                    key_data = response.read(2 * 1024 * 1024 + 1).decode('utf-8', errors='replace')
                    if len(key_data.encode('utf-8')) > 2 * 1024 * 1024:
                        return False, "Keyserver response is too large."
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
            keyserver = (smtp_config.get('_recipient_keyserver') or smtp_config.get('keyserver') or '').strip()
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
                server = open_smtp_connection(smtp_config['host'], smtp_config['port'], "newsletter SMTP delivery", timeout=30)
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


def _write_campaign_log(task, line):
    if not task or not task.log_file:
        return
    ensure_parent_dir(task.log_file)
    with open(task.log_file, "a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")


def _campaign_counts(campaign_id):
    counts = {"Sent": 0, "Failed": 0, "Skipped": 0, "Unknown": 0, "Pending": 0, "Sending": 0}
    rows = db.session.query(NewsletterDelivery.status, db.func.count(NewsletterDelivery.id)).filter_by(
        campaign_id=campaign_id
    ).group_by(NewsletterDelivery.status).all()
    for status, count in rows:
        counts[status] = int(count)
    return counts


def execute_queued_campaign(app, campaign_id):
    """Execute one durable campaign. The dedicated worker is the only production caller."""
    with app.app_context():
        campaign = db.session.get(NewsletterCampaign, campaign_id)
        if not campaign or campaign.status != "Sending":
            return False
        task = db.session.get(Task, campaign.task_id) if campaign.task_id else None
        profiles = load_smtp_profiles()
        smtp_config = profiles.get(campaign.sender_email)
        if not smtp_config:
            campaign.status = "Failed"
            campaign.error_summary = "Sender profile not found."
            campaign.ended_at = datetime.utcnow()
            if task:
                task.status = "Error"
                task.ended_at = campaign.ended_at
            db.session.commit()
            return False

        attachments = attachment_restore(campaign.attachments_json)
        gpg_path = app.config.get('GPG_PATH') or os.environ.get('GPG_PATH', 'gpg')
        keyserver = str(campaign.keyserver_override or smtp_config.get('keyserver') or '').strip()
        rate_delay = max(0.0, float(os.environ.get("NEWSLETTER_SEND_DELAY_SECONDS", "0.05") or 0.05))
        server = None
        _write_campaign_log(task, f"========== [ {kyiv_log_timestamp()} ] NEWSLETTER CAMPAIGN {campaign.id} ==========")

        try:
            if campaign.use_gpg:
                gpg_ok, gpg_message = validate_gpg(gpg_path)
                if not gpg_ok:
                    raise RuntimeError(f"GPG unavailable: {gpg_message}")

            server = open_smtp_connection(smtp_config['host'], smtp_config['port'], "newsletter SMTP delivery", timeout=30)
            server.login(campaign.sender_email, decrypt_pass(smtp_config['password']))
            deliveries = NewsletterDelivery.query.filter_by(campaign_id=campaign.id, status="Pending").order_by(NewsletterDelivery.id.asc()).all()
            for delivery in deliveries:
                db.session.refresh(campaign)
                if campaign.cancel_requested:
                    delivery.status = "Skipped"
                    delivery.error = "Campaign cancelled before delivery."
                    delivery.updated_at = datetime.utcnow()
                    db.session.commit()
                    continue

                recipient = delivery.recipient
                delivery.status = "Sending"
                delivery.attempts = int(delivery.attempts or 0) + 1
                delivery.updated_at = datetime.utcnow()
                delivery.message_id = f"<newsletter.{campaign.id}.{delivery.recipient_hash[:16]}@winhub.local>"
                db.session.commit()

                try:
                    clear_msg = build_clear_message(
                        campaign.sender_email, recipient, campaign.subject,
                        campaign.body_text, campaign.body_html, attachments,
                    )
                    clear_msg["Message-ID"] = delivery.message_id
                    final_msg = clear_msg
                    if campaign.use_gpg:
                        ready, reason = ensure_gpg_key_ready(gpg_path, keyserver, recipient)
                        if not ready:
                            raise ValueError(reason)
                        encrypted, payload = encrypt_with_gpg(gpg_path, recipient, clear_msg.as_bytes())
                        if not encrypted:
                            raise ValueError(payload)
                        final_msg = build_encrypted_message(campaign.sender_email, recipient, campaign.subject, payload)
                        final_msg["Message-ID"] = delivery.message_id

                    try:
                        server.send_message(final_msg)
                    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError):
                        try:
                            server.quit()
                        except Exception:
                            pass
                        server = open_smtp_connection(smtp_config['host'], smtp_config['port'], "newsletter SMTP retry", timeout=30)
                        server.login(campaign.sender_email, decrypt_pass(smtp_config['password']))
                        server.send_message(final_msg)

                    delivery.status = "Sent"
                    delivery.error = None
                    delivery.sent_at = datetime.utcnow()
                    _write_campaign_log(task, f"Sent recipient hash {delivery.recipient_hash[:12]}.")
                except Exception as error:
                    delivery.status = "Failed"
                    delivery.error = str(error)[:2000]
                    _write_campaign_log(task, f"Failed recipient hash {delivery.recipient_hash[:12]}: {type(error).__name__}.")
                delivery.updated_at = datetime.utcnow()
                db.session.commit()
                if rate_delay:
                    time.sleep(rate_delay)

            counts = _campaign_counts(campaign.id)
            campaign.sent_count = counts["Sent"]
            campaign.failed_count = counts["Failed"] + counts["Unknown"]
            campaign.skipped_count = counts["Skipped"]
            campaign.ended_at = datetime.utcnow()
            if campaign.cancel_requested:
                campaign.status = "Cancelled"
            elif campaign.failed_count or campaign.skipped_count:
                campaign.status = "Partial" if campaign.sent_count else "Failed"
            else:
                campaign.status = "Completed"
            campaign.error_summary = None
            if task:
                task.status = "Success" if campaign.status == "Completed" else ("Warning" if campaign.sent_count else "Error")
                task.ended_at = campaign.ended_at
            db.session.commit()
            WinHubCore.audit(
                user_id=campaign.user_id,
                username="Newsletter Worker",
                module="Newsletter",
                action="Campaign Finished",
                target_type="newsletter_campaign",
                target_id=campaign.id,
                details={
                    "campaign_id": campaign.id,
                    "source": campaign.source,
                    "recipients_count": campaign.total_count,
                    "sent_count": campaign.sent_count,
                    "failed_count": campaign.failed_count,
                    "skipped_count": campaign.skipped_count,
                    "use_gpg": campaign.use_gpg,
                },
                status="Success" if campaign.status == "Completed" else "Warning",
            )
            return True
        except Exception as error:
            log.error("Newsletter campaign %s failed: %s", campaign.id, traceback.format_exc())
            campaign.status = "Failed"
            campaign.error_summary = str(error)[:2000]
            campaign.ended_at = datetime.utcnow()
            NewsletterDelivery.query.filter_by(campaign_id=campaign.id, status="Sending").update({
                "status": "Unknown",
                "error": "Worker stopped after delivery began; not retried automatically to avoid duplicates.",
                "updated_at": datetime.utcnow(),
            }, synchronize_session=False)
            if task:
                task.status = "Error"
                task.ended_at = campaign.ended_at
            db.session.commit()
            return False
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass


def claim_next_campaign():
    campaign = NewsletterCampaign.query.filter_by(status="Queued").order_by(NewsletterCampaign.created_at.asc()).first()
    if not campaign:
        return None
    campaign.status = "Sending"
    campaign.started_at = campaign.started_at or datetime.utcnow()
    if campaign.task_id:
        task = db.session.get(Task, campaign.task_id)
        if task:
            task.status = "Running"
    db.session.commit()
    return campaign.id


def recover_interrupted_campaigns():
    interrupted = NewsletterCampaign.query.filter_by(status="Sending").all()
    for campaign in interrupted:
        NewsletterDelivery.query.filter_by(campaign_id=campaign.id, status="Sending").update({
            "status": "Unknown",
            "error": "Worker restarted after delivery began; manual review is required before retry.",
            "updated_at": datetime.utcnow(),
        }, synchronize_session=False)
        pending = NewsletterDelivery.query.filter_by(campaign_id=campaign.id, status="Pending").count()
        campaign.status = "Queued" if pending else "Partial"
        if not pending:
            campaign.ended_at = datetime.utcnow()
    db.session.commit()


def run_newsletter_worker(app, once=False):
    poll_seconds = env_int("NEWSLETTER_WORKER_POLL_SECONDS", 5, 1)
    inbound_poll_seconds = env_int("NEWSLETTER_INBOUND_POLL_SECONDS", 60, 10)
    next_inbound_poll = 0.0
    with app.app_context():
        recover_interrupted_campaigns()
    while True:
        try:
            atomic_json_write(WORKER_HEARTBEAT_FILE, {"timestamp": datetime.utcnow().isoformat() + "Z"})
        except Exception:
            log.warning("Could not update Newsletter worker heartbeat.")
        now = time.monotonic()
        if inbound_relay_enabled() and now >= next_inbound_poll:
            with app.app_context():
                for mailbox in inbound_mailboxes(include_legacy=True):
                    if mailbox.get("enabled", True):
                        if not mailbox.get("allowed_signer_fingerprints"):
                            log.warning(
                                "Newsletter inbound mailbox '%s' is paused until an approved GPG signer fingerprint is configured.",
                                mailbox.get("name") or mailbox.get("imap_user") or "unnamed",
                            )
                            continue
                        try:
                            poll_inbound_mailbox(app, mailbox)
                        except Exception:
                            log.error("Newsletter inbound mailbox poll failed: %s", traceback.format_exc())
            next_inbound_poll = now + inbound_poll_seconds
        with app.app_context():
            campaign_id = claim_next_campaign()
        if campaign_id:
            execute_queued_campaign(app, campaign_id)
        elif once:
            return
        else:
            time.sleep(poll_seconds)
