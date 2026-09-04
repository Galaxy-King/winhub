import os
import json
import uuid
import hashlib
import base64
import html
import logging
import threading
import smtplib
import ssl
import ast
import re
from decimal import Decimal, InvalidOperation
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from zoneinfo import ZoneInfo
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, current_app, Response, send_from_directory, stream_with_context, g, has_request_context
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import load_only, selectinload
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from apscheduler.triggers.cron import CronTrigger

from core.database import db, User, Endpoint, EndpointGroup, EndpointDuplicateException, AgentTask, TaskTemplate, TelemetryHistory, ConnectionIpHistory, ScheduledTask, EndpointMetric, AgentUpdateRollout, TriggerRule, AggregatedJob, AiReportRequest, ApiKey, RegistrationHistory, AuditLog, ReportRevision, ReportDelivery, HistorySearchToken, endpoint_group_m2m
from core.sdk import WinHubCore
from core.admin import send_notification_email
from core.security import sec_manager
from core.config import Config
from core.host_security import encryption_status_from_host_info
from core.permissions import has_module_access, has_permission, request_api_group_scope, user_permissions
from core.gpg import fetch_public_key, gpg_env
from core.report_renderer import validate_report_template
from core.template_security import current_template_hash, template_approval_valid
from core.outbound_security import normalized_origin, pinned_outbound_host, pinned_outbound_url
from core.sensitive_data import is_sensitive_name, mask_sensitive_text, masked_variables
from core.ai_client import OpenWebUIClient, load_ai_provider, save_ai_provider
from core.ai_reports import create_ai_report_request, latest_ai_request, validate_ai_report_payload
from core.api_access import (
    api_target_count_allowed,
    api_template_allowed,
    effective_client_ip,
)
from core.report_versions import (
    create_report_revision,
    ensure_report_revision,
    finish_report_delivery,
    record_report_delivery,
)
from core.group_access import (
    allowed_group_ids_for_action,
    allowed_host_ids_for_action,
    group_action_allowed,
)

infrastructure_bp = Blueprint('infrastructure', __name__, template_folder='templates')
from modules.Infrastructure.ai_editor import register_ai_editor, stamp_ai_origin
register_ai_editor(infrastructure_bp)
kyiv_tz = ZoneInfo("Europe/Kyiv")

SMTP_FILE = os.path.join(Config.DATA_DIR, "infra_smtp_profiles.json")
CONFLUENCE_FILE = os.path.join(Config.DATA_DIR, "infra_confluence_profiles.json")
SCHEDULED_REPORTS_FILE = os.path.join(Config.DATA_DIR, "infra_scheduled_reports.json")
SECRETS_FILE = os.path.join(Config.DATA_DIR, "infra_template_secrets.json")
AGENT_PACKAGES_FILE = os.path.join(Config.DATA_DIR, "infra_agent_packages.json")
AGENT_PACKAGES_DIR = os.path.join(Config.DATA_DIR, "agent_packages")
SOFTWARE_PACKAGES_FILE = os.path.join(Config.DATA_DIR, "infra_software_packages.json")
SOFTWARE_PACKAGES_DIR = os.path.join(Config.DATA_DIR, "software_packages")
AGENT_PACKAGE_PLATFORMS = ("windows", "linux", "macos")
AGENT_PACKAGE_PLATFORM_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "unknown": "Unknown",
}

# Глобальні змінні для фонового потоку автовідправки
auto_thread_started = False
auto_thread_lock = threading.Lock()
auto_email_skip_cache = set()
live_state_cache = {}
live_state_cache_lock = threading.Lock()
LIVE_STATE_CACHE_TTL_SECONDS = 10
LIVE_EVENT_CHECK_INTERVAL_SECONDS = 15
AUTO_EMAIL_SKIP_CACHE_LIMIT = 4096
AUTO_EMAIL_CHECK_INTERVAL_SECONDS = 30
AUTO_EMAIL_SCAN_LIMIT = 200
AUTO_EMAIL_NEW_CHECK_LIMIT = 10


@infrastructure_bp.errorhandler(Exception)
def infrastructure_api_error(error):
    if request.path.startswith("/api/"):
        try:
            from flask import g
            request_id = getattr(g, "request_id", None)
        except Exception:
            request_id = None
        if isinstance(error, HTTPException):
            return jsonify({
                "success": False,
                "message": error.description or error.name,
                "request_id": request_id,
            }), error.code or 500
        logging.getLogger("winhub").exception("Infrastructure API error path=%s request_id=%s", request.path, request_id or "-")
        return jsonify({
            "success": False,
            "message": "Internal server error",
            "request_id": request_id,
        }), 500
    raise error

ENDPOINT_LIST_COLUMNS = (
    Endpoint.id,
    Endpoint.hostname,
    Endpoint.display_name,
    Endpoint.os_version,
    Endpoint.os_type,
    Endpoint.public_key_pem_plain,
    Endpoint.task_signing_key_id,
    Endpoint.task_signature_v2_seen_at,
    Endpoint.connection_ip,
    Endpoint.approval_status,
    Endpoint.agent_version,
    Endpoint.encryption_status,
    Endpoint.encryption_level,
    Endpoint.encryption_methods,
    Endpoint.first_seen,
    Endpoint.last_enrollment_at,
    Endpoint.enrollment_attempts,
    Endpoint.identity_fingerprint,
    Endpoint.identity_warning,
    Endpoint.identity_duplicate_allowed,
    Endpoint.reenroll_allowed_until,
    Endpoint.last_seen,
    Endpoint.is_blocked,
)


def endpoint_has_public_key_map(endpoint_ids):
    if not endpoint_ids:
        return {}
    rows = db.session.query(
        Endpoint.id,
        or_(
            Endpoint.public_key_pem_plain.isnot(None),
            Endpoint.public_key_pem.isnot(None),
        ).label("has_public_key"),
    ).filter(Endpoint.id.in_(endpoint_ids)).all()
    return {row.id: bool(row.has_public_key) for row in rows}


def endpoint_encryption_payload(endpoint):
    methods = [
        method.strip()
        for method in str(getattr(endpoint, "encryption_methods", "") or "").split(",")
        if method.strip()
    ]
    status = getattr(endpoint, "encryption_status", None) or "Unknown"
    level = getattr(endpoint, "encryption_level", None) or "unknown"
    summary = ", ".join(methods) if methods else (
        "No encryption method detected." if level == "none" else "Encryption inventory has not been reported yet."
    )
    return {"status": status, "level": level, "methods": methods, "summary": summary}


def endpoint_pair_key(left_id, right_id):
    values = sorted([str(left_id or "").strip(), str(right_id or "").strip()])
    if not values[0] or not values[1] or values[0] == values[1]:
        return None
    return tuple(values)


def duplicate_exception_pairs(endpoint_ids):
    ids = [str(item) for item in endpoint_ids if item]
    if not ids:
        return set()
    rows = EndpointDuplicateException.query.filter(
        EndpointDuplicateException.endpoint_a_id.in_(ids),
        EndpointDuplicateException.endpoint_b_id.in_(ids),
    ).all()
    return {
        endpoint_pair_key(row.endpoint_a_id, row.endpoint_b_id)
        for row in rows
        if endpoint_pair_key(row.endpoint_a_id, row.endpoint_b_id)
    }


def endpoint_duplicate_pair_accepted(left, right, ignored_pairs=None):
    pair_key = endpoint_pair_key(getattr(left, "id", None), getattr(right, "id", None))
    if pair_key and ignored_pairs and pair_key in ignored_pairs:
        return True
    if bool(getattr(left, "identity_duplicate_allowed", False)) and bool(getattr(right, "identity_duplicate_allowed", False)):
        return True

    left_status = getattr(left, "approval_status", "Approved") or "Approved"
    right_status = getattr(right, "approval_status", "Approved") or "Approved"
    left_hostname = str(getattr(left, "hostname", "") or "").strip().upper()
    right_hostname = str(getattr(right, "hostname", "") or "").strip().upper()
    if left_status == "Approved" and right_status == "Approved" and left_hostname and left_hostname == right_hostname:
        left_alias = str(getattr(left, "display_name", "") or "").strip().upper()
        right_alias = str(getattr(right, "display_name", "") or "").strip().upper()
        if (left_alias and left_alias != left_hostname) or (right_alias and right_alias != right_hostname):
            return True
    return False


def effective_endpoint_identity_warning(endpoint):
    warning = getattr(endpoint, "identity_warning", None)
    if not warning:
        return None
    if (getattr(endpoint, "approval_status", "Approved") or "Approved") != "Approved":
        return warning
    if bool(getattr(endpoint, "identity_duplicate_allowed", False)):
        return None
    hostname = str(getattr(endpoint, "hostname", "") or "").strip().upper()
    display_name = str(getattr(endpoint, "display_name", "") or "").strip().upper()
    if hostname and display_name and display_name != hostname:
        return None
    return warning


def identity_warning_is_hostname_stale_only(endpoint):
    warning = str(getattr(endpoint, "identity_warning", "") or "").lower()
    if not warning:
        return False
    if "hostname" not in warning or "stale_agent_version" not in warning:
        return False
    strong_terms = ("token_proof", "fingerprint", "identity_key", "public_key")
    return not any(term in warning for term in strong_terms)


def allow_hostname_duplicate_pairs_for_approved_agent(agent, created_by=None):
    if not identity_warning_is_hostname_stale_only(agent):
        return 0

    hostname_key = str(getattr(agent, "hostname", "") or "").strip().upper()
    if not hostname_key:
        return 0

    matches = Endpoint.query.filter(
        Endpoint.id != agent.id,
        Endpoint.approval_status == "Approved",
        func.upper(Endpoint.hostname) == hostname_key,
    ).all()
    created = 0
    for match in matches:
        pair_key = endpoint_pair_key(agent.id, match.id)
        if not pair_key:
            continue
        existing = EndpointDuplicateException.query.filter_by(
            endpoint_a_id=pair_key[0],
            endpoint_b_id=pair_key[1],
        ).first()
        if not existing:
            db.session.add(EndpointDuplicateException(
                endpoint_a_id=pair_key[0],
                endpoint_b_id=pair_key[1],
                reason="Approved hostname-only clone as distinct endpoint",
                created_by=created_by,
            ))
            created += 1
        match.identity_duplicate_allowed = True
        match.identity_warning = None

    if matches:
        agent.identity_duplicate_allowed = True
    return created


def attach_endpoint_list_flags(endpoints):
    key_map = endpoint_has_public_key_map([endpoint.id for endpoint in endpoints])
    for endpoint in endpoints:
        endpoint.agent_identity_key_enrolled = key_map.get(endpoint.id, False)
        endpoint.encryption = endpoint_encryption_payload(endpoint)
        endpoint.effective_identity_warning = effective_endpoint_identity_warning(endpoint)
        endpoint.possible_duplicate = bool(endpoint.effective_identity_warning)
        endpoint.duplicate_matches = []
    return endpoints


def get_allowed_hosts_light(user_id, approved_only=False, action_id="view_hosts"):
    user = current_user() if user_id == session.get("user_id") else User.query.get(user_id)
    if not user or not has_permission(user, "Infrastructure", action_id):
        return []

    query = Endpoint.query.options(
        load_only(*ENDPOINT_LIST_COLUMNS),
        selectinload(Endpoint.groups).load_only(EndpointGroup.id, EndpointGroup.name),
    )
    if approved_only:
        query = query.filter(db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None)))

    if user.is_admin and request_api_group_scope() is None:
        return attach_endpoint_list_flags(query.all())

    group_ids = allowed_group_ids_for_action(user, action_id)
    if not group_ids:
        return []
    query = query.filter(Endpoint.groups.any(EndpointGroup.id.in_(group_ids)))
    if not approved_only:
        query = query.filter(Endpoint.approval_status == "Approved")
    return attach_endpoint_list_flags(query.all())


def allowed_endpoint_query(user_id, approved_only=False, action_id="view_hosts"):
    user = current_user() if user_id == session.get("user_id") else User.query.get(user_id)
    if not user or not has_permission(user, "Infrastructure", action_id):
        return Endpoint.query.filter(False)

    query = Endpoint.query.options(
        load_only(*ENDPOINT_LIST_COLUMNS),
        selectinload(Endpoint.groups).load_only(EndpointGroup.id, EndpointGroup.name),
    )
    if approved_only:
        query = query.filter(db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None)))

    if user.is_admin and request_api_group_scope() is None:
        return query

    group_ids = allowed_group_ids_for_action(user, action_id)
    if not group_ids:
        return query.filter(False)
    query = query.filter(Endpoint.groups.any(EndpointGroup.id.in_(group_ids)))
    if not approved_only:
        query = query.filter(Endpoint.approval_status == "Approved")
    return query


def bounded_int_arg(name, default, min_value, max_value):
    try:
        value = int(request.args.get(name, default) or default)
    except (TypeError, ValueError):
        value = default
    return min(max_value, max(min_value, value))

def load_smtp_profiles():
    if not os.path.exists(SMTP_FILE): return {}
    try:
        with open(SMTP_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_smtp_profiles(data):
    with open(SMTP_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def load_confluence_profiles():
    if not os.path.exists(CONFLUENCE_FILE):
        return {}
    try:
        with open(CONFLUENCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        logging.getLogger("winhub").exception("Failed to load Confluence profiles")
        return {}

def save_confluence_profiles(data):
    os.makedirs(os.path.dirname(CONFLUENCE_FILE), exist_ok=True)
    with open(CONFLUENCE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def safe_confluence_profiles(profiles):
    safe_profiles = []
    for name, profile in sorted(profiles.items()):
        safe_profiles.append({
            "name": name,
            "base_url": profile.get("base_url", ""),
            "auth_type": profile.get("auth_type", "bearer"),
            "username": profile.get("username", ""),
            "default_page_id": profile.get("default_page_id", ""),
            "last_published_at": profile.get("last_published_at", ""),
            "last_status": profile.get("last_status", ""),
        })
    return safe_profiles

def normalize_confluence_base_url(value):
    base_url = str(value or "").strip().rstrip("/")
    parsed = urlsplit(base_url)
    if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return base_url


class NoCredentialRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def confluence_auth_headers(profile):
    encrypted_token = profile.get("token", "")
    if not encrypted_token:
        raise ValueError("Confluence token is missing")
    token = sec_manager.decrypt_data(encrypted_token)
    auth_type = str(profile.get("auth_type") or "bearer").lower()
    if auth_type == "basic":
        username = str(profile.get("username") or "").strip()
        if not username:
            raise ValueError("Confluence Basic auth requires username/email")
        raw = f"{username}:{token}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    return {"Authorization": f"Bearer {token}"}

def confluence_request(profile, method, path, payload=None, timeout=20):
    base_url = normalize_confluence_base_url(profile.get("base_url"))
    if not base_url:
        return False, None, "Invalid Confluence base URL"

    url = base_url + path
    data = None
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "WinHUB-Confluence-Publisher/1.0",
    }
    try:
        allowed_schemes = ("https",) if Config.OUTBOUND_POLICY_MODE == "enforce" else ("https", "http")
        with pinned_outbound_url(url, "Confluence API", allowed_schemes=allowed_schemes):
            headers.update(confluence_auth_headers(profile))
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
            req = Request(url, data=data, headers=headers, method=method.upper())
            with build_opener(ProxyHandler({}), NoCredentialRedirectHandler()).open(req, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                if not body:
                    return True, {}, "OK"
                return True, json.loads(body), "OK"
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        return False, None, f"Confluence HTTP {exc.code}: {body or exc.reason}"
    except URLError as exc:
        return False, None, f"Confluence connection failed: {exc.reason}"
    except Exception as exc:
        return False, None, str(exc)

SAFE_REPORT_HTML_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr", "table", "thead",
    "tbody", "tr", "th", "td", "ul", "ol", "li", "pre", "code", "strong", "em",
    "div", "section", "article", "blockquote", "span",
}
SAFE_REPORT_VOID_TAGS = {"br", "hr"}
SUPPRESSED_REPORT_HTML_TAGS = {
    "script", "style", "noscript", "template", "iframe", "object", "embed", "svg", "math",
}


class _SafeReportHtmlParser(HTMLParser):
    """Keep inert report structure while discarding every source attribute."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.open_tags = []
        self.suppressed_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = str(tag or "").lower()
        if self.suppressed_depth:
            if tag not in SAFE_REPORT_VOID_TAGS:
                self.suppressed_depth += 1
            return
        if tag in SUPPRESSED_REPORT_HTML_TAGS:
            self.suppressed_depth = 1
            return
        if tag not in SAFE_REPORT_HTML_TAGS:
            return
        if tag in SAFE_REPORT_VOID_TAGS:
            self.output.append(f"<{tag} />")
            return
        self.output.append(f"<{tag}>")
        self.open_tags.append(tag)

    def handle_startendtag(self, tag, attrs):
        if self.suppressed_depth:
            return
        tag = str(tag or "").lower()
        if tag in SAFE_REPORT_VOID_TAGS:
            self.output.append(f"<{tag} />")

    def handle_endtag(self, tag):
        tag = str(tag or "").lower()
        if self.suppressed_depth:
            self.suppressed_depth = max(0, self.suppressed_depth - 1)
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
            self.output.append(html.escape(str(data or ""), quote=True))

    def close(self):
        super().close()
        while self.open_tags:
            self.output.append(f"</{self.open_tags.pop()}>")


def report_body_looks_like_html(value):
    return bool(re.search(
        r"<(?:!doctype|html|body|h[1-6]|p|br|hr|table|thead|tbody|tr|th|td|ul|ol|li|pre|code|strong|em|div|section|article|blockquote|span)\b",
        str(value or ""),
        re.IGNORECASE,
    ))


def safe_report_html(value):
    """Return formatted report HTML with a strict tag allowlist and no source attributes."""
    source = str(value or "")
    if not report_body_looks_like_html(source):
        return f"<pre>{html.escape(source, quote=True)}</pre>"
    parser = _SafeReportHtmlParser()
    parser.feed(source)
    parser.close()
    rendered = "".join(parser.output).strip()
    return rendered or "<p>No report content.</p>"


def report_body_plain_text(value):
    """Convert a report body to readable inert text for fallbacks and downloads."""
    source = str(value or "")
    if not re.search(r"<[a-z][\s\S]*>", source, re.IGNORECASE):
        return source.strip()
    source = re.sub(r"<(script|style|noscript|template)\b[^>]*>[\s\S]*?</\1>", "", source, flags=re.IGNORECASE)
    source = re.sub(r"<br\s*/?>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"</(?:p|div|li|tr|h[1-6]|section|article|blockquote)\s*>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"<[^>]+>", "", source)
    source = html.unescape(source)
    source = re.sub(r"\n[ \t]+", "\n", source)
    return re.sub(r"\n{3,}", "\n\n", source).strip()


def confluence_report_storage_html(report, report_body, custom_note="", formatted=False):
    title = html.escape(str(report.title or "WinHUB Report"))
    status = html.escape(str(report.status or ""))
    created_at = html.escape(to_kyiv_time(report.created_at))
    published_at = html.escape(datetime.now(kyiv_tz).strftime("%Y-%m-%d %H:%M:%S %Z"))
    note_html = ""
    if custom_note:
        note_html = f"<p><strong>Note:</strong> {html.escape(str(custom_note))}</p>"
    body_html = safe_report_html(report_body) if formatted else f"<pre>{html.escape(str(report_body or ''))}</pre>"
    heading_html = "" if formatted else f"<h1>{title}</h1>"
    return (
        f"{heading_html}"
        f"<p><strong>Generated:</strong> {created_at}<br />"
        f"<strong>Published:</strong> {published_at}<br />"
        f"<strong>Status:</strong> {status}<br />"
        f"<strong>Total:</strong> {int(report.total_count or 0)} / "
        f"<strong>Success:</strong> {int(report.success_count or 0)} / "
        f"<strong>Error:</strong> {int(report.error_count or 0)}</p>"
        f"{note_html}"
        f"{body_html}"
    )

def publish_report_to_confluence(profile, report, page_id, title=None, body_format="safe_html", custom_note="", report_body=None):
    page_id = str(page_id or "").strip()
    if not page_id:
        return False, "Confluence page ID is required", None

    ok, page, message = confluence_request(
        profile,
        "GET",
        f"/rest/api/content/{quote(page_id, safe='')}?expand=version,body.storage",
    )
    if not ok:
        return False, message, None

    current_version = int(((page or {}).get("version") or {}).get("number") or 0)
    if current_version <= 0:
        return False, "Confluence page version was not returned by API", None

    final_title = str(title or (page or {}).get("title") or report.title or "WinHUB Report").strip()
    report_body = report.report_data if report_body is None else report_body
    report_body = report_body or ""
    if body_format == "storage_html":
        storage_value = str(report_body or "")
    elif body_format == "safe_html":
        storage_value = confluence_report_storage_html(report, report_body, custom_note, formatted=True)
    else:
        storage_value = confluence_report_storage_html(report, report_body, custom_note)

    payload = {
        "id": page_id,
        "type": (page or {}).get("type") or "page",
        "title": final_title,
        "version": {"number": current_version + 1},
        "body": {"storage": {"value": storage_value, "representation": "storage"}},
    }

    ok, updated, message = confluence_request(
        profile,
        "PUT",
        f"/rest/api/content/{quote(page_id, safe='')}",
        payload=payload,
        timeout=30,
    )
    if not ok:
        return False, message, None

    base_url = normalize_confluence_base_url(profile.get("base_url")) or ""
    links = (updated or {}).get("_links") or {}
    web_url = links.get("base", base_url) + links.get("webui", "") if links.get("webui") else base_url
    return True, "Published to Confluence", web_url

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
            if not isinstance(data, list):
                return []
            for package in data:
                if isinstance(package, dict) and not package.get("platform"):
                    package["platform"] = detect_agent_package_platform(package.get("original_filename") or package.get("filename") or "")
            return data
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

def detect_agent_package_platform(filename):
    value = str(filename or "").lower()
    if any(marker in value for marker in ("macos", "darwin", "osx", "os-x", "mac-x64", "mac-arm64", "apple")):
        return "macos"
    if "linux" in value or value.endswith(".tar.gz") or value.endswith(".tgz"):
        return "linux"
    if "windows" in value or "-win" in value or "_win" in value or "win-x64" in value or "win-arm64" in value or value.endswith(".zip"):
        return "windows"
    return "unknown"

def endpoint_agent_platform(endpoint):
    os_type = str(getattr(endpoint, "os_type", "") or "").lower()
    os_version = str(getattr(endpoint, "os_version", "") or "").lower()
    combined = f"{os_type} {os_version}"
    if any(marker in combined for marker in ("macos", "mac os", "darwin", "osx", "os x")):
        return "macos"
    if "linux" in os_type or "debian" in os_version or "ubuntu" in os_version:
        return "linux"
    return "windows"

def agent_version_sort_key(version):
    value = re.sub(r"^[^\d]+", "", str(version or "").lower())
    parts = []
    for part in re.findall(r"\d+|[a-zA-Z]+", value):
        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part))
    return tuple(parts)

def find_agent_package_for_platform(version, platform):
    version = str(version or "").strip()
    platform = str(platform or "").strip().lower()
    for package in load_agent_packages():
        if str(package.get("version") or "").strip() == version and str(package.get("platform") or "").lower() == platform:
            return package
    return None

def agent_package_download_path(package_id):
    return url_for("infrastructure.download_agent_package_public", package_id=package_id)

def usable_agent_public_base_url():
    value = str(getattr(Config, "AGENT_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        logging.getLogger("winhub").warning(
            "Ignoring invalid AGENT_PUBLIC_BASE_URL for agent package downloads: %s",
            value,
        )
        return ""
    return value

def agent_package_public_url(package_id):
    path = agent_package_download_path(package_id)
    public_base_url = usable_agent_public_base_url()
    if public_base_url:
        return f"{public_base_url}{path}"
    return url_for("infrastructure.download_agent_package_public", package_id=package_id, _external=True)

def agent_package_update_url(package_id):
    if getattr(Config, "AGENT_PACKAGE_URL_MODE", "absolute") == "relative":
        return agent_package_download_path(package_id)
    return usable_agent_package_url(agent_package_public_url(package_id)) or agent_package_download_path(package_id)

def usable_agent_package_url(value):
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        return ""
    return value

def resolved_agent_package_update_url(package_id, preferred_url=""):
    return usable_agent_package_url(preferred_url) or agent_package_update_url(package_id)

def latest_agent_package_versions_by_platform():
    latest = {}
    for package in load_agent_packages():
        platform = str(package.get("platform") or detect_agent_package_platform(package.get("original_filename") or package.get("filename") or "")).lower()
        version = str(package.get("version") or "").strip()
        if platform not in AGENT_PACKAGE_PLATFORMS or not version:
            continue
        current = latest.get(platform)
        if not current or agent_version_sort_key(version) > agent_version_sort_key(current):
            latest[platform] = version
    return latest


def latest_agent_package_version(platform=None):
    platform = str(platform or "").strip().lower()
    if platform:
        return latest_agent_package_versions_by_platform().get(platform, "")
    packages = load_agent_packages()
    versions = [str(package.get("version") or "").strip() for package in packages if str(package.get("version") or "").strip()]
    if versions:
        return max(versions, key=agent_version_sort_key)
    return Config.LATEST_AGENT_VERSION


def latest_version_for_endpoint(endpoint, latest_versions=None):
    latest_versions = latest_versions or latest_agent_package_versions_by_platform()
    platform = endpoint_agent_platform(endpoint)
    return latest_versions.get(platform) or ""


def endpoint_platform_clause(platform):
    linux_clause = or_(
        Endpoint.os_type.ilike("%linux%"),
        Endpoint.os_version.ilike("%debian%"),
        Endpoint.os_version.ilike("%ubuntu%"),
    )
    macos_clause = or_(
        Endpoint.os_type.ilike("%mac%"),
        Endpoint.os_type.ilike("%darwin%"),
        Endpoint.os_version.ilike("%mac%"),
        Endpoint.os_version.ilike("%darwin%"),
        Endpoint.os_version.ilike("%os x%"),
    )
    if platform == "linux":
        return linux_clause
    if platform == "macos":
        return macos_clause
    return and_(~linux_clause, ~macos_clause)


def platform_agent_version_clauses(latest_versions, current=False):
    clauses = []
    for platform in AGENT_PACKAGE_PLATFORMS:
        latest = latest_versions.get(platform)
        if not latest:
            continue
        version_clause = Endpoint.agent_version == latest if current else or_(Endpoint.agent_version.is_(None), Endpoint.agent_version != latest)
        clauses.append(and_(endpoint_platform_clause(platform), version_clause))
    return clauses


def agent_package_response(package, latest_versions=None):
    item = dict(package or {})
    platform = str(item.get("platform") or detect_agent_package_platform(item.get("original_filename") or item.get("filename") or "")).lower()
    item["platform"] = platform
    item["platform_label"] = AGENT_PACKAGE_PLATFORM_LABELS.get(platform, "Unknown")
    latest_versions = latest_versions or latest_agent_package_versions_by_platform()
    item["is_latest_for_platform"] = bool(item.get("version") and latest_versions.get(platform) == str(item.get("version") or "").strip())
    if item.get("id"):
        item["download_url"] = agent_package_public_url(item["id"])
    return item

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

def endpoint_display_name(endpoint):
    if not endpoint:
        return "Unknown"
    return (getattr(endpoint, "display_name", None) or getattr(endpoint, "hostname", None) or getattr(endpoint, "id", None) or "Unknown").strip()

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

def datetime_to_epoch_ms(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)

def report_source_job_id(report_id):
    split_match = re.match(r"^([0-9a-fA-F]{32})\.(\d{3})$", str(report_id or ""))
    if split_match:
        try:
            return str(uuid.UUID(hex=split_match.group(1)))
        except ValueError:
            return report_id
    return report_id


def accessible_report_id_set(report_ids, user_id=None, action_id="view_reports"):
    report_ids = [str(report_id) for report_id in (report_ids or []) if report_id]
    if not report_ids:
        return set()
    if session.get('is_admin'):
        return set(report_ids)

    allowed_hosts = infra_allowed_host_ids(user_id or session.get('user_id'), action_id)
    if not allowed_hosts:
        return set()
    allowed_host_set = set(allowed_hosts)

    source_by_report = {report_id: report_source_job_id(report_id) for report_id in report_ids}
    source_job_ids = set(source_by_report.values())
    endpoint_key = func.coalesce(AgentTask.endpoint_id, AgentTask.endpoint_id_snapshot)
    allowed_endpoint = case(
        (endpoint_key.in_(allowed_hosts), endpoint_key),
        else_=None,
    )
    job_scope_rows = db.session.query(
        AgentTask.job_id,
        func.count(func.distinct(endpoint_key)),
        func.count(func.distinct(allowed_endpoint)),
    ).filter(
        AgentTask.job_id.in_(source_job_ids)
    ).group_by(AgentTask.job_id).all()
    allowed_source_ids = {
        str(job_id)
        for job_id, total_targets, allowed_targets in job_scope_rows
        if job_id and total_targets > 0 and total_targets == allowed_targets
    }

    unresolved_source_ids = source_job_ids - allowed_source_ids
    if unresolved_source_ids:
        direct_rows = db.session.query(AgentTask.id, endpoint_key).filter(
            AgentTask.id.in_(unresolved_source_ids)
        ).all()
        allowed_source_ids.update(
            str(task_id)
            for task_id, endpoint_id in direct_rows
            if endpoint_id in allowed_host_set
        )
    return {
        report_id
        for report_id, source_job_id in source_by_report.items()
        if str(source_job_id) in allowed_source_ids
    }


def can_access_report(report_id, action_id="view_reports"):
    if session.get('is_admin'):
        return True
    return str(report_id) in accessible_report_id_set([report_id], action_id=action_id)

def load_template_payload(template):
    try:
        parsed = json.loads(template.payload) if template.payload else {}
        if isinstance(parsed, dict):
            return parsed
        return {"script": str(parsed)}
    except Exception:
        return {"script": str(template.payload or "")}


def next_template_clone_name(source_name, existing_names):
    source_name = str(source_name or "Template").strip() or "Template"
    existing = {str(name or "").strip().casefold() for name in existing_names}
    clone_number = 1
    while True:
        suffix = " clone" if clone_number == 1 else f" clone {clone_number}"
        prefix = source_name[:max(1, 150 - len(suffix))].rstrip()
        candidate = f"{prefix}{suffix}"
        if candidate.casefold() not in existing:
            return candidate
        clone_number += 1


def clone_template_payload(template):
    payload = dict(load_template_payload(template))
    # Approval and governance policy belongs to the original template. A clone
    # starts as an editable private draft and must be reviewed independently.
    payload.pop(TEMPLATE_POLICY_KEY, None)
    return payload


def template_deletion_impact(template_id, sample_limit=5):
    scheduled_query = ScheduledTask.query.filter_by(template_id=template_id)
    trigger_query = TriggerRule.query.filter_by(action_template_id=template_id)
    scheduled_count = scheduled_query.count()
    trigger_count = trigger_query.count()
    scheduled_names = [
        row.name for row in scheduled_query.order_by(ScheduledTask.name).limit(sample_limit).all()
    ]
    trigger_names = [
        row.name for row in trigger_query.order_by(TriggerRule.name).limit(sample_limit).all()
    ]
    return {
        "scheduled_tasks": {
            "count": scheduled_count,
            "names": scheduled_names,
            "truncated": scheduled_count > len(scheduled_names),
        },
        "trigger_rules": {
            "count": trigger_count,
            "names": trigger_names,
            "truncated": trigger_count > len(trigger_names),
        },
    }


def approved_report_template(template_id):
    template = TaskTemplate.query.get(str(template_id or "")) if template_id else None
    if not template or getattr(template, "type", "action") != "report" or not template_approval_valid(template):
        return None
    return template


def validate_report_template_payload(template_type, payload):
    if str(template_type or "action") != "report":
        return
    script = payload.get("script", "") if isinstance(payload, dict) else ""
    if not str(script or "").strip():
        raise ValueError("Report template script is required")
    validate_report_template(str(script))


TEMPLATE_POLICY_KEY = "__template_policy"
TEMPLATE_VARIABLE_SCHEMA_KEY = "__variable_schema"


def template_policy(template_or_payload):
    payload = template_or_payload if isinstance(template_or_payload, dict) else load_template_payload(template_or_payload)
    policy = payload.get(TEMPLATE_POLICY_KEY, {}) if isinstance(payload, dict) else {}
    return policy if isinstance(policy, dict) else {}

def template_variable_schema(template_or_payload):
    payload = template_or_payload if isinstance(template_or_payload, dict) else load_template_payload(template_or_payload)
    schema = payload.get(TEMPLATE_VARIABLE_SCHEMA_KEY, {}) if isinstance(payload, dict) else {}
    return schema if isinstance(schema, dict) else {}


API_UNSAFE_INTERPOLATION_PATTERN = re.compile(r"[\x00\r\n`$;|&<>\"'()\[\]{}]")


def validate_api_template_variables(payload, variables):
    """Validate values before literal substitution into an executable payload.

    API execution requires every variable to have an explicit schema. Text
    values must be constrained by an allowlist (options/choices) or a full-match
    regular expression. This prevents an Element bot from turning a variable
    such as a login into arbitrary PowerShell/shell syntax.
    """
    if not session.get("api_key_auth"):
        return variables or {}
    if not isinstance(variables, dict):
        raise ValueError("Variables must be an object")

    schema = template_variable_schema(payload)
    required = set()
    for key, value in (payload or {}).items():
        if isinstance(value, str) and not str(key).startswith("__"):
            required.update(VARIABLE_PATTERN.findall(value))

    missing_schema = sorted(required - set(schema))
    if missing_schema:
        raise ValueError(
            "API execution requires a variable schema for: " + ", ".join(missing_schema)
        )
    unknown = sorted(set(variables) - set(schema))
    if unknown:
        raise ValueError("Variables are not declared by this template: " + ", ".join(unknown))
    missing = sorted(required - set(variables))
    if missing:
        raise ValueError("Missing template variables: " + ", ".join(missing))

    normalized = {}
    for name, raw_value in variables.items():
        spec = schema.get(name)
        if not isinstance(spec, dict):
            raise ValueError(f"Variable '{name}' has an invalid API schema")
        if isinstance(raw_value, (dict, list)):
            raise ValueError(f"Variable '{name}' must be a scalar value")

        value_type = str(spec.get("type") or "text").strip().lower()
        options = spec.get("options", spec.get("choices"))
        if isinstance(options, str):
            options = [item.strip() for item in re.split(r"[,\r\n]+", options) if item.strip()]
        if isinstance(options, list):
            option_values = [
                str(item.get("value", item.get("label", ""))) if isinstance(item, dict) else str(item)
                for item in options
            ]
        else:
            option_values = []

        if value_type in ("boolean", "checkbox"):
            bool_value = str(raw_value).strip().lower()
            if bool_value not in ("true", "false", "1", "0"):
                raise ValueError(f"Variable '{name}' must be true or false")
            value = "true" if bool_value in ("true", "1") else "false"
        elif value_type in ("integer", "int"):
            try:
                value = str(int(str(raw_value).strip()))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Variable '{name}' must be an integer") from exc
        elif value_type in ("number", "float", "decimal"):
            try:
                value = format(Decimal(str(raw_value).strip()), "f")
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(f"Variable '{name}' must be a number") from exc
        else:
            value = "" if raw_value is None else str(raw_value)

        try:
            max_length = max(1, min(int(spec.get("max_length", 256)), 2048))
        except (TypeError, ValueError):
            raise ValueError(f"Variable '{name}' has an invalid max_length")
        if len(value) > max_length:
            raise ValueError(f"Variable '{name}' is longer than {max_length} characters")
        if API_UNSAFE_INTERPOLATION_PATTERN.search(value):
            raise ValueError(f"Variable '{name}' contains characters unsafe for command interpolation")

        if option_values:
            if value not in option_values:
                raise ValueError(f"Variable '{name}' must be one of the configured options")
        elif value_type not in ("boolean", "checkbox", "integer", "int", "number", "float", "decimal"):
            pattern = spec.get("pattern")
            if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
                raise ValueError(
                    f"Variable '{name}' must define options/choices or a pattern for API use"
                )
            try:
                if re.fullmatch(pattern, value) is None:
                    raise ValueError(f"Variable '{name}' does not match its allowed format")
            except re.error as exc:
                raise ValueError(f"Variable '{name}' has an invalid validation pattern") from exc
        normalized[str(name)] = value
    return normalized


def template_variable_names(template):
    payload = load_template_payload(template)
    values = []
    names = set(template_variable_schema(payload).keys())
    if isinstance(payload, dict):
        values = [str(value) for key, value in payload.items() if isinstance(value, str) and not str(key).startswith("__")]
    else:
        values = [str(payload or "")]
    for value in values:
        names.update(VARIABLE_PATTERN.findall(value))
    return sorted(names)


def mobile_template_risk(template):
    """Return a presentation hint for extra confirmation on small screens.

    This is deliberately not an authorization decision. The regular template
    permissions and target checks remain the security boundary.
    """
    action_type = str(getattr(template, "action_type", "") or "").strip().lower()
    name = str(getattr(template, "name", "") or "").strip().lower()
    high_risk_terms = ("reboot", "restart", "shutdown", "poweroff", "agent update", "agent_update")
    if action_type in {"reboot", "agent_update"} or any(term in name for term in high_risk_terms):
        return "high"
    if action_type not in {"run_script", "metric", "inventory", "audit"}:
        return "elevated"
    return "standard"


def mobile_variable_schema(template):
    """Expose variable UI metadata without leaking sensitive defaults."""
    source = template_variable_schema(template)
    try:
        schema = json.loads(json.dumps(source, ensure_ascii=False))
    except (TypeError, ValueError):
        schema = {}
    if not isinstance(schema, dict):
        return {}
    for name, spec in schema.items():
        if is_sensitive_name(name) and isinstance(spec, dict):
            spec.pop("default", None)
    return schema


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


def _policy_list(policy, key):
    value = policy.get(key)
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[,;\s]+", value) if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _current_user_group_ids():
    api_scope = request_api_group_scope()
    if api_scope is not None:
        return {str(group_id) for group_id in api_scope if group_id}
    user = current_user()
    if not user:
        return set()
    groups = getattr(user, "allowed_host_groups", [])
    if hasattr(groups, "all"):
        groups = groups.all()
    return {str(group.id) for group in groups}


def template_run_policy_allows(template):
    policy = template_policy(template)
    if bool(policy.get("disable_run")):
        return False
    if bool(policy.get("allow_all_users")):
        return True

    username = str(session.get("username") or "")
    allowed_users = set(_policy_list(policy, "allowed_users"))
    allowed_groups = set(_policy_list(policy, "allowed_groups"))
    allowed_permissions = _policy_list(policy, "allowed_permissions")

    if not allowed_users and not allowed_groups and not allowed_permissions:
        return True

    if username and username in allowed_users:
        return True

    if allowed_groups and allowed_groups.intersection(_current_user_group_ids()):
        return True

    if any(can(permission_id) for permission_id in allowed_permissions):
        return True

    return False


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
def can_view_sensitive_reports(report_id=None, host_id=None, group_id=None):
    if not can("view_sensitive_reports"):
        return False
    if session.get("is_admin"):
        return True
    if report_id is not None:
        return can_access_report(report_id, "view_sensitive_reports")
    if host_id is not None:
        return str(host_id) in set(infra_allowed_host_ids(session.get("user_id"), "view_sensitive_reports"))
    if group_id is not None:
        return group_action_allowed(current_user(), group_id, "view_sensitive_reports")
    return False


def can_view_sensitive_target(target_type, target_id):
    if str(target_type or "").lower() == "host":
        return can_view_sensitive_reports(host_id=target_id)
    if str(target_type or "").lower() == "group":
        return can_view_sensitive_reports(group_id=target_id)
    return False


def report_body_for_current_user(report_body, report_id=None, host_id=None, group_id=None):
    if can_view_sensitive_reports(report_id=report_id, host_id=host_id, group_id=group_id):
        return report_body
    return mask_sensitive_text(report_body)


def apply_template_variables(payload, variables):
    payload_dict = dict(payload or {})
    if payload_dict.get('__ai_generated'):
        # AI action scripts use configuration constants, never the legacy textual
        # parameter/secret interpolation path. This also covers later manual edits.
        if any(re.search(r'{{|{%', value) for key, value in payload_dict.items()
               if isinstance(value, str) and not str(key).startswith('__')):
            raise ValueError('AI action templates cannot use legacy variable or secret substitution')
        return payload_dict, []
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
        variable_pattern = re.compile(r"{{\s*" + re.escape(str(key)) + r"\s*}}")
        for field_name, field_value in rendered_fields.items():
            # Use a callable replacement so Windows and UNC backslashes are
            # inserted literally. Passing `value` directly makes re.sub treat
            # sequences such as \2, \B, or \g<2> as replacement syntax.
            rendered_fields[field_name] = variable_pattern.sub(lambda _match, replacement=value: replacement, field_value)

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
        actor = current_user()
        audit_session_id = session.get("audit_session_id")
        entry = AuditLog(
            user=session.get("username") or "System",
            actor_user_id=getattr(actor, "id", None),
            actor_type="api_key" if session.get("api_key_auth") else "user",
            actor_name=current_actor_label(),
            actor_role="superadmin" if getattr(actor, "is_admin", False) else (
                "api_key" if session.get("api_key_auth") else "operator"
            ),
            source_type="api" if session.get("api_key_auth") else "web",
            session_id_hash=hashlib.sha256(str(audit_session_id).encode("utf-8")).hexdigest()
            if audit_session_id else None,
            user_agent=request.headers.get("User-Agent", "")[:1000],
            module="Infrastructure",
            action=action,
            target_type=target_type,
            target_id=str(target_id or ""),
            ip_address=effective_client_ip(request),
            request_id=getattr(g, "request_id", None),
            details=json.dumps(details or {}, ensure_ascii=False),
            status=status,
        )
        db.session.add(entry)
        db.session.flush()
        from core.history_search import index_audit_log
        index_audit_log(entry)
    except Exception:
        logging.getLogger("winhub").exception("Failed to write Infrastructure audit")


def dispatch_infrastructure_task(
    user_id, action_type, target_ids, payload, title, created_by=None, source_type=None,
    ai_report=None,
):
    user = current_user() if user_id == session.get("user_id") else User.query.get(user_id)
    if not user:
        raise PermissionError("Invalid user")

    report_template_id = payload.get("__report_template_id") if isinstance(payload, dict) else None
    if report_template_id and ai_report:
        raise ValueError("Choose either an AI report or a report template, not both")
    if report_template_id and not approved_report_template(report_template_id):
        raise PermissionError("Approved report template not found or approval seal is invalid")

    payload_json = json.dumps(payload, ensure_ascii=False)
    job_id = str(uuid.uuid4())
    requested_ids = list(dict.fromkeys(str(host_id) for host_id in target_ids if host_id))
    hosts_by_id = {
        host.id: host
        for host in Endpoint.query.filter(Endpoint.id.in_(requested_ids)).all()
    }
    allowed_host_ids = WinHubCore.authorized_target_ids(user_id, requested_ids)
    tasks = []
    resolved_source = str(source_type or "").strip().lower()
    if not resolved_source:
        if session.get("api_key_auth"):
            resolved_source = "api"
        elif str(title or "").startswith("[Auto-Fix]"):
            resolved_source = "trigger"
        elif str(title or "").startswith("[Auto]"):
            resolved_source = "scheduler"
        else:
            resolved_source = "manual"
    template_id = (
        payload.get("__template_id") or payload.get("__report_template_id")
        if isinstance(payload, dict) else None
    )
    schedule_id = payload.get("__schedule_id") if isinstance(payload, dict) else None

    for host_id in requested_ids:
        host = hosts_by_id.get(host_id)
        if not host:
            raise ValueError(f"Unknown endpoint: {host_id}")
        if getattr(host, "approval_status", "Approved") != "Approved":
            raise PermissionError(f"Endpoint is not approved: {host.hostname or host.id}")
        if bool(getattr(host, "is_blocked", False)):
            continue
        if host_id not in allowed_host_ids:
            continue
        task_id = str(uuid.uuid4())
        tasks.append(AgentTask(
            id=task_id,
            job_id=job_id,
            endpoint_id=host_id,
            endpoint_id_snapshot=host_id,
            endpoint_hostname_snapshot=host.hostname,
            endpoint_name_snapshot=host.display_name,
            endpoint_groups_snapshot=json.dumps([
                {"id": group.id, "name": group.name}
                for group in host.groups
            ], ensure_ascii=False),
            title=title,
            module_source="Infrastructure",
            action_type=action_type,
            source_type=resolved_source,
            actor_user_id=user.id,
            template_id=str(template_id) if template_id else None,
            schedule_id=str(schedule_id) if schedule_id else None,
            payload=payload_json,
            created_by=created_by or user.username
        ))

    if not tasks:
        raise PermissionError("No authorized targets selected")

    db.session.add_all(tasks)
    db.session.flush()
    if ai_report:
        create_ai_report_request(
            job_id,
            ai_report,
            actor_user_id=user.id,
            actor_name=created_by or user.username,
        )
    from core.history_search import index_agent_task
    for task in tasks:
        index_agent_task(task)
    db.session.commit()
    WinHubCore.audit(
        user_id=user.id,
        username=created_by or user.username,
        module="Infrastructure",
        action="Task Dispatched",
        details={
            "job_id": job_id,
            "title": title,
            "action_type": action_type,
            "target_count": len(tasks),
            "template_id": template_id,
            "schedule_id": schedule_id,
        },
        target_type="task_job",
        target_id=job_id,
        source_type=resolved_source,
        status="Success",
    )
    return job_id, [task.id for task in tasks]

def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    if has_request_context():
        cached_user = getattr(g, "infrastructure_current_user", None)
        if cached_user is not None and getattr(cached_user, "id", None) == user_id:
            return cached_user
    user = User.query.get(user_id)
    if has_request_context():
        g.infrastructure_current_user = user
    return user

def can(permission_id):
    return has_permission(current_user(), "Infrastructure", permission_id)


def is_interactive_superadmin():
    user = current_user()
    return bool(user and user.is_admin and not session.get("api_key_auth"))


def require_interactive_superadmin():
    if not is_interactive_superadmin():
        return jsonify({
            "success": False,
            "message": "This permanent deletion requires an interactive superadmin session",
        }), 403
    return None

def infra_allowed_host_ids(user_id, action_id="view_hosts"):
    user = current_user() if user_id == session.get("user_id") else User.query.get(user_id)
    if not user or not has_permission(user, "Infrastructure", action_id):
        return []
    approved_only = not (user.is_admin and request_api_group_scope() is None)
    return list(allowed_host_ids_for_action(user, action_id, approved_only=approved_only))


def infra_allowed_group_ids(user_id, action_id="view_groups"):
    """Return action-specific group scope from the request cache."""
    user = current_user() if user_id == session.get("user_id") else User.query.get(user_id)
    if not user or not has_permission(user, "Infrastructure", action_id):
        return []
    return list(allowed_group_ids_for_action(user, action_id))

def infra_live_state():
    """Small, non-sensitive revision snapshot for browser live refresh."""
    user_id = session.get("user_id")
    allowed_host_ids = infra_allowed_host_ids(user_id)
    empty_section = {"revision": "0", "count": 0, "latest": None}
    if not allowed_host_ids:
        return {
            "nodes": empty_section,
            "review": empty_section,
            "queue": empty_section,
            "reports": empty_section,
        }

    def row_revision(*parts):
        raw = "|".join("" if part is None else str(part) for part in parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    endpoint_rows = db.session.query(
        Endpoint.id,
        Endpoint.hostname,
        Endpoint.display_name,
        Endpoint.approval_status,
        Endpoint.agent_version,
        or_(
            Endpoint.public_key_pem_plain.isnot(None),
            Endpoint.public_key_pem.isnot(None),
        ).label("has_public_key"),
        Endpoint.last_seen,
        Endpoint.is_blocked,
        Endpoint.identity_warning,
        Endpoint.identity_duplicate_allowed,
    ).filter(Endpoint.id.in_(allowed_host_ids)).all()

    endpoint_parts = []
    review_parts = []
    review_count = 0
    latest_endpoint = None
    online_since = datetime.utcnow() - timedelta(minutes=5)
    for endpoint in endpoint_rows:
        is_online = bool(endpoint.last_seen and endpoint.last_seen >= online_since)
        identity_warning = effective_endpoint_identity_warning(endpoint)
        endpoint_parts.append(row_revision(
            endpoint.id,
            endpoint.hostname,
            endpoint.display_name,
            endpoint.approval_status,
            endpoint.agent_version,
            bool(endpoint.has_public_key),
            is_online,
            endpoint.is_blocked,
            identity_warning,
        ))
        if endpoint.last_seen and (latest_endpoint is None or endpoint.last_seen > latest_endpoint):
            latest_endpoint = endpoint.last_seen
        approval = endpoint.approval_status or "Approved"
        if approval != "Approved" or identity_warning:
            review_count += 1
            review_parts.append(endpoint_parts[-1])

    queue_host_ids = infra_allowed_host_ids(user_id, "view_queue")
    task_rows = db.session.query(
        AgentTask.id,
        AgentTask.job_id,
        AgentTask.endpoint_id,
        AgentTask.status,
        AgentTask.created_at,
        AgentTask.finished_at,
    ).filter(AgentTask.endpoint_id.in_(queue_host_ids)).order_by(AgentTask.created_at.desc()).limit(250).all() if queue_host_ids else []
    task_parts = [
        row_revision(
            task.id,
            task.job_id,
            task.endpoint_id,
            task.status,
            task.created_at.isoformat() if task.created_at else "",
            task.finished_at.isoformat() if task.finished_at else "",
        )
        for task in task_rows
    ]
    latest_task = max((task.created_at for task in task_rows if task.created_at), default=None)

    reports = db.session.query(
        AggregatedJob.id,
        AggregatedJob.status,
        AggregatedJob.total_count,
        AggregatedJob.success_count,
        AggregatedJob.error_count,
        AggregatedJob.created_at,
    ).order_by(AggregatedJob.created_at.desc()).limit(100).all() if can("view_reports") else []
    if reports and not session.get("is_admin"):
        accessible_reports = accessible_report_id_set([report.id for report in reports], user_id, "view_reports")
        reports = [report for report in reports if str(report.id) in accessible_reports]
    report_parts = [
        row_revision(
            report.id,
            report.status,
            report.total_count,
            report.success_count,
            report.error_count,
            report.created_at.isoformat() if report.created_at else "",
        )
        for report in reports
    ]
    latest_report = max((report.created_at for report in reports if report.created_at), default=None)

    return {
        "nodes": {
            "revision": row_revision("nodes", len(endpoint_parts), *sorted(endpoint_parts)),
            "count": len(endpoint_parts),
            "latest": latest_endpoint.isoformat() if latest_endpoint else None,
        },
        "review": {
            "revision": row_revision("review", review_count, *sorted(review_parts)),
            "count": review_count,
            "latest": latest_endpoint.isoformat() if latest_endpoint else None,
        },
        "queue": {
            "revision": row_revision("queue", len(task_parts), *task_parts),
            "count": len(task_parts),
            "latest": latest_task.isoformat() if latest_task else None,
        },
        "reports": {
            "revision": row_revision("reports", len(report_parts), *report_parts),
            "count": len(report_parts),
            "latest": latest_report.isoformat() if latest_report else None,
        },
    }

def infra_live_state_cached():
    """Reuse short-lived live-state snapshots across browser SSE clients."""
    user_id = session.get("user_id")
    if not user_id:
        return infra_live_state()
    cache_key = (int(user_id), bool(session.get("is_admin")))
    now = time.monotonic()
    with live_state_cache_lock:
        cached = live_state_cache.get(cache_key)
        if cached and now - cached["at"] < LIVE_STATE_CACHE_TTL_SECONDS:
            return cached["state"]

    state = infra_live_state()
    with live_state_cache_lock:
        live_state_cache[cache_key] = {"at": time.monotonic(), "state": state}
        if len(live_state_cache) > 256:
            cutoff = time.monotonic() - (LIVE_STATE_CACHE_TTL_SECONDS * 6)
            stale_keys = [key for key, value in live_state_cache.items() if value.get("at", 0) < cutoff]
            for key in stale_keys:
                live_state_cache.pop(key, None)
    return state

def endpoint_health_score(endpoint, latest_version=None):
    now = datetime.utcnow()
    if isinstance(latest_version, dict):
        latest_version = latest_version_for_endpoint(endpoint, latest_version)
    else:
        latest_version = latest_version if latest_version is not None else latest_agent_package_version(endpoint_agent_platform(endpoint))
    last_seen = endpoint.last_seen
    if last_seen and getattr(last_seen, "tzinfo", None):
        last_seen = last_seen.replace(tzinfo=None)
    online = bool(last_seen and last_seen >= now - timedelta(minutes=5))
    outdated = bool(latest_version and (getattr(endpoint, "agent_version", "") or "") != latest_version)
    enrolled_flag = getattr(endpoint, "agent_identity_key_enrolled", None)
    has_key = bool(enrolled_flag) if enrolled_flag is not None else bool(
        getattr(endpoint, "public_key_pem_plain", None) or getattr(endpoint, "public_key_pem", None)
    )

    score = 100
    reasons = []
    if outdated:
        score -= 20
        reasons.append("agent_outdated")
    if not has_key:
        score -= 15
        reasons.append("missing_identity_key")
    if getattr(endpoint, "is_blocked", False):
        score -= 30
        reasons.append("blocked")
    if getattr(endpoint, "approval_status", "Approved") != "Approved":
        score -= 25
        reasons.append("not_approved")
    if effective_endpoint_identity_warning(endpoint):
        score -= 15
        reasons.append("identity_warning")

    if "host_info" in getattr(endpoint, "__dict__", {}):
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
        "signed_key": has_key,
    }

def annotate_endpoint_duplicates(agents):
    def normalized_hostname(agent):
        return str(getattr(agent, "hostname", "") or "").strip().upper()

    def host_domain_identity(agent):
        try:
            host_info = json.loads(agent.host_info or "{}")
            if not isinstance(host_info, dict):
                host_info = {}
        except Exception:
            host_info = {}
        machine_name = str(host_info.get("machine_name") or "").strip()
        user_domain = str(host_info.get("user_domain_name") or "").strip()
        dns_domain = str(host_info.get("domain_name") or "").strip()
        if user_domain and user_domain.upper() != machine_name.upper():
            domain = user_domain
        elif bool(host_info.get("likely_domain_joined")) and dns_domain:
            domain = dns_domain
        else:
            domain = ""
        return (domain or "WORKGROUP").upper()

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
            "domain": host_domain_identity(agent),
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
            "domain": host_domain_identity(agent),
        }

    approved = [
        agent for agent in agents
        if getattr(agent, "approval_status", "Approved") == "Approved"
    ]
    signals_by_id = {agent.id: endpoint_signals(agent) for agent in agents}
    approved_by_fingerprint = {}
    approved_by_hostname = {}
    approved_by_id = {agent.id: agent for agent in approved}
    ignored_pairs = duplicate_exception_pairs([agent.id for agent in agents])
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
            if endpoint_duplicate_pair_accepted(agent, approved_agent, ignored_pairs):
                continue
            approved_signals = signals_by_id.get(approved_agent.id, {})
            approved_fingerprints = approved_signals.get("fingerprints", set())
            reasons = []
            if hostname and hostname == approved_signals.get("hostname"):
                reasons.append("hostname")
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
    if not api_template_allowed(getattr(template, "id", None)):
        return False
    if getattr(template, "created_by", None) == session.get("username") and can("manage_templates"):
        return True
    return template_run_policy_allows(template)


def can_access_template_library_entry(template):
    if not template:
        return False
    if session.get("is_admin"):
        return True
    if getattr(template, "created_by", None) == session.get("username") and can("manage_templates"):
        return True
    return bool(getattr(template, "is_approved", False) and can_use_template(template))


def require_permission(permission_id):
    if not can(permission_id):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None


def requested_ai_report(data):
    value = (data or {}).get("ai_report")
    if not isinstance(value, dict) or not value.get("enabled"):
        return None
    if not can("use_ai_reports"):
        raise PermissionError("AI report permission is required")
    if (data or {}).get("report_template_id"):
        raise ValueError("Choose either an AI report or a report template, not both")
    return validate_ai_report_payload(value)

def require_superadmin():
    if not session.get("is_admin"):
        return jsonify({"success": False, "message": "Superadmin access required"}), 403
    return None

def require_any_permission(*permission_ids):
    if not any(can(permission_id) for permission_id in permission_ids):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    return None


def schedule_target_in_scope(scheduled_task, allowed_host_ids, allowed_group_ids):
    """Return whether a scheduled task targets a host/group visible to the user."""
    if not scheduled_task:
        return False
    target_type = str(getattr(scheduled_task, "target_type", "") or "").strip().lower()
    target_id = str(getattr(scheduled_task, "target_id", "") or "").strip()
    if target_type == "host":
        return target_id in set(allowed_host_ids or [])
    if target_type == "group":
        return target_id in set(allowed_group_ids or [])
    return False


def scheduled_tasks_visible_to_user(user, permissions, allowed_host_ids, allowed_group_ids):
    if not user or (not user.is_admin and not permissions.get("manage_scheduler")):
        return []

    scheduled_query = ScheduledTask.query
    if getattr(ScheduledTask, "template", None) is not None:
        scheduled_query = scheduled_query.options(selectinload(ScheduledTask.template))
    scheduled_tasks = scheduled_query.order_by(
        ScheduledTask.category,
        ScheduledTask.name,
    ).all()
    if user.is_admin:
        return scheduled_tasks

    return [
        scheduled_task
        for scheduled_task in scheduled_tasks
        if schedule_target_in_scope(scheduled_task, allowed_host_ids, allowed_group_ids)
        and can_access_template_library_entry(scheduled_task.template)
        and can_use_template(scheduled_task.template)
    ]

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

def get_report_gpg_key_status(gpg_path, email):
    try:
        proc = subprocess.run(
            [gpg_path, "--batch", "--with-colons", "--list-keys", email],
            capture_output=True,
            text=True,
            timeout=5,
            env=gpg_env(),
            **hidden_subprocess_kwargs(),
        )
    except Exception as exc:
        return {"usable": False, "reason": f"GPG key check failed: {exc}"}

    if proc.returncode != 0:
        return {"usable": False, "reason": "Missing public key"}

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
        return {"usable": True, "reason": "Public key is usable"}

    if not saw_public_key:
        return {"usable": False, "reason": "Missing public key"}
    return {"usable": False, "reason": unusable_reasons[0] if unusable_reasons else "No usable public key"}


def ensure_report_gpg_key_ready(gpg_path, recipient, keyserver=None):
    status = get_report_gpg_key_status(gpg_path, recipient)
    if status["usable"]:
        return True, status["reason"]

    keyserver = str(keyserver or "").strip()
    if keyserver:
        fetched, fetch_message = fetch_public_key(keyserver, recipient)
        if not fetched:
            return False, f"{status['reason']}; keyserver fetch failed: {fetch_message}"
        refreshed = get_report_gpg_key_status(gpg_path, recipient)
        if refreshed["usable"]:
            return True, "Public key refreshed successfully"
        return False, f"{refreshed['reason']} after keyserver refresh"

    return False, f"{status['reason']}. Import a valid public key in Administration > GPG Keys or set a GPG keyserver on the SMTP profile."


def encrypt_report_body(body, recipient, sender_email, keyserver=None):
    gpg_path = getattr(Config, 'GPG_PATH', os.environ.get('GPG_PATH', 'gpg'))
    if os.path.sep in gpg_path and not os.path.exists(gpg_path):
        return False, body, f"GPG executable not found: {gpg_path}"

    unique_id = str(uuid.uuid4())
    tmp_in = os.path.join(tempfile.gettempdir(), f"winhub_report_{unique_id}.txt")
    tmp_out = tmp_in + ".asc"
    try:
        key_ready, key_message = ensure_report_gpg_key_ready(gpg_path, recipient, keyserver)
        if not key_ready:
            return False, body, key_message

        with open(tmp_in, 'w', encoding='utf-8') as f:
            f.write(body)
        cmd = [
            gpg_path, "--batch", "--yes", "--trust-model", "always", "--no-auto-key-locate",
            "--encrypt", "--armor", "-r", recipient,
            "-o", tmp_out, tmp_in
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL, env=gpg_env(), **hidden_subprocess_kwargs())
        if result.returncode != 0 or not os.path.exists(tmp_out):
            error_text = (result.stderr or result.stdout or "GPG encryption failed").strip()
            return False, body, error_text
        with open(tmp_out, 'r', encoding='utf-8') as f:
            return True, f.read(), None
    except subprocess.TimeoutExpired:
        return False, body, "GPG encryption timed out after 15 seconds"
    except Exception as e:
        return False, body, str(e)
    finally:
        for path in [tmp_in, tmp_out]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass


def report_email_bodies(report_body, custom_message=""):
    """Build a readable text fallback and a sanitized formatted HTML body."""
    report_html = safe_report_html(report_body)
    report_text = report_body_plain_text(report_body)
    note = str(custom_message or "").strip()
    note_text = f"{note}\n\n{'=' * 50}\n\n" if note else ""
    note_html = ""
    if note:
        escaped_note = html.escape(note, quote=True).replace("\n", "<br />")
        note_html = (
            '<div class="winhub-note">'
            f"{escaped_note}"
            "</div><hr />"
        )
    html_body = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<style>"
        "body{margin:0;padding:24px;background:#f8fafc;color:#0f172a;font-family:Arial,sans-serif;line-height:1.55}"
        ".winhub-report{max-width:960px;margin:0 auto;background:#fff;border:1px solid #cbd5e1;border-radius:12px;padding:28px}"
        ".winhub-note{margin:0 0 20px;padding:14px 16px;background:#eef2ff;border-left:4px solid #6366f1}"
        "h1,h2,h3,h4,h5,h6{color:#0f172a;line-height:1.25}"
        "table{width:100%;border-collapse:collapse;margin:16px 0}"
        "th,td{border:1px solid #cbd5e1;padding:8px 10px;text-align:left;vertical-align:top}"
        "th{background:#e2e8f0}tr:nth-child(even) td{background:#f8fafc}"
        "pre,code{font-family:Consolas,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:14px}"
        "blockquote{margin:16px 0;padding:10px 16px;border-left:4px solid #6366f1;background:#eef2ff}"
        "</style></head><body><div class=\"winhub-report\">"
        f"{note_html}{report_html}"
        "</div></body></html>"
    )
    return f"{note_text}{report_text}", html_body


def report_email_alternative(report_body, custom_message=""):
    plain_body, html_body = report_email_bodies(report_body, custom_message)
    message = MIMEMultipart("alternative")
    message.attach(MIMEText(plain_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))
    return message


def pgp_mime_message(encrypted_body):
    """Wrap an armored encrypted MIME entity using the PGP/MIME wire format."""
    message = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
    version = MIMEBase("application", "pgp-encrypted")
    version.set_payload("Version: 1\r\n")
    version["Content-Transfer-Encoding"] = "7bit"
    encrypted = MIMEBase("application", "octet-stream", name="encrypted.asc")
    encrypted.set_payload(str(encrypted_body or ""))
    encrypted["Content-Transfer-Encoding"] = "7bit"
    encrypted.add_header("Content-Disposition", "inline", filename="encrypted.asc")
    message.attach(version)
    message.attach(encrypted)
    return message


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

        sent_count = 0
        server_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        tls_context = ssl.create_default_context() if Config.OUTBOUND_POLICY_MODE == "enforce" else None
        with pinned_outbound_host(host, port, "report SMTP delivery"):
            server_options = {"timeout": 20}
            if port == 465 and tls_context is not None:
                server_options["context"] = tls_context
            with server_class(host, port, **server_options) as server:
                if port != 465:
                    server.starttls(context=tls_context) if tls_context is not None else server.starttls()
                dec_pass = sec_manager.decrypt_data(smtp_conf['password'])
                server.login(sender_email, dec_pass)

                for rec in recipients:
                    alternative = report_email_alternative(report_body, custom_message)
                    if use_gpg:
                        encrypted_ok, encrypted_body, error_text = encrypt_report_body(
                            alternative.as_string(),
                            rec,
                            sender_email,
                            smtp_conf.get("keyserver"),
                        )
                        if not encrypted_ok:
                            return False, f"GPG encryption failed for {rec}: {error_text}", sent_count
                        msg = pgp_mime_message(encrypted_body)
                    else:
                        msg = alternative

                    msg['Subject'] = str(title or '').strip() or "Report"
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
    report = AggregatedJob.query.get(report_id)
    delivery = None
    if report:
        delivery, _ = record_report_delivery(
            report,
            channel="email",
            destination={"sender": sender_email, "recipients": parse_recipients(recipient_list), "gpg": use_gpg},
            subject=title,
            content_snapshot=report_body,
            actor_name="System",
            status="Sending",
        )
        db.session.commit()
    success, message, sent_count = send_report_email(
        title=title,
        report_body=report_body,
        sender_email=sender_email,
        recipient_list=recipient_list,
        use_gpg=use_gpg
    )
    if not success:
        logging.getLogger("winhub").error(f"[Auto-Email] {message}")
    if delivery:
        delivery = ReportDelivery.query.get(delivery.id)
        finish_report_delivery(
            delivery,
            success=success,
            details={"message": message, "sent_count": sent_count, "automatic": True},
        )
        db.session.commit()
    return success, message, sent_count


def update_report_send_status(report_id, success, sent_count=0):
    report = AggregatedJob.query.get(report_id)
    if not report:
        return
    if success:
        time_str = datetime.now(kyiv_tz).strftime("%H:%M")
        report.status = f'Sent ({sent_count}) {time_str}'
    else:
        report.status = 'Send Error'
    db.session.commit()

def perform_auto_confluence_publish(report_id, profile_name, page_id, title=None, body_format="safe_html", custom_note=""):
    profiles = load_confluence_profiles()
    profile_name = str(profile_name or "").strip()
    profile = profiles.get(profile_name)
    if not profile:
        return False, "Confluence profile was not found.", None

    report = AggregatedJob.query.get(report_id)
    if not report:
        return False, "Report not found.", None

    page_id = str(page_id or profile.get("default_page_id") or "").strip()
    body_format = str(body_format or "safe_html").strip()
    if body_format not in ("safe_html", "escaped_pre", "storage_html"):
        body_format = "safe_html"

    outbound_snapshot = (
        report.report_data or ""
        if body_format == "storage_html"
        else confluence_report_storage_html(
            report,
            report.report_data or "",
            custom_note,
            formatted=body_format == "safe_html",
        )
    )
    delivery, _ = record_report_delivery(
        report,
        channel="confluence",
        destination={"profile": profile_name, "page_id": page_id},
        subject=str(title or report.title or ""),
        note=custom_note,
        content_snapshot=outbound_snapshot,
        actor_name="System",
        status="Sending",
    )
    db.session.commit()

    success, message, web_url = publish_report_to_confluence(
        profile=profile,
        report=report,
        page_id=page_id,
        title=str(title or "").strip() or None,
        body_format=body_format,
        custom_note=str(custom_note or "").strip(),
        report_body=report.report_data or "",
    )

    now_str = datetime.now(kyiv_tz).strftime("%Y-%m-%d %H:%M:%S %Z")
    profile["last_published_at"] = now_str if success else profile.get("last_published_at", "")
    profile["last_status"] = "Published" if success else message
    profiles[profile_name] = profile
    save_confluence_profiles(profiles)
    delivery = ReportDelivery.query.get(delivery.id)
    finish_report_delivery(
        delivery,
        success=success,
        details={"message": message, "url": web_url, "automatic": True},
    )
    db.session.commit()
    if not success:
        logging.getLogger("winhub").error("[Auto-Confluence] %s", message)
    return success, message, web_url

def update_report_delivery_status(report_id, outcomes):
    report = AggregatedJob.query.get(report_id)
    if not report:
        return
    failures = [item for item in outcomes if not item.get("success")]
    time_str = datetime.now(kyiv_tz).strftime("%H:%M")
    if failures:
        labels = ", ".join(item.get("label", "Delivery") for item in failures)
        report.status = f"{labels} Error"
    elif outcomes:
        labels = "+".join(item.get("label", "Delivered") for item in outcomes)
        report.status = f"{labels} {time_str}"
    db.session.commit()

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
        signed = Endpoint.query.filter(
            or_(
                Endpoint.public_key_pem_plain.isnot(None),
                Endpoint.public_key_pem.isnot(None),
            )
        ).count()
        latest_versions = latest_agent_package_versions_by_platform()
        approved_endpoints = Endpoint.query.filter_by(approval_status="Approved").all()
        outdated = sum(
            1 for endpoint in approved_endpoints
            if latest_version_for_endpoint(endpoint, latest_versions)
            and (endpoint.agent_version or "") != latest_version_for_endpoint(endpoint, latest_versions)
        )
        latest_label = ", ".join(f"{platform}: {version}" for platform, version in sorted(latest_versions.items())) or (Config.LATEST_AGENT_VERSION or "unknown")
        online_since = datetime.utcnow() - timedelta(minutes=5)
        online = Endpoint.query.filter(Endpoint.last_seen >= online_since).count()
        lines += [
            "== Endpoint Summary ==",
            f"Total endpoints: {total}",
            f"Approved: {approved} | Pending: {pending} | Rejected: {rejected}",
            f"Online now: {online}",
            f"Signed identity keys: {signed}",
            f"Latest agent: {latest_label} | Outdated approved agents: {outdated}",
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
        last_auto_email_check = 0
        while True:
            try:
                now_monotonic = time.monotonic()
                if now_monotonic - last_auto_email_check >= AUTO_EMAIL_CHECK_INTERVAL_SECONDS:
                    last_auto_email_check = now_monotonic
                    db.session.commit()
                    jobs = AggregatedJob.query.options(
                        load_only(
                            AggregatedJob.id,
                            AggregatedJob.title,
                            AggregatedJob.status,
                            AggregatedJob.created_at,
                        )
                    ).filter_by(status='Waiting Review').order_by(
                        AggregatedJob.created_at.desc()
                    ).limit(AUTO_EMAIL_SCAN_LIMIT).all()

                    checked_unknown = 0
                    for job in jobs:
                        source_job_id = job.id
                        split_match = re.match(r"^([0-9a-fA-F]{32})\.(\d{3})$", str(job.id or ""))
                        if split_match:
                            try:
                                source_job_id = str(uuid.UUID(hex=split_match.group(1)))
                            except ValueError:
                                source_job_id = job.id
                        cache_key = f"{job.id}:{source_job_id}"
                        if cache_key in auto_email_skip_cache:
                            continue
                        if checked_unknown >= AUTO_EMAIL_NEW_CHECK_LIMIT:
                            break
                        checked_unknown += 1

                        ai_request = latest_ai_request(source_job_id)
                        if ai_request and ai_request.status != "Success":
                            # Recheck later so a successful retry becomes deliverable.
                            continue

                        task = AgentTask.query.options(
                            load_only(
                                AgentTask.id,
                                AgentTask.job_id,
                                AgentTask.payload,
                            )
                        ).filter((AgentTask.job_id == source_job_id) | (AgentTask.id == job.id)).first()

                        if not task:
                            auto_email_skip_cache.add(cache_key)
                            continue

                        payload = get_task_payload(task)
                        auto_email_enabled = bool(payload.get('__auto_email_toggle') or payload.get('auto_email_toggle'))
                        auto_confluence_enabled = bool(payload.get('__auto_confluence_toggle') or payload.get('auto_confluence_toggle'))

                        if not (auto_email_enabled or auto_confluence_enabled):
                            auto_email_skip_cache.add(cache_key)
                            continue

                        sender = payload.get('__auto_email_sender') or payload.get('auto_email_sender')
                        recipients = payload.get('__auto_email_recipients') or payload.get('auto_email_recipients')
                        use_gpg = payload.get('__auto_email_use_gpg', payload.get('auto_email_use_gpg', True))
                        confluence_profile = payload.get('__auto_confluence_profile') or payload.get('auto_confluence_profile')
                        confluence_page_id = payload.get('__auto_confluence_page_id') or payload.get('auto_confluence_page_id')
                        confluence_title = payload.get('__auto_confluence_title') or payload.get('auto_confluence_title')
                        confluence_format = payload.get('__auto_confluence_body_format') or payload.get('auto_confluence_body_format') or 'safe_html'
                        confluence_note = payload.get('__auto_confluence_note') or payload.get('auto_confluence_note') or ''

                        if auto_email_enabled and not (sender and recipients):
                            auto_email_enabled = False
                        if auto_confluence_enabled and not (confluence_profile and confluence_page_id):
                            auto_confluence_enabled = False
                        if not (auto_email_enabled or auto_confluence_enabled):
                            auto_email_skip_cache.add(cache_key)
                            continue

                        report_id = job.id
                        report_title = job.title
                        report_body = job.report_data

                        job.status = 'Delivering...'
                        db.session.commit()
                        db.session.remove()

                        outcomes = []
                        if auto_email_enabled:
                            success, message, sent_count = perform_auto_email_send(
                                report_id,
                                report_title,
                                report_body,
                                sender,
                                recipients,
                                use_gpg,
                            )
                            outcomes.append({"label": "Sent", "success": success, "message": message, "count": sent_count})

                        if auto_confluence_enabled:
                            success, message, web_url = perform_auto_confluence_publish(
                                report_id,
                                confluence_profile,
                                confluence_page_id,
                                title=confluence_title or report_title,
                                body_format=confluence_format,
                                custom_note=confluence_note,
                            )
                            outcomes.append({"label": "Published", "success": success, "message": message, "url": web_url})

                        update_report_delivery_status(report_id, outcomes)
                        auto_email_skip_cache.discard(cache_key)

                    if len(auto_email_skip_cache) > AUTO_EMAIL_SKIP_CACHE_LIMIT:
                        auto_email_skip_cache.clear()
                    db.session.commit()
            except Exception:
                db.session.rollback()
                logging.getLogger("winhub").exception("Auto-email checker failed")
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
            finally:
                db.session.remove()
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

    is_api_request = request.path.startswith("/api/")
    user_id = session.get('user_id')
    if not user_id:
        if is_api_request:
            return jsonify({"success": False, "message": "Authentication required. Please sign in again."}), 401
        return redirect(url_for('auth.login_page'))
    user = User.query.get(user_id)
    if not user:
        session.clear()
        if is_api_request:
            return jsonify({"success": False, "message": "Session expired. Please sign in again."}), 401
        return redirect(url_for('auth.login_page'))
    g.infrastructure_current_user = user

    if not has_module_access(user, 'Infrastructure'):
        if is_api_request:
            return jsonify({"success": False, "message": "Access denied for Endpoint Management."}), 403
        return "Access Denied", 403

# ==========================================
# UI ROUTES
# ==========================================
@infrastructure_bp.route('/module/infrastructure')
def index():
    user_id = session.get('user_id')
    now = datetime.utcnow()
    online_threshold = now - timedelta(minutes=5)

    agents = get_allowed_hosts_light(user_id)
    groups = WinHubCore.get_allowed_groups(user_id)
    group_ids = [group.id for group in groups]
    group_member_counts = dict(
        db.session.query(
            endpoint_group_m2m.c.group_id,
            func.count(endpoint_group_m2m.c.endpoint_id),
        ).filter(
            endpoint_group_m2m.c.group_id.in_(group_ids)
        ).group_by(endpoint_group_m2m.c.group_id).all()
    ) if group_ids else {}
    for group in groups:
        group.endpoint_count = int(group_member_counts.get(group.id, 0))
    latest_versions = latest_agent_package_versions_by_platform()

    def is_agent_current(agent):
        latest = latest_version_for_endpoint(agent, latest_versions)
        return bool(latest and (getattr(agent, "agent_version", "") or "") == latest)

    def is_agent_outdated(agent):
        latest = latest_version_for_endpoint(agent, latest_versions)
        return bool(latest and (getattr(agent, "agent_version", "") or "") != latest)

    stats = {
        'total': len(agents),
        'online': sum(1 for a in agents if a.last_seen and a.last_seen >= online_threshold),
        'offline': len(agents) - sum(1 for a in agents if a.last_seen and a.last_seen >= online_threshold),
        'blocked': sum(1 for a in agents if a.is_blocked),
        'pending': sum(1 for a in agents if getattr(a, "approval_status", "Approved") == "Pending"),
        'rejected': sum(1 for a in agents if getattr(a, "approval_status", "Approved") == "Rejected"),
        'current': sum(1 for a in agents if is_agent_current(a)),
        'outdated': sum(1 for a in agents if is_agent_outdated(a)),
        'signed': sum(1 for a in agents if bool(getattr(a, "agent_identity_key_enrolled", False))),
        'task_signature_v2': sum(1 for a in agents if bool(getattr(a, "task_signature_v2_seen_at", None))),
    }

    for a in agents:
        a.is_online = (a.last_seen and a.last_seen >= online_threshold)
        a.last_seen_str = to_kyiv_time(a.last_seen)
        a.last_enrollment_str = to_kyiv_time(getattr(a, "last_enrollment_at", None))
        a.agent_outdated = is_agent_outdated(a)
        if not hasattr(a, "encryption"):
            a.encryption = endpoint_encryption_payload(a)

    available_hosts = [{
        "id": a.id,
        "name": endpoint_display_name(a),
        "display_name": getattr(a, "display_name", None) or "",
        "hostname": a.hostname or a.id,
        "ip": getattr(a, "connection_ip", None) or "",
        "os_type": getattr(a, 'os_type', 'Windows'),
        "is_blocked": bool(a.is_blocked),
        "approval_status": getattr(a, 'approval_status', 'Approved'),
        "agent_version": getattr(a, 'agent_version', '') or '',
        "agent_outdated": is_agent_outdated(a),
        "agent_identity_key_enrolled": bool(getattr(a, "agent_identity_key_enrolled", False)),
        "task_signature_v2_ready": bool(getattr(a, "task_signature_v2_seen_at", None)),
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
    approved_duplicate_pairs = []
    seen_duplicate_pairs = set()
    approved_by_hostname = {}
    ignored_duplicate_pairs = duplicate_exception_pairs([agent.id for agent in agents])
    for agent in agents:
        if getattr(agent, "approval_status", "Approved") != "Approved":
            continue
        hostname_key = str(agent.hostname or "").strip().upper()
        if not hostname_key:
            continue
        duplicate_agent = approved_by_hostname.get(hostname_key)
        if duplicate_agent:
            pair_key = tuple(sorted([agent.id, duplicate_agent.id]))
            if (
                pair_key in seen_duplicate_pairs
                or endpoint_duplicate_pair_accepted(agent, duplicate_agent, ignored_duplicate_pairs)
            ):
                continue
            seen_duplicate_pairs.add(pair_key)
            approved_duplicate_pairs.append({
                "left": agent,
                "right": duplicate_agent,
                "reasons": ["hostname"],
            })
        else:
            approved_by_hostname[hostname_key] = agent
    stats["review"] = len(pending_agents) + len(rejected_agents) + len(approved_duplicate_pairs)

    is_admin = session.get('is_admin')
    user = current_user()
    permissions = user_permissions(user, "Infrastructure")
    if is_admin:
        templates_raw = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
        triggers_raw = TriggerRule.query.order_by(TriggerRule.name).all()
    else:
        templates_raw = TaskTemplate.query.filter(
            (TaskTemplate.is_approved == True) | (TaskTemplate.created_by == session.get("username"))
        ).order_by(TaskTemplate.category, TaskTemplate.name).all()
        templates_raw = [t for t in templates_raw if can_use_template(t)]
        triggers_raw = []

    scheduled_raw = scheduled_tasks_visible_to_user(
        user,
        permissions,
        set(infra_allowed_host_ids(user_id, "run_tasks")),
        set(infra_allowed_group_ids(user_id, "run_tasks")),
    )
    template_name_by_id = {template.id: template.name for template in templates_raw}

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
        "variable_schema": template_variable_schema(t),
    } for t in templates_raw]
    template_categories = sorted({
        (template.get("category") or "General").strip() or "General"
        for template in templates
    })

    def scheduled_task_variables(st):
        try:
            value = json.loads(st.variables) if st.variables else {}
            if not isinstance(value, dict):
                return {}
            return value if can_view_sensitive_target(st.target_type, st.target_id) else masked_variables(value)
        except Exception:
            return {}

    schedule_host_ids = {
        str(st.target_id) for st in scheduled_raw if str(st.target_type or "").lower() == "host"
    }
    schedule_group_ids = {
        str(st.target_id) for st in scheduled_raw if str(st.target_type or "").lower() == "group"
    }
    schedule_host_names = dict(
        db.session.query(Endpoint.id, Endpoint.hostname).filter(Endpoint.id.in_(schedule_host_ids)).all()
    ) if schedule_host_ids else {}
    schedule_group_names = dict(
        db.session.query(EndpointGroup.id, EndpointGroup.name).filter(EndpointGroup.id.in_(schedule_group_ids)).all()
    ) if schedule_group_ids else {}

    def scheduled_target_name(st):
        if str(st.target_type or "").lower() == "host":
            return schedule_host_names.get(str(st.target_id)) or "Unknown Target"
        return schedule_group_names.get(str(st.target_id)) or "Unknown Target"

    scheduled_tasks = [{
        "id": st.id, "name": st.name, "category": st.category, "cron": st.cron_expr, "is_active": st.is_active,
        "target_type": st.target_type,
        "target_name": scheduled_target_name(st),
        "template_name": st.template.name if st.template else "Deleted Template",
        "template_id": st.template_id,
        "target_id": st.target_id,
        "variables": scheduled_task_variables(st),
        "last_run": to_kyiv_time_short(st.last_run),
        "next_run": to_kyiv_time_short(getattr(st, "next_run_at", None)),
        "last_status": getattr(st, "last_status", None) or "Never run",
        "timeout_minutes": getattr(st, "timeout_minutes", None) or ""
    } for st in scheduled_raw]

    trigger_rules = []
    for tr in triggers_raw:
        trigger_rules.append({
            "id": tr.id, "name": tr.name, "metric_name": tr.metric_name,
            "operator": tr.operator, "threshold_value": tr.threshold_value,
            "action_template_id": tr.action_template_id,
            "action_name": template_name_by_id.get(tr.action_template_id, "Deleted Template"),
            "is_active": tr.is_active
        })

    return render_template('infrastructure_index.html', agents=agents, groups=groups, templates=templates,
                           template_categories=template_categories,
                           available_hosts=available_hosts,
                           pending_agents=pending_agents,
                           rejected_agents=rejected_agents,
                           approved_duplicate_pairs=approved_duplicate_pairs,
                           scheduled_tasks=scheduled_tasks, trigger_rules=trigger_rules, stats=stats,
                           latest_agent_versions=latest_versions,
                           agent_package_platforms=AGENT_PACKAGE_PLATFORMS,
                           agent_package_platform_labels=AGENT_PACKAGE_PLATFORM_LABELS,
                           username=session.get('username'), is_admin=is_admin, permissions=permissions)


@infrastructure_bp.route('/mobile')
@infrastructure_bp.route('/module/infrastructure/mobile')
def mobile_operator():
    user = User.query.get(session.get('user_id'))
    if not user or not has_module_access(user, 'Infrastructure'):
        return "Access Denied", 403
    permissions = user_permissions(user, "Infrastructure")
    mobile_permissions = {
        "run_tasks": bool(permissions.get("run_tasks")),
        "view_queue": bool(permissions.get("view_queue")),
        "view_reports": bool(permissions.get("view_reports")),
        "send_reports": bool(permissions.get("send_reports")),
    }
    if not any(mobile_permissions.get(permission) for permission in ("run_tasks", "view_queue", "view_reports")):
        return "Access Denied", 403
    return render_template(
        'mobile_operator.html',
        username=session.get('username'),
        is_admin=bool(session.get('is_admin')),
        permissions=permissions,
        mobile_permissions=mobile_permissions,
    )


@infrastructure_bp.route('/api/infrastructure/live/state', methods=['GET'])
def infrastructure_live_state_api():
    denied = require_permission("view_hosts")
    if denied:
        return denied
    return jsonify({"success": True, "state": infra_live_state_cached()})


@infrastructure_bp.route('/api/infrastructure/live/events', methods=['GET'])
def infrastructure_live_events():
    denied = require_permission("view_hosts")
    if denied:
        return denied

    return infrastructure_live_event_response(("nodes", "review", "queue", "reports"))


def infrastructure_live_event_response(section_names):
    """Stream small revision snapshots for the sections a user may view."""
    section_names = tuple(dict.fromkeys(section_names))

    def event_payload(event_name, payload):
        return f"event: {event_name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"

    @stream_with_context
    def generate():
        previous_state = None
        heartbeat_at = time.monotonic()
        yield event_payload("connected", {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"})
        while True:
            try:
                full_state = infra_live_state_cached()
                state = {
                    section: full_state.get(section, {"revision": "0", "count": 0, "latest": None})
                    for section in section_names
                }
                if previous_state is None:
                    previous_state = state
                    yield event_payload("state", {"state": state})
                else:
                    changes = {
                        section: state.get(section)
                        for section in section_names
                        if (state.get(section) or {}).get("revision") != (previous_state.get(section) or {}).get("revision")
                    }
                    if changes:
                        previous_state = state
                        yield event_payload("changed", {"changes": changes})

                if time.monotonic() - heartbeat_at >= 25:
                    heartbeat_at = time.monotonic()
                    yield event_payload("heartbeat", {"ts": datetime.utcnow().isoformat() + "Z"})
                db.session.remove()
                time.sleep(LIVE_EVENT_CHECK_INTERVAL_SECONDS)
            except GeneratorExit:
                break
            except Exception:
                current_app.logger.exception("Infrastructure live event stream failed")
                db.session.rollback()
                db.session.remove()
                yield event_payload("error", {"message": "live stream error"})
                time.sleep(10)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )


@infrastructure_bp.route('/api/infrastructure/mobile/events', methods=['GET'])
def mobile_live_events():
    sections = []
    if can("view_queue"):
        sections.append("queue")
    if can("view_reports"):
        sections.append("reports")
    if not sections:
        return jsonify({"success": False, "message": "Live updates are not available for this role."}), 403
    return infrastructure_live_event_response(sections)


@infrastructure_bp.route('/api/infrastructure/hosts', methods=['GET'])
def list_hosts():
    denied = require_permission("view_hosts")
    if denied:
        return denied

    now = datetime.utcnow()
    online_threshold = now - timedelta(minutes=5)
    hosts = get_allowed_hosts_light(session.get("user_id"))
    return jsonify({
        "success": True,
        "hosts": [{
            "id": host.id,
            "hostname": host.hostname,
            "display_name": getattr(host, "display_name", None) or "",
            "name": endpoint_display_name(host),
            "ip": getattr(host, "connection_ip", None) or "",
            "os": host.os_version,
            "os_type": getattr(host, "os_type", "Windows"),
            "last_seen": to_kyiv_time(host.last_seen),
            "is_online": bool(host.last_seen and host.last_seen >= online_threshold),
            "is_blocked": bool(host.is_blocked),
	            "approval_status": getattr(host, "approval_status", "Approved"),
            "agent_version": getattr(host, "agent_version", None),
            "agent_outdated": bool(Config.LATEST_AGENT_VERSION and (getattr(host, "agent_version", "") or "") != Config.LATEST_AGENT_VERSION),
            "agent_identity_key_enrolled": bool(getattr(host, "agent_identity_key_enrolled", False)),
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
    group_ids = [group.id for group in groups]
    member_counts = dict(
        db.session.query(
            endpoint_group_m2m.c.group_id,
            func.count(endpoint_group_m2m.c.endpoint_id),
        ).filter(endpoint_group_m2m.c.group_id.in_(group_ids))
        .group_by(endpoint_group_m2m.c.group_id)
        .all()
    ) if group_ids else {}
    return jsonify({
        "success": True,
        "groups": [{
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "hosts_count": int(member_counts.get(group.id, 0)),
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
        safe_profiles = [{"email": k, "host": v.get("host"), "port": v.get("port"), "keyserver": v.get("keyserver", "")} for k, v in profiles.items()]
        return jsonify({"success": True, "profiles": safe_profiles})

    denied = require_permission("manage_smtp")
    if denied: return denied

    if request.method == 'POST':
        data = request.json
        email = data.get("email", "").strip()
        host = data.get("host", "").strip()
        port = data.get("port", 587)
        password = data.get("password", "")
        keyserver = data.get("keyserver", "").strip()

        if not email or not host or not password:
            return jsonify({"success": False, "message": "Email, Host, and Password are required."}), 400

        profiles[email] = {
            "host": host, "port": int(port),
            "password": sec_manager.encrypt_data(password),
            "keyserver": keyserver,
        }
        save_smtp_profiles(profiles)
        return jsonify({"success": True})

    if request.method == 'DELETE':
        email = request.json.get("email")
        if email in profiles:
            del profiles[email]
            save_smtp_profiles(profiles)
        return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/confluence', methods=['GET', 'POST', 'DELETE'])
def manage_confluence_profiles():
    profiles = load_confluence_profiles()

    if request.method == 'GET':
        if not (can("send_reports") or can("manage_smtp")):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        return jsonify({"success": True, "profiles": safe_confluence_profiles(profiles)})

    denied = require_permission("manage_smtp")
    if denied:
        return denied

    data = request.json or {}
    if request.method == 'POST':
        name = str(data.get("name") or "").strip()
        base_url = normalize_confluence_base_url(data.get("base_url"))
        token = str(data.get("token") or "").strip()
        auth_type = str(data.get("auth_type") or "bearer").strip().lower()
        username = str(data.get("username") or "").strip()
        default_page_id = str(data.get("default_page_id") or "").strip()

        if not name:
            return jsonify({"success": False, "message": "Profile name is required."}), 400
        if not base_url:
            return jsonify({"success": False, "message": "Valid Confluence URL is required."}), 400
        if auth_type not in ("bearer", "basic"):
            return jsonify({"success": False, "message": "Auth type must be bearer or basic."}), 400
        if auth_type == "basic" and not username:
            return jsonify({"success": False, "message": "Basic auth requires username/email."}), 400

        existing = profiles.get(name, {})
        origin_changed = bool(existing.get("base_url")) and normalized_origin(existing.get("base_url")) != normalized_origin(base_url)
        if origin_changed and not token:
            return jsonify({"success": False, "message": "Confluence URL changed; re-enter the token to bind it to the new origin."}), 400
        if not token and not existing.get("token"):
            return jsonify({"success": False, "message": "Token is required for a new profile."}), 400

        profiles[name] = {
            "base_url": base_url,
            "auth_type": auth_type,
            "username": username,
            "default_page_id": default_page_id,
            "token": sec_manager.encrypt_data(token) if token else existing.get("token", ""),
            "last_published_at": existing.get("last_published_at", ""),
            "last_status": existing.get("last_status", ""),
        }
        save_confluence_profiles(profiles)
        write_infra_audit("confluence_profile_saved", "confluence_profile", name, {"base_url": base_url, "auth_type": auth_type})
        db.session.commit()
        return jsonify({"success": True, "profiles": safe_confluence_profiles(profiles)})

    name = str(data.get("name") or "").strip()
    if name in profiles:
        del profiles[name]
        save_confluence_profiles(profiles)
        write_infra_audit("confluence_profile_deleted", "confluence_profile", name)
        db.session.commit()
    return jsonify({"success": True, "profiles": safe_confluence_profiles(profiles)})


@infrastructure_bp.route('/api/infrastructure/confluence/test', methods=['POST'])
def test_confluence_profile():
    denied = require_permission("manage_smtp")
    if denied:
        return denied
    profiles = load_confluence_profiles()
    data = request.json or {}
    name = str(data.get("name") or "").strip()
    profile = profiles.get(name)
    if not profile:
        return jsonify({"success": False, "message": "Confluence profile was not found."}), 404

    page_id = str(data.get("page_id") or profile.get("default_page_id") or "").strip()
    path = f"/rest/api/content/{quote(page_id, safe='')}?expand=version" if page_id else "/rest/api/content?limit=1"
    ok, payload, message = confluence_request(profile, "GET", path, timeout=15)
    if not ok:
        profile["last_status"] = message
        save_confluence_profiles(profiles)
        return jsonify({"success": False, "message": message}), 400

    profile["last_status"] = "Connection OK"
    save_confluence_profiles(profiles)
    return jsonify({"success": True, "message": "Confluence connection OK", "data": payload})


@infrastructure_bp.route('/api/infrastructure/ai-provider', methods=['GET', 'POST'])
def manage_ai_provider():
    if request.method == "GET":
        denied = require_any_permission("use_ai_reports", "manage_ai")
        if denied:
            return denied
        return jsonify({"success": True, "provider": load_ai_provider()})

    denied = require_permission("manage_ai")
    if denied:
        return denied
    try:
        provider = save_ai_provider(request.get_json(silent=True) or {})
        write_infra_audit(
            "AI Provider Saved",
            "ai_provider",
            "open_webui",
            {"base_url": provider.get("base_url"), "model": provider.get("model"), "enabled": provider.get("enabled")},
        )
        db.session.commit()
        return jsonify({"success": True, "provider": provider})
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@infrastructure_bp.route('/api/infrastructure/ai-provider/test', methods=['POST'])
def test_ai_provider():
    denied = require_permission("manage_ai")
    if denied:
        return denied
    try:
        submitted = request.get_json(silent=True) or {}
        current = load_ai_provider(include_secret=True)
        candidate = {
            "base_url": str(submitted.get("base_url") or current.get("base_url") or ""),
            "api_key": str(submitted.get("api_key") or current.get("api_key") or ""),
            "model": str(submitted.get("model") or current.get("model") or ""),
        }
        client = OpenWebUIClient(candidate)
        models = client.models()
        return jsonify({
            "success": True,
            "message": "Open WebUI connection OK",
            "models": models,
            "configured_model_available": client.model in models,
        })
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


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
    denied = require_interactive_superadmin()
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
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(10, min(200, int(request.args.get("per_page", 100))))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid pagination"}), 400

    query = AggregatedJob.query.options(load_only(
        AggregatedJob.id,
        AggregatedJob.title,
        AggregatedJob.status,
        AggregatedJob.total_count,
        AggregatedJob.success_count,
        AggregatedJob.error_count,
        AggregatedJob.created_at,
        AggregatedJob.actor_user_id,
        AggregatedJob.created_by,
        AggregatedJob.source_type,
        AggregatedJob.template_id,
        AggregatedJob.current_revision_number,
    ))
    q = str(request.args.get("q") or "").strip()
    actor = str(request.args.get("actor") or "").strip()
    source = str(request.args.get("source") or "").strip().lower()
    statuses = [item.strip() for item in str(request.args.get("status") or "").split(",") if item.strip()]
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            AggregatedJob.title.ilike(like),
            AggregatedJob.id.ilike(like),
            AggregatedJob.created_by.ilike(like),
            AggregatedJob.status.ilike(like),
        ))
    if actor:
        query = query.filter(AggregatedJob.created_by.ilike(f"%{actor}%"))
    actor_id = request.args.get("actor_id", type=int)
    if actor_id:
        query = query.filter(AggregatedJob.actor_user_id == actor_id)
    if source:
        query = query.filter(AggregatedJob.source_type == source)
    if statuses:
        status_predicates = [
            AggregatedJob.status.ilike(f"{item}%") if item in {"Sent", "Published"}
            else AggregatedJob.status == item
            for item in statuses
        ]
        query = query.filter(or_(*status_predicates))
    if request.args.get("has_errors") in {"1", "true", "yes"}:
        query = query.filter(AggregatedJob.error_count > 0)

    def parse_report_date(value, end=False):
        if not value:
            return None
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=kyiv_tz)
        if end and len(str(value)) == 10:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)

    try:
        date_from = parse_report_date(request.args.get("date_from"))
        date_to = parse_report_date(request.args.get("date_to"), end=True)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date filter"}), 400
    if date_from:
        query = query.filter(AggregatedJob.created_at >= date_from)
    if date_to:
        query = query.filter(AggregatedJob.created_at <= date_to)

    content = str(request.args.get("content") or "").strip()
    if content:
        if not can("view_sensitive_reports"):
            return jsonify({"success": False, "message": "Sensitive report search permission required"}), 403
        from core.history_search import matching_entity_ids
        fields = [item for item in str(request.args.get("content_field") or "current,original,revisions,deliveries").split(",") if item]
        matched = matching_entity_ids(
            "report", content, fields=fields, mode=request.args.get("content_mode", "all")
        )
        if matched is not None:
            query = query.filter(AggregatedJob.id.in_(matched))
        else:
            query = query.filter(False)

    query = query.order_by(AggregatedJob.created_at.desc(), AggregatedJob.id.desc())
    if not session.get('is_admin'):
        candidate_ids = [row.id for row in query.all()]
        accessible_reports = accessible_report_id_set(candidate_ids)
        query = query.filter(AggregatedJob.id.in_(accessible_reports)) if accessible_reports else query.filter(False)
    total = query.count()
    reports = query.offset((page - 1) * per_page).limit(per_page).all()
    report_ids = {str(report.id) for report in reports}
    latest_ai_by_report = {}
    if report_ids:
        for ai_row in AiReportRequest.query.filter(AiReportRequest.report_id.in_(report_ids)).order_by(
            AiReportRequest.created_at
        ).all():
            latest_ai_by_report[ai_row.report_id] = ai_row
    data = [{
        "id": r.id, "title": r.title, "status": r.status,
        "total": r.total_count, "success": r.success_count, "error": r.error_count,
        "created_at": to_kyiv_time(r.created_at), "has_body": True,
        "created_by": r.created_by or "System",
        "source": r.source_type or "system",
        "template_id": r.template_id,
        "revision": int(r.current_revision_number or 0),
        "ai_report": ({
            "requested": True,
            "status": latest_ai_by_report[str(r.id)].status,
        } if str(r.id) in latest_ai_by_report else {"requested": False, "status": "NotRequested"}),
    } for r in reports]
    return jsonify({
        "success": True,
        "data": data,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "has_more": page * per_page < total,
        },
    })

@infrastructure_bp.route('/api/infrastructure/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    denied = require_permission("view_reports")
    if denied: return denied
    r = AggregatedJob.query.get(report_id)
    if not r:
        return jsonify({"success": False, "message": "Report not found"}), 404
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403

    revision = ensure_report_revision(
        r,
        actor_user_id=session.get("user_id"),
        actor_name=current_actor_label(),
    )
    db.session.commit()
    visible_body = report_body_for_current_user(r.report_data, report_id=report_id)
    ai_request = latest_ai_request(report_source_job_id(report_id), report_id=report_id)
    if Config.AUDIT_SENSITIVE_READS:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Report Viewed",
            details={"revision": revision.revision_number, "content_hash": revision.content_hash},
            target_type="report",
            target_id=report_id,
            status="Success",
        )

    return jsonify({
        "success": True,
        "data": {
            "id": r.id,
            "title": r.title,
            "status": r.status,
            "total": r.total_count,
            "success": r.success_count,
            "error": r.error_count,
            "created_at": to_kyiv_time(r.created_at),
            "report_data": visible_body,
            "revision": revision.revision_number,
            "content_hash": revision.content_hash,
            "original_content_hash": r.original_content_hash,
            "ai_report": ({
                "requested": True,
                "status": ai_request.status,
                "attempt": ai_request.attempt,
                "error": ai_request.error if ai_request.status == "Error" else None,
                "completed_at": to_kyiv_time(ai_request.completed_at),
            } if ai_request else {"requested": False, "status": "NotRequested"}),
        }
    })


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/ai-regenerate', methods=['POST'])
def regenerate_report_with_ai(report_id):
    denied = require_any_permission("use_ai_reports", "edit_reports")
    if denied:
        return denied
    if not can("use_ai_reports") or not can("edit_reports"):
        return jsonify({"success": False, "message": "AI report and edit report permissions are required"}), 403
    report = AggregatedJob.query.get(report_id)
    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404
    if not can_access_report(report_id, "edit_reports"):
        return jsonify({"success": False, "message": "Access denied"}), 403
    try:
        # AI processing always appends a revision. Capture a legacy/current body
        # first so Sent, Dismissed, Superseded and split reports keep their prior
        # content as an immutable snapshot.
        ensure_report_revision(
            report,
            actor_user_id=session.get("user_id"),
            actor_name=current_actor_label(),
        )
        ai_report = validate_ai_report_payload({
            "enabled": True,
            "prompt": (request.get_json(silent=True) or {}).get("prompt"),
        })
        row = create_ai_report_request(
            report_source_job_id(report_id),
            ai_report,
            actor_user_id=session.get("user_id"),
            actor_name=current_actor_label(),
            report_id=report_id,
        )
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="AI Report Regeneration Queued",
            details={
                "request_id": row.id,
                "report_id": report_id,
                "source_job_id": report_source_job_id(report_id),
                "report_status": report.status,
            },
            target_type="report",
            target_id=report_id,
            status="Success",
        )
        return jsonify({"success": True, "request_id": row.id, "status": row.status})
    except ValueError as exc:
        db.session.rollback()
        return jsonify({"success": False, "message": str(exc)}), 400


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/revisions', methods=['GET'])
def get_report_revisions(report_id):
    denied = require_permission("view_reports")
    if denied:
        return denied
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403
    report = AggregatedJob.query.get(report_id)
    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404
    ensure_report_revision(report)
    db.session.commit()
    revisions = ReportRevision.query.filter_by(report_id=report_id).order_by(
        ReportRevision.revision_number.desc()
    ).all()
    return jsonify({
        "success": True,
        "revisions": [{
            "id": item.id,
            "number": item.revision_number,
            "kind": item.kind,
            "actor": item.actor_name or "System",
            "reason": item.reason or "",
            "created_at": to_kyiv_time(item.created_at),
            "content_hash": item.content_hash,
            "is_original": item.revision_number == 1 and item.kind == "generated",
            "is_current": item.revision_number == int(report.current_revision_number or 0),
        } for item in revisions],
    })


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/revisions/<revision_id>', methods=['GET'])
def get_report_revision(report_id, revision_id):
    denied = require_permission("view_reports")
    if denied:
        return denied
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403
    revision = ReportRevision.query.filter_by(id=revision_id, report_id=report_id).first()
    if not revision:
        return jsonify({"success": False, "message": "Revision not found"}), 404
    body = revision.content
    if not can_view_sensitive_reports(report_id=report_id):
        body = mask_sensitive_text(body)
    if Config.AUDIT_SENSITIVE_READS:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Report Revision Viewed",
            details={"revision": revision.revision_number, "content_hash": revision.content_hash},
            target_type="report",
            target_id=report_id,
            status="Success",
        )
    return jsonify({
        "success": True,
        "revision": {
            "id": revision.id,
            "number": revision.revision_number,
            "kind": revision.kind,
            "actor": revision.actor_name or "System",
            "reason": revision.reason or "",
            "created_at": to_kyiv_time(revision.created_at),
            "content_hash": revision.content_hash,
            "content": body or "",
        },
    })


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/deliveries', methods=['GET'])
def get_report_deliveries(report_id):
    denied = require_permission("view_reports")
    if denied:
        return denied
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403
    rows = ReportDelivery.query.filter_by(report_id=report_id).order_by(
        ReportDelivery.created_at.desc()
    ).limit(250).all()
    can_view_destination = bool(is_interactive_superadmin() or can("send_reports"))
    return jsonify({
        "success": True,
        "deliveries": [{
            "id": row.id,
            "revision_id": row.revision_id,
            "channel": row.channel,
            "destination": row.destination if can_view_destination else "Restricted",
            "subject": row.subject or "",
            "actor": row.actor_name or "System",
            "status": row.status,
            "content_hash": row.content_hash,
            "created_at": to_kyiv_time(row.created_at),
            "completed_at": to_kyiv_time(row.completed_at),
            "result": row.result_details or "",
        } for row in rows],
    })


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/deliveries/<delivery_id>', methods=['GET'])
def get_report_delivery(report_id, delivery_id):
    denied = require_permission("view_reports")
    if denied:
        return denied
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403
    row = ReportDelivery.query.filter_by(id=delivery_id, report_id=report_id).first()
    if not row:
        return jsonify({"success": False, "message": "Delivery not found"}), 404
    content = row.content_snapshot or ""
    if not can_view_sensitive_reports(report_id=report_id):
        content = mask_sensitive_text(content)
    if Config.AUDIT_SENSITIVE_READS:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Report Delivery Snapshot Viewed",
            details={"delivery_id": row.id, "channel": row.channel, "content_hash": row.content_hash},
            target_type="report",
            target_id=report_id,
            status="Success",
        )
    return jsonify({
        "success": True,
        "delivery": {
            "id": row.id,
            "revision_id": row.revision_id,
            "channel": row.channel,
            "destination": row.destination if (is_interactive_superadmin() or can("send_reports")) else "Restricted",
            "subject": row.subject or "",
            "note": row.note or "",
            "actor": row.actor_name or "System",
            "status": row.status,
            "content_hash": row.content_hash,
            "content": content,
            "created_at": to_kyiv_time(row.created_at),
            "completed_at": to_kyiv_time(row.completed_at),
            "result": row.result_details or "",
        },
    })


def report_text_download_body(value):
    """Convert a visible report body to readable, inert plain text."""
    return report_body_plain_text(value)


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/download', methods=['GET'])
def download_report_text(report_id):
    denied = require_permission("view_reports")
    if denied:
        return denied
    report = AggregatedJob.query.get(report_id)
    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404
    if not can_access_report(report_id):
        return jsonify({"success": False, "message": "Access denied"}), 403

    visible_body = report_body_for_current_user(report.report_data, report_id=report_id)
    if Config.AUDIT_SENSITIVE_READS:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Report Downloaded",
            details={"format": "text"},
            target_type="report",
            target_id=report_id,
            status="Success",
        )
    filename_base = secure_filename(report.title or "")[:80] or f"winhub-report-{report.id}"
    return Response(
        report_text_download_body(visible_body),
        content_type="text/plain; charset=utf-8",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename_base}.txt"',
        },
    )

@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/action', methods=['POST'])
def action_report(report_id):
    r = AggregatedJob.query.get(report_id)
    if not r: return jsonify({"success": False}), 404
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    action_permission = {
        "save": "edit_reports",
        "dismiss": "dismiss_reports",
        "send": "send_reports",
    }.get(action, "view_reports")
    denied = require_permission(action_permission)
    if denied:
        return denied
    if not can_access_report(report_id, action_permission):
        return jsonify({"success": False, "message": "Access denied for this report group scope"}), 403

    if action == 'save':
        if not can_view_sensitive_reports(report_id=report_id):
            return jsonify({
                "success": False,
                "message": "This report contains masked sensitive data. Users without sensitive report access cannot save report text."
            }), 403
        current_revision = ensure_report_revision(r)
        expected_hash = str(data.get("expected_content_hash") or "").strip()
        if expected_hash and expected_hash != current_revision.content_hash:
            db.session.rollback()
            return jsonify({
                "success": False,
                "message": "This report was changed by another user. Reopen it before saving.",
                "current_revision": current_revision.revision_number,
                "current_content_hash": current_revision.content_hash,
            }), 409
        revision = create_report_revision(
            r,
            data.get('report_data', ''),
            kind="edited",
            actor_user_id=session.get("user_id"),
            actor_name=current_actor_label(),
            reason=str(data.get("reason") or "Manual report edit")[:500],
        )
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Report Edited",
            details={
                "revision": revision.revision_number,
                "content_hash": revision.content_hash,
                "reason": revision.reason,
            },
            target_type="report",
            target_id=report_id,
            status="Success",
        )
        return jsonify({
            "success": True,
            "revision": revision.revision_number,
            "content_hash": revision.content_hash,
        })

    elif action == 'dismiss':
        r.status = 'Dismissed'
        db.session.commit()
        WinHubCore.audit(
            user_id=session.get("user_id"), module="Infrastructure", action="Report Dismissed",
            details={"title": r.title}, target_type="report", target_id=report_id,
            status="Success", source_type="interactive",
        )
        return jsonify({"success": True})

    elif action == 'send':
        sender = str(data.get('sender') or '').strip()
        emails = data.get('email')
        subject = str(data.get('subject') or f"Report: {r.title}").strip()
        custom_message = str(data.get('custom_message') or '').strip()
        use_gpg = data.get('use_gpg') is True
        recipients = parse_recipients(emails)

        if not sender:
            return jsonify({"success": False, "message": "Sender SMTP profile is required."}), 400
        if not recipients:
            return jsonify({"success": False, "message": "At least one valid recipient email is required."}), 400
        if len(recipients) > 50:
            return jsonify({"success": False, "message": "A report can be sent to at most 50 recipients."}), 400
        if not subject:
            return jsonify({"success": False, "message": "Email subject is required."}), 400
        if len(subject) > 255 or "\r" in subject or "\n" in subject:
            return jsonify({"success": False, "message": "Email subject must be one line and at most 255 characters."}), 400
        if len(custom_message) > 5000:
            return jsonify({"success": False, "message": "Custom note cannot exceed 5000 characters."}), 400

        # Sending is a blind delivery operation: the operator may be allowed to send
        # the original report without being allowed to reveal its sensitive values in
        # the UI, downloads, or task logs.  Never return this body in the API response.
        outbound_snapshot = r.report_data or ""
        if custom_message:
            outbound_snapshot = f"{custom_message}\n\n{'=' * 50}\n\n{outbound_snapshot}"
        delivery, revision = record_report_delivery(
            r,
            channel="email",
            destination={"sender": sender, "recipients": recipients, "gpg": use_gpg},
            subject=subject,
            note=custom_message,
            content_snapshot=outbound_snapshot,
            actor_user_id=session.get("user_id"),
            actor_name=current_actor_label(),
            status="Sending",
        )
        report_body = revision.content or ""
        revision_number = revision.revision_number
        revision_hash = revision.content_hash
        delivery_hash = delivery.content_hash

        r.status = 'Sending...'
        db.session.commit()
        delivery_id = delivery.id
        db.session.remove()
        success, message, sent_count = send_report_email(
            title=subject,
            report_body=report_body,
            sender_email=sender,
            recipient_list=recipients,
            custom_message=custom_message,
            use_gpg=use_gpg
        )

        delivery = ReportDelivery.query.get(delivery_id)
        if delivery:
            finish_report_delivery(
                delivery,
                success=success,
                details={"message": message, "sent_count": sent_count},
            )

        write_infra_audit(
            "Report Email",
            "report",
            report_id,
            {
                "success": success,
                "recipient_count": sent_count if success else len(recipients),
                "gpg": use_gpg,
                "delivery_mode": "original_report",
                "delivery_id": delivery_id,
                "revision": revision_number,
                "content_hash": revision_hash,
                "delivery_content_hash": delivery_hash,
            },
            status="Success" if success else "Error",
        )
        update_report_send_status(report_id, success, sent_count)
        if success:
            return jsonify({"success": True, "message": message, "sent": sent_count})
        return jsonify({"success": False, "message": message}), 400

    return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/reports/<report_id>/confluence', methods=['POST'])
def publish_report_confluence(report_id):
    denied = require_permission("send_reports")
    if denied:
        return denied

    report = AggregatedJob.query.get(report_id)
    if not report:
        return jsonify({"success": False, "message": "Report not found"}), 404
    if not can_access_report(report_id, "send_reports"):
        return jsonify({"success": False, "message": "Access denied"}), 403

    profiles = load_confluence_profiles()
    data = request.json or {}
    profile_name = str(data.get("profile") or "").strip()
    profile = profiles.get(profile_name)
    if not profile:
        return jsonify({"success": False, "message": "Confluence profile was not found."}), 404

    page_id = str(data.get("page_id") or profile.get("default_page_id") or "").strip()
    title = str(data.get("title") or "").strip() or None
    body_format = str(data.get("body_format") or "safe_html").strip()
    custom_note = str(data.get("custom_note") or "").strip()
    if body_format not in ("safe_html", "escaped_pre", "storage_html"):
        return jsonify({"success": False, "message": "Invalid Confluence body format."}), 400
    if body_format == "storage_html" and not can_view_sensitive_reports(report_id=report_id):
        return jsonify({"success": False, "message": "Raw Confluence HTML publishing requires sensitive report access."}), 403
    visible_report_body = (
        report.report_data
        if can_view_sensitive_reports(report_id=report_id)
        else report_body_for_current_user(report.report_data, report_id=report_id)
    )

    outbound_snapshot = (
        visible_report_body
        if body_format == "storage_html"
        else confluence_report_storage_html(
            report,
            visible_report_body,
            custom_note,
            formatted=body_format == "safe_html",
        )
    )
    delivery, revision = record_report_delivery(
        report,
        channel="confluence",
        destination={"profile": profile_name, "page_id": page_id},
        subject=title or report.title,
        note=custom_note,
        content_snapshot=outbound_snapshot,
        actor_user_id=session.get("user_id"),
        actor_name=current_actor_label(),
        status="Sending",
    )
    delivery_id = delivery.id
    revision_number = revision.revision_number
    db.session.commit()

    success, message, web_url = publish_report_to_confluence(
        profile=profile,
        report=report,
        page_id=page_id,
        title=title,
        body_format=body_format,
        custom_note=custom_note,
        report_body=visible_report_body,
    )

    delivery = ReportDelivery.query.get(delivery_id)
    if delivery:
        finish_report_delivery(
            delivery,
            success=success,
            details={"message": message, "url": web_url, "page_id": page_id},
        )

    now_str = datetime.now(kyiv_tz).strftime("%Y-%m-%d %H:%M:%S %Z")
    profile["last_published_at"] = now_str if success else profile.get("last_published_at", "")
    profile["last_status"] = "Published" if success else message
    profiles[profile_name] = profile
    save_confluence_profiles(profiles)

    write_infra_audit(
        "report_publish_confluence",
        "report",
        report_id,
        {
            "profile": profile_name,
            "page_id": page_id,
            "success": success,
            "message": message,
            "delivery_id": delivery_id,
            "revision": revision_number,
            "delivery_content_hash": delivery.content_hash if delivery else None,
        },
        status="Success" if success else "Error",
    )
    if success:
        time_str = datetime.now(kyiv_tz).strftime("%H:%M")
        report.status = f"Published {time_str}"
    db.session.commit()

    if success:
        return jsonify({"success": True, "message": message, "url": web_url})
    return jsonify({"success": False, "message": message}), 400

@infrastructure_bp.route('/api/infrastructure/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    denied = require_interactive_superadmin()
    if denied: return denied
    r = AggregatedJob.query.get(report_id)
    if r:
        write_infra_audit("Delete Report", "report", report_id, {"title": r.title})
        ReportDelivery.query.filter_by(report_id=str(report_id)).delete(synchronize_session=False)
        ReportRevision.query.filter_by(report_id=str(report_id)).delete(synchronize_session=False)
        HistorySearchToken.query.filter_by(entity_type="report", entity_id=str(report_id)).delete(
            synchronize_session=False
        )
        db.session.delete(r)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Report not found"}), 404

# ==========================================
# API: TRIGGERS & SCHEDULER
# ==========================================
def validate_schedule_expression(value, *, active=True, now=None):
    expression = str(value or "").strip()
    if not expression or len(expression) > 100:
        raise ValueError("Schedule expression is required and cannot exceed 100 characters")

    if expression.startswith("DATE:"):
        raw_date = expression[5:].strip()
        try:
            run_date = datetime.strptime(raw_date, "%Y-%m-%d %H:%M").replace(tzinfo=kyiv_tz)
        except ValueError as exc:
            raise ValueError("One-time schedule must use DATE:YYYY-MM-DD HH:MM in 24-hour Kyiv time") from exc
        if active and run_date <= (now or datetime.now(kyiv_tz)):
            raise ValueError("Active one-time schedule must be set in the future")
        return f"DATE:{run_date.strftime('%Y-%m-%d %H:%M')}"

    fields = expression.split()
    if len(fields) != 5:
        raise ValueError("Recurring schedule must contain exactly five cron fields")
    normalized = " ".join(fields)
    try:
        CronTrigger.from_crontab(normalized, timezone=kyiv_tz)
    except (TypeError, ValueError) as exc:
        raise ValueError("Recurring schedule contains an invalid cron expression") from exc
    return normalized


def schedule_required_variable_names(template):
    payload = load_template_payload(template)
    required = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, str) and not str(key).startswith("__"):
                required.update(VARIABLE_PATTERN.findall(value))
    return sorted(required)


def validate_schedule_target(target_type, target_id):
    target_type = str(target_type or "").strip().lower()
    target_id = str(target_id or "").strip()
    if target_type not in ("host", "group") or not target_id:
        raise ValueError("Select a valid schedule target")

    user = current_user()
    if not user:
        raise PermissionError("Invalid user")

    if target_type == "host":
        endpoint = Endpoint.query.get(target_id)
        if not endpoint:
            raise ValueError("Selected endpoint does not exist")
        if getattr(endpoint, "approval_status", "Approved") not in (None, "Approved"):
            raise ValueError("Selected endpoint is not approved")
        if target_id not in set(infra_allowed_host_ids(user.id, "run_tasks")):
            raise PermissionError("You are not allowed to schedule tasks for this endpoint")
        return target_type, target_id

    group = EndpointGroup.query.get(target_id)
    if not group:
        raise ValueError("Selected endpoint group does not exist")
    allowed = group_action_allowed(user, target_id, "run_tasks")
    if not allowed:
        raise PermissionError("You are not allowed to schedule tasks for this endpoint group")
    return target_type, target_id


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
    denied = require_interactive_superadmin()
    if denied: return denied
    tr = TriggerRule.query.get(tid)
    if tr: db.session.delete(tr); db.session.commit()
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/schedule', methods=['POST'])
def manage_schedule():
    denied = require_permission("manage_scheduler")
    if denied: return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "A JSON schedule object is required"}), 400

    tid = str(data.get('id') or '').strip() or None
    name = str(data.get('name') or '').strip()
    category = str(data.get('category') or 'Scheduled').strip() or 'Scheduled'
    template_id = str(data.get('template_id') or '').strip()
    is_active = data.get('is_active', True)
    if not name:
        return jsonify({"success": False, "message": "Job name is required"}), 400
    if len(name) > 150:
        return jsonify({"success": False, "message": "Job name cannot exceed 150 characters"}), 400
    if len(category) > 100:
        return jsonify({"success": False, "message": "Category cannot exceed 100 characters"}), 400
    if not isinstance(is_active, bool):
        return jsonify({"success": False, "message": "Schedule active state must be true or false"}), 400

    template = TaskTemplate.query.get(template_id) if template_id else None
    if not template or getattr(template, "type", "action") == "report":
        return jsonify({"success": False, "message": "Runnable template was not found"}), 404
    if not can_access_template_library_entry(template) or not can_use_template(template):
        return jsonify({"success": False, "message": "Template is not available for scheduled execution"}), 403

    try:
        target_type, target_id = validate_schedule_target(data.get('target_type'), data.get('target_id'))
        cron_expression = validate_schedule_expression(data.get('cron'), active=is_active)
    except PermissionError as exc:
        return jsonify({"success": False, "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    try:
        timeout_minutes = int(data.get("timeout_minutes") or 0)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Execution time limit must be a number of minutes"}), 400
    if timeout_minutes < 0 or timeout_minutes > 10080:
        return jsonify({"success": False, "message": "Execution time limit must be between 0 and 10080 minutes"}), 400
    timeout_minutes = timeout_minutes or None

    variables = data.get('variables') or {}
    if not isinstance(variables, dict):
        return jsonify({"success": False, "message": "Schedule variables must be an object"}), 400
    clean_variables = {}
    for key, value in variables.items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(key)):
            return jsonify({"success": False, "message": f"Invalid variable name: {key}"}), 400
        if isinstance(value, (dict, list)):
            return jsonify({"success": False, "message": f"Variable '{key}' must be a scalar value"}), 400
        value = "" if value is None else str(value)
        if len(value) > 2048:
            return jsonify({"success": False, "message": f"Variable '{key}' is too long"}), 400
        if any(ch in value for ch in ("\x00", "\r")):
            return jsonify({"success": False, "message": f"Variable '{key}' contains unsupported control characters"}), 400
        clean_variables[str(key)] = value

    missing_variables = sorted(set(schedule_required_variable_names(template)) - set(clean_variables))
    if missing_variables:
        return jsonify({
            "success": False,
            "message": "Missing template variables",
            "missing_variables": missing_variables,
        }), 400

    if tid:
        st = ScheduledTask.query.get(tid)
        if not st:
            return jsonify({"success": False, "message": "Scheduled task was not found"}), 404
        if not current_user().is_admin:
            try:
                validate_schedule_target(st.target_type, st.target_id)
            except PermissionError as exc:
                return jsonify({"success": False, "message": str(exc)}), 403
            except ValueError as exc:
                return jsonify({"success": False, "message": str(exc)}), 400
        if not can_view_sensitive_target(target_type, target_id):
            try:
                existing_variables = json.loads(st.variables) if st.variables else {}
            except (TypeError, ValueError):
                existing_variables = {}
            if isinstance(existing_variables, dict):
                for key, value in list(clean_variables.items()):
                    if is_sensitive_name(key) and value == "***" and key in existing_variables:
                        clean_variables[key] = existing_variables[key]
    else:
        st = ScheduledTask(created_by=session.get('username'))
        db.session.add(st)

    variables_raw = json.dumps(clean_variables, ensure_ascii=False)
    st.name = name
    st.category = category
    st.template_id = template.id
    st.target_type = target_type
    st.target_id = target_id
    st.cron_expr = cron_expression
    st.is_active = is_active
    st.variables = variables_raw
    st.timeout_minutes = timeout_minutes
    db.session.flush()
    write_infra_audit(
        "Scheduled Task Saved",
        "scheduled_task",
        st.id,
        {"name": name, "category": category, "target_type": target_type, "active": is_active},
    )
    db.session.commit()
    from core import reload_scheduler_jobs
    reload_scheduler_jobs(current_app)
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/schedule/<tid>', methods=['DELETE'])
def delete_schedule(tid):
    denied = require_interactive_superadmin()
    if denied: return denied
    st = ScheduledTask.query.get(tid)
    if not st:
        return jsonify({"success": False, "message": "Scheduled task was not found"}), 404
    if not current_user().is_admin:
        try:
            validate_schedule_target(st.target_type, st.target_id)
        except PermissionError as exc:
            return jsonify({"success": False, "message": str(exc)}), 403
        except ValueError as exc:
            return jsonify({"success": False, "message": str(exc)}), 400
    write_infra_audit("Scheduled Task Deleted", "scheduled_task", st.id, {"name": st.name})
    db.session.delete(st)
    db.session.commit()
    from core import reload_scheduler_jobs
    reload_scheduler_jobs(current_app)
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/schedule/<tid>/run-now', methods=['POST'])
def run_schedule_now(tid):
    denied = require_permission("manage_scheduler")
    if denied: return denied
    st = ScheduledTask.query.get(tid)
    if not st:
        return jsonify({"success": False, "message": "Scheduled task was not found"}), 404
    if not st.template or getattr(st.template, "type", "action") == "report":
        return jsonify({"success": False, "message": "Runnable template was not found"}), 404
    if not can_access_template_library_entry(st.template) or not can_use_template(st.template):
        return jsonify({"success": False, "message": "Template is not available for scheduled execution"}), 403
    try:
        validate_schedule_target(st.target_type, st.target_id)
    except PermissionError as exc:
        return jsonify({"success": False, "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    from core import run_scheduled_job
    result = run_scheduled_job(
        tid,
        manual_run=True,
        actor_user_id=session.get("user_id"),
        actor_name=current_actor_label(),
    ) or {"success": False, "message": "Schedule did not run"}
    status = 200 if result.get("success") else 400
    return jsonify(result), status

# ==========================================
# API: TEMPLATES & TASKS
# ==========================================
@infrastructure_bp.route('/api/infrastructure/task-launch/options', methods=['GET'])
def task_launch_options():
    denied = require_permission("run_tasks")
    if denied:
        return denied

    templates = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
    runnable_templates = []
    for template in templates:
        own_runnable = bool(
            getattr(template, "created_by", None) == session.get("username")
            and can("manage_templates")
        )
        if getattr(template, "type", "action") == "report":
            continue
        if not bool(getattr(template, "is_approved", False)) and not own_runnable:
            continue
        if not can_use_template(template):
            continue
        runnable_templates.append({
            "id": template.id,
            "name": template.name,
            "category": template.category or "General",
            "action_type": template.action_type or "run_script",
            "type": getattr(template, "type", "action") or "action",
            "variables": template_variable_names(template),
            "variable_schema": mobile_variable_schema(template),
            "risk_level": mobile_template_risk(template),
        })

    now = datetime.utcnow()
    online_threshold = now - timedelta(minutes=5)
    hosts = [
        host for host in get_allowed_hosts_light(session.get("user_id"), approved_only=True, action_id="run_tasks")
        if not bool(getattr(host, "is_blocked", False))
        and (getattr(host, "approval_status", "Approved") or "Approved") == "Approved"
    ]
    allowed_host_ids = {str(host.id) for host in hosts}
    allowed_groups = WinHubCore.get_allowed_groups(session.get("user_id"), "run_tasks")
    group_ids = [group.id for group in allowed_groups]
    group_host_counts = dict(
        db.session.query(
            endpoint_group_m2m.c.group_id,
            func.count(endpoint_group_m2m.c.endpoint_id),
        ).filter(
            endpoint_group_m2m.c.group_id.in_(group_ids),
            endpoint_group_m2m.c.endpoint_id.in_(allowed_host_ids),
        ).group_by(endpoint_group_m2m.c.group_id).all()
    ) if group_ids and allowed_host_ids else {}
    groups = []
    for group in allowed_groups:
        eligible_count = int(group_host_counts.get(group.id, 0))
        if eligible_count:
            groups.append({
                "id": group.id,
                "name": group.name,
                "hosts_count": eligible_count,
            })

    return jsonify({
        "success": True,
        "templates": runnable_templates,
        "hosts": [{
            "id": host.id,
            "name": endpoint_display_name(host),
            "hostname": host.hostname or host.id,
            "display_name": getattr(host, "display_name", None) or "",
            "ip": getattr(host, "connection_ip", None) or "",
            "os_type": getattr(host, "os_type", "Windows") or "Windows",
            "is_online": bool(host.last_seen and host.last_seen >= online_threshold),
        } for host in hosts],
        "groups": groups,
    })


@infrastructure_bp.route('/api/infrastructure/templates', methods=['GET'])
def list_templates():
    denied = require_permission("run_tasks")
    if denied:
        return denied

    templates = TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
    if not session.get("is_admin"):
        templates = [
            t for t in templates
            if (
                template_approval_valid(t)
                or (
                    not session.get("api_key_auth")
                    and getattr(t, "created_by", None) == session.get("username")
                    and can("manage_templates")
                )
            )
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
    denied = require_permission("manage_templates")
    if denied:
        return denied

    t = TaskTemplate.query.get(tid)
    if not t:
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_access_template_library_entry(t):
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_view_template_code(t):
        return jsonify({"success": False, "message": "Template code export is blocked by superadmin policy"}), 403

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
            is_approved = bool(item.get("is_approved", False)) and bool(session.get("is_admin"))
            validate_report_template_payload(t_type, incoming_payload)

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
                template.approved_content_hash = current_template_hash(template) if is_approved else None
                template.approved_at = datetime.utcnow() if is_approved else None
                template.approved_by = session.get("username") if is_approved else None
                updated += 1
            else:
                template = TaskTemplate(
                    id=template_id or str(uuid.uuid4()),
                    name=name,
                    category=category,
                    action_type=action_type,
                    type=t_type,
                    payload=payload_raw,
                    is_approved=is_approved,
                    created_by=session.get('username')
                )
                if is_approved:
                    template.approved_content_hash = current_template_hash(template)
                    template.approved_at = datetime.utcnow()
                    template.approved_by = session.get("username")
                db.session.add(template)
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
        latest_versions = latest_agent_package_versions_by_platform()
        packages = [agent_package_response(package, latest_versions) for package in load_agent_packages()]
        return jsonify({"success": True, "packages": packages, "latest_versions": latest_versions})

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
        platform = detect_agent_package_platform(base_name)
        if platform == "unknown":
            return jsonify({"success": False, "message": "Package platform could not be detected. Use win-x64, linux-x64, or macos/darwin in the agent package name."}), 400
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
            "platform": platform,
            "size": size,
            "notes": str(request.form.get("notes") or "").strip(),
            "uploaded_by": session.get("username"),
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
        }
        packages.insert(0, record)
        save_agent_packages(packages[:50])
        latest_versions = latest_agent_package_versions_by_platform()
        record = agent_package_response(record, latest_versions)
        write_infra_audit("Agent Package Upload", "agent_package", package_id, {"version": version, "platform": platform, "sha256": record["sha256"], "size": size})
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


def build_agent_update_plan(target_ids, selected_package):
    selected_version = str(selected_package.get("version") or "").strip()
    selected_platform = str(selected_package.get("platform") or detect_agent_package_platform(selected_package.get("original_filename") or selected_package.get("filename") or "")).lower()
    endpoints = Endpoint.query.filter(Endpoint.id.in_(target_ids)).all()
    endpoint_by_id = {endpoint.id: endpoint for endpoint in endpoints}
    plan = []
    skipped = []
    for host_id in target_ids:
        endpoint = endpoint_by_id.get(host_id)
        if not endpoint:
            skipped.append({"id": host_id, "reason": "missing_endpoint"})
            continue
        platform = endpoint_agent_platform(endpoint)
        package = selected_package if selected_platform == platform else find_agent_package_for_platform(selected_version, platform)
        if not package:
            skipped.append({"id": host_id, "reason": f"missing_{platform}_package", "platform": platform})
            continue
        package = dict(package)
        package["platform"] = str(package.get("platform") or platform).lower()
        package["update_url"] = resolved_agent_package_update_url(package["id"], package.get("update_url"))
        package["download_url"] = package.get("download_url") or agent_package_public_url(package["id"])
        plan.append({"host_id": host_id, "platform": platform, "package": package})
    return plan, skipped


def create_agent_update_wave(update_items, created_by, wave_index, wave_total):
    job_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    updater_script = agent_updater_bootstrap_script()
    host_ids = [str(item.get("host_id")) for item in update_items if item.get("host_id")]
    hosts = {row.id: row for row in Endpoint.query.filter(Endpoint.id.in_(host_ids)).all()}
    actor = User.query.filter_by(username=created_by).first() if created_by and created_by != "System" else None
    created_tasks = []

    def add_update_task(host, **values):
        task = AgentTask(
            endpoint_id=host.id,
            endpoint_id_snapshot=host.id,
            endpoint_hostname_snapshot=host.hostname,
            endpoint_name_snapshot=host.display_name,
            endpoint_groups_snapshot=json.dumps([
                {"id": group.id, "name": group.name} for group in host.groups
            ], ensure_ascii=False),
            source_type="scheduler",
            actor_user_id=getattr(actor, "id", None),
            **values,
        )
        db.session.add(task)
        created_tasks.append(task)

    for item in update_items:
        host_id = item["host_id"]
        host = hosts.get(host_id)
        if not host:
            continue
        platform = item.get("platform") or "windows"
        package = item["package"]
        payload = {
            "package_url": resolved_agent_package_update_url(package["id"], package.get("update_url")),
            "sha256": package.get("sha256"),
            "target_version": package.get("version"),
            "platform": platform,
        }
        title = f"Agent Update {package.get('version')} {platform} - Wave {wave_index}/{wave_total}"
        task_created_at = created_at
        if platform == "windows":
            add_update_task(host,
                id=str(uuid.uuid4()),
                job_id=job_id,
                title=f"Prepare Agent Updater - Wave {wave_index}/{wave_total}",
                module_source="Infrastructure",
                action_type="run_script",
                payload=json.dumps({"script": updater_script}, ensure_ascii=False),
                created_by=created_by,
                created_at=created_at,
            )
            task_created_at = created_at + timedelta(seconds=1)
        add_update_task(host,
            id=str(uuid.uuid4()),
            job_id=job_id,
            title=title,
            module_source="Infrastructure",
            action_type="agent_update",
            payload=json.dumps(payload, ensure_ascii=False),
            created_by=created_by,
            created_at=task_created_at,
        )
    db.session.flush()
    from core.history_search import index_agent_task, index_audit_log
    for task in created_tasks:
        index_agent_task(task)
    audit_entry = AuditLog(
        user=created_by or "System", actor_user_id=getattr(actor, "id", None),
        actor_type="system", actor_name=created_by or "System",
        actor_role="system", source_type="scheduler", module="Infrastructure",
        action="Agent Update Wave Dispatched", target_type="job", target_id=job_id,
        details=json.dumps({"wave": wave_index, "total_waves": wave_total, "tasks": len(created_tasks)}, ensure_ascii=False),
        status="Success",
    )
    db.session.add(audit_entry)
    db.session.flush()
    index_audit_log(audit_entry)
    return job_id


def process_due_agent_update_rollouts():
    now = datetime.utcnow()
    rollout_ids = [
        row[0] for row in db.session.query(AgentUpdateRollout.id).filter(
            AgentUpdateRollout.status == "Running",
            AgentUpdateRollout.next_run_at <= now
        ).order_by(AgentUpdateRollout.created_at.asc()).all()
    ]
    for rollout_id in rollout_ids:
        rollout = AgentUpdateRollout.query.filter(
            AgentUpdateRollout.id == rollout_id,
            AgentUpdateRollout.status == "Running",
            AgentUpdateRollout.next_run_at <= datetime.utcnow()
        ).with_for_update(skip_locked=True).first()
        if not rollout:
            continue
        try:
            waves_created = 0
            max_waves = max(1, int(getattr(Config, "AGENT_UPDATE_ROLLOUT_MAX_WAVES_PER_TICK", 25) or 25))
            while (
                rollout.status == "Running"
                and rollout.next_run_at
                and rollout.next_run_at <= datetime.utcnow()
                and waves_created < max_waves
            ):
                created = process_one_agent_update_rollout(rollout)
                if not created:
                    break
                waves_created += 1
            db.session.commit()
        except Exception:
            db.session.rollback()
            logging.getLogger("winhub").exception("Failed to process agent update rollout %s", rollout_id)


def process_one_agent_update_rollout(rollout):
    now = datetime.utcnow()
    target_ids = json.loads(rollout.target_ids or "[]")
    target_ids = list(dict.fromkeys([str(item) for item in target_ids if str(item or "").strip()])) if isinstance(target_ids, list) else []
    if not isinstance(target_ids, list) or not target_ids:
        rollout.status = "Completed"
        rollout.updated_at = now
        return False

    package = find_agent_package(rollout.package_id)
    if not package:
        package = {
            "id": rollout.package_id,
            "version": rollout.package_version,
            "download_url": rollout.package_url,
            "sha256": None,
        }
    package["platform"] = package.get("platform") or detect_agent_package_platform(package.get("original_filename") or package.get("filename") or "")
    package["update_url"] = resolved_agent_package_update_url(package["id"], rollout.package_url)
    package["download_url"] = package.get("download_url") or agent_package_public_url(package["id"])

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
        return False

    update_plan, skipped = build_agent_update_plan(target_ids, package)
    if skipped:
        logging.getLogger("winhub").warning(
            "Skipping %s endpoint(s) from agent update rollout %s due to package/platform mismatch: %s",
            len(skipped),
            rollout.id,
            skipped[:20],
        )
    if not update_plan:
        rollout.status = "Completed"
        rollout.updated_at = now
        return False

    recalculated_total_waves = max(1, (len(update_plan) + wave_size - 1) // wave_size)
    rollout.total_waves = recalculated_total_waves
    index = max(1, int(rollout.next_wave_index or 1))
    if index > recalculated_total_waves:
        rollout.status = "Completed"
        rollout.updated_at = now
        return False
    start = (index - 1) * wave_size
    wave_items = update_plan[start:start + wave_size]
    if not wave_items:
        rollout.status = "Completed"
        rollout.updated_at = now
        return False

    create_agent_update_wave(wave_items, rollout.created_by or "System", index, recalculated_total_waves)
    rollout.next_wave_index = index + 1
    rollout.updated_at = datetime.utcnow()
    if rollout.next_wave_index > recalculated_total_waves:
        rollout.status = "Completed"
    else:
        current_due_at = rollout.next_run_at or datetime.utcnow()
        rollout.next_run_at = current_due_at + timedelta(seconds=max(0, int(rollout.wave_delay_seconds or 0)))
    return True


def planned_agent_update_rollout_jobs(allowed_host_ids):
    allowed = set(allowed_host_ids or [])
    if not allowed:
        return []

    rollouts = AgentUpdateRollout.query.filter_by(status="Running").order_by(
        AgentUpdateRollout.created_at.desc()
    ).limit(25).all()
    planned_jobs = []

    for rollout in rollouts:
        try:
            target_ids = json.loads(rollout.target_ids or "[]")
            target_ids = list(dict.fromkeys([str(item) for item in target_ids if str(item or "").strip()])) if isinstance(target_ids, list) else []
            if not target_ids:
                continue

            package = find_agent_package(rollout.package_id) or {
                "id": rollout.package_id,
                "version": rollout.package_version,
                "download_url": rollout.package_url,
                "sha256": None,
            }
            package["platform"] = package.get("platform") or detect_agent_package_platform(package.get("original_filename") or package.get("filename") or "")
            package["update_url"] = resolved_agent_package_update_url(package["id"], rollout.package_url)

            update_plan, _ = build_agent_update_plan(target_ids, package)
            if not update_plan:
                continue

            wave_size = max(1, int(rollout.wave_size or 50))
            total_waves = max(1, (len(update_plan) + wave_size - 1) // wave_size)
            next_index = max(1, int(rollout.next_wave_index or 1))
            if next_index > total_waves:
                continue

            endpoint_ids = [item["host_id"] for item in update_plan if item["host_id"] in allowed]
            endpoint_rows = db.session.query(Endpoint.id, Endpoint.hostname, Endpoint.display_name).filter(
                Endpoint.id.in_(endpoint_ids)
            ).all() if endpoint_ids else []
            endpoint_map = {
                endpoint_id: {"hostname": hostname, "display_name": display_name or ""}
                for endpoint_id, hostname, display_name in endpoint_rows
            }

            base_due_at = rollout.next_run_at or rollout.updated_at or rollout.created_at or datetime.utcnow()
            delay_seconds = max(0, int(rollout.wave_delay_seconds or 0))
            for wave_index in range(next_index, total_waves + 1):
                start = (wave_index - 1) * wave_size
                wave_items = update_plan[start:start + wave_size]
                visible_items = [item for item in wave_items if item["host_id"] in allowed]
                if not visible_items:
                    continue

                due_at = base_due_at + timedelta(seconds=delay_seconds * max(0, wave_index - next_index))
                platforms = sorted({str(item.get("platform") or "unknown").lower() for item in visible_items})
                platform_label = platforms[0] if len(platforms) == 1 else "mixed"
                title = f"Agent Update {rollout.package_version or package.get('version') or ''} {platform_label} - Wave {wave_index}/{total_waves}".strip()
                tasks = []
                for item in visible_items:
                    host_id = item["host_id"]
                    endpoint_info = endpoint_map.get(host_id, {})
                    display_label = (endpoint_info.get("display_name") or endpoint_info.get("hostname") or host_id or "Unknown").strip()
                    tasks.append({
                        "task_id": "",
                        "endpoint_id": host_id,
                        "hostname": endpoint_info.get("hostname") or "",
                        "display_name": endpoint_info.get("display_name") or "",
                        "name": display_label,
                        "status": "Scheduled",
                    })

                planned_jobs.append({
                    "job_id": f"rollout:{rollout.id}:wave:{wave_index}",
                    "rollout_id": rollout.id,
                    "wave_index": wave_index,
                    "planned": True,
                    "title": title,
                    "action": "agent_update",
                    "created_at": to_kyiv_time(due_at),
                    "_sort_at": due_at,
                    "created_by": rollout.created_by or "System",
                    "tasks": tasks,
                    "total": len(tasks),
                    "success": 0,
                    "error": 0,
                    "pending": len(tasks),
                    "running": 0,
                    "cancelled": 0,
                    "status": "Scheduled",
                    "target_summary": f"Scheduled wave ({len(tasks)} hosts)",
                })
        except Exception:
            logging.getLogger("winhub").exception("Failed to build planned rollout preview for %s", getattr(rollout, "id", "-"))

    return planned_jobs


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

    allowed = [h for h in WinHubCore.get_allowed_hosts(session.get("user_id"), "run_tasks") if getattr(h, "approval_status", "Approved") == "Approved"]
    allowed_by_id = {h.id: h for h in allowed}
    target_mode = str(data.get("target_mode") or "selected")
    if target_mode == "group":
        group = EndpointGroup.query.get(data.get("group_id"))
        if group and not group_action_allowed(current_user(), group.id, "run_tasks"):
            return jsonify({"success": False, "message": "Task execution is denied for this group"}), 403
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

    user = current_user()
    latest_versions = latest_agent_package_versions_by_platform()
    latest_version = latest_agent_package_version()
    page = bounded_int_arg("page", 1, 1, 100000)
    page_size = bounded_int_arg("page_size", 50, 10, 100)
    search = str(request.args.get("search") or "").strip()
    status_filter = str(request.args.get("status") or "all").strip().lower()
    sort_key = str(request.args.get("sort") or "hostname").strip().lower()
    sort_dir = str(request.args.get("direction") or "asc").strip().lower()
    group_filters = [
        item.strip()
        for item in str(request.args.get("groups") or "").split(",")
        if item.strip()
    ]
    group_match = str(request.args.get("group_match") or "contains").strip().lower()

    access_note = None
    if user and not user.is_admin and not list(user.allowed_host_groups):
        access_note = "No host groups are assigned to this user. Ask an administrator to assign at least one host group."

    query = allowed_endpoint_query(session.get("user_id"), approved_only=True)
    online_since = datetime.utcnow() - timedelta(minutes=5)

    if search:
        like = f"%{search}%"
        query = query.filter(or_(
            Endpoint.id.ilike(like),
            Endpoint.hostname.ilike(like),
            Endpoint.display_name.ilike(like),
            Endpoint.connection_ip.ilike(like),
            Endpoint.os_version.ilike(like),
            Endpoint.os_type.ilike(like),
            Endpoint.agent_version.ilike(like),
            Endpoint.identity_fingerprint.ilike(like),
            Endpoint.encryption_status.ilike(like),
            Endpoint.encryption_methods.ilike(like),
            Endpoint.groups.any(EndpointGroup.name.ilike(like)),
        ))

    selected_group_ids = [group_id for group_id in group_filters if group_id != "ungrouped"]
    if selected_group_ids:
        for group_id in selected_group_ids:
            query = query.filter(Endpoint.groups.any(EndpointGroup.id == group_id))
        if group_match == "exact":
            membership_count = (
                db.session.query(func.count(endpoint_group_m2m.c.group_id))
                .filter(endpoint_group_m2m.c.endpoint_id == Endpoint.id)
                .correlate(Endpoint)
                .scalar_subquery()
            )
            query = query.filter(membership_count == len(selected_group_ids))
    elif "ungrouped" in group_filters:
        query = query.filter(~Endpoint.groups.any())

    has_key_expr = or_(Endpoint.public_key_pem_plain.isnot(None), Endpoint.public_key_pem.isnot(None))
    active_identity_warning_expr = and_(
        Endpoint.identity_warning.isnot(None),
        or_(Endpoint.identity_duplicate_allowed.is_(False), Endpoint.identity_duplicate_allowed.is_(None)),
        or_(
            Endpoint.display_name.is_(None),
            Endpoint.display_name == "",
            func.upper(Endpoint.display_name) == func.upper(Endpoint.hostname),
        ),
    )
    outdated_clauses = platform_agent_version_clauses(latest_versions, current=False)
    current_clauses = platform_agent_version_clauses(latest_versions, current=True)
    if status_filter == "outdated":
        query = query.filter(or_(*outdated_clauses) if outdated_clauses else Endpoint.id == "__no_agent_package_latest__")
    elif status_filter == "current":
        query = query.filter(or_(*current_clauses) if current_clauses else Endpoint.id == "__no_agent_package_latest__")
    elif status_filter == "offline":
        query = query.filter(or_(Endpoint.last_seen.is_(None), Endpoint.last_seen < online_since))
    elif status_filter == "unsigned":
        query = query.filter(~has_key_expr)
    elif status_filter == "warning":
        warning_clauses = [
            Endpoint.last_seen.is_(None),
            Endpoint.last_seen < online_since,
            ~has_key_expr,
            Endpoint.is_blocked.is_(True),
            active_identity_warning_expr,
        ]
        warning_clauses.extend(outdated_clauses)
        query = query.filter(or_(*warning_clauses))

    total = query.order_by(None).with_entities(Endpoint.id).count()
    sort_columns = {
        "hostname": func.lower(func.coalesce(Endpoint.display_name, Endpoint.hostname, Endpoint.id)),
        "ip": Endpoint.connection_ip,
        "agent_version": Endpoint.agent_version,
        "last_seen": Endpoint.last_seen,
        "health": Endpoint.last_seen,
        "encryption": Endpoint.encryption_level,
    }
    sort_column = sort_columns.get(sort_key, sort_columns["hostname"])
    if sort_dir == "desc":
        query = query.order_by(sort_column.desc().nullslast(), Endpoint.hostname.asc().nullslast(), Endpoint.id.asc())
    else:
        query = query.order_by(sort_column.asc().nullslast(), Endpoint.hostname.asc().nullslast(), Endpoint.id.asc())

    allowed_hosts = attach_endpoint_list_flags(
        query.offset((page - 1) * page_size).limit(page_size).all()
    )
    hosts = []
    for endpoint in allowed_hosts:
        health = endpoint_health_score(endpoint, latest_versions)
        hosts.append({
            "id": endpoint.id,
            "hostname": endpoint.hostname or endpoint.id,
            "display_name": getattr(endpoint, "display_name", None) or "",
            "name": endpoint_display_name(endpoint),
            "ip": getattr(endpoint, "connection_ip", None) or "",
            "os": endpoint.os_version or getattr(endpoint, "os_type", "Windows"),
            "agent_version": getattr(endpoint, "agent_version", "") or "",
            "agent_identity_key_enrolled": bool(getattr(endpoint, "agent_identity_key_enrolled", False)),
            "task_signature_v2_ready": bool(getattr(endpoint, "task_signature_v2_seen_at", None)),
            "task_signature_v2_seen_at": to_kyiv_time_short(getattr(endpoint, "task_signature_v2_seen_at", None)),
            "identity_fingerprint": getattr(endpoint, "identity_fingerprint", "") or "",
            "possible_duplicate": bool(getattr(endpoint, "possible_duplicate", False)),
            "duplicate_matches": getattr(endpoint, "duplicate_matches", []),
            "identity_warning": effective_endpoint_identity_warning(endpoint),
            "last_seen": to_kyiv_time_short(endpoint.last_seen),
            "groups": [{"id": group.id, "name": group.name} for group in endpoint.groups],
            "health": health,
            "encryption": getattr(endpoint, "encryption", endpoint_encryption_payload(endpoint)),
        })

    packages = [agent_package_response(package, latest_versions) for package in load_agent_packages()]

    return jsonify({
        "success": True,
        "latest_version": latest_version,
        "latest_versions": latest_versions,
        "hosts": hosts,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": max(1, (total + page_size - 1) // page_size),
        },
        "access_note": access_note,
        "packages": packages,
        "task_signature_v2": {
            "ready": sum(1 for endpoint in allowed_hosts if getattr(endpoint, "task_signature_v2_seen_at", None)),
            "visible": len(allowed_hosts),
            "server_mode": Config.AGENT_TASK_SIGNATURE_MODE,
        },
    })


@infrastructure_bp.route('/api/infrastructure/fleet/update', methods=['POST'])
def run_fleet_update():
    denied = require_permission("run_tasks")
    if denied: return denied
    data = request.get_json(force=True) or {}
    package = find_agent_package(str(data.get("package_id") or ""))
    if not package:
        return jsonify({"success": False, "message": "Agent package not found"}), 404
    package = agent_package_response(package)
    package["update_url"] = resolved_agent_package_update_url(package["id"])

    target_mode = str(data.get("target_mode") or "outdated")
    allowed = [h for h in WinHubCore.get_allowed_hosts(session.get("user_id"), "run_tasks") if getattr(h, "approval_status", "Approved") == "Approved"]
    allowed_by_id = {h.id: h for h in allowed}
    latest_version = package.get("version")
    selected_platform = str(package.get("platform") or "").lower()

    if target_mode == "selected":
        target_ids = [str(item) for item in (data.get("target_ids") or []) if str(item) in allowed_by_id]
    elif target_mode == "group":
        group = EndpointGroup.query.get(data.get("group_id"))
        if group and not group_action_allowed(current_user(), group.id, "run_tasks"):
            return jsonify({"success": False, "message": "Task execution is denied for this group"}), 403
        group_ids = {h.id for h in group.endpoints} if group else set()
        target_ids = [host_id for host_id in allowed_by_id if host_id in group_ids]
    else:
        target_ids = [
            host_id for host_id, host in allowed_by_id.items()
            if (
                latest_version
                and endpoint_agent_platform(host) == selected_platform
                and (getattr(host, "agent_version", "") or "") != latest_version
            )
        ]

    target_ids = list(dict.fromkeys(target_ids))
    if not target_ids:
        return jsonify({"success": False, "message": "No eligible targets selected"}), 400
    update_plan, skipped_targets = build_agent_update_plan(target_ids, package)
    if not update_plan:
        return jsonify({"success": False, "message": "No selected targets match this agent package platform/version"}), 400
    if skipped_targets:
        logging.getLogger("winhub").warning(
            "Agent rollout will skip %s target(s) without a matching package: %s",
            len(skipped_targets),
            skipped_targets[:20],
        )

    wave_size = max(1, int(data.get("wave_size") or 50))
    wave_delay_seconds = max(0, int(data.get("wave_delay_seconds") or 0))
    waves = [update_plan[i:i + wave_size] for i in range(0, len(update_plan), wave_size)]
    rollout_target_ids = [item["host_id"] for item in update_plan]
    created_by = current_actor_label()

    rollout = AgentUpdateRollout(
        package_id=package["id"],
        package_url=package["update_url"],
        package_version=package.get("version"),
        target_ids=json.dumps(rollout_target_ids, ensure_ascii=False),
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
    db.session.commit()
    process_due_agent_update_rollouts()
    job_id = rollout.id

    write_infra_audit("Fleet Agent Update", "agent_package", package["id"], {
        "version": package.get("version"),
        "targets": len(update_plan),
        "skipped": len(skipped_targets),
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
        "targets": len(update_plan),
        "skipped": len(skipped_targets),
        "waves": len(waves),
        "wave_size": wave_size,
        "wave_delay_seconds": wave_delay_seconds,
    })


@infrastructure_bp.route('/api/infrastructure/templates', methods=['POST'])
def create_template():
    denied = require_permission("manage_templates")
    if denied: return denied
    data = request.json or {}
    payload_dict = data.get('payload', {})
    if not isinstance(payload_dict, dict):
        return jsonify({"success": False, "message": "Template payload must be an object"}), 400
    payload_dict = dict(payload_dict)
    if data.get('ai_draft_id'):
        try:
            stamp_ai_origin(payload_dict, str(data['ai_draft_id']))
        except (ValueError, TypeError):
            return jsonify(success=False, message='AI draft is not accessible or has not passed validation'), 400
        # Applying AI content never inherits an old approval checkbox.
        data['is_approved'] = False

    if 'report_template_id' in data and data['report_template_id']:
        if not approved_report_template(data['report_template_id']):
            return jsonify({"success": False, "message": "Approved report template not found or approval seal is invalid"}), 400
        payload_dict['__report_template_id'] = data['report_template_id']

    is_approved = bool(data.get('is_approved', False))
    if is_approved and not session.get("is_admin"):
        return jsonify({"success": False, "message": "Only a superadmin can approve executable templates"}), 403
    category = data.get('category', 'General').strip() or 'General'
    t_type = data.get('type', 'action')
    try:
        validate_report_template_payload(t_type, payload_dict)
    except Exception as exc:
        return jsonify({"success": False, "message": f"Unsafe or invalid report template: {exc}"}), 400
    payload_raw = json.dumps(payload_dict, ensure_ascii=False)

    tid = data.get('id')
    if tid:
        t = TaskTemplate.query.get(tid)
        if t:
            if not can_edit_template(t):
                return jsonify({"success": False, "message": "Template editing is locked by superadmin policy"}), 403
            prior_ai_origin = load_template_payload(t).get('__ai_generated')
            if prior_ai_origin:
                payload_dict['__ai_generated'] = prior_ai_origin
                payload_raw = json.dumps(payload_dict, ensure_ascii=False)
            if not session.get("is_admin"):
                payload_dict[TEMPLATE_POLICY_KEY] = template_policy(t)
                payload_raw = json.dumps(payload_dict, ensure_ascii=False)
            previous_hash = str(getattr(t, "approved_content_hash", "") or "")
            t.name = data.get('name'); t.category = category; t.action_type = data.get('action')
            t.type = t_type; t.payload = payload_raw
            new_hash = current_template_hash(t)
            if session.get("is_admin") and is_approved:
                t.is_approved = True
                t.approved_content_hash = new_hash
                t.approved_at = datetime.utcnow()
                t.approved_by = session.get("username")
            elif previous_hash != new_hash or (session.get("is_admin") and "is_approved" in data and not is_approved):
                t.is_approved = False
                t.approved_content_hash = None
                t.approved_at = None
                t.approved_by = None
    else:
        t = TaskTemplate(name=data.get('name'), category=category, action_type=data.get('action'), type=t_type, payload=payload_raw, is_approved=is_approved, created_by=session.get('username'))
        if is_approved:
            t.approved_content_hash = current_template_hash(t)
            t.approved_at = datetime.utcnow()
            t.approved_by = session.get("username")
        db.session.add(t)
    db.session.commit()
    return jsonify({"success": True})


@infrastructure_bp.route('/api/infrastructure/templates/<tid>/clone', methods=['POST'])
def clone_template(tid):
    denied = require_permission("manage_templates")
    if denied:
        return denied

    source = TaskTemplate.query.get(tid)
    if not source:
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_access_template_library_entry(source):
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_view_template_code(source) or not can_edit_template(source):
        return jsonify({"success": False, "message": "Template cloning is blocked by superadmin policy"}), 403

    payload_dict = clone_template_payload(source)
    template_type = getattr(source, "type", "action") or "action"
    try:
        validate_report_template_payload(template_type, payload_dict)
    except Exception as exc:
        return jsonify({"success": False, "message": f"Unsafe or invalid report template: {exc}"}), 400

    existing_names = [row[0] for row in db.session.query(TaskTemplate.name).all()]
    cloned = TaskTemplate(
        name=next_template_clone_name(source.name, existing_names),
        category=(str(source.category or "General").strip() or "General"),
        action_type=source.action_type,
        type=template_type,
        payload=json.dumps(payload_dict, ensure_ascii=False),
        is_approved=False,
        approved_content_hash=None,
        approved_at=None,
        approved_by=None,
        created_by=session.get("username"),
    )
    db.session.add(cloned)
    db.session.flush()
    write_infra_audit(
        "template_cloned",
        "task_template",
        cloned.id,
        {
            "source_template_id": source.id,
            "source_template_name": source.name,
            "clone_template_name": cloned.name,
        },
    )
    db.session.commit()
    return jsonify({
        "success": True,
        "template": {
            "id": cloned.id,
            "name": cloned.name,
        },
    }), 201


@infrastructure_bp.route('/api/infrastructure/templates/<tid>/deletion-impact', methods=['GET'])
def template_deletion_impact_api(tid):
    denied = require_permission("manage_templates")
    if denied:
        return denied

    template = TaskTemplate.query.get(tid)
    if not template or not can_access_template_library_entry(template):
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_delete_template(template):
        return jsonify({"success": False, "message": "Template deletion is locked by superadmin policy"}), 403

    return jsonify({
        "success": True,
        "template": {
            "id": template.id,
            "name": template.name,
            "type": getattr(template, "type", "action") or "action",
        },
        "impact": template_deletion_impact(template.id),
    })


@infrastructure_bp.route('/api/infrastructure/templates/<tid>', methods=['DELETE'])
def delete_template(tid):
    denied = require_interactive_superadmin()
    if denied:
        return denied

    template = TaskTemplate.query.get(tid)
    if not template or not can_access_template_library_entry(template):
        return jsonify({"success": False, "message": "Template not found"}), 404
    if not can_delete_template(template):
        return jsonify({"success": False, "message": "Template deletion is locked by superadmin policy"}), 403

    data = request.get_json(silent=True) or {}
    confirmation = data.get("confirm_name")
    if not isinstance(confirmation, str) or confirmation != template.name:
        return jsonify({
            "success": False,
            "message": "Type the exact template name to confirm deletion",
        }), 400

    try:
        impact = template_deletion_impact(template.id)
        ScheduledTask.query.filter_by(template_id=tid).delete(synchronize_session=False)
        TriggerRule.query.filter_by(action_template_id=tid).update(
            {"action_template_id": None},
            synchronize_session=False
        )
        write_infra_audit(
            "template_deleted",
            "task_template",
            template.id,
            {
                "template_name": template.name,
                "template_type": getattr(template, "type", "action") or "action",
                "scheduled_tasks_deleted": impact["scheduled_tasks"]["count"],
                "trigger_rules_detached": impact["trigger_rules"]["count"],
            },
        )
        db.session.delete(template)
        db.session.commit()
        return jsonify({"success": True, "impact": impact})
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
    if template and load_template_payload(template).get('__ai_generated') and not template_approval_valid(template):
        return jsonify(success=False, message='AI-generated templates require explicit approval before execution'), 403

    # ТЕПЕР ДЛЯ ВСІХ КОРИСТУВАЧІВ (І АДМІНІВ І ЗВИЧАЙНИХ) МИ ПРИЙМАЄМО СКРИПТ З ФРОНТЕНДУ
    if not is_admin:
        own_runnable = bool(
            not session.get("api_key_auth")
            and template
            and getattr(template, "created_by", None) == session.get("username")
            and can("manage_templates")
            and not load_template_payload(template).get('__ai_generated')
        )
        if not template or (not template_approval_valid(template) and not own_runnable) or getattr(template, 'type', 'action') == 'report' or not can_use_template(template):
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
        own_runnable = bool(
            not session.get("api_key_auth")
            and t
            and getattr(t, "created_by", None) == session.get("username")
            and can("manage_templates")
        )
        if not t or (not is_admin and ((not template_approval_valid(t) and not own_runnable) or not can_use_template(t))):
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

    if template:
        payload_dict['__template_id'] = template.id

    try:
        timeout_minutes = int(data.get("timeout_minutes") or 0)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Execution time limit must be a number of minutes"}), 400
    if timeout_minutes < 0 or timeout_minutes > 10080:
        return jsonify({"success": False, "message": "Execution time limit must be between 0 and 10080 minutes"}), 400
    if timeout_minutes > 0:
        deadline = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        payload_dict["__deadline_utc"] = deadline.replace(microsecond=0).isoformat() + "Z"
        payload_dict["__agent_timeout_seconds"] = max(60, timeout_minutes * 60)

    # Метадані для звітності та автовідправки
    if data.get('report_template_id'):
        payload_dict['__report_template_id'] = data.get('report_template_id')
    if data.get('auto_email_toggle'):
        denied = require_permission("send_reports")
        if denied:
            return denied
        if not data.get('auto_email_sender') or not data.get('auto_email_recipients'):
            return jsonify({"success": False, "message": "Auto-email sender and recipients are required"}), 400
        payload_dict['__auto_email_toggle'] = True
        payload_dict['__auto_email_sender'] = data.get('auto_email_sender')
        payload_dict['__auto_email_recipients'] = data.get('auto_email_recipients')
        payload_dict['__auto_email_use_gpg'] = data.get('auto_email_use_gpg', True)
    if data.get('auto_confluence_toggle'):
        denied = require_permission("send_reports")
        if denied:
            return denied
        if not data.get('auto_confluence_profile') or not data.get('auto_confluence_page_id'):
            return jsonify({"success": False, "message": "Auto-Confluence profile and page ID are required"}), 400
        payload_dict['__auto_confluence_toggle'] = True
        payload_dict['__auto_confluence_profile'] = data.get('auto_confluence_profile')
        payload_dict['__auto_confluence_page_id'] = data.get('auto_confluence_page_id')
        payload_dict['__auto_confluence_title'] = data.get('auto_confluence_title')
        payload_dict['__auto_confluence_body_format'] = data.get('auto_confluence_body_format', 'safe_html')
        payload_dict['__auto_confluence_note'] = data.get('auto_confluence_note', '')

    try:
        ai_report = requested_ai_report(data)
    except (PermissionError, ValueError) as exc:
        return jsonify({"success": False, "message": str(exc)}), 403 if isinstance(exc, PermissionError) else 400

    # ЗАМІНА ДИНАМІЧНИХ ЗМІННИХ (VARIABLES) У СКРИПТІ
    tpl_vars = data.get('variables', {})
    if session.get("api_key_auth") and template:
        try:
            tpl_vars = validate_api_template_variables(
                payload_dict,
                tpl_vars if isinstance(tpl_vars, dict) else {},
            )
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 400
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
                return jsonify({"success": False, "message": "Agent update requires a valid 64-character SHA256 hash"}), 400
        else:
            return jsonify({"success": False, "message": "Agent update requires sha256"}), 400

    # Розбір цілей
    agent_ids = []
    if target_type == "hosts":
        agent_ids = data.get('target_ids', [])
    elif target_type == "group":
        group = EndpointGroup.query.get(data.get('target_id'))
        if group and not group_action_allowed(current_user(), group.id, "run_tasks"):
            return jsonify({"success": False, "message": "Task execution is denied for this group"}), 403
        if group: agent_ids = [a.id for a in group.endpoints]

    if not agent_ids:
        return jsonify({"success": False, "message": "No targets selected"}), 400
    if not api_target_count_allowed(agent_ids):
        return jsonify({"success": False, "message": "Target count exceeds this API key policy"}), 403
    if session.get("api_key_auth"):
        authorized = WinHubCore.authorized_target_ids(session.get("user_id"), agent_ids, "run_tasks")
        if set(str(item) for item in agent_ids) != set(str(item) for item in authorized):
            return jsonify({"success": False, "message": "One or more targets are outside this API key group policy"}), 403
    if data.get('auto_email_toggle') or data.get('auto_confluence_toggle'):
        send_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "send_reports"))
        if any(str(agent_id) not in send_host_ids for agent_id in agent_ids):
            return jsonify({"success": False, "message": "Report delivery is denied for one or more target groups"}), 403

    try:
        job_id = WinHubCore.dispatch_task(
            session.get('user_id'), "Infrastructure", action_type, agent_ids, payload_dict,
            data.get('title', 'Task'), ai_report=ai_report,
        )
        return jsonify({"success": True, "job_id": job_id})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@infrastructure_bp.route('/api/infrastructure/templates/<template_id>/run', methods=['POST'])
def run_template_api(template_id):
    denied = require_permission("run_tasks")
    if denied:
        return denied

    data = request.json or {}
    template = TaskTemplate.query.get(template_id)
    own_runnable = bool(
        not session.get("api_key_auth")
        and template
        and getattr(template, "created_by", None) == session.get("username")
        and can("manage_templates")
    )
    if not template or (not template_approval_valid(template) and not own_runnable) or getattr(template, "type", "action") == "report":
        return jsonify({"success": False, "message": "Approved action template not found"}), 404
    if not can_use_template(template):
        return jsonify({"success": False, "message": "Template denied"}), 403

    if data.get("target_type") == "group" and not group_action_allowed(
        current_user(), data.get("target_id"), "run_tasks"
    ):
        return jsonify({"success": False, "message": "Task execution is denied for this group"}), 403
    target_ids, missing_targets = resolve_target_ids(data)
    if missing_targets:
        return jsonify({
            "success": False,
            "message": "Unknown target endpoints",
            "missing_targets": missing_targets
        }), 400
    if not target_ids:
        return jsonify({"success": False, "message": "No targets selected"}), 400
    if not api_target_count_allowed(target_ids):
        return jsonify({"success": False, "message": "Target count exceeds this API key policy"}), 403
    if session.get("api_key_auth"):
        authorized = WinHubCore.authorized_target_ids(session.get("user_id"), target_ids, "run_tasks")
        if set(target_ids) != set(authorized):
            return jsonify({"success": False, "message": "One or more targets are outside this API key group policy"}), 403
    if data.get("auto_email_toggle") or data.get("auto_confluence_toggle"):
        send_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "send_reports"))
        if any(str(target_id) not in send_host_ids for target_id in target_ids):
            return jsonify({"success": False, "message": "Report delivery is denied for one or more target groups"}), 403

    variables = data.get("variables", {}) or {}
    if not isinstance(variables, dict):
        return jsonify({"success": False, "message": "Variables must be an object"}), 400

    try:
        ai_report = requested_ai_report(data)
        payload_dict = load_template_payload(template)
        payload_dict["__template_id"] = template.id
        if "script" not in payload_dict and "command" in payload_dict:
            payload_dict["script"] = payload_dict["command"]
        variables = validate_api_template_variables(payload_dict, variables)
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
        if data.get("auto_confluence_toggle"):
            denied = require_permission("send_reports")
            if denied:
                return denied
            if not data.get("auto_confluence_profile") or not data.get("auto_confluence_page_id"):
                return jsonify({"success": False, "message": "Auto-Confluence profile and page ID are required"}), 400
            payload_dict["__auto_confluence_toggle"] = True
            payload_dict["__auto_confluence_profile"] = data.get("auto_confluence_profile")
            payload_dict["__auto_confluence_page_id"] = data.get("auto_confluence_page_id")
            payload_dict["__auto_confluence_title"] = data.get("auto_confluence_title")
            payload_dict["__auto_confluence_body_format"] = data.get("auto_confluence_body_format", "safe_html")
            payload_dict["__auto_confluence_note"] = data.get("auto_confluence_note", "")

        title = data.get("title") or template.name or "API Template Run"
        job_id, task_ids = dispatch_infrastructure_task(
            session.get("user_id"),
            template.action_type or "run_script",
            target_ids,
            payload_dict,
            title,
            created_by=current_actor_label(),
            ai_report=ai_report,
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

def parse_iso_datetime(value, *, end=False):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if len(raw) == 10 and end:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=kyiv_tz)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


@infrastructure_bp.route('/api/infrastructure/tasks/all')
def get_tasks():
    denied = require_permission("view_queue")
    if denied: return denied
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = max(5, min(50, int(request.args.get("page_size", 20))))
    except (TypeError, ValueError):
        page_size = 20
    user_id = session.get('user_id')
    allowed_hosts = infra_allowed_host_ids(user_id, "view_queue")
    full_admin = bool(session.get("is_admin") and not session.get("api_key_auth"))
    if not allowed_hosts and not full_admin:
        return jsonify({
            "success": True,
            "jobs": [],
            "pagination": {"page": page, "page_size": page_size, "total": 0, "has_more": False},
        })
    planned_jobs = planned_agent_update_rollout_jobs(allowed_hosts)

    search_term = str(request.args.get("q") or "").strip()
    content_term = str(request.args.get("content") or "").strip()
    can_search_sensitive_content = can("view_sensitive_reports")
    if content_term and not can_search_sensitive_content:
        return jsonify({"success": False, "message": "Sensitive task-content search permission required"}), 403
    actor_filter = str(request.args.get("actor") or "").strip()
    source_filter = str(request.args.get("source") or "").strip().lower()
    status_filter = str(request.args.get("status") or "").strip().lower()
    target_filter = str(request.args.get("target") or "").strip()
    date_from = parse_iso_datetime(request.args.get("date_from"))
    date_to = parse_iso_datetime(request.args.get("date_to"), end=True)

    if content_term or target_filter or date_from or date_to:
        planned_jobs = []
    else:
        if search_term:
            planned_jobs = [job for job in planned_jobs if search_term.casefold() in " ".join((
                str(job.get("title") or ""), str(job.get("created_by") or ""),
                str(job.get("job_id") or ""), str(job.get("target_summary") or ""),
            )).casefold()]
        if actor_filter:
            planned_jobs = [job for job in planned_jobs if str(job.get("created_by") or "") == actor_filter]
        if source_filter in {"manual", "auto-fix"}:
            planned_jobs = []
        if status_filter and status_filter != "scheduled":
            planned_jobs = []

    base_filters = [AgentTask.job_id.isnot(None)]
    if status_filter == "scheduled":
        base_filters.append(False)
    if not full_admin:
        base_filters.append(or_(
            AgentTask.endpoint_id.in_(allowed_hosts),
            AgentTask.endpoint_id_snapshot.in_(allowed_hosts),
        ))
    if actor_filter:
        base_filters.append(AgentTask.created_by == actor_filter)
    if source_filter:
        source_aliases = {
            "manual": ["manual", "interactive", "api"],
            "auto": ["scheduler", "scheduled"],
            "auto-fix": ["trigger", "auto-fix"],
        }
        base_filters.append(AgentTask.source_type.in_(source_aliases.get(source_filter, [source_filter])))
    if target_filter:
        target_like = f"%{target_filter}%"
        base_filters.append(or_(
            AgentTask.endpoint_id.ilike(target_like),
            AgentTask.endpoint_id_snapshot.ilike(target_like),
            AgentTask.endpoint_hostname_snapshot.ilike(target_like),
            AgentTask.endpoint_name_snapshot.ilike(target_like),
        ))
    if date_from:
        base_filters.append(AgentTask.created_at >= date_from)
    if date_to:
        base_filters.append(AgentTask.created_at <= date_to)

    from core.history_search import matching_entity_ids
    content_ids = matching_entity_ids(
        "task", content_term, fields=["input", "output"],
        mode=request.args.get("content_mode", "all"),
    ) if content_term else None
    if content_term:
        base_filters.append(AgentTask.id.in_(content_ids) if content_ids is not None else False)
    if search_term:
        search_like = f"%{search_term}%"
        search_tokens = matching_entity_ids("task", search_term, fields=["input", "output"], mode="all") if can_search_sensitive_content else None
        metadata_filter = or_(
            AgentTask.title.ilike(search_like),
            AgentTask.created_by.ilike(search_like),
            AgentTask.action_type.ilike(search_like),
            AgentTask.module_source.ilike(search_like),
            AgentTask.job_id.ilike(search_like),
            AgentTask.endpoint_id_snapshot.ilike(search_like),
            AgentTask.endpoint_hostname_snapshot.ilike(search_like),
            AgentTask.endpoint_name_snapshot.ilike(search_like),
        )
        base_filters.append(or_(metadata_filter, AgentTask.id.in_(search_tokens)) if search_tokens is not None else metadata_filter)

    last_created_at = func.max(AgentTask.created_at).label("last_created_at")
    recent_jobs_query = db.session.query(
        AgentTask.job_id,
        last_created_at
    ).filter(*base_filters).group_by(
        AgentTask.job_id
    )
    error_count_expr = func.sum(case((func.lower(func.coalesce(AgentTask.status, "pending")) == "error", 1), else_=0))
    active_count_expr = func.sum(case((func.lower(func.coalesce(AgentTask.status, "pending")).in_(["pending", "pickedup", "running"]), 1), else_=0))
    cancelled_count_expr = func.sum(case((func.lower(func.coalesce(AgentTask.status, "pending")) == "cancelled", 1), else_=0))
    if status_filter == "error":
        recent_jobs_query = recent_jobs_query.having(error_count_expr > 0)
    elif status_filter in {"pending", "running"}:
        recent_jobs_query = recent_jobs_query.having(error_count_expr == 0, active_count_expr > 0)
    elif status_filter == "cancelled":
        recent_jobs_query = recent_jobs_query.having(cancelled_count_expr == func.count(AgentTask.id))
    elif status_filter == "success":
        recent_jobs_query = recent_jobs_query.having(error_count_expr == 0, active_count_expr == 0, cancelled_count_expr < func.count(AgentTask.id))
    recent_jobs_query = recent_jobs_query.order_by(last_created_at.desc())
    total_persisted_jobs = recent_jobs_query.count()
    recent_jobs = recent_jobs_query.offset((page - 1) * page_size).limit(page_size).all()

    job_ids = [job_id for job_id, _ in recent_jobs if job_id]
    if not job_ids:
        page_planned_jobs = planned_jobs if page == 1 else []
        for job in page_planned_jobs:
            job.pop("_sort_at", None)
        return jsonify({
            "success": True,
            "jobs": page_planned_jobs,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total_persisted_jobs + len(planned_jobs),
                "has_more": page * page_size < total_persisted_jobs,
            },
        })

    latest_ai_by_job = {}
    for ai_row in AiReportRequest.query.filter(AiReportRequest.job_id.in_(job_ids)).order_by(
        AiReportRequest.created_at
    ).all():
        latest_ai_by_job[ai_row.job_id] = ai_row
    task_scope_filter = True if full_admin else or_(
        AgentTask.endpoint_id.in_(allowed_hosts),
        AgentTask.endpoint_id_snapshot.in_(allowed_hosts),
    )
    tasks = db.session.query(AgentTask, Endpoint.hostname, Endpoint.display_name).outerjoin(
        Endpoint, Endpoint.id == AgentTask.endpoint_id
    ).filter(
        task_scope_filter,
        AgentTask.job_id.in_(job_ids)
    ).order_by(AgentTask.created_at.desc()).all()

    jobs = {}
    job_sort_at = {job_id: created_at for job_id, created_at in recent_jobs if job_id}
    for t, hostname, display_name in tasks:
        jid = t.job_id or t.id
        if jid not in jobs:
            ai_row = latest_ai_by_job.get(jid)
            jobs[jid] = {"job_id": jid, "title": t.title or "Untitled Task", "action": t.action_type, "created_at": to_kyiv_time(t.created_at), "_sort_at": job_sort_at.get(jid) or t.created_at, "created_by": t.created_by, "ai_report": ({"requested": True, "status": ai_row.status} if ai_row else {"requested": False, "status": "NotRequested"}), "tasks": [], "total": 0, "success": 0, "error": 0, "pending": 0, "running": 0, "cancelled": 0}
        if is_agent_updater_prepare_task(t):
            continue
        resolved_hostname = hostname or t.endpoint_hostname_snapshot or ""
        resolved_name = display_name or t.endpoint_name_snapshot or ""
        resolved_endpoint_id = t.endpoint_id or t.endpoint_id_snapshot
        display_label = (resolved_name or resolved_hostname or resolved_endpoint_id or "Deleted host").strip()
        jobs[jid]["tasks"].append({"task_id": t.id, "endpoint_id": resolved_endpoint_id, "hostname": resolved_hostname, "display_name": resolved_name, "name": display_label, "status": t.status or "Pending"})
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
        if data["total"] == 1:
            data["target_summary"] = data["tasks"][0].get("name") or data["tasks"][0].get("hostname") or "Unknown"
        else:
            data["target_summary"] = f"Group Deployment ({data['total']} hosts)"
        if data["error"] > 0: data["status"] = "Error"
        elif data["cancelled"] == data["total"]: data["status"] = "Cancelled"
        elif data["pending"] > 0 or data["running"] > 0: data["status"] = "Pending"
        else: data["status"] = "Success"
        result.append(data)

    if page == 1:
        result.extend(planned_jobs)
    result.sort(key=lambda item: item.get("_sort_at") or datetime.min, reverse=True)
    for item in result:
        item.pop("_sort_at", None)

    return jsonify({
        "success": True,
        "jobs": result,
        "filters": {
            "actors": [row[0] for row in db.session.query(AgentTask.created_by).filter(
                task_scope_filter,
                AgentTask.created_by.isnot(None)
            ).distinct().order_by(AgentTask.created_by).all() if row[0]],
            "sources": [row[0] for row in db.session.query(AgentTask.source_type).filter(
                task_scope_filter,
                AgentTask.source_type.isnot(None)
            ).distinct().order_by(AgentTask.source_type).all() if row[0]],
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total_persisted_jobs + len(planned_jobs),
            "has_more": page * page_size < total_persisted_jobs,
        },
    })

@infrastructure_bp.route('/api/infrastructure/task/<task_id>', methods=['GET'])
def get_single_task(task_id):
    denied = require_permission("view_queue")
    if denied: return denied
    task = AgentTask.query.get(task_id)
    if not task: return jsonify({"success": False}), 404
    resolved_endpoint_id = task.endpoint_id or task.endpoint_id_snapshot
    if not is_interactive_superadmin() and not WinHubCore.can_manage_host(session.get('user_id'), resolved_endpoint_id, "view_queue"):
        return jsonify({"success": False}), 403
    task_log = task.result_log if task.result_log else "Waiting..."
    endpoint_name = endpoint_display_name(task.endpoint) if task.endpoint else "Unknown"
    visible_log = report_body_for_current_user(task_log, host_id=task.endpoint_id)
    visible_payload = task.payload if is_interactive_superadmin() else None
    if Config.AUDIT_SENSITIVE_READS:
        WinHubCore.audit(
            user_id=session.get("user_id"),
            module="Infrastructure",
            action="Task Result Viewed",
            details={"job_id": task.job_id, "endpoint_id": task.endpoint_id or task.endpoint_id_snapshot},
            target_type="agent_task",
            target_id=task.id,
            status="Success",
        )
    return jsonify({"success": True, "data": {
        "id": task.id,
        "job_id": task.job_id,
        "title": task.title or "Untitled",
        "action": task.action_type or "",
        "source": task.source_type or "manual",
        "created_by": task.created_by or "System",
        "created_at": to_kyiv_time(task.created_at),
        "finished_at": to_kyiv_time(task.finished_at),
        "status": task.status or "Pending",
        "log": visible_log,
        "payload": visible_payload,
        "hostname": task.endpoint.hostname if task.endpoint else (task.endpoint_hostname_snapshot or "Unknown"),
        "display_name": getattr(task.endpoint, "display_name", None) if task.endpoint else (task.endpoint_name_snapshot or ""),
        "name": endpoint_name if task.endpoint else (task.endpoint_name_snapshot or task.endpoint_hostname_snapshot or task.endpoint_id_snapshot or "Unknown"),
    }})


@infrastructure_bp.route('/api/infrastructure/jobs/<job_id>/status', methods=['GET'])
def get_job_status_api(job_id):
    """Return bot-safe execution and notification status without result content."""
    denied = require_permission("view_queue")
    if denied:
        return denied
    tasks = AgentTask.query.filter_by(job_id=job_id).order_by(AgentTask.created_at).all()
    if not tasks:
        return jsonify({"success": False, "message": "Job not found"}), 404

    endpoint_ids = {
        str(task.endpoint_id or task.endpoint_id_snapshot)
        for task in tasks
        if task.endpoint_id or task.endpoint_id_snapshot
    }
    authorized_ids = WinHubCore.authorized_target_ids(
        session.get("user_id"), endpoint_ids, "view_queue"
    )
    if endpoint_ids != {str(item) for item in authorized_ids}:
        return jsonify({"success": False, "message": "Job is outside this API key group policy"}), 403

    counters = {"total": len(tasks), "success": 0, "error": 0, "pending": 0, "cancelled": 0}
    for task in tasks:
        status = str(task.status or "Pending").strip().lower()
        if status == "success":
            counters["success"] += 1
        elif status == "error":
            counters["error"] += 1
        elif status == "cancelled":
            counters["cancelled"] += 1
        else:
            counters["pending"] += 1

    if counters["error"]:
        job_status = "Error"
    elif counters["cancelled"] == counters["total"]:
        job_status = "Cancelled"
    elif counters["pending"]:
        job_status = "Pending"
    else:
        job_status = "Success"

    expected_channels = []
    try:
        internal_payload = json.loads(tasks[0].payload or "{}")
        if internal_payload.get("__auto_email_toggle"):
            expected_channels.append("email")
        if internal_payload.get("__auto_confluence_toggle"):
            expected_channels.append("confluence")
    except (TypeError, ValueError):
        pass

    report_ids = [str(job_id)]
    try:
        split_prefix = f"{uuid.UUID(str(job_id)).hex}.%"
    except (TypeError, ValueError, AttributeError):
        split_prefix = None
    delivery_filter = ReportDelivery.report_id == str(job_id)
    if split_prefix:
        delivery_filter = or_(delivery_filter, ReportDelivery.report_id.like(split_prefix))
    deliveries = ReportDelivery.query.filter(delivery_filter).order_by(ReportDelivery.created_at).all()
    ai_request = latest_ai_request(job_id)

    if not expected_channels:
        notification_status = "NotRequested"
    elif not deliveries:
        notification_status = "Pending"
    elif any(str(row.status).lower() == "error" for row in deliveries):
        notification_status = "Error"
    elif all(str(row.status).lower() == "success" for row in deliveries):
        notification_status = "Success"
    else:
        notification_status = "Pending"

    return jsonify({
        "success": True,
        "job_id": str(job_id),
        "status": job_status,
        "counts": counters,
        "ai_report": ({
            "requested": True,
            "status": ai_request.status,
            "attempt": ai_request.attempt,
            "report_id": ai_request.report_id,
            "error": ai_request.error if ai_request.status == "Error" else None,
            "completed_at": to_kyiv_time(ai_request.completed_at),
        } if ai_request else {"requested": False, "status": "NotRequested"}),
        "notification": {
            "expected_channels": expected_channels,
            "status": notification_status,
            "deliveries": [{
                "channel": row.channel,
                "status": row.status,
                "completed_at": to_kyiv_time(row.completed_at),
            } for row in deliveries],
        },
    })

@infrastructure_bp.route('/api/infrastructure/tasks/cleanup', methods=['POST'])
def cleanup_tasks():
    denied = require_interactive_superadmin()
    if denied:
        return denied
    try:
        days = max(1, min(3650, int((request.get_json(silent=True) or {}).get('days', 30))))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Days must be a number between 1 and 3650"}), 400

    cutoff = datetime.utcnow() - timedelta(days=days)
    expired_ids = db.session.query(AgentTask.id).filter(AgentTask.created_at < cutoff)
    HistorySearchToken.query.filter(
        HistorySearchToken.entity_type == "task",
        HistorySearchToken.entity_id.in_(expired_ids),
    ).delete(synchronize_session=False)
    deleted = AgentTask.query.filter(
        AgentTask.created_at < cutoff
    ).delete(synchronize_session=False)

    write_infra_audit("Cleanup Scoped Task History", "task", "bulk", {"days": days, "deleted": deleted})
    db.session.commit()
    return jsonify({"success": True, "deleted": deleted})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    denied = require_interactive_superadmin()
    if denied:
        return denied
    task_count = AgentTask.query.filter(
        or_(AgentTask.job_id == job_id, AgentTask.id == job_id)
    ).count()
    if not task_count:
        return jsonify({"success": False, "message": "Task job not found"}), 404
    task_ids = db.session.query(AgentTask.id).filter(
        or_(AgentTask.job_id == job_id, AgentTask.id == job_id)
    )
    HistorySearchToken.query.filter(
        HistorySearchToken.entity_type == "task",
        HistorySearchToken.entity_id.in_(task_ids),
    ).delete(synchronize_session=False)
    deleted = AgentTask.query.filter(
        or_(AgentTask.job_id == job_id, AgentTask.id == job_id)
    ).delete(synchronize_session=False)
    write_infra_audit("Delete Task Job", "job", job_id, {"deleted_tasks": deleted})
    db.session.commit()
    return jsonify({"success": True, "deleted": deleted})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>/cancel-pending', methods=['POST'])
def cancel_pending_job(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if not can_access_report(job_id, "run_tasks"):
        return jsonify({"success": False, "message": "Permission denied"}), 403
    tasks = AgentTask.query.filter_by(job_id=job_id).filter(
        or_(
            AgentTask.status.is_(None),
            AgentTask.status.in_(["Pending", "PickedUp", "Running"])
        )
    ).all()
    cancelled = 0
    allowed_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "run_tasks"))
    for task in tasks:
        if task.endpoint_id in allowed_host_ids:
            previous_status = task.status or "Pending"
            task.status = "Cancelled"
            task.result_log = f"Cancelled by operator while task status was {previous_status}. If the agent had already started the script, the local process may still finish, but WinHUB will keep this task cancelled."
            task.finished_at = datetime.utcnow()
            cancelled += 1
    from core.history_search import index_agent_task
    for task in tasks:
        if task.status == "Cancelled":
            index_agent_task(task)
    write_infra_audit("Cancel Job Tasks", "job", job_id, {"cancelled": cancelled})
    db.session.commit()
    pending_tasks = AgentTask.query.filter(
        AgentTask.job_id == job_id,
        AgentTask.status.in_(["Pending", "PickedUp", "Running"])
    ).count()
    if pending_tasks == 0:
        WinHubCore.process_job_completion(job_id, include_statuses=["Success", "Error", "Cancelled"], force=True)
    return jsonify({"success": True, "cancelled": cancelled})


@infrastructure_bp.route('/api/infrastructure/agent-rollout/<rollout_id>/cancel', methods=['POST'])
def cancel_agent_update_rollout(rollout_id):
    denied = require_permission("run_tasks")
    if denied:
        return denied

    rollout = AgentUpdateRollout.query.filter_by(id=rollout_id).with_for_update().first()
    if not rollout:
        return jsonify({"success": False, "message": "Scheduled rollout not found"}), 404
    if rollout.status != "Running":
        return jsonify({"success": True, "status": rollout.status, "message": "Rollout is not running"})

    try:
        target_ids = json.loads(rollout.target_ids or "[]")
        target_ids = set(str(item) for item in target_ids if str(item or "").strip()) if isinstance(target_ids, list) else set()
    except Exception:
        target_ids = set()

    if target_ids:
        existing_target_ids = {
            row[0]
            for row in db.session.query(Endpoint.id).filter(Endpoint.id.in_(target_ids)).all()
        }
        allowed_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "run_tasks"))
        unauthorized = existing_target_ids - allowed_host_ids
        if unauthorized:
            return jsonify({"success": False, "message": "Permission denied for one or more rollout hosts"}), 403

    previous_status = rollout.status or "Running"
    rollout.status = "Cancelled"
    rollout.updated_at = datetime.utcnow()
    write_infra_audit(
        "Cancel Scheduled Agent Update Rollout",
        "agent_update_rollout",
        rollout.id,
        {
            "previous_status": previous_status,
            "package_version": rollout.package_version,
            "next_wave_index": rollout.next_wave_index,
            "total_waves": rollout.total_waves,
            "target_count": len(target_ids),
        }
    )
    db.session.commit()

    return jsonify({"success": True, "status": rollout.status})


@infrastructure_bp.route('/api/infrastructure/job/<job_id>/finalize-report', methods=['POST'])
def finalize_job_report(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if not can_access_report(job_id, "run_tasks"):
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
    allowed_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "run_tasks"))
    for task in pending_tasks:
        if task.endpoint_id in allowed_host_ids:
            task.status = "Cancelled"
            task.result_log = "Excluded from finalized report before completion."
            task.finished_at = datetime.utcnow()
            cancelled += 1

    from core.history_search import index_agent_task
    for task in pending_tasks:
        if task.status == "Cancelled":
            index_agent_task(task)

    db.session.commit()

    WinHubCore.process_job_completion(job_id, include_statuses=["Success", "Error"], force=True)
    write_infra_audit("Finalize Job Report", "job", job_id, {"cancelled_pending": cancelled, "included_completed": completed_count})
    return jsonify({"success": True, "cancelled": cancelled, "included": completed_count})

@infrastructure_bp.route('/api/infrastructure/job/<job_id>/retry-failed', methods=['POST'])
def retry_failed_job(job_id):
    denied = require_permission("run_tasks")
    if denied: return denied
    if session.get("api_key_auth"):
        # Stored task payloads already contain rendered variables/secrets and may
        # predate the key's current template policy. API clients must perform a
        # fresh approved-template run so all current checks are evaluated again.
        return jsonify({
            "success": False,
            "message": "API retry is disabled; run the approved template again",
        }), 403
    if not can_access_report(job_id, "run_tasks"):
        return jsonify({"success": False, "message": "Permission denied"}), 403

    failed_tasks = AgentTask.query.filter_by(job_id=job_id).filter(AgentTask.status.in_(["Error", "Cancelled"])).all()
    new_job_id = str(uuid.uuid4())
    created = 0
    created_tasks = []
    allowed_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "run_tasks"))
    for task in failed_tasks:
        if task.endpoint_id not in allowed_host_ids:
            continue
        endpoint = task.endpoint
        retry_task = AgentTask(
            id=str(uuid.uuid4()),
            job_id=new_job_id,
            endpoint_id=task.endpoint_id,
            endpoint_id_snapshot=task.endpoint_id_snapshot or task.endpoint_id,
            endpoint_hostname_snapshot=task.endpoint_hostname_snapshot or getattr(endpoint, "hostname", None),
            endpoint_name_snapshot=task.endpoint_name_snapshot or getattr(endpoint, "display_name", None),
            endpoint_groups_snapshot=task.endpoint_groups_snapshot,
            title=f"[Retry] {task.title or 'Untitled Task'}",
            module_source=task.module_source or "Infrastructure",
            action_type=task.action_type,
            payload=task.payload,
            source_type="manual",
            actor_user_id=session.get("user_id"),
            template_id=task.template_id,
            created_by=current_actor_label(),
        )
        db.session.add(retry_task)
        created_tasks.append(retry_task)
        created += 1
    if not created:
        return jsonify({"success": False, "message": "No failed tasks available to retry"}), 400
    db.session.flush()
    from core.history_search import index_agent_task
    for retry_task in created_tasks:
        index_agent_task(retry_task)
    write_infra_audit("Retry Failed Job Tasks", "job", job_id, {"new_job_id": new_job_id, "created": created})
    db.session.commit()
    return jsonify({"success": True, "job_id": new_job_id, "created": created})

# ==========================================
# API: GROUPS & HOSTS
# ==========================================
@infrastructure_bp.route('/api/infrastructure/host/<host_id>', methods=['GET', 'DELETE', 'PATCH'])
def host_operations(host_id):
    action_permission = {
        "GET": "view_hosts",
        "DELETE": "delete_hosts",
        "PATCH": "manage_hosts",
    }[request.method]
    denied = require_permission(action_permission)
    if denied:
        return denied
    if host_id not in set(infra_allowed_host_ids(session.get('user_id'), action_permission)):
        return jsonify({"success": False, "message": "Host action is outside your group scope"}), 403
    agent = Endpoint.query.get(host_id)
    if not agent:
        return jsonify({"success": False, "message": "Host not found"}), 404
    if request.method == 'DELETE':
        superadmin_denied = require_interactive_superadmin()
        if superadmin_denied:
            return superadmin_denied
        group_snapshot = json.dumps([
            {"id": group.id, "name": group.name}
            for group in agent.groups
        ], ensure_ascii=False)
        AgentTask.query.filter_by(endpoint_id=agent.id).update({
            "endpoint_id_snapshot": agent.id,
            "endpoint_hostname_snapshot": agent.hostname,
            "endpoint_name_snapshot": agent.display_name,
            "endpoint_groups_snapshot": group_snapshot,
            "endpoint_id": None,
        }, synchronize_session=False)
        write_infra_audit("Delete Host", "endpoint", agent.id, {"hostname": agent.hostname})
        db.session.delete(agent); db.session.commit()
        return jsonify({"success": True})
    if request.method == 'PATCH':
        data = request.get_json(force=True) or {}
        display_name = str(data.get("display_name") or "").strip()
        if len(display_name) > 120:
            return jsonify({"success": False, "message": "Display Name must be 120 characters or less"}), 400
        agent.display_name = display_name or None
        if not effective_endpoint_identity_warning(agent):
            agent.identity_warning = None
        write_infra_audit(
            "Update Endpoint Display Name",
            "endpoint",
            agent.id,
            {"hostname": agent.hostname, "display_name": agent.display_name}
        )
        db.session.commit()
        return jsonify({
            "success": True,
            "display_name": agent.display_name or "",
            "name": endpoint_display_name(agent),
            "hostname": agent.hostname or agent.id,
            "identity_warning": effective_endpoint_identity_warning(agent),
            "possible_duplicate": bool(effective_endpoint_identity_warning(agent)),
        })
    denied = require_permission("view_hosts")
    if denied: return denied
    history = AgentTask.query.options(
        load_only(
            AgentTask.id,
            AgentTask.title,
            AgentTask.status,
            AgentTask.created_at,
            AgentTask.created_by,
        )
    ).filter_by(endpoint_id=host_id).order_by(AgentTask.created_at.desc()).limit(20).all()
    try:
        network_info = json.loads(agent.network_info or "[]")
    except Exception:
        network_info = []
    try:
        host_info = json.loads(agent.host_info or "{}")
    except Exception:
        host_info = {}
    reenroll_until = getattr(agent, "reenroll_allowed_until", None)
    if reenroll_until and getattr(reenroll_until, "tzinfo", None):
        reenroll_until = reenroll_until.replace(tzinfo=None)
    active_reenroll_until = reenroll_until if reenroll_until and reenroll_until >= datetime.utcnow() else None
    return jsonify({
        "success": True,
        "data": {
            "id": agent.id,
            "hostname": agent.hostname,
            "display_name": getattr(agent, "display_name", None) or "",
            "name": endpoint_display_name(agent),
            "os": agent.os_version,
            "ip": getattr(agent, "connection_ip", None) or agent.ip_address,
            "os_type": getattr(agent, 'os_type', 'Windows'),
            "last_seen": to_kyiv_time(agent.last_seen),
            "first_seen": to_kyiv_time(getattr(agent, "first_seen", None)),
            "last_enrollment_at": to_kyiv_time(getattr(agent, "last_enrollment_at", None)),
            "last_enrollment_ip": getattr(agent, "last_enrollment_ip", None),
            "enrollment_attempts": int(getattr(agent, "enrollment_attempts", 0) or 0),
            "identity_fingerprint": getattr(agent, "identity_fingerprint", None),
            "identity_duplicate_allowed": bool(getattr(agent, "identity_duplicate_allowed", False)),
            "agent_identity_key_enrolled": bool(getattr(agent, "public_key_pem_plain", None) or getattr(agent, "public_key_pem", None)),
            "reenroll_allowed_until": to_kyiv_time(active_reenroll_until),
            "duplicate_matches": getattr(agent, "duplicate_matches", []),
            "identity_warning": effective_endpoint_identity_warning(agent),
            "is_blocked": agent.is_blocked,
            "approval_status": getattr(agent, "approval_status", "Approved"),
            "agent_version": getattr(agent, "agent_version", None),
            "network_info": network_info,
            "host_info": host_info,
            "encryption": encryption_status_from_host_info(host_info),
            "groups": [{"id": g.id, "name": g.name} for g in agent.groups],
            "history": [
                {
                    "id": h.id,
                    "title": h.title,
                    "status": h.status or "Pending",
                    "date": to_kyiv_time_short(h.created_at),
                    "by": h.created_by,
                }
                for h in history
            ],
        },
    })

def build_activity_segments(host_id, telemetry_records, threshold, end_time, fallback_ip=""):
    records = sorted([r for r in telemetry_records if r.timestamp], key=lambda r: r.timestamp)
    if not records:
        return []

    gaps = []
    for index in range(1, len(records)):
        gap = (records[index].timestamp - records[index - 1].timestamp).total_seconds()
        if gap > 0:
            gaps.append(gap)
    gaps.sort()
    expected_gap_seconds = gaps[len(gaps) // 2] if gaps else 120
    expected_gap_seconds = max(30, min(expected_gap_seconds, 600))
    offline_gap_seconds = max(300, expected_gap_seconds * 3)

    previous_ip_record = ConnectionIpHistory.query.filter(
        ConnectionIpHistory.endpoint_id == host_id,
        ConnectionIpHistory.timestamp < threshold
    ).order_by(ConnectionIpHistory.timestamp.desc()).first()
    ip_records = ConnectionIpHistory.query.filter(
        ConnectionIpHistory.endpoint_id == host_id,
        ConnectionIpHistory.timestamp >= threshold,
        ConnectionIpHistory.timestamp <= end_time
    ).order_by(ConnectionIpHistory.timestamp.asc()).all()
    ip_events = []
    if previous_ip_record:
        ip_events.append((threshold, previous_ip_record.ip_address or fallback_ip or "-"))
    elif fallback_ip:
        ip_events.append((threshold, fallback_ip))
    for record in ip_records:
        if record.timestamp:
            ip_events.append((record.timestamp, record.ip_address or "-"))
    ip_events.sort(key=lambda item: item[0])

    def ip_at(moment):
        current_ip = fallback_ip or "-"
        for event_time, event_ip in ip_events:
            if event_time <= moment:
                current_ip = event_ip or current_ip
            else:
                break
        return current_ip or "-"

    def append_segment(segments, start, end, state, ip=None):
        if not start or not end or end <= start:
            return
        duration_minutes = max(1, int(round((end - start).total_seconds() / 60)))
        segments.append({
            "start": to_kyiv_time(start),
            "end": to_kyiv_time(end),
            "start_ms": datetime_to_epoch_ms(start),
            "end_ms": datetime_to_epoch_ms(end),
            "state": state,
            "ip": ip or "-",
            "duration_minutes": duration_minutes,
        })

    def append_online_with_ip_splits(segments, start, end):
        boundaries = [start]
        for event_time, _event_ip in ip_events:
            if start < event_time < end:
                boundaries.append(event_time)
        boundaries.append(end)
        boundaries = sorted(set(boundaries))
        for index in range(1, len(boundaries)):
            piece_start = boundaries[index - 1]
            piece_end = boundaries[index]
            append_segment(segments, piece_start, piece_end, "online", ip_at(piece_start))

    segments = []
    cluster_start = records[0].timestamp
    cluster_last = records[0].timestamp
    for record in records[1:]:
        gap = (record.timestamp - cluster_last).total_seconds()
        if gap > offline_gap_seconds:
            online_end = min(cluster_last + timedelta(seconds=expected_gap_seconds), record.timestamp)
            append_online_with_ip_splits(segments, cluster_start, online_end)
            append_segment(segments, online_end, record.timestamp, "offline")
            cluster_start = record.timestamp
        cluster_last = record.timestamp

    final_online_end = min(cluster_last + timedelta(seconds=expected_gap_seconds), end_time)
    append_online_with_ip_splits(segments, cluster_start, final_online_end)
    if final_online_end < end_time:
        append_segment(segments, final_online_end, end_time, "offline")
    return segments

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/telemetry', methods=['GET'])
def get_host_telemetry(host_id):
    denied = require_permission("view_hosts")
    if denied: return denied
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id): return jsonify({"success": False}), 403
    days = int(request.args.get('days', 1))
    threshold = datetime.utcnow() - timedelta(days=days)
    raw_records = TelemetryHistory.query.filter(TelemetryHistory.endpoint_id == host_id, TelemetryHistory.timestamp >= threshold).order_by(TelemetryHistory.timestamp.asc()).all()
    agent = Endpoint.query.get(host_id)
    activity_segments = build_activity_segments(host_id, raw_records, threshold, datetime.utcnow(), getattr(agent, "ip_address", "") if agent else "")
    records = raw_records
    if len(records) > 100: records = records[::max(1, len(records) // 100)]
    return jsonify({"success": True, "data": [{
        "time": to_kyiv_time_short(r.timestamp),
        "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else None,
        "cpu": r.cpu_usage,
        "ram": r.ram_usage,
        "disk": r.disk_c_free
    } for r in records], "activity_segments": activity_segments})

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
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id, "manage_hosts"):
        return jsonify({"success": False, "message": "Host action is outside your group scope"}), 403
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

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/allow-reenroll', methods=['POST'])
def allow_host_reenroll(host_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    agent = Endpoint.query.get(host_id)
    if not agent:
        return jsonify({"success": False, "message": "Host not found"}), 404
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id, "manage_hosts"):
        return jsonify({"success": False, "message": "Host denied"}), 403

    minutes = 30
    try:
        requested = int((request.json or {}).get("minutes", minutes))
        minutes = max(5, min(240, requested))
    except Exception:
        pass
    allowed_until = datetime.utcnow() + timedelta(minutes=minutes)
    agent.reenroll_allowed_until = allowed_until
    db.session.add(RegistrationHistory(
        hw_id=agent.id,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        event_type="Re-enroll Allowed"
    ))
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Allow Host Re-enroll",
        details={"host_id": agent.id, "hostname": agent.hostname, "minutes": minutes, "allowed_until": allowed_until.isoformat()},
        status="Success"
    )
    return jsonify({"success": True, "reenroll_allowed_until": to_kyiv_time(allowed_until)})

@infrastructure_bp.route('/api/infrastructure/host/<host_id>/approval', methods=['POST'])
def update_host_approval(host_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    agent = Endpoint.query.get(host_id)
    if not agent:
        return jsonify({"success": False, "message": "Host not found"}), 404
    if not WinHubCore.can_manage_host(session.get('user_id'), host_id, "manage_hosts"):
        return jsonify({"success": False, "message": "Host action is outside your group scope"}), 403
    status = (request.json or {}).get("status")
    if status not in ("Pending", "Approved", "Rejected"):
        return jsonify({"success": False, "message": "Invalid approval status"}), 400
    agent.approval_status = status
    if status == "Rejected":
        agent.is_blocked = True
    elif status == "Approved":
        allow_hostname_duplicate_pairs_for_approved_agent(agent, session.get("username"))
        agent.identity_warning = None
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
    allowed_host_ids = set(infra_allowed_host_ids(session.get("user_id"), "manage_hosts"))
    if any(agent.id not in allowed_host_ids for agent in agents):
        return jsonify({"success": False, "message": "One or more hosts are outside your group scope"}), 403

    ensure_default_groups_and_assign = None
    if status == "Approved":
        from core.agent_gateway import ensure_default_groups_and_assign as assign_defaults
        ensure_default_groups_and_assign = assign_defaults

    for agent in agents:
        agent.approval_status = status
        if status == "Rejected":
            agent.is_blocked = True
        elif status == "Approved":
            allow_hostname_duplicate_pairs_for_approved_agent(agent, session.get("username"))
            agent.identity_warning = None
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
    if not WinHubCore.can_manage_host(session.get("user_id"), keep_id, "manage_hosts") or not WinHubCore.can_manage_host(session.get("user_id"), remove_id, "manage_hosts"):
        return jsonify({"success": False, "message": "Access denied"}), 403

    allowed_hosts = WinHubCore.get_allowed_hosts(session.get("user_id"), "manage_hosts")
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

@infrastructure_bp.route('/api/infrastructure/host/duplicate-exception', methods=['POST'])
def create_duplicate_exception():
    denied = require_permission("manage_hosts")
    if denied:
        return denied
    payload = request.json or {}
    left_id = str(payload.get("left_id") or "").strip()
    right_id = str(payload.get("right_id") or "").strip()
    pair_key = endpoint_pair_key(left_id, right_id)
    if not pair_key:
        return jsonify({"success": False, "message": "Select two different endpoint records"}), 400

    left = Endpoint.query.get(pair_key[0])
    right = Endpoint.query.get(pair_key[1])
    if not left or not right:
        return jsonify({"success": False, "message": "Endpoint record not found"}), 404
    if not WinHubCore.can_manage_host(session.get("user_id"), left.id, "manage_hosts") or not WinHubCore.can_manage_host(session.get("user_id"), right.id, "manage_hosts"):
        return jsonify({"success": False, "message": "Access denied"}), 403

    existing = EndpointDuplicateException.query.filter_by(endpoint_a_id=pair_key[0], endpoint_b_id=pair_key[1]).first()
    if not existing:
        existing = EndpointDuplicateException(
            endpoint_a_id=pair_key[0],
            endpoint_b_id=pair_key[1],
            reason=str(payload.get("reason") or "Accepted as distinct endpoints")[:255],
            created_by=session.get("username"),
        )
        db.session.add(existing)
    left.identity_duplicate_allowed = True
    right.identity_duplicate_allowed = True
    left.identity_warning = None
    right.identity_warning = None
    db.session.commit()

    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Accept Endpoint Duplicate Pair",
        details={
            "endpoint_a_id": pair_key[0],
            "endpoint_b_id": pair_key[1],
            "reason": existing.reason,
        },
        status="Success"
    )
    return jsonify({"success": True, "endpoint_a_id": pair_key[0], "endpoint_b_id": pair_key[1]})

@infrastructure_bp.route('/api/infrastructure/group', methods=['POST'])
def create_group():
    denied = require_permission("manage_groups")
    if denied: return denied
    data = request.get_json(silent=True) or {}
    group = EndpointGroup(name=data.get('name', 'Untitled'), description=data.get('description', ''))
    db.session.add(group)
    user = current_user()
    if user and not user.is_admin and not session.get("api_key_auth"):
        user.allowed_host_groups.append(group)
    db.session.flush()
    write_infra_audit("Create Group", "endpoint_group", group.id, {"name": group.name})
    db.session.commit()
    return jsonify({"success": True, "id": group.id})

@infrastructure_bp.route('/api/infrastructure/group/<group_id>', methods=['GET', 'DELETE'])
def manage_group(group_id):
    group = EndpointGroup.query.get(group_id)
    if not group:
        return jsonify({"success": False}), 404
    if request.method == 'DELETE':
        denied = require_permission("delete_groups")
        if denied: return denied
        if group.id not in set(infra_allowed_group_ids(session.get('user_id'), "delete_groups")):
            return jsonify({"success": False, "message": "Group is outside your assigned scope"}), 403
        member_count = db.session.query(func.count()).select_from(endpoint_group_m2m).filter(
            endpoint_group_m2m.c.group_id == group.id
        ).scalar() or 0
        write_infra_audit(
            "Delete Group",
            "endpoint_group",
            group.id,
            {"name": group.name, "member_count": member_count},
        )
        db.session.delete(group); db.session.commit()
        return jsonify({"success": True})

    denied = require_permission("view_groups")
    if denied: return denied
    include_non_members = request.args.get("include_non_members") == "1"
    base_member_query = Endpoint.query.options(
        load_only(*ENDPOINT_LIST_COLUMNS),
        selectinload(Endpoint.groups).load_only(EndpointGroup.id, EndpointGroup.name),
    ).join(Endpoint.groups).filter(EndpointGroup.id == group.id)
    if not session.get('is_admin'):
        allowed_group_ids = set(infra_allowed_group_ids(session.get('user_id'), "view_groups"))
        if group.id not in allowed_group_ids:
            return jsonify({"success": False}), 403
        allowed_host_ids = set(infra_allowed_host_ids(session.get('user_id')))
        members_source = attach_endpoint_list_flags(base_member_query.filter(Endpoint.id.in_(allowed_host_ids)).all())
        group_endpoint_ids = {
            row[0]
            for row in db.session.query(Endpoint.id)
            .join(Endpoint.groups)
            .filter(EndpointGroup.id == group.id)
            .all()
        }
        if include_non_members and can("manage_groups") and group_action_allowed(current_user(), group.id, "manage_groups"):
            non_member_query = Endpoint.query.options(load_only(*ENDPOINT_LIST_COLUMNS)).filter(
                Endpoint.id.in_(allowed_host_ids),
                db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None)),
                ~Endpoint.id.in_(group_endpoint_ids)
            ).order_by(Endpoint.hostname, Endpoint.id)
            non_members = [{"id": a.id, "hostname": a.hostname or a.id, "display_name": getattr(a, "display_name", None) or "", "name": endpoint_display_name(a)} for a in non_member_query.all()]
        else:
            non_members = []
    else:
        group_endpoint_ids = {
            row[0]
            for row in db.session.query(Endpoint.id)
            .join(Endpoint.groups)
            .filter(EndpointGroup.id == group.id)
            .all()
        }
        members_source = attach_endpoint_list_flags(base_member_query.all())
        if include_non_members:
            non_members = [
                {"id": a.id, "hostname": a.hostname or a.id, "display_name": getattr(a, "display_name", None) or "", "name": endpoint_display_name(a)}
                for a in Endpoint.query.options(load_only(*ENDPOINT_LIST_COLUMNS)).filter(
                    db.or_(Endpoint.approval_status == "Approved", Endpoint.approval_status.is_(None)),
                    ~Endpoint.id.in_(group_endpoint_ids),
                ).order_by(Endpoint.hostname, Endpoint.id).all()
            ]
        else:
            non_members = []

    members = [{"id": a.id, "hostname": a.hostname or a.id, "display_name": getattr(a, "display_name", None) or "", "name": endpoint_display_name(a), "ip": getattr(a, "connection_ip", None) or "", "os_type": getattr(a, 'os_type', 'Windows')} for a in members_source]
    user = current_user()
    capabilities = {
        action_id: bool(can(action_id) and group_action_allowed(user, group.id, action_id))
        for action_id in ("manage_hosts", "manage_groups", "delete_groups")
    }
    return jsonify({
        "success": True,
        "data": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "members": members,
            "non_members": non_members,
            "capabilities": capabilities,
        },
    })

@infrastructure_bp.route('/api/infrastructure/group/<group_id>/members', methods=['POST'])
def update_group_members(group_id):
    denied = require_permission("manage_groups")
    if denied: return denied
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if action not in {'add', 'remove'}:
        return jsonify({"success": False, "message": "Action must be add or remove"}), 400
    group = EndpointGroup.query.get(group_id)
    agent = Endpoint.query.get(data.get('agent_id'))
    if not group or not agent:
        return jsonify({"success": False, "message": "Group or host not found"}), 404
    if not session.get('is_admin'):
        allowed_group_ids = set(infra_allowed_group_ids(session.get('user_id'), "manage_groups"))
        if group.id not in allowed_group_ids:
            return jsonify({"success": False, "message": "Group denied"}), 403
        if agent.id not in set(infra_allowed_host_ids(session.get('user_id'))):
            return jsonify({"success": False, "message": "Host is outside your assigned scope"}), 403
        if (getattr(agent, "approval_status", "Approved") or "Approved") != "Approved":
            return jsonify({"success": False, "message": "Only approved hosts can be added to groups"}), 403
    if action == 'add' and agent not in group.endpoints: group.endpoints.append(agent)
    elif action == 'remove' and agent in group.endpoints: group.endpoints.remove(agent)
    db.session.commit()
    WinHubCore.audit(
        user_id=session.get("user_id"),
        module="Infrastructure",
        action="Group Membership",
        details={"group_id": group.id, "group": group.name, "host_id": agent.id, "hostname": agent.hostname, "action": action},
        status="Success"
    )
    return jsonify({"success": True})

@infrastructure_bp.route('/api/infrastructure/group/<group_id>/block', methods=['POST'])
def block_group_hosts(group_id):
    denied = require_permission("manage_hosts")
    if denied: return denied
    group = EndpointGroup.query.get(group_id)
    if not group:
        return jsonify({"success": False, "message": "Group not found"}), 404
    if group.id not in set(infra_allowed_group_ids(session.get('user_id'), "manage_hosts")):
        return jsonify({"success": False, "message": "Group is outside your assigned scope"}), 403
    action = (request.get_json(silent=True) or {}).get('action')
    if action not in {'block', 'unblock'}:
        return jsonify({"success": False, "message": "Action must be block or unblock"}), 400
    member_ids = db.session.query(endpoint_group_m2m.c.endpoint_id).filter(
        endpoint_group_m2m.c.group_id == group.id
    )
    updated = Endpoint.query.filter(Endpoint.id.in_(member_ids)).update(
        {"is_blocked": action == 'block'},
        synchronize_session=False,
    )
    write_infra_audit(
        "Block Group Hosts" if action == "block" else "Unblock Group Hosts",
        "endpoint_group",
        group.id,
        {"updated_hosts": updated},
    )
    db.session.commit()
    return jsonify({"success": True, "updated": updated})
