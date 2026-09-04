import os
import json
import secrets
import logging
import hmac
import hashlib
import ipaddress
import base64
import time
from datetime import datetime
from functools import lru_cache
from threading import Lock
from flask import Blueprint, request, jsonify
from sqlalchemy.orm import load_only
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core.database import db, Endpoint, AgentTask, RegistrationHistory, TelemetryHistory, ConnectionIpHistory, EndpointGroup, EndpointMetric, TriggerRule, User, TaskTemplate, ScheduledTask
from core.security import sec_manager
from core.host_security import apply_endpoint_encryption_status
from core.sdk import WinHubCore
from core.config import Config

agent_gateway_bp = Blueprint('agent_gateway', __name__, url_prefix='/api/agent')
log = logging.getLogger("winhub.triggers")

GLOBAL_ENROLLMENT_TOKEN = Config.AGENT_API_KEY
POLL_SIGNATURE_CACHE_TTL_SECONDS = 120
PENDING_TASK_MISS_CACHE_TTL_SECONDS = int(getattr(Config, "AGENT_PENDING_TASK_MISS_CACHE_SECONDS", 10))
AGENT_SIGNATURE_NONCE_TTL_SECONDS = max(900, int(getattr(Config, "AGENT_SIGNATURE_MAX_SKEW_SECONDS", 900) or 900))
AGENT_SIGNATURE_FIELDS = {"body_hash", "signed_at", "signed_nonce", "signature"}
poll_signature_cache = {}
poll_signature_cache_lock = Lock()
agent_signature_nonce_cache = {}
agent_signature_nonce_cache_lock = Lock()
pending_task_miss_cache = {}
pending_task_miss_cache_lock = Lock()

def update_scheduled_task_completion_status(job_id):
    scheduled_task = ScheduledTask.query.filter_by(last_job_id=job_id).first()
    if not scheduled_task:
        return
    total = AgentTask.query.filter_by(job_id=job_id).count()
    success = AgentTask.query.filter_by(job_id=job_id, status="Success").count()
    errors = AgentTask.query.filter(
        AgentTask.job_id == job_id,
        AgentTask.status.in_(["Error", "Cancelled"])
    ).count()
    scheduled_task.last_status = f"Completed: {success}/{total} success, {errors} failed"


POLL_AGENT_COLUMNS = (
    Endpoint.id,
    Endpoint.hostname,
    Endpoint.auth_token,
    Endpoint.is_blocked,
    Endpoint.approval_status,
    Endpoint.public_key_pem_plain,
    Endpoint.task_signing_private_key,
    Endpoint.task_signing_public_key,
    Endpoint.task_signing_key_id,
    Endpoint.task_signing_sequence,
    Endpoint.task_signature_v2_seen_at,
    Endpoint.connection_ip,
    Endpoint.last_seen,
    Endpoint.agent_version,
)

REQUEST_AGENT_COLUMNS = POLL_AGENT_COLUMNS

TASK_DELIVERY_COLUMNS = (
    AgentTask.id,
    AgentTask.job_id,
    AgentTask.endpoint_id,
    AgentTask.action_type,
    AgentTask.payload,
    AgentTask.status,
    AgentTask.created_at,
)

TASK_RESULT_COLUMNS = (
    AgentTask.id,
    AgentTask.job_id,
    AgentTask.endpoint_id,
    AgentTask.title,
    AgentTask.payload,
    AgentTask.status,
    AgentTask.created_at,
    AgentTask.finished_at,
)


def get_poll_agent(hw_id):
    if not hw_id:
        return None
    return Endpoint.query.options(load_only(*POLL_AGENT_COLUMNS)).filter(Endpoint.id == hw_id).first()


def get_request_agent(hw_id):
    if not hw_id:
        return None
    return Endpoint.query.options(load_only(*REQUEST_AGENT_COLUMNS)).filter(Endpoint.id == hw_id).first()

def current_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or ""


def update_agent_connection(agent):
    current_ip = current_client_ip()
    changed = False
    if current_ip and current_ip != (getattr(agent, "connection_ip", None) or ""):
        agent.connection_ip = current_ip
        db.session.add(ConnectionIpHistory(endpoint_id=agent.id, ip_address=current_ip, source="agent"))
        agent.ip_address = current_ip
        changed = True
    return changed


def agent_poll_timing(mode="idle"):
    if mode == "task":
        next_poll_after = int(getattr(Config, "AGENT_TASK_POLL_SECONDS", 15))
    elif mode == "pending":
        next_poll_after = int(getattr(Config, "AGENT_PENDING_POLL_SECONDS", 60))
    else:
        next_poll_after = int(getattr(Config, "AGENT_IDLE_POLL_SECONDS", 75))

    return {
        "next_poll_after": max(10, min(3600, next_poll_after)),
        "poll_jitter_seconds": max(0, min(3600, int(getattr(Config, "AGENT_POLL_JITTER_SECONDS", 30)))),
        "telemetry_after": max(60, min(86400, int(getattr(Config, "AGENT_TELEMETRY_SECONDS", 300)))),
    }

def enrollment_source_allowed(remote_addr):
    allowlist = [item.strip() for item in str(getattr(Config, "AGENT_ENROLLMENT_ALLOWLIST", "") or "").split(",") if item.strip()]
    if not allowlist:
        return True
    try:
        remote_ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if "/" in item:
                if remote_ip in ipaddress.ip_network(item, strict=False):
                    return True
            elif remote_ip == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def sign_task_message(task_id, action, payload):
    body = json.dumps({
        "task_id": task_id,
        "action": action,
        "payload": payload,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    secret = str(Config.AGENT_TASK_HMAC_SECRET or Config.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_task_payload(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def ensure_endpoint_task_signing_key(agent):
    private_pem = str(getattr(agent, "task_signing_private_key", "") or "").strip()
    public_pem = str(getattr(agent, "task_signing_public_key", "") or "").strip()
    key_id = str(getattr(agent, "task_signing_key_id", "") or "").strip()
    if private_pem and public_pem and key_id:
        return private_pem, public_pem, key_id

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(public_der).hexdigest()
    agent.task_signing_private_key = private_pem
    agent.task_signing_public_key = public_pem
    agent.task_signing_key_id = key_id
    agent.task_signing_sequence = int(getattr(agent, "task_signing_sequence", 0) or 0)
    return private_pem, public_pem, key_id


def sign_task_message_v2(agent, task_id, action, payload, timeout_seconds):
    # Serialize sequence allocation on PostgreSQL so concurrent polls cannot
    # receive the same anti-replay sequence.
    try:
        db.session.refresh(agent, with_for_update=True)
    except TypeError:
        db.session.refresh(agent)
    private_pem, public_pem, key_id = ensure_endpoint_task_signing_key(agent)
    issued_at = int(time.time())
    sequence = int(getattr(agent, "task_signing_sequence", 0) or 0) + 1
    agent.task_signing_sequence = sequence
    fields = {
        "action": str(action or ""),
        "endpoint_id": str(agent.id),
        "expires_at": issued_at + max(120, min(int(timeout_seconds or 1800) + 300, 86400)),
        "issued_at": issued_at,
        "key_id": key_id,
        "payload_hash": hashlib.sha256(canonical_task_payload(payload).encode("utf-8")).hexdigest(),
        "protocol_version": 2,
        "sequence": sequence,
        "task_id": str(task_id),
        "timeout_seconds": int(timeout_seconds or 1800),
    }
    canonical = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    private_key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    signature = private_key.sign(
        canonical.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return {
        "fields": fields,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signature_alg": "rsa-pss-sha256",
        "public_key_pem": public_pem,
    }


@lru_cache(maxsize=2048)
def load_agent_public_key(public_key_pem):
    return serialization.load_pem_public_key(str(public_key_pem or "").encode("utf-8"))


@lru_cache(maxsize=2048)
def agent_key_fingerprint_cached(public_key_pem):
    public_key = load_agent_public_key(public_key_pem)
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def agent_key_fingerprint(public_key_pem):
    try:
        return agent_key_fingerprint_cached(str(public_key_pem or ""))
    except Exception:
        return ""


def get_agent_public_key(agent):
    public_key = str(getattr(agent, "public_key_pem_plain", None) or "").strip()
    if public_key:
        return public_key

    public_key = str(getattr(agent, "public_key_pem", None) or "").strip()
    if public_key:
        agent.public_key_pem_plain = public_key
        setattr(agent, "_public_key_plain_backfilled", True)
    return public_key


def set_agent_public_key(agent, public_key):
    public_key = str(public_key or "").strip()
    agent.public_key_pem = public_key
    agent.public_key_pem_plain = public_key
    setattr(agent, "_public_key_plain_backfilled", False)


def canonical_agent_signature_message(path, hw_id, auth_token, agent_version, body_hash, signed_at, nonce):
    return "\n".join([
        str(path or ""),
        str(hw_id or ""),
        str(auth_token or ""),
        str(agent_version or ""),
        str(body_hash or ""),
        str(signed_at or ""),
        str(nonce or ""),
    ])


def canonical_agent_request_body(data):
    body = {
        key: value
        for key, value in (data or {}).items()
        if key not in AGENT_SIGNATURE_FIELDS
    }
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def agent_request_body_hash(data):
    return hashlib.sha256(canonical_agent_request_body(data).encode("utf-8")).hexdigest()


def remember_agent_signature_nonce(path, data):
    nonce = str(data.get("signed_nonce") or "").strip()
    hw_id = str(data.get("hw_id") or "").strip()
    signed_at = str(data.get("signed_at") or "").strip()
    if not nonce or not hw_id or not signed_at:
        return False

    key = (str(path or ""), hw_id, nonce)
    now = time.monotonic()
    with agent_signature_nonce_cache_lock:
        if key in agent_signature_nonce_cache:
            return False
        agent_signature_nonce_cache[key] = now
        if len(agent_signature_nonce_cache) > 8192:
            cutoff = now - (AGENT_SIGNATURE_NONCE_TTL_SECONDS * 2)
            stale_keys = [cache_key for cache_key, timestamp in agent_signature_nonce_cache.items() if timestamp < cutoff]
            for cache_key in stale_keys:
                agent_signature_nonce_cache.pop(cache_key, None)
    return True


def verify_agent_signature(public_key_pem, data, path, auth_token, agent_version_override=None):
    signature = str(data.get("signature") or "").strip()
    signed_at = str(data.get("signed_at") or "").strip()
    nonce = str(data.get("signed_nonce") or "").strip()
    body_hash = str(data.get("body_hash") or "").strip().lower()
    allow_legacy_signature = bool(getattr(Config, "AGENT_ALLOW_LEGACY_AGENT_SIGNATURES", False))
    if not signature or not signed_at or not nonce:
        return False, "missing_signature"
    if not body_hash:
        if allow_legacy_signature:
            body_hash = ""
        else:
            return False, "missing_body_hash"
    if body_hash:
        expected_body_hash = agent_request_body_hash(data)
        if not hmac.compare_digest(body_hash, expected_body_hash):
            return False, "body_hash_mismatch"
    try:
        signed_ts = int(signed_at)
        max_skew_seconds = int(getattr(Config, "AGENT_SIGNATURE_MAX_SKEW_SECONDS", 0) or 0)
        if max_skew_seconds > 0 and abs(int(time.time()) - signed_ts) > max_skew_seconds:
            return False, "signature_expired"
    except Exception:
        return False, "invalid_signature_timestamp"
    try:
        public_key = load_agent_public_key(str(public_key_pem or ""))
        message = canonical_agent_signature_message(
            path,
            data.get("hw_id"),
            auth_token,
            agent_version_override if agent_version_override is not None else data.get("agent_version"),
            body_hash,
            signed_at,
            nonce,
        )
        public_key.verify(
            base64.b64decode(signature),
            message.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        if not remember_agent_signature_nonce(path, data):
            return False, "replayed_signature_nonce"
        return True, "ok"
    except InvalidSignature:
        return False, "invalid_signature"
    except Exception:
        return False, "invalid_public_key_or_signature"


def agent_request_signature_timestamp_valid(data):
    if not data.get("signature") or not data.get("signed_at") or not data.get("signed_nonce"):
        return False
    try:
        max_skew_seconds = int(getattr(Config, "AGENT_SIGNATURE_MAX_SKEW_SECONDS", 0) or 0)
        if max_skew_seconds <= 0:
            return True
        signed_ts = int(str(data.get("signed_at") or "").strip())
        return abs(int(time.time()) - signed_ts) <= max_skew_seconds
    except Exception:
        return False


def agent_signature_timestamp_debug(data):
    try:
        signed_ts = int(str(data.get("signed_at") or "").strip())
        server_ts = int(time.time())
        return {
            "server_time": server_ts,
            "signed_at": signed_ts,
            "skew_seconds": server_ts - signed_ts,
        }
    except Exception:
        return {"server_time": int(time.time())}


def agent_signature_error_payload(reason, data):
    payload = {"status": "error", "message": reason}
    if reason in {"signature_expired", "invalid_signature_timestamp"}:
        payload.update(agent_signature_timestamp_debug(data))
    return payload


def poll_signature_cache_key(agent, data, auth_token):
    return (
        str(agent.id or ""),
        hashlib.sha256(str(auth_token or "").encode("utf-8")).hexdigest()[:16],
        str(data.get("agent_version") or "").strip()[:50],
    )


def remember_poll_signature(agent, data, auth_token):
    key = poll_signature_cache_key(agent, data, auth_token)
    now = time.monotonic()
    with poll_signature_cache_lock:
        poll_signature_cache[key] = now
        if len(poll_signature_cache) > 4096:
            cutoff = now - (POLL_SIGNATURE_CACHE_TTL_SECONDS * 3)
            stale_keys = [cache_key for cache_key, timestamp in poll_signature_cache.items() if timestamp < cutoff]
            for cache_key in stale_keys:
                poll_signature_cache.pop(cache_key, None)


def verify_poll_signature_cached(agent, data, auth_token):
    ok, reason = verify_or_bind_agent_key(agent, data, "/api/agent/poll", auth_token)
    if ok:
        remember_poll_signature(agent, data, auth_token)
    return ok, reason


def get_pending_task_for_agent(endpoint_id):
    now = time.monotonic()
    with pending_task_miss_cache_lock:
        missed_at = pending_task_miss_cache.get(endpoint_id)
    if missed_at and now - missed_at <= PENDING_TASK_MISS_CACHE_TTL_SECONDS:
        return None

    task = AgentTask.query.options(load_only(*TASK_DELIVERY_COLUMNS)).filter_by(
        endpoint_id=endpoint_id,
        status="Pending",
    ).order_by(AgentTask.created_at.asc()).with_for_update(skip_locked=True).first()
    with pending_task_miss_cache_lock:
        if task:
            pending_task_miss_cache.pop(endpoint_id, None)
        else:
            pending_task_miss_cache[endpoint_id] = now
            if len(pending_task_miss_cache) > 4096:
                cutoff = now - (PENDING_TASK_MISS_CACHE_TTL_SECONDS * 6)
                stale_keys = [cache_key for cache_key, timestamp in pending_task_miss_cache.items() if timestamp < cutoff]
                for cache_key in stale_keys:
                    pending_task_miss_cache.pop(cache_key, None)
    return task


def bind_enrollment_public_key(agent, data):
    provided_key = str(data.get("agent_public_key_pem") or "").strip()
    provided_fingerprint = str(data.get("agent_key_fingerprint") or "").strip().lower()
    if not provided_key:
        return
    calculated_fingerprint = agent_key_fingerprint(provided_key)
    if not calculated_fingerprint:
        agent.identity_warning = "Agent provided an invalid public identity key."
        return
    if provided_fingerprint and provided_fingerprint != calculated_fingerprint:
        agent.identity_warning = "Agent public key fingerprint did not match the provided key."
        return
    signature_ok, signature_reason = verify_agent_signature(
        provided_key,
        data,
        "/api/agent/enroll",
        data.get("previous_auth_token") or "",
    )
    if not signature_ok:
        agent.identity_warning = f"Agent public key proof failed during enrollment: {signature_reason}."
        return
    stored_key = get_agent_public_key(agent)
    if not stored_key:
        set_agent_public_key(agent, provided_key)
    elif stored_key != provided_key:
        agent.identity_warning = "Agent public identity key changed. Review endpoint identity before trusting this host."


def verify_or_bind_agent_key(agent, data, path, auth_token):
    provided_key = str(data.get("agent_public_key_pem") or "").strip()
    stored_key = get_agent_public_key(agent)
    candidate_key = stored_key or provided_key
    has_signature_fields = bool(data.get("signature") or data.get("signed_at") or data.get("signed_nonce"))
    if not candidate_key:
        return not getattr(Config, "AGENT_REQUIRE_SIGNED_REQUESTS", False), "missing_public_key"

    ok, reason = verify_agent_signature(candidate_key, data, path, auth_token)
    if not ok:
        if path == "/api/agent/result" and not data.get("agent_version") and getattr(agent, "agent_version", None):
            ok, reason = verify_agent_signature(candidate_key, data, path, auth_token, getattr(agent, "agent_version", ""))
            if ok:
                if not stored_key and provided_key:
                    set_agent_public_key(agent, provided_key)
                    db.session.add(RegistrationHistory(
                        hw_id=agent.id,
                        hostname=agent.hostname,
                        ip_address=current_client_ip(),
                        event_type="Agent Identity Key Enrolled",
                    ))
                return True, "ok"
        if stored_key and has_signature_fields:
            return False, reason
        return not getattr(Config, "AGENT_REQUIRE_SIGNED_REQUESTS", False), reason

    if not stored_key and provided_key:
        set_agent_public_key(agent, provided_key)
        db.session.add(RegistrationHistory(
            hw_id=agent.id,
            hostname=agent.hostname,
            ip_address=current_client_ip(),
            event_type="Agent Identity Key Enrolled",
        ))
    elif stored_key and provided_key and agent_key_fingerprint(stored_key) != agent_key_fingerprint(provided_key):
        agent.identity_warning = "Agent request was signed by the stored key but advertised a different public key."

    return True, "ok"


def host_domain_identity(host_info):
    if not isinstance(host_info, dict):
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
    if not domain:
        domain = "WORKGROUP"
    return domain.upper()


def agent_identity_fingerprint(hw_id, hostname, os_type, network_interfaces, host_info=None):
    macs = []
    if isinstance(network_interfaces, list):
        for item in network_interfaces:
            if isinstance(item, dict):
                mac = str(item.get("mac") or "").strip().upper()
                if mac:
                    macs.append(mac)
    source = json.dumps({
        "hostname": str(hostname or "").strip().upper(),
        "domain": host_domain_identity(host_info),
        "os_type": os_type,
        "macs": sorted(set(macs)),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def agent_version_tuple(value):
    parts = []
    for part in str(value or "").strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        parts.append(int(digits or 0))
        if len(parts) >= 4:
            break
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def endpoint_stable_identity_fingerprint(endpoint):
    try:
        network_interfaces = json.loads(endpoint.network_info or "[]")
        if not isinstance(network_interfaces, list):
            network_interfaces = []
    except Exception:
        network_interfaces = []
    try:
        host_info = json.loads(endpoint.host_info or "{}")
        if not isinstance(host_info, dict):
            host_info = {}
    except Exception:
        host_info = {}
    return agent_identity_fingerprint(
        None,
        endpoint.hostname,
        endpoint.os_type or "Windows",
        network_interfaces,
        host_info,
    )


def find_approved_duplicate_endpoint(hw_id, hostname, source_ip, fingerprint):
    fingerprints = set()
    if isinstance(fingerprint, (list, tuple, set)):
        fingerprints.update(str(item).strip() for item in fingerprint if item)
    elif fingerprint:
        fingerprints.add(str(fingerprint).strip())
    fingerprints.discard("")

    approved = Endpoint.query.filter(
        Endpoint.id != hw_id,
        Endpoint.approval_status == "Approved"
    ).all()
    for endpoint in approved:
        reasons = []
        if hostname and endpoint.hostname and hostname == endpoint.hostname:
            reasons.append("hostname")
        endpoint_fingerprints = {
            getattr(endpoint, "identity_fingerprint", None),
            endpoint_stable_identity_fingerprint(endpoint),
        }
        endpoint_fingerprints.discard(None)
        endpoint_fingerprints.discard("")
        if fingerprints and fingerprints.intersection(endpoint_fingerprints):
            reasons.append("identity")
        if "identity" in reasons:
            return endpoint, reasons
    return None, []


def find_approved_hostname_stale_endpoint(hw_id, hostname, agent_version):
    hostname_key = str(hostname or "").strip().upper()
    if not hostname_key:
        return None, []
    incoming_version = agent_version_tuple(agent_version)
    approved = Endpoint.query.filter(
        Endpoint.id != hw_id,
        Endpoint.approval_status == "Approved",
    ).all()
    newest_match = None
    newest_version = (0, 0, 0, 0)
    for endpoint in approved:
        if str(endpoint.hostname or "").strip().upper() != hostname_key:
            continue
        endpoint_version = agent_version_tuple(getattr(endpoint, "agent_version", "") or "")
        if newest_match is None or endpoint_version > newest_version:
            newest_match = endpoint
            newest_version = endpoint_version
    if newest_match and newest_version >= incoming_version:
        return newest_match, ["hostname", "stale_agent_version"]
    return None, []


def find_approved_endpoint_by_previous_token(previous_auth_token, previous_hw_id=None):
    previous_auth_token = str(previous_auth_token or "").strip()
    previous_hw_id = str(previous_hw_id or "").strip()
    if not previous_auth_token:
        return None, []

    if previous_hw_id:
        endpoint = Endpoint.query.get(previous_hw_id)
        if (
            endpoint
            and getattr(endpoint, "approval_status", "Approved") == "Approved"
            and endpoint.auth_token == previous_auth_token
        ):
            return endpoint, ["token_proof"]

    endpoint = Endpoint.query.filter_by(
        auth_token=previous_auth_token,
        approval_status="Approved"
    ).first()
    if endpoint:
        return endpoint, ["token_proof"]
    return None, []


def should_adopt_duplicate_enrollment(reasons):
    reason_set = set(reasons or [])
    return "identity" in reason_set or "token_proof" in reason_set


def duplicate_enrollment_requires_rejection(reasons):
    reason_set = set(reasons or [])
    return bool(reason_set.intersection({"identity", "token_proof"}))


def duplicate_enrollment_review_status(reasons):
    return "Rejected" if duplicate_enrollment_requires_rejection(reasons) else "Pending"


def endpoint_reenroll_allowed(agent):
    allowed_until = getattr(agent, "reenroll_allowed_until", None)
    if not allowed_until:
        return False
    if getattr(allowed_until, "tzinfo", None):
        allowed_until = allowed_until.replace(tzinfo=None)
    return allowed_until >= datetime.utcnow()


def adopt_duplicate_endpoint_identity(existing_endpoint, new_hw_id, raw_token, data, source_ip, fingerprint, network_info, host_info, agent_version):
    old_id = existing_endpoint.id
    groups = list(existing_endpoint.groups)
    inherited_ip = source_ip or getattr(existing_endpoint, "connection_ip", None) or existing_endpoint.ip_address
    inherited_public_key = get_agent_public_key(existing_endpoint)
    adopted = Endpoint(
        id=new_hw_id,
        hostname=data.get("hostname", existing_endpoint.hostname),
        auth_token=raw_token,
        public_key_pem=inherited_public_key,
        public_key_pem_plain=inherited_public_key,
        task_signing_private_key=getattr(existing_endpoint, "task_signing_private_key", None),
        task_signing_public_key=getattr(existing_endpoint, "task_signing_public_key", None),
        task_signing_key_id=getattr(existing_endpoint, "task_signing_key_id", None),
        task_signing_sequence=int(getattr(existing_endpoint, "task_signing_sequence", 0) or 0),
        task_signature_v2_seen_at=getattr(existing_endpoint, "task_signature_v2_seen_at", None),
        os_version=data.get("os_version", existing_endpoint.os_version),
        os_type=data.get("os_type", existing_endpoint.os_type or "Windows"),
        connection_ip=inherited_ip,
        ip_address=inherited_ip,
        approval_status="Approved",
        agent_version=agent_version or existing_endpoint.agent_version,
        network_info=network_info,
        host_info=host_info,
        first_seen=existing_endpoint.first_seen,
        last_enrollment_at=datetime.utcnow(),
        last_enrollment_ip=source_ip,
        enrollment_attempts=int(existing_endpoint.enrollment_attempts or 0) + 1,
        identity_fingerprint=fingerprint,
        identity_warning=None,
        last_seen=datetime.utcnow(),
        is_blocked=bool(existing_endpoint.is_blocked),
    )
    apply_endpoint_encryption_status(adopted, host_info)
    adopted.groups = groups
    db.session.add(adopted)
    db.session.flush()

    AgentTask.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    TelemetryHistory.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    EndpointMetric.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    ConnectionIpHistory.query.filter_by(endpoint_id=old_id).update({"endpoint_id": new_hw_id})
    db.session.add(RegistrationHistory(
        hw_id=new_hw_id,
        hostname=adopted.hostname,
        ip_address=source_ip,
        event_type="Adopted Identity"
    ))
    db.session.add(ConnectionIpHistory(endpoint_id=new_hw_id, ip_address=source_ip, source="identity_adoption"))
    db.session.delete(existing_endpoint)
    return adopted


def trim_result_log(value):
    text = str(value or "")
    max_bytes = max(4096, int(getattr(Config, "AGENT_MAX_RESULT_LOG_BYTES", 262144)))
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text
    trimmed = raw[:max_bytes].decode("utf-8", errors="replace")
    return f"{trimmed}\n\n[WinHUB] Result log truncated to {max_bytes} bytes."

def ensure_default_groups_and_assign(agent, os_type):
    group_name = f"{os_type} Hosts"
    group = EndpointGroup.query.filter_by(name=group_name).first()
    if not group:
        group = EndpointGroup(name=group_name, description=f"System generated group for {os_type} endpoints")
        db.session.add(group)
        db.session.commit()

    if group not in agent.groups:
        agent.groups.append(group)

def evaluate_and_fire_triggers(agent_id, metric_name, value):
    active_triggers = TriggerRule.query.filter_by(metric_name=metric_name, is_active=True).all()
    if not active_triggers: return

    val_str = str(value).strip().lower()

    for tr in active_triggers:
        thr_str = str(tr.threshold_value).strip().lower()
        is_triggered = False

        if tr.operator == '==': is_triggered = (val_str == thr_str)
        elif tr.operator == '!=': is_triggered = (val_str != thr_str)
        elif tr.operator == 'contains': is_triggered = (thr_str in val_str)
        else:
            try:
                v_num = float(value)
                t_num = float(tr.threshold_value)
                if tr.operator == '>': is_triggered = (v_num > t_num)
                elif tr.operator == '<': is_triggered = (v_num < t_num)
            except:
                pass

        if is_triggered:
            action_tpl = TaskTemplate.query.get(tr.action_template_id)
            if not action_tpl: continue

            try:
                admin_user = User.query.filter_by(is_admin=True).first()
                admin_id = admin_user.id if admin_user else 1

                payload_dict = json.loads(action_tpl.payload) if action_tpl.payload else {}

                WinHubCore.dispatch_task(
                    user_id=admin_id,
                    module_name="Auto-Remediation",
                    action=action_tpl.action_type,
                    target_ids=[agent_id],
                    payload=payload_dict,
                    title=f"[Auto-Fix] {tr.name}"
                )
                log.warning(f"🚨 TRIGGER FIRED: Rule '{tr.name}' matched value '{value}' on host {agent_id}. Firing '{action_tpl.name}'.")
            except Exception as e:
                log.error(f"❌ TRIGGER DISPATCH ERROR: Could not fire action for '{tr.name}': {e}")


@agent_gateway_bp.route('/enroll', methods=['POST'])
def enroll_agent():
    data = request.json or {}
    if not getattr(Config, "AGENT_ENROLLMENT_ENABLED", True):
        return jsonify({"error": "Enrollment Disabled"}), 403
    source_ip = current_client_ip()
    if not enrollment_source_allowed(source_ip):
        return jsonify({"error": "Enrollment Source Denied"}), 403
    if data.get('global_token') != GLOBAL_ENROLLMENT_TOKEN:
        return jsonify({"error": "Auth Failed"}), 401

    hw_id = data.get('hw_id')
    hostname = data.get('hostname', 'Unknown')
    os_type = data.get('os_type', 'Windows')
    network_interfaces = data.get('network_interfaces', [])
    network_info = json.dumps(network_interfaces if isinstance(network_interfaces, list) else [], ensure_ascii=False)
    host_inventory = data.get('host_info', {})
    host_info = json.dumps(host_inventory if isinstance(host_inventory, dict) else {}, ensure_ascii=False)
    agent_version = str(data.get('agent_version') or '').strip()[:50]
    previous_auth_token = str(data.get("previous_auth_token") or "").strip()
    previous_hw_id = str(data.get("previous_hw_id") or "").strip()

    if not hw_id: return jsonify({"error": "Missing Hardware ID"}), 400
    fingerprint = agent_identity_fingerprint(hw_id, hostname, os_type, network_interfaces, host_inventory)
    token_proof_endpoint, token_proof_reasons = find_approved_endpoint_by_previous_token(previous_auth_token, previous_hw_id)
    identity_duplicate_endpoint, identity_duplicate_reasons = find_approved_duplicate_endpoint(hw_id, hostname, source_ip, fingerprint)
    stale_hostname_endpoint, stale_hostname_reasons = find_approved_hostname_stale_endpoint(hw_id, hostname, agent_version)
    duplicate_endpoint = token_proof_endpoint or identity_duplicate_endpoint or stale_hostname_endpoint
    duplicate_reasons = token_proof_reasons or identity_duplicate_reasons or stale_hostname_reasons
    raw_token = f"agt_{secrets.token_urlsafe(32)}"

    agent = Endpoint.query.get(hw_id)
    adopted_identity = False
    if (
        agent
        and getattr(agent, "approval_status", "Pending") != "Approved"
        and duplicate_endpoint
        and should_adopt_duplicate_enrollment(duplicate_reasons)
    ):
        db.session.delete(agent)
        db.session.flush()
        agent = adopt_duplicate_endpoint_identity(
            duplicate_endpoint,
            hw_id,
            raw_token,
            data,
            source_ip,
            fingerprint,
            network_info,
            host_info,
            agent_version,
        )
        adopted_identity = True
    if agent and agent.is_blocked:
        return jsonify({"status": "error", "message": "Blocked"}), 403
    if (
        agent
        and getattr(agent, "approval_status", "Approved") == "Approved"
        and not adopted_identity
        and not getattr(Config, "AGENT_ALLOW_REENROLL_EXISTING", False)
        and not endpoint_reenroll_allowed(agent)
    ):
        return jsonify({"status": "error", "message": "Endpoint already enrolled. Delete or reset the endpoint record before re-enrollment."}), 409
    if not agent and duplicate_endpoint and should_adopt_duplicate_enrollment(duplicate_reasons):
        agent = adopt_duplicate_endpoint_identity(
            duplicate_endpoint,
            hw_id,
            raw_token,
            data,
            source_ip,
            fingerprint,
            network_info,
            host_info,
            agent_version,
        )
        adopted_identity = True
    elif not agent:
        agent = Endpoint(id=hw_id, hostname=hostname, auth_token=raw_token,
                         os_version=data.get('os_version'), os_type=os_type, connection_ip=source_ip, ip_address=source_ip)
        agent.approval_status = duplicate_enrollment_review_status(duplicate_reasons) if duplicate_endpoint else "Pending"
        agent.first_seen = datetime.utcnow()
        agent.last_enrollment_at = datetime.utcnow()
        agent.last_enrollment_ip = source_ip
        agent.enrollment_attempts = 1
        agent.identity_fingerprint = fingerprint
        agent.agent_version = agent_version
        agent.network_info = network_info
        agent.host_info = host_info
        apply_endpoint_encryption_status(agent, host_inventory)
        if duplicate_endpoint:
            agent.identity_warning = (
                "Possible duplicate of approved endpoint "
                f"{duplicate_endpoint.hostname or duplicate_endpoint.id} "
                f"({duplicate_endpoint.id}); matched: {', '.join(duplicate_reasons)}"
            )
        db.session.add(agent)
        db.session.add(RegistrationHistory(
            hw_id=hw_id,
            hostname=hostname,
            ip_address=source_ip,
            event_type=("Rejected Duplicate" if duplicate_enrollment_requires_rejection(duplicate_reasons) else "Pending Duplicate Review") if duplicate_endpoint else "Pending Approval"
        ))
        db.session.add(ConnectionIpHistory(endpoint_id=hw_id, ip_address=source_ip, source="enrollment"))
    else:
        previous_fingerprint = getattr(agent, "identity_fingerprint", None)
        agent.hostname = hostname
        if source_ip and source_ip != (getattr(agent, "connection_ip", None) or ""):
            agent.connection_ip = source_ip
            db.session.add(ConnectionIpHistory(endpoint_id=agent.id, ip_address=source_ip, source="enrollment"))
            agent.ip_address = source_ip
        agent.last_seen = datetime.utcnow()
        agent.last_enrollment_at = datetime.utcnow()
        agent.last_enrollment_ip = source_ip
        agent.enrollment_attempts = int(agent.enrollment_attempts or 0) + 1
        agent.auth_token = raw_token
        agent.os_version = data.get('os_version', agent.os_version)
        agent.os_type = os_type
        agent.agent_version = agent_version or agent.agent_version
        agent.network_info = network_info
        agent.host_info = host_info
        apply_endpoint_encryption_status(agent, host_inventory)
        if not previous_fingerprint:
            agent.identity_fingerprint = fingerprint
        elif previous_fingerprint != fingerprint:
            agent.identity_warning = "Enrollment identity changed. Review hostname, IP and network interfaces before approval."
            agent.identity_fingerprint = fingerprint
        if duplicate_endpoint and getattr(agent, "approval_status", "Pending") != "Approved":
            agent.approval_status = duplicate_enrollment_review_status(duplicate_reasons)
            agent.identity_warning = (
                "Possible duplicate of approved endpoint "
                f"{duplicate_endpoint.hostname or duplicate_endpoint.id} "
                f"({duplicate_endpoint.id}); matched: {', '.join(duplicate_reasons)}"
            )
        if not getattr(agent, "approval_status", None):
            agent.approval_status = "Approved"
        if endpoint_reenroll_allowed(agent):
            agent.reenroll_allowed_until = None
        db.session.add(RegistrationHistory(hw_id=hw_id, hostname=hostname, ip_address=source_ip, event_type="Re-enrolled"))

    if getattr(agent, "approval_status", "Approved") == "Approved":
        ensure_default_groups_and_assign(agent, os_type)
    bind_enrollment_public_key(agent, data)
    db.session.commit()
    return jsonify({
        "status": "success",
        "auth_token": raw_token,
        "approval_status": getattr(agent, "approval_status", "Pending"),
        "adopted_identity": bool(adopted_identity),
    })

@agent_gateway_bp.route('/poll', methods=['POST'])
def agent_poll():
    data = request.json or {}
    agent = get_poll_agent(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403
    if getattr(agent, "approval_status", "Approved") != "Approved":
        signature_ok, signature_reason = verify_or_bind_agent_key(agent, data, "/api/agent/poll", data.get("auth_token"))
        if not signature_ok:
            return jsonify(agent_signature_error_payload(signature_reason, data)), 403
        source_ip = current_client_ip() or getattr(agent, "connection_ip", None) or agent.ip_address
        duplicate_endpoint, duplicate_reasons = find_approved_duplicate_endpoint(
            agent.id,
            agent.hostname,
            source_ip,
            {
                getattr(agent, "identity_fingerprint", None),
                endpoint_stable_identity_fingerprint(agent),
            },
        )
        if duplicate_endpoint and should_adopt_duplicate_enrollment(duplicate_reasons):
            existing_network_info = agent.network_info or "[]"
            existing_host_info = agent.host_info or "{}"
            pending_hostname = agent.hostname
            pending_os_version = agent.os_version
            pending_os_type = agent.os_type
            pending_fingerprint = getattr(agent, "identity_fingerprint", None)
            db.session.delete(agent)
            db.session.flush()
            agent = adopt_duplicate_endpoint_identity(
                duplicate_endpoint,
                data.get("hw_id"),
                data.get("auth_token"),
                {
                    "hostname": pending_hostname,
                    "os_version": pending_os_version,
                    "os_type": pending_os_type,
                },
                source_ip,
                pending_fingerprint,
                existing_network_info,
                existing_host_info,
                str(data.get("agent_version") or duplicate_endpoint.agent_version or "")[:50],
            )
            db.session.commit()
    if getattr(agent, "approval_status", "Approved") != "Approved":
        agent.last_seen = datetime.utcnow()
        update_agent_connection(agent)
        db.session.commit()
        return jsonify({"status": "pending_approval", **agent_poll_timing("pending")}), 200

    task = get_pending_task_for_agent(agent.id)
    signature_ok, signature_reason = (
        verify_or_bind_agent_key(agent, data, "/api/agent/poll", data.get("auth_token"))
        if task
        else verify_poll_signature_cached(agent, data, data.get("auth_token"))
    )
    if not signature_ok:
        return jsonify(agent_signature_error_payload(signature_reason, data)), 403
    if task:
        remember_poll_signature(agent, data, data.get("auth_token"))

    now = datetime.utcnow()
    needs_commit = bool(getattr(agent, "_public_key_plain_backfilled", False))
    refresh_seen = not agent.last_seen or (now - agent.last_seen).total_seconds() > 60
    agent_version = str(data.get('agent_version') or '').strip()[:50]
    if refresh_seen and update_agent_connection(agent):
        needs_commit = True
    if agent_version and agent_version != (agent.agent_version or ""):
        agent.agent_version = agent_version
        needs_commit = True

    if refresh_seen:
        agent.last_seen = now
        needs_commit = True

    resp = {"status": "idle", **agent_poll_timing("idle")}

    signature_mode = str(getattr(Config, "AGENT_TASK_SIGNATURE_MODE", "dual") or "dual").lower()
    if signature_mode not in {"hmac", "dual", "v2"}:
        signature_mode = "dual"
    supports_v2 = "rsa-pss-sha256-v2" in str(data.get("task_signature_capabilities") or "").lower()

    if task and signature_mode == "v2" and not supports_v2:
        resp = {"status": "upgrade_required", "required_task_signature": "rsa-pss-sha256-v2", **agent_poll_timing("idle")}
    elif task:
        task.status = "PickedUp"

        # --- БРОНЕБІЙНИЙ ПАРСИНГ PAYLOAD ДЛЯ АГЕНТА ---
        try:
            raw_t = str(task.payload).strip() if task.payload else "{}"
            try:
                # Перша спроба: стандартний JSON
                payload_dict = json.loads(raw_t)
            except Exception:
                # Друга спроба: Python dict string (одинарні лапки)
                import ast
                payload_dict = ast.literal_eval(raw_t)

            if not isinstance(payload_dict, dict):
                payload_dict = {"script": str(raw_t)}
        except Exception:
            payload_dict = {"script": str(task.payload or "")}

        # Гарантія наявності ключа "script", на який очікує агент
        if 'script' not in payload_dict and 'command' in payload_dict:
            payload_dict['script'] = payload_dict['command']

        try:
            task_timeout_seconds = int(payload_dict.get("__agent_timeout_seconds") or getattr(Config, "AGENT_TASK_TIMEOUT_SECONDS", 1800))
        except Exception:
            task_timeout_seconds = int(getattr(Config, "AGENT_TASK_TIMEOUT_SECONDS", 1800))

        resp = {
            "status": "task",
            "task_id": task.id,
            "action": task.action_type,
            "payload": payload_dict,
            "timeout_seconds": max(60, task_timeout_seconds),
            **agent_poll_timing("task"),
        }
        if signature_mode in {"hmac", "dual"}:
            resp["signature"] = sign_task_message(task.id, task.action_type, payload_dict)
            resp["signature_alg"] = "hmac-sha256"
        if supports_v2 and signature_mode in {"dual", "v2"}:
            resp["task_signature_v2"] = sign_task_message_v2(
                agent,
                task.id,
                task.action_type,
                payload_dict,
                resp["timeout_seconds"],
            )
        needs_commit = True

    if needs_commit:
        db.session.commit()

    return jsonify(resp)

@agent_gateway_bp.route('/result', methods=['POST'])
def agent_result():
    data = request.json or {}
    agent = get_request_agent(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403
    signature_ok, signature_reason = verify_or_bind_agent_key(agent, data, "/api/agent/result", data.get("auth_token"))
    if not signature_ok:
        return jsonify(agent_signature_error_payload(signature_reason, data)), 403
    update_agent_connection(agent)
    acknowledged_key_id = str(data.get("task_signature_v2_key_id") or "").strip()
    try:
        acknowledged_sequence = int(data.get("task_signature_v2_sequence") or 0)
    except (TypeError, ValueError):
        acknowledged_sequence = 0
    if (
        acknowledged_key_id
        and acknowledged_key_id == str(getattr(agent, "task_signing_key_id", "") or "")
        and 0 < acknowledged_sequence <= int(getattr(agent, "task_signing_sequence", 0) or 0)
    ):
        agent.task_signature_v2_seen_at = datetime.utcnow()

    task = AgentTask.query.options(load_only(*TASK_RESULT_COLUMNS)).filter_by(
        id=data.get('task_id'),
        endpoint_id=agent.id,
    ).first()
    if task:
        if task.status == "Cancelled":
            db.session.commit()
            pending_tasks = AgentTask.query.filter(
                AgentTask.job_id == task.job_id,
                AgentTask.status.in_(['Pending', 'PickedUp', 'Running'])
            ).count()
            if pending_tasks == 0:
                update_scheduled_task_completion_status(task.job_id)
                db.session.commit()
                WinHubCore.process_job_completion(task.job_id)
            return jsonify({"status": "success", "message": "Task was already cancelled"})

        if task.status in ("Success", "Error") and task.finished_at:
            db.session.commit()
            return jsonify({"status": "success", "message": "Task was already finalized"})

        log_text = trim_result_log(data.get('log', ''))
        status = data.get('status')
        task.status = status if status in ("Success", "Error", "Cancelled") else "Error"
        task.result_log = log_text
        task.finished_at = datetime.utcnow()

        if task.status == 'Success':
            try:
                # Намагаємося прочитати як JSON, якщо не вийде - як словник (ast)
                raw_p = str(task.payload).strip() if task.payload else "{}"
                try:
                    payload_dict = json.loads(raw_p)
                except:
                    import ast
                    payload_dict = ast.literal_eval(raw_p)

                if isinstance(payload_dict, dict) and payload_dict.get('__is_metric'):
                    metric_name = payload_dict.get('__metric_name', task.title.replace("[Auto] ", ""))
                    val = str(log_text).strip()

                    metric = EndpointMetric.query.filter_by(endpoint_id=agent.id, item_name=metric_name).first()
                    if not metric:
                        metric = EndpointMetric(endpoint_id=agent.id, item_name=metric_name)
                        db.session.add(metric)

                    metric.last_value = val
                    metric.last_updated = datetime.utcnow()

                    evaluate_and_fire_triggers(agent.id, metric_name, val)

            except Exception as e:
                log.error(f"Error processing metric result: {e}")

        from core.history_search import index_agent_task
        index_agent_task(task)
        db.session.commit()

        pending_tasks = AgentTask.query.filter(
            AgentTask.job_id == task.job_id,
            AgentTask.status.in_(['Pending', 'PickedUp', 'Running'])
        ).count()

        if pending_tasks == 0:
            update_scheduled_task_completion_status(task.job_id)
            db.session.commit()
            WinHubCore.process_job_completion(task.job_id)

        return jsonify({"status": "success"})

    return jsonify({"status": "error"}), 404

@agent_gateway_bp.route('/telemetry', methods=['POST'])
def agent_telemetry():
    data = request.json or {}
    agent = get_request_agent(data.get('hw_id'))

    if not agent or agent.is_blocked or agent.auth_token != data.get('auth_token'):
        return jsonify({"status": "error"}), 403
    signature_ok, signature_reason = verify_or_bind_agent_key(agent, data, "/api/agent/telemetry", data.get("auth_token"))
    if not signature_ok:
        return jsonify(agent_signature_error_payload(signature_reason, data)), 403

    agent_version = str(data.get('agent_version') or '').strip()[:50]
    if agent_version:
        agent.agent_version = agent_version
    host_inventory = data.get('host_info')
    if isinstance(host_inventory, dict):
        agent.host_info = json.dumps(host_inventory, ensure_ascii=False)
        apply_endpoint_encryption_status(agent, host_inventory)
    update_agent_connection(agent)

    telemetry = TelemetryHistory(
        endpoint_id=agent.id,
        cpu_usage=data.get('cpu', 0.0),
        ram_usage=data.get('ram', 0.0),
        disk_c_free=data.get('disk_c', 0.0)
    )

    agent.last_seen = datetime.utcnow()
    db.session.add(telemetry)
    db.session.commit()

    return jsonify({"status": "success"})
