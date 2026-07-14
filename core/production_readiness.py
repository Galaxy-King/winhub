import os
from datetime import datetime, timezone

from core.config import Config


DEFAULT_AGENT_API_KEY = "WinHUB-Secret-Enroll-2026"
PLACEHOLDER_MARKERS = (
    "replace-with",
    "change-me",
    "changeme",
    "default",
    "example",
)


def _env_value(name):
    value = os.environ.get(name)
    return value.strip() if isinstance(value, str) else ""


def _looks_secret(value, min_length=32):
    if not value or len(str(value)) < min_length:
        return False
    lowered = str(value).lower()
    return not any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _check(checks, check_id, title, ok, severity="critical", detail="", action=""):
    checks.append({
        "id": check_id,
        "title": title,
        "status": "ok" if ok else "fail",
        "severity": severity,
        "detail": detail,
        "action": action,
    })


def _warn(checks, check_id, title, ok, detail="", action=""):
    checks.append({
        "id": check_id,
        "title": title,
        "status": "ok" if ok else "warning",
        "severity": "warning",
        "detail": detail,
        "action": action,
    })


def _file_mode(path):
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except OSError:
        return ""


def build_production_readiness(db=None, User=None, Endpoint=None):
    checks = []
    production = bool(getattr(Config, "PRODUCTION_MODE", False))
    secret_key = str(getattr(Config, "SECRET_KEY", "") or "")
    agent_api_key = str(getattr(Config, "AGENT_API_KEY", "") or "")
    task_secret = str(getattr(Config, "AGENT_TASK_HMAC_SECRET", "") or "")
    database_uri = str(getattr(Config, "SQLALCHEMY_DATABASE_URI", "") or "")
    env_file = _env_value("ENV_FILE") or "/etc/winhub/winhub.env"

    _check(
        checks,
        "production_mode",
        "Production mode",
        production,
        detail="WINHUB_ENV is production." if production else "WINHUB_ENV is not set to production.",
        action="Set WINHUB_ENV=production in /etc/winhub/winhub.env.",
    )
    _check(
        checks,
        "secret_key",
        "Flask SECRET_KEY",
        _looks_secret(secret_key, 48) and not secret_key.startswith("default-dev-secret-key"),
        detail="SECRET_KEY is non-default and long enough.",
        action="Set a unique 64+ character SECRET_KEY and restart WinHUB.",
    )
    _check(
        checks,
        "agent_api_key",
        "Agent enrollment secret",
        _looks_secret(agent_api_key, 32) and agent_api_key != DEFAULT_AGENT_API_KEY,
        detail="AGENT_API_KEY is non-default.",
        action="Set a long random AGENT_API_KEY. Close enrollment after rollout.",
    )
    _check(
        checks,
        "agent_task_hmac",
        "Agent task HMAC secret",
        _looks_secret(task_secret, 32) and task_secret != secret_key,
        detail="AGENT_TASK_HMAC_SECRET is separate from SECRET_KEY.",
        action="Set AGENT_TASK_HMAC_SECRET to a separate long random value.",
    )
    _check(
        checks,
        "signed_requests",
        "Signed agent requests required",
        bool(getattr(Config, "AGENT_REQUIRE_SIGNED_REQUESTS", False)),
        detail="Server rejects unsigned agent requests.",
        action="Set AGENT_REQUIRE_SIGNED_REQUESTS=true.",
    )
    _check(
        checks,
        "signature_freshness",
        "Agent signature freshness",
        300 <= int(getattr(Config, "AGENT_SIGNATURE_MAX_SKEW_SECONDS", 0) or 0) <= 1800,
        detail=f"AGENT_SIGNATURE_MAX_SKEW_SECONDS={getattr(Config, 'AGENT_SIGNATURE_MAX_SKEW_SECONDS', '')}.",
        action="Set AGENT_SIGNATURE_MAX_SKEW_SECONDS=900.",
    )
    _warn(
        checks,
        "legacy_agent_signatures",
        "Legacy agent signature bridge",
        not bool(getattr(Config, "AGENT_ALLOW_LEGACY_AGENT_SIGNATURES", False)),
        detail="Legacy bridge is disabled." if not bool(getattr(Config, "AGENT_ALLOW_LEGACY_AGENT_SIGNATURES", False)) else "Legacy bridge is enabled for rollout.",
        action="After all agents are upgraded, set AGENT_ALLOW_LEGACY_AGENT_SIGNATURES=false.",
    )
    _warn(
        checks,
        "enrollment_window",
        "Agent enrollment window",
        not bool(getattr(Config, "AGENT_ENROLLMENT_ENABLED", True)) or bool(str(getattr(Config, "AGENT_ENROLLMENT_ALLOWLIST", "") or "").strip()),
        detail="Enrollment is closed or source-restricted.",
        action="After rollout set AGENT_ENROLLMENT_ENABLED=false, or set AGENT_ENROLLMENT_ALLOWLIST.",
    )
    _check(
        checks,
        "session_cookie_secure",
        "Secure session cookies",
        bool(getattr(Config, "SESSION_COOKIE_SECURE", False)) and str(getattr(Config, "SESSION_COOKIE_SAMESITE", "")).lower() == "strict",
        detail=f"Secure={getattr(Config, 'SESSION_COOKIE_SECURE', '')}, SameSite={getattr(Config, 'SESSION_COOKIE_SAMESITE', '')}.",
        action="Set SESSION_COOKIE_SECURE=true and SESSION_COOKIE_SAMESITE=Strict.",
    )
    _check(
        checks,
        "hsts",
        "HSTS enabled",
        bool(getattr(Config, "HSTS_ENABLED", False)),
        detail="HSTS is enabled.",
        action="Set HSTS_ENABLED=true and serve only through HTTPS.",
    )
    _warn(
        checks,
        "database_backend",
        "Production database backend",
        not database_uri.startswith("sqlite:"),
        detail=f"Database backend: {database_uri.split(':', 1)[0] or 'unknown'}.",
        action="Use PostgreSQL for production multi-host deployments.",
    )
    _warn(
        checks,
        "rate_limit_backend",
        "Rate-limit storage",
        str(getattr(Config, "RATELIMIT_STORAGE_URI", "") or "") != "memory://",
        detail=f"RATELIMIT_STORAGE_URI={getattr(Config, 'RATELIMIT_STORAGE_URI', '')}.",
        action="Use Redis-backed rate limiting for multi-worker or exposed production.",
    )

    cert_path = str(getattr(Config, "SERVER_CERT_PATH", "") or "")
    key_path = str(getattr(Config, "SERVER_KEY_PATH", "") or "")
    _warn(
        checks,
        "tls_files",
        "TLS certificate files",
        bool(cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path)),
        detail=f"cert={cert_path}, key={key_path}.",
        action="Install TLS certificate files or terminate TLS at a hardened reverse proxy.",
    )
    if key_path:
        mode = _file_mode(key_path)
        _warn(
            checks,
            "tls_key_permissions",
            "TLS private key permissions",
            bool(mode and int(mode, 8) & 0o077 == 0),
            detail=f"{key_path} mode is {mode or 'missing'}.",
            action="Set private key permissions to 0640 or stricter.",
        )

    if os.path.exists(env_file):
        mode = _file_mode(env_file)
        _check(
            checks,
            "env_file_permissions",
            "Environment file permissions",
            bool(mode and int(mode, 8) & 0o077 == 0),
            detail=f"{env_file} mode is {mode}.",
            action="Run chmod 0640 /etc/winhub/winhub.env and keep ownership root:winhub.",
        )
    else:
        _check(
            checks,
            "env_file_permissions",
            "Environment file permissions",
            False,
            detail=f"{env_file} was not found.",
            action="Create /etc/winhub/winhub.env from the deployment template.",
        )

    if db is not None and User is not None:
        try:
            active_admins = User.query.filter_by(is_admin=True, is_active=True).count()
            _check(
                checks,
                "active_admin",
                "Active administrator account",
                active_admins >= 1,
                detail=f"Active administrators: {active_admins}.",
                action="Keep at least one active admin account.",
            )
        except Exception as exc:
            _warn(checks, "active_admin", "Active administrator account", False, detail=str(exc), action="Check database connectivity.")

    if db is not None and Endpoint is not None:
        try:
            approved = Endpoint.query.filter_by(approval_status="Approved").count()
            approved_without_key = Endpoint.query.filter(
                Endpoint.approval_status == "Approved",
                (Endpoint.public_key_pem_plain.is_(None)) | (Endpoint.public_key_pem_plain == ""),
            ).count()
            _warn(
                checks,
                "agent_identity_keys",
                "Approved agents have identity keys",
                approved == 0 or approved_without_key == 0,
                detail=f"Approved endpoints: {approved}; without public key: {approved_without_key}.",
                action="Upgrade/re-enroll old agents so every approved endpoint has a bound public key.",
            )
        except Exception as exc:
            _warn(checks, "agent_identity_keys", "Approved agents have identity keys", False, detail=str(exc), action="Check endpoint table.")

    critical_failures = [item for item in checks if item["severity"] == "critical" and item["status"] != "ok"]
    warnings = [item for item in checks if item["status"] == "warning"]
    if critical_failures:
        status = "blocked"
    elif warnings:
        status = "warning"
    else:
        status = "ready"

    return {
        "status": status,
        "production_mode": production,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(checks),
            "ok": len([item for item in checks if item["status"] == "ok"]),
            "warnings": len(warnings),
            "critical": len(critical_failures),
        },
        "checks": checks,
        "recommended_env": {
            "WINHUB_ENV": "production",
            "AGENT_REQUIRE_SIGNED_REQUESTS": "true",
            "AGENT_SIGNATURE_MAX_SKEW_SECONDS": "900",
            "AGENT_ALLOW_LEGACY_AGENT_SIGNATURES": "false",
            "SESSION_COOKIE_SECURE": "true",
            "SESSION_COOKIE_SAMESITE": "Strict",
            "HSTS_ENABLED": "true",
        },
    }
