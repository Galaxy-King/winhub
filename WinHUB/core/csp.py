"""Content Security Policy helpers shared by the app and tests."""

from __future__ import annotations

import re
import secrets


CSP_NONCE_PLACEHOLDER = "{nonce}"
COMPATIBILITY_CSP_POLICY = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:"
)
DEFAULT_CSP_POLICY = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; script-src 'self' 'nonce-{nonce}'; script-src-attr 'unsafe-inline'; "
    "style-src 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:"
)

_VALID_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def new_csp_nonce():
    """Return a per-response CSP nonce with enough entropy for enforcement."""
    return secrets.token_urlsafe(32)


def render_csp_policy(policy, nonce):
    """Insert a validated nonce into the configured CSP policy."""
    value = str(nonce or "")
    if not _VALID_NONCE.fullmatch(value):
        raise ValueError("Invalid CSP nonce")
    return str(policy or "").replace(CSP_NONCE_PLACEHOLDER, value)


def build_csp_headers(
    compatibility_mode,
    compatibility_policy,
    nonce_mode,
    nonce_policy,
    nonce,
):
    """Build dual-policy headers for a report-only-to-enforce nonce rollout."""
    compatibility_mode = str(compatibility_mode or "off").lower()
    nonce_mode = str(nonce_mode or "off").lower()
    compatibility_policy = render_csp_policy(compatibility_policy, nonce)
    nonce_policy = render_csp_policy(nonce_policy, nonce)
    headers = {}

    if nonce_mode == "enforce":
        headers["Content-Security-Policy"] = nonce_policy
    elif compatibility_mode == "enforce":
        headers["Content-Security-Policy"] = compatibility_policy

    if nonce_mode == "report-only":
        headers["Content-Security-Policy-Report-Only"] = nonce_policy
    elif compatibility_mode == "report-only":
        headers["Content-Security-Policy-Report-Only"] = compatibility_policy

    return headers
