"""Approval integrity helpers shared by template APIs and report generation."""

from __future__ import annotations

import hashlib
import hmac
import json


def canonical_template_payload(payload):
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            pass
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def template_content_hash(action_type, template_type, payload):
    canonical = json.dumps(
        {
            "action_type": str(action_type or ""),
            "type": str(template_type or "action"),
            "payload": canonical_template_payload(payload),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def current_template_hash(template):
    return template_content_hash(template.action_type, getattr(template, "type", "action"), template.payload or "")


def template_approval_valid(template):
    expected = str(getattr(template, "approved_content_hash", "") or "")
    return bool(template and template.is_approved and expected and expected == current_template_hash(template))


def ai_template_source_hash(language, source):
    """Bind an AI validation result to one exact script and language."""
    canonical = json.dumps(
        {
            "language": str(language or "").strip().lower(),
            "script": str(source or ""),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ai_template_validation_valid(payload):
    """Return True only when the saved AI marker matches the current script."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return False
    if not isinstance(payload, dict):
        return False
    marker = payload.get("__ai_generated")
    if not isinstance(marker, dict) or marker.get("validation_ok") is not True:
        return False
    language = str(marker.get("language") or "").strip().lower()
    expected = str(marker.get("source_hash") or "")
    if language not in {"powershell", "bash", "jinja"} or len(expected) != 64:
        return False
    actual = ai_template_source_hash(language, payload.get("script", ""))
    return hmac.compare_digest(expected, actual)
