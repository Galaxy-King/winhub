"""Approval integrity helpers shared by template APIs and report generation."""

from __future__ import annotations

import hashlib
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
