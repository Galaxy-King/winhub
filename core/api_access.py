"""Security policy helpers for human-created API keys.

The API key is only the first authorization factor.  Every request is also
restricted by source network, global permissions, per-group actions and an
approved-template allowlist.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime

from flask import current_app, g, has_request_context, request, session

from core.database import (
    ApiKey,
    EndpointGroup,
    TaskTemplate,
    api_key_group_m2m,
    api_key_template_m2m,
    db,
)
from core.group_access import GROUP_ACTION_IDS, parse_group_permissions, serialize_group_permissions
from core.permissions import parse_allowed_modules
from core.template_security import template_approval_valid


MAX_API_NETWORKS = 64
MAX_API_GROUPS = 500
MAX_API_TEMPLATES = 500
MAX_API_TARGETS_PER_RUN = 500


def _list_value(raw):
    if raw is None:
        return []
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            return []
        if value.startswith("["):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, list):
                return parsed
        return [item for item in re.split(r"[,;\r\n]+", value) if item.strip()]
    if isinstance(raw, (list, tuple, set)):
        return list(raw)
    raise ValueError("Expected a list or a comma-separated string")


def normalize_allowed_networks(raw):
    """Return canonical IPv4/IPv6 CIDRs; a single IP becomes /32 or /128."""
    result = []
    for item in _list_value(raw):
        value = str(item or "").strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid allowed IP or CIDR: {value}") from exc
        canonical = str(network)
        if canonical not in result:
            result.append(canonical)
        if len(result) > MAX_API_NETWORKS:
            raise ValueError(f"A key may contain at most {MAX_API_NETWORKS} allowed networks")
    return result


def serialize_allowed_networks(raw):
    return json.dumps(normalize_allowed_networks(raw), ensure_ascii=False)


def stored_allowed_networks(key):
    try:
        return normalize_allowed_networks(getattr(key, "allowed_networks", None))
    except ValueError:
        # A malformed stored policy must fail closed when enforcement is active.
        return []


def _trusted_proxy_networks():
    value = ""
    if has_request_context():
        value = current_app.config.get("TRUSTED_PROXY_CIDRS", "")
    try:
        return [ipaddress.ip_network(item, strict=False) for item in normalize_allowed_networks(value)]
    except ValueError:
        return []


def _address(value):
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
        return parsed.ipv4_mapped if getattr(parsed, "ipv4_mapped", None) else parsed
    except ValueError:
        return None


def _in_networks(address, networks):
    if address is None:
        return False
    return any(address.version == network.version and address in network for network in networks)


def effective_client_ip(http_request=None):
    """Resolve the client IP without trusting a caller-supplied XFF header.

    The forwarding chain is walked right-to-left and only proxy hops configured
    in TRUSTED_PROXY_CIDRS are discarded.
    """
    http_request = http_request or request
    remote = _address(getattr(http_request, "remote_addr", None))
    if remote is None:
        return ""
    trusted = _trusted_proxy_networks()
    if not _in_networks(remote, trusted):
        return str(remote)

    forwarded = str(http_request.headers.get("X-Forwarded-For", "") or "")
    if not forwarded:
        real_ip = _address(http_request.headers.get("X-Real-IP", ""))
        return str(real_ip) if real_ip is not None else str(remote)

    chain = []
    for item in forwarded.split(","):
        parsed = _address(item)
        if parsed is None:
            return str(remote)
        chain.append(parsed)
    chain.append(remote)
    while chain and _in_networks(chain[-1], trusted):
        chain.pop()
    return str(chain[-1] if chain else remote)


def api_key_source_allowed(key, source_ip):
    if not bool(getattr(key, "ip_allowlist_enforced", False)):
        return True
    address = _address(source_ip)
    networks = [ipaddress.ip_network(item, strict=False) for item in stored_allowed_networks(key)]
    return bool(networks and _in_networks(address, networks))


def api_key_group_permission_map(key_id, legacy_permissions=None):
    rows = db.session.query(
        api_key_group_m2m.c.group_id,
        api_key_group_m2m.c.permissions,
    ).filter(api_key_group_m2m.c.api_key_id == key_id).all()
    if rows:
        return {
            str(group_id): frozenset(parse_group_permissions(permissions, legacy_default=False))
            for group_id, permissions in rows
        }

    # Compatibility for keys created before per-group action matrices existed.
    prefix = "scope:group:"
    legacy_group_ids = [
        str(item)[len(prefix):]
        for item in parse_allowed_modules(legacy_permissions)
        if isinstance(item, str) and item.startswith(prefix)
    ]
    return {group_id: frozenset(GROUP_ACTION_IDS) for group_id in legacy_group_ids if group_id}


def api_key_group_permissions_for_keys(key_ids):
    ids = [int(key_id) for key_id in key_ids if key_id is not None]
    result = {key_id: {} for key_id in ids}
    if not ids:
        return result
    rows = db.session.query(
        api_key_group_m2m.c.api_key_id,
        api_key_group_m2m.c.group_id,
        api_key_group_m2m.c.permissions,
    ).filter(api_key_group_m2m.c.api_key_id.in_(ids)).all()
    for key_id, group_id, permissions in rows:
        result.setdefault(key_id, {})[str(group_id)] = [
            action_id
            for action_id in GROUP_ACTION_IDS
            if action_id in parse_group_permissions(permissions, legacy_default=False)
        ]
    return result


def replace_api_key_group_permissions(key_id, entries):
    if not isinstance(entries, list):
        raise ValueError("Group access must be a list")
    if len(entries) > MAX_API_GROUPS:
        raise ValueError(f"A key may contain at most {MAX_API_GROUPS} host groups")
    requested = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        group_id = str(entry.get("group_id") or "").strip()
        permissions = parse_group_permissions(entry.get("permissions", []), legacy_default=False)
        if group_id and permissions:
            requested[group_id] = serialize_group_permissions(permissions)

    valid_ids = {
        str(row[0])
        for row in db.session.query(EndpointGroup.id).filter(EndpointGroup.id.in_(requested)).all()
    } if requested else set()
    unknown = set(requested) - valid_ids
    if unknown:
        raise ValueError("One or more host groups do not exist")

    db.session.execute(
        api_key_group_m2m.delete().where(api_key_group_m2m.c.api_key_id == key_id)
    )
    if requested:
        db.session.execute(api_key_group_m2m.insert(), [
            {
                "api_key_id": key_id,
                "group_id": group_id,
                "permissions": requested[group_id],
            }
            for group_id in requested
        ])
    return {
        group_id: parse_group_permissions(permissions, legacy_default=False)
        for group_id, permissions in requested.items()
    }


def api_key_template_ids(key_id):
    return {
        str(row[0])
        for row in db.session.query(api_key_template_m2m.c.template_id)
        .filter(api_key_template_m2m.c.api_key_id == key_id).all()
    }


def api_key_template_ids_for_keys(key_ids):
    ids = [int(key_id) for key_id in key_ids if key_id is not None]
    result = {key_id: set() for key_id in ids}
    if not ids:
        return result
    rows = db.session.query(
        api_key_template_m2m.c.api_key_id,
        api_key_template_m2m.c.template_id,
    ).filter(api_key_template_m2m.c.api_key_id.in_(ids)).all()
    for key_id, template_id in rows:
        result.setdefault(key_id, set()).add(str(template_id))
    return result


def approved_action_templates():
    return [
        template
        for template in TaskTemplate.query.order_by(TaskTemplate.category, TaskTemplate.name).all()
        if getattr(template, "type", "action") != "report" and template_approval_valid(template)
    ]


def replace_api_key_template_ids(key_id, template_ids):
    values = list(dict.fromkeys(str(item) for item in _list_value(template_ids) if item))
    if len(values) > MAX_API_TEMPLATES:
        raise ValueError(f"A key may contain at most {MAX_API_TEMPLATES} templates")
    valid_ids = {
        str(template.id)
        for template in TaskTemplate.query.filter(TaskTemplate.id.in_(values)).all()
        if getattr(template, "type", "action") != "report" and template_approval_valid(template)
    } if values else set()
    if set(values) != valid_ids:
        raise ValueError("Only currently approved action templates may be assigned to an API key")

    db.session.execute(
        api_key_template_m2m.delete().where(api_key_template_m2m.c.api_key_id == key_id)
    )
    if values:
        db.session.execute(api_key_template_m2m.insert(), [
            {"api_key_id": key_id, "template_id": template_id}
            for template_id in values
        ])
    return valid_ids


def normalize_max_targets(value, default=1):
    try:
        number = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise ValueError("Max targets per run must be a number") from exc
    if number < 1 or number > MAX_API_TARGETS_PER_RUN:
        raise ValueError(f"Max targets per run must be between 1 and {MAX_API_TARGETS_PER_RUN}")
    return number


def prime_api_request_policy(key, source_ip):
    """Cache the resolved key policy in request-local state (not the cookie)."""
    g.winhub_api_key = key
    g.winhub_api_permissions = parse_allowed_modules(key.permissions)
    g.winhub_api_group_permissions = api_key_group_permission_map(key.id, key.permissions)
    g.winhub_api_template_ids = api_key_template_ids(key.id)
    g.winhub_api_template_scope_enforced = bool(getattr(key, "template_scope_enforced", False))
    g.winhub_api_max_targets = normalize_max_targets(getattr(key, "max_targets_per_run", 1), default=1)
    g.winhub_api_source_ip = str(source_ip or "")


def api_template_allowed(template_id):
    if not has_request_context() or not session.get("api_key_auth"):
        return True
    enforced = bool(getattr(g, "winhub_api_template_scope_enforced", False))
    if not enforced:
        return True
    return str(template_id or "") in set(getattr(g, "winhub_api_template_ids", set()) or set())


def api_target_count_allowed(target_ids):
    if not has_request_context() or not session.get("api_key_auth"):
        return True
    unique_ids = {str(item) for item in (target_ids or []) if item}
    limit = int(getattr(g, "winhub_api_max_targets", 1) or 1)
    return len(unique_ids) <= limit


def touch_api_key(key, source_ip, interval_seconds=300):
    now = datetime.utcnow()
    last_used = getattr(key, "last_used_at", None)
    if last_used and (now - last_used).total_seconds() < interval_seconds and key.last_used_ip == source_ip:
        return
    key.last_used_at = now
    key.last_used_ip = str(source_ip or "")[:255]
    db.session.commit()
