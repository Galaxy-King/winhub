"""Per-group authorization scopes for Infrastructure resources."""

import json

from flask import g, has_request_context

from core.database import (
    db,
    Endpoint,
    EndpointGroup,
    endpoint_group_m2m,
    user_group_m2m,
)
from core.permissions import request_api_group_permissions, request_api_group_scope


LEGACY_ALL = "*"

GROUP_ACTION_CATALOG = [
    {"id": "view_hosts", "name": "View hosts", "category": "Visibility"},
    {"id": "view_groups", "name": "View group", "category": "Visibility"},
    {"id": "view_queue", "name": "View tasks and logs", "category": "Visibility"},
    {"id": "view_reports", "name": "View reports", "category": "Visibility"},
    {"id": "view_sensitive_reports", "name": "Reveal passwords and secrets", "category": "Visibility"},
    {"id": "run_tasks", "name": "Run and retry tasks", "category": "Operations"},
    {"id": "send_reports", "name": "Send reports", "category": "Operations"},
    {"id": "edit_reports", "name": "Edit report body", "category": "Operations"},
    {"id": "dismiss_reports", "name": "Dismiss reports", "category": "Operations"},
    {"id": "manage_hosts", "name": "Edit, approve and block hosts", "category": "Management"},
    {"id": "manage_groups", "name": "Change group membership", "category": "Management"},
    {"id": "delete_hosts", "name": "Delete hosts", "category": "Deletion"},
    {"id": "delete_groups", "name": "Delete group", "category": "Deletion"},
]
GROUP_ACTION_IDS = tuple(item["id"] for item in GROUP_ACTION_CATALOG)
GROUP_ACTION_ID_SET = frozenset(GROUP_ACTION_IDS)
FULL_GROUP_ACTIONS = frozenset(GROUP_ACTION_IDS)


def parse_group_permissions(raw, legacy_default=True):
    if raw is None:
        return set(GROUP_ACTION_IDS) if legacy_default else set()
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            parsed = [raw]
    else:
        parsed = raw
    if not isinstance(parsed, (list, tuple, set, frozenset)):
        return set(GROUP_ACTION_IDS) if legacy_default else set()
    values = {str(item) for item in parsed if item is not None}
    if LEGACY_ALL in values:
        return set(GROUP_ACTION_IDS)
    return values.intersection(GROUP_ACTION_ID_SET)


def serialize_group_permissions(values):
    normalized = parse_group_permissions(values, legacy_default=False)
    return json.dumps(
        [action_id for action_id in GROUP_ACTION_IDS if action_id in normalized],
        ensure_ascii=False,
    )


def _request_cache(name):
    if not has_request_context():
        return None
    cache = getattr(g, name, None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(g, name, cache)
    return cache


def user_group_permission_map(user_id):
    """Load all group grants for a user once per request."""
    cache = _request_cache("winhub_group_permission_maps")
    cache_key = str(user_id or "")
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    rows = db.session.query(
        user_group_m2m.c.group_id,
        user_group_m2m.c.permissions,
    ).filter(user_group_m2m.c.user_id == user_id).all()
    result = {
        str(group_id): frozenset(parse_group_permissions(permissions))
        for group_id, permissions in rows
    }
    if cache is not None:
        cache[cache_key] = result
    return result


def group_permissions_for_users(user_ids):
    """Batch payload for the admin user list, avoiding one query per user."""
    ids = [int(user_id) for user_id in user_ids if user_id is not None]
    result = {user_id: {} for user_id in ids}
    if not ids:
        return result
    rows = db.session.query(
        user_group_m2m.c.user_id,
        user_group_m2m.c.group_id,
        user_group_m2m.c.permissions,
    ).filter(user_group_m2m.c.user_id.in_(ids)).all()
    for user_id, group_id, permissions in rows:
        result.setdefault(user_id, {})[str(group_id)] = [
            action_id
            for action_id in GROUP_ACTION_IDS
            if action_id in parse_group_permissions(permissions)
        ]
    return result


def scoped_group_permission_map(user):
    """Resolve interactive-user or API-key group grants."""
    if not user:
        return {}
    api_group_permissions = request_api_group_permissions()
    api_group_ids = request_api_group_scope()
    cache = _request_cache("winhub_scoped_group_permission_maps")
    cache_key = (
        getattr(user, "id", None),
        None if api_group_permissions is None else tuple(
            sorted((str(group_id), tuple(sorted(actions))) for group_id, actions in api_group_permissions.items())
        ),
        None if api_group_ids is None else tuple(sorted(str(group_id) for group_id in api_group_ids if group_id)),
        bool(getattr(user, "is_admin", False)),
    )
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    if api_group_permissions is not None:
        result = {
            str(group_id): frozenset(parse_group_permissions(actions, legacy_default=False))
            for group_id, actions in api_group_permissions.items()
        }
    elif api_group_ids is not None:
        result = {str(group_id): FULL_GROUP_ACTIONS for group_id in api_group_ids if group_id}
    elif getattr(user, "is_admin", False):
        result = {
            str(row[0]): FULL_GROUP_ACTIONS
            for row in db.session.query(EndpointGroup.id).all()
        }
    else:
        result = user_group_permission_map(user.id)
    if cache is not None:
        cache[cache_key] = result
    return result


def allowed_group_ids_for_action(user, action_id):
    action_id = str(action_id or "")
    cache = _request_cache("winhub_action_group_ids")
    cache_key = (
        getattr(user, "id", None),
        action_id,
        bool(request_api_group_scope() is not None),
    )
    if cache is not None and cache_key in cache:
        return set(cache[cache_key])
    result = {
        group_id
        for group_id, permissions in scoped_group_permission_map(user).items()
        if action_id in permissions
    }
    if cache is not None:
        cache[cache_key] = frozenset(result)
    return result


def group_action_allowed(user, group_id, action_id):
    if not user or not group_id:
        return False
    if getattr(user, "is_admin", False) and request_api_group_scope() is None:
        return True
    permissions = scoped_group_permission_map(user).get(str(group_id), frozenset())
    return str(action_id or "") in permissions


def allowed_host_ids_for_action(user, action_id, approved_only=True):
    """Resolve all hosts granted for an action with one indexed SQL query."""
    if not user:
        return set()
    cache = _request_cache("winhub_action_host_ids")
    cache_key = (
        getattr(user, "id", None),
        str(action_id),
        bool(approved_only),
        bool(request_api_group_scope() is not None),
    )
    if cache is not None and cache_key in cache:
        return set(cache[cache_key])

    granted_group_ids = None
    if getattr(user, "is_admin", False) and request_api_group_scope() is None:
        query = db.session.query(Endpoint.id)
    else:
        granted_group_ids = allowed_group_ids_for_action(user, action_id)
        if not granted_group_ids:
            if cache is not None:
                cache[cache_key] = frozenset()
            return set()
        query = db.session.query(Endpoint.id).join(Endpoint.groups).filter(
            EndpointGroup.id.in_(granted_group_ids)
        ).distinct()
    if approved_only:
        query = query.filter(Endpoint.approval_status == "Approved")
    result = {str(row[0]) for row in query.all()}

    # Deleting a host affects every group that contains it. For this destructive
    # operation we therefore use deny-wins semantics: one permitted membership
    # cannot be used to bypass another membership where deletion is forbidden.
    if str(action_id) == "delete_hosts" and granted_group_ids and result:
        denied_rows = db.session.query(endpoint_group_m2m.c.endpoint_id).filter(
            endpoint_group_m2m.c.endpoint_id.in_(result),
            ~endpoint_group_m2m.c.group_id.in_(granted_group_ids),
        ).distinct().all()
        result.difference_update(str(row[0]) for row in denied_rows)

    if cache is not None:
        cache[cache_key] = frozenset(result)
    return result


def replace_user_group_permissions(user_id, entries):
    """Replace a user's group grants atomically after validating group IDs."""
    if not isinstance(entries, list):
        entries = []
    requested = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        group_id = str(entry.get("group_id") or "").strip()
        if not group_id:
            continue
        requested[group_id] = serialize_group_permissions(entry.get("permissions", []))

    valid_ids = {
        str(row[0])
        for row in db.session.query(EndpointGroup.id).filter(EndpointGroup.id.in_(requested)).all()
    } if requested else set()
    db.session.execute(
        user_group_m2m.delete().where(user_group_m2m.c.user_id == user_id)
    )
    if valid_ids:
        db.session.execute(
            user_group_m2m.insert(),
            [
                {
                    "user_id": user_id,
                    "group_id": group_id,
                    "permissions": requested[group_id],
                }
                for group_id in requested
                if group_id in valid_ids
            ],
        )
    return valid_ids
