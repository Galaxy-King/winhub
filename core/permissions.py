import json

from flask import g, has_request_context, session


MODULE_INTERNAL_PERMISSION_CATALOG = {
    "Administration": [
        {"id": "manage_gpg_keys", "name": "Manage GPG keys"},
    ],
    "Infrastructure": [
        {"id": "view_hosts", "name": "View hosts"},
        {"id": "view_groups", "name": "View groups"},
        {"id": "view_queue", "name": "View task queue"},
        {"id": "view_reports", "name": "View reports"},
        {"id": "view_sensitive_reports", "name": "Reveal sensitive task/report values"},
        {"id": "edit_reports", "name": "Edit reports"},
        {"id": "dismiss_reports", "name": "Dismiss reports"},
        {"id": "delete_reports", "name": "Delete reports"},
        {"id": "delete_tasks", "name": "Delete task history"},
        {"id": "run_tasks", "name": "Run approved templates"},
        {"id": "manage_software", "name": "Manage software packages"},
        {"id": "send_reports", "name": "Send reports by email"},
        {"id": "manage_templates", "name": "Manage templates"},
        {"id": "manage_smtp", "name": "Manage SMTP profiles"},
        {"id": "manage_scheduler", "name": "Manage scheduler"},
        {"id": "manage_triggers", "name": "Manage triggers"},
        {"id": "manage_hosts", "name": "Edit/block hosts"},
        {"id": "delete_hosts", "name": "Delete hosts"},
        {"id": "manage_groups", "name": "Create/edit groups"},
        {"id": "delete_groups", "name": "Delete groups"},
    ],
    "Newsletter": [
        {"id": "send_campaigns", "name": "Send mailings"},
        {"id": "manage_lists", "name": "Manage mailing lists"},
        {"id": "manage_smtp", "name": "Manage SMTP profiles"},
    ],
    "HistoryAudit": [
        {"id": "view_history", "name": "View history"},
        {"id": "manage_history", "name": "Cleanup/delete history"},
    ],
}

MODULE_PERMISSION_CATALOG = {
    "Administration": [
        {"id": "gpg_keys", "name": "GPG Keys"},
    ],
    "Infrastructure": [
        {"id": "view", "name": "View"},
        {"id": "change", "name": "Change"},
        {"id": "delete", "name": "Delete"},
        {"id": "scheduler", "name": "Scheduler"},
    ],
    "Newsletter": [
        {"id": "view", "name": "View"},
        {"id": "change", "name": "Change"},
        {"id": "delete", "name": "Delete"},
    ],
    "HistoryAudit": [
        {"id": "view", "name": "View"},
        {"id": "delete", "name": "Delete"},
    ],
}

PERMISSION_ALIASES = {
    "Administration": {
        "gpg_keys": {
            "manage_gpg_keys",
        },
    },
    "Infrastructure": {
        "view": {
            "view_hosts",
            "view_groups",
            "view_queue",
            "view_reports",
        },
        "change": {
            "run_tasks",
            "edit_reports",
            "dismiss_reports",
            "send_reports",
            "manage_software",
            "manage_templates",
            "manage_smtp",
            "manage_scheduler",
            "manage_triggers",
            "manage_groups",
        },
        "delete": {
            "delete_reports",
            "delete_tasks",
            "delete_hosts",
            "delete_groups",
        },
        # Compatibility for users that had the former exact cleanup permission.
        "cleanup_tasks": {
            "delete_tasks",
        },
        "scheduler": {
            "manage_scheduler",
        },
    },
    "Newsletter": {
        "view": {
            "send_campaigns",
        },
        "change": {
            "send_campaigns",
            "manage_lists",
            "manage_smtp",
        },
        "delete": {
            "manage_lists",
        },
    },
    "HistoryAudit": {
        "view": {
            "view_history",
        },
        "delete": {
            "manage_history",
        },
    },
}

# A legacy module-wide grant (for example ``Infrastructure``) is convenient for
# ordinary module actions, but must never silently grant secret disclosure or
# destructive capabilities.  Those permissions require either their exact token,
# a legacy action alias such as ``Infrastructure:delete``, or superadmin status.
EXPLICIT_ONLY_PERMISSIONS = {
    "Infrastructure": {
        "view_sensitive_reports",
        "delete_reports",
        "delete_tasks",
        "delete_hosts",
        "delete_groups",
    },
}


def parse_allowed_modules(raw):
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        if isinstance(raw, str):
            return [raw]
        return []


def permission_token(module_id, permission_id):
    return f"{module_id}:{permission_id}"


def module_tokens(allowed, module_id):
    prefix = f"{module_id}:"
    return [item for item in allowed if isinstance(item, str) and item.startswith(prefix)]


def request_api_permissions():
    if not has_request_context() or not session.get("api_key_auth"):
        return None
    cached = getattr(g, "winhub_api_permissions", None)
    if cached is not None:
        return cached
    parsed = parse_allowed_modules(session.get("api_permissions"))
    g.winhub_api_permissions = parsed
    return parsed


def user_allowed_permissions(user):
    raw = getattr(user, "allowed_modules", None)
    if not has_request_context():
        return parse_allowed_modules(raw)
    cache = getattr(g, "winhub_user_permissions", None)
    if not isinstance(cache, dict):
        cache = {}
        g.winhub_user_permissions = cache
    cache_key = (getattr(user, "id", id(user)), str(raw or ""))
    if cache_key not in cache:
        cache[cache_key] = parse_allowed_modules(raw)
    return cache[cache_key]


def request_api_group_scope():
    api_permissions = request_api_permissions()
    if api_permissions is None:
        return None
    prefix = "scope:group:"
    return [
        item[len(prefix):]
        for item in api_permissions
        if isinstance(item, str) and item.startswith(prefix)
    ]


def has_module_access(user, module_id):
    if not user:
        return False
    api_permissions = request_api_permissions()
    if api_permissions is not None:
        return module_id in api_permissions or bool(module_tokens(api_permissions, module_id))
    if getattr(user, "is_admin", False):
        return True
    allowed = user_allowed_permissions(user)
    return module_id in allowed or bool(module_tokens(allowed, module_id))


def has_permission(user, module_id, permission_id):
    if not user:
        return False

    api_permissions = request_api_permissions()
    if api_permissions is not None:
        allowed = api_permissions
    else:
        if getattr(user, "is_admin", False):
            return True
        allowed = user_allowed_permissions(user)

    token = permission_token(module_id, permission_id)
    tokens = module_tokens(allowed, module_id)

    if token in allowed:
        return True

    if module_id in allowed and permission_id not in EXPLICIT_ONLY_PERMISSIONS.get(module_id, set()):
        return True

    aliases = PERMISSION_ALIASES.get(module_id, {})
    for alias_id, granted_permissions in aliases.items():
        alias_token = permission_token(module_id, alias_id)
        if alias_token in allowed and permission_id in granted_permissions:
            return True

    return False


def all_permission_ids(module_id):
    ids = []
    for item in MODULE_INTERNAL_PERMISSION_CATALOG.get(module_id, []):
        if item["id"] not in ids:
            ids.append(item["id"])
    for item in MODULE_PERMISSION_CATALOG.get(module_id, []):
        if item["id"] not in ids:
            ids.append(item["id"])
    return ids


def user_permissions(user, module_id):
    if not user:
        return {}
    api_permissions = request_api_permissions()
    if api_permissions is not None:
        return {
            permission_id: has_permission(user, module_id, permission_id)
            for permission_id in all_permission_ids(module_id)
        }
    if getattr(user, "is_admin", False):
        return {permission_id: True for permission_id in all_permission_ids(module_id)}
    return {
        permission_id: has_permission(user, module_id, permission_id)
        for permission_id in all_permission_ids(module_id)
    }


def permission_tokens_for_module(module_id):
    return [
        permission_token(module_id, permission["id"])
        for permission in MODULE_PERMISSION_CATALOG.get(module_id, [])
    ]


def granular_permission_catalog(module_id):
    """Permissions suitable for assignment in the UI and to API keys."""
    return list(
        MODULE_INTERNAL_PERMISSION_CATALOG.get(module_id)
        or MODULE_PERMISSION_CATALOG.get(module_id, [])
    )


def all_permission_tokens_for_module(module_id):
    return [
        permission_token(module_id, permission_id)
        for permission_id in all_permission_ids(module_id)
    ]


def full_module_grants(module_ids=None):
    grants = []
    selected = module_ids or MODULE_PERMISSION_CATALOG.keys()
    for module_id in selected:
        if module_id not in grants:
            grants.append(module_id)
        for token in permission_tokens_for_module(module_id):
            if token not in grants:
                grants.append(token)
    return grants
