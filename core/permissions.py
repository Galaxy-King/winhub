import json

from flask import has_request_context, session


MODULE_PERMISSION_CATALOG = {
    "Infrastructure": [
        {"id": "view_hosts", "name": "View hosts"},
        {"id": "view_groups", "name": "View groups"},
        {"id": "view_queue", "name": "View task queue"},
        {"id": "view_reports", "name": "View reports"},
        {"id": "view_sensitive_reports", "name": "View sensitive report values"},
        {"id": "edit_reports", "name": "Edit reports"},
        {"id": "dismiss_reports", "name": "Dismiss reports"},
        {"id": "delete_reports", "name": "Delete reports"},
        {"id": "run_tasks", "name": "Run approved templates"},
        {"id": "manage_software", "name": "Manage software packages"},
        {"id": "send_reports", "name": "Send reports by email"},
        {"id": "manage_templates", "name": "Manage templates"},
        {"id": "manage_smtp", "name": "Manage SMTP profiles"},
        {"id": "manage_scheduler", "name": "Manage scheduler"},
        {"id": "manage_triggers", "name": "Manage triggers"},
        {"id": "manage_hosts", "name": "Block/delete hosts"},
        {"id": "manage_groups", "name": "Create/edit/delete groups"},
        {"id": "cleanup_tasks", "name": "Cleanup task history"},
    ],
    "Newsletter": [
        {"id": "send_campaigns", "name": "Send campaigns"},
        {"id": "manage_lists", "name": "Manage mailing lists"},
        {"id": "manage_smtp", "name": "Manage SMTP profiles"},
    ],
    "HistoryAudit": [
        {"id": "view_history", "name": "View history"},
        {"id": "manage_history", "name": "Cleanup/delete history"},
    ],
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
    return parse_allowed_modules(session.get("api_permissions"))


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
    allowed = parse_allowed_modules(getattr(user, "allowed_modules", None))
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
        allowed = parse_allowed_modules(getattr(user, "allowed_modules", None))

    token = permission_token(module_id, permission_id)
    tokens = module_tokens(allowed, module_id)

    if module_id in allowed:
        return True

    if token in allowed:
        return True

    return False


def user_permissions(user, module_id):
    if not user:
        return {}
    api_permissions = request_api_permissions()
    if api_permissions is not None:
        if module_id in api_permissions:
            return {p["id"]: True for p in MODULE_PERMISSION_CATALOG.get(module_id, [])}
        return {
            p["id"]: permission_token(module_id, p["id"]) in api_permissions
            for p in MODULE_PERMISSION_CATALOG.get(module_id, [])
        }
    if getattr(user, "is_admin", False):
        return {p["id"]: True for p in MODULE_PERMISSION_CATALOG.get(module_id, [])}
    return {
        p["id"]: has_permission(user, module_id, p["id"])
        for p in MODULE_PERMISSION_CATALOG.get(module_id, [])
    }


def permission_tokens_for_module(module_id):
    return [
        permission_token(module_id, permission["id"])
        for permission in MODULE_PERMISSION_CATALOG.get(module_id, [])
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
