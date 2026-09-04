REQUIRED_MODULES = ["Infrastructure", "HistoryAudit"]

MODULE_REGISTRY = {}


def reset_module_registry():
    MODULE_REGISTRY.clear()


def set_module_status(module_id, **updates):
    current = MODULE_REGISTRY.get(module_id, {
        "id": module_id,
        "name": module_id,
        "url": f"/module/{module_id}",
        "icon": "",
        "status": "disabled",
        "required": module_id in REQUIRED_MODULES,
        "optional": module_id not in REQUIRED_MODULES,
        "error_message": None,
    })
    current.update(updates)
    current["required"] = module_id in REQUIRED_MODULES
    current["optional"] = module_id not in REQUIRED_MODULES
    MODULE_REGISTRY[module_id] = current
    return current


def get_module_registry():
    return MODULE_REGISTRY


def get_loaded_modules():
    return [m for m in MODULE_REGISTRY.values() if m.get("status") == "loaded"]
