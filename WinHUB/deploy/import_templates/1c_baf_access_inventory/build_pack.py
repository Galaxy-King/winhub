#!/usr/bin/env python3
import json
from pathlib import Path


BASE = Path(__file__).resolve().parent
ACTION_ID = "f5c28e6c-34e8-4927-a772-c9c1c3f20801"
REPORT_ID = "a4d079e8-8384-46a9-9b08-a20ce1bb3147"

script = (BASE / "1c_baf_access_inventory.ps1").read_text(encoding="utf-8")
report = (BASE / "1c_baf_access_inventory_report.jinja").read_text(encoding="utf-8")

template_policy = {
    "hide_code": False,
    "lock_edit": False,
    "lock_delete": False,
    "disable_run": False,
}

data = {
    "format": "winhub-template-library",
    "version": 1,
    "exported_at": "2026-08-21T00:00:00Z",
    "templates": [
        {
            "id": REPORT_ID,
            "name": "1C / BAF Access Inventory Report",
            "category": "Inventory",
            "action_type": "run_script",
            "type": "report",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {
                "script": report,
                "__template_policy": template_policy,
            },
        },
        {
            "id": ACTION_ID,
            "name": "1C / BAF Access Inventory",
            "category": "Inventory",
            "action_type": "run_script",
            "type": "action",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {
                "__report_template_id": REPORT_ID,
                "__agent_timeout_seconds": 300,
                "__variable_schema": {},
                "__template_policy": template_policy,
                "script": script,
            },
        },
    ],
}

(BASE / "1c_baf_access_inventory_pack.json").write_text(
    json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
