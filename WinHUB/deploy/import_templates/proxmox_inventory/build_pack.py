#!/usr/bin/env python3
import json
from pathlib import Path

base = Path(__file__).resolve().parent
script = (base / "proxmox_inventory.sh").read_text(encoding="utf-8")
report = (base / "proxmox_inventory_report.jinja").read_text(encoding="utf-8")
data = {
    "format": "winhub-template-library",
    "version": 1,
    "exported_at": "2026-07-22T00:00:00Z",
    "templates": [
        {
            "id": "3a6e2b5c-a2ac-4d21-962c-7c91bd70a2b8",
            "name": "Proxmox Inventory Report",
            "category": "Proxmox",
            "action_type": "run_script",
            "type": "report",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {"script": report},
        },
        {
            "id": "2cb8f3a8-3743-4478-8542-c9c658fcae86",
            "name": "Proxmox Cluster Inventory",
            "category": "Proxmox",
            "action_type": "run_script",
            "type": "action",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {
                "__report_template_id": "3a6e2b5c-a2ac-4d21-962c-7c91bd70a2b8",
                "__template_policy": {"hide_code": False, "lock_edit": False, "lock_delete": False},
                "script": script,
            },
        },
    ],
}
(base / "proxmox_inventory_pack.json").write_text(
    json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
