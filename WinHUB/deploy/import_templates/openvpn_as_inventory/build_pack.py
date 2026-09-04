#!/usr/bin/env python3
import json
from pathlib import Path

base = Path(__file__).resolve().parent
action_id = "db46366a-f973-4f53-b96b-c30292bc755d"
report_id = "8878c4e8-6206-48a9-bdd7-f72021a7e86e"
data = {
    "format": "winhub-template-library", "version": 1, "exported_at": "2026-07-23T00:00:00Z",
    "templates": [
        {"id": report_id, "name": "OpenVPN AS Inventory Report", "category": "OpenVPN AS", "action_type": "run_script", "type": "report", "is_approved": True, "created_by": "Template Pack", "payload": {"script": (base / "openvpn_as_inventory_report.jinja").read_text(encoding="utf-8")}},
        {"id": action_id, "name": "OpenVPN AS Inventory", "category": "OpenVPN AS", "action_type": "run_script", "type": "action", "is_approved": True, "created_by": "Template Pack", "payload": {"__report_template_id": report_id, "__agent_timeout_seconds": 300, "__template_policy": {"hide_code": False, "lock_edit": False, "lock_delete": False}, "script": (base / "openvpn_as_inventory.sh").read_text(encoding="utf-8")}},
    ],
}
(base / "openvpn_as_inventory_pack.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
