#!/usr/bin/env python3
import json
import re
from pathlib import Path


BASE = Path(__file__).resolve().parent
ACTION_ID = "f8f15dd2-994d-4a7d-8c98-e639df2f5b0e"
REPORT_ID = "c1fa1a74-18e2-4b3b-9a6b-d51e14a5823f"

script = (BASE / "vss_winrar_backup.ps1").read_text(encoding="utf-8")
report = (BASE / "vss_winrar_backup_report.jinja").read_text(encoding="utf-8")

variable_schema = {
    "project_name": {
        "type": "text",
        "label": "Project / customer",
        "default": "Backup",
        "placeholder": "2Scope",
    },
    "task_name": {
        "type": "text",
        "label": "Backup task name",
        "default": "Daily VSS backup",
        "placeholder": "term36_101",
    },
    "backup_destination": {
        "type": "text",
        "label": "SMB destination (UNC)",
        "default": "",
        "placeholder": r"\\192.168.36.201\2Scope_backup\term36_101",
    },
    "recursive_folders": {
        "type": "textarea",
        "label": "Recursive source folders (one per line)",
        "default": "C:\\Bases\nC:\\ProgramData\\Medoc",
        "placeholder": "C:\\Bases\nC:\\ProgramData\\Medoc",
    },
    "single_folders": {
        "type": "textarea",
        "label": "Single-level source folders (one per line)",
        "default": "",
        "placeholder": "C:\\Exports",
    },
    "archive_prefix": {
        "type": "text",
        "label": "Archive filename prefix",
        "default": "WinHUB",
    },
    "winrar_path": {
        "type": "text",
        "label": "RAR console executable",
        "default": r"C:\Program Files\WinRAR\Rar.exe",
    },
    "temp_root": {
        "type": "text",
        "label": "Local temporary root",
        "default": r"C:\ProgramData\WinHUB\BackupTemp",
    },
    "compression_level": {
        "type": "select",
        "label": "WinRAR compression level",
        "default": "5",
        "options": [
            {"value": "0", "label": "0 - store only"},
            {"value": "1", "label": "1 - fastest"},
            {"value": "2", "label": "2 - fast"},
            {"value": "3", "label": "3 - normal"},
            {"value": "4", "label": "4 - good"},
            {"value": "5", "label": "5 - best"},
        ],
    },
    "verify_mode": {
        "type": "select",
        "label": "Verification after SMB copy",
        "default": "Size",
        "options": [
            {"value": "Size", "label": "Compare file size"},
            {"value": "SHA256", "label": "Compare SHA256 (slower)"},
            {"value": "None", "label": "No verification"},
        ],
    },
    "retention_days": {
        "type": "number",
        "label": "Retention on SMB destination (days; 0 disables)",
        "default": "0",
        "placeholder": "30",
    },
    "fail_on_missing_source": {
        "type": "checkbox",
        "label": "Fail when a configured source folder is missing",
        "checkbox_label": "Treat a missing source folder as an error",
        "default": "true",
    },
}

variables = set(re.findall(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}", script))
missing_schema = sorted(variables - set(variable_schema))
unused_schema = sorted(set(variable_schema) - variables)
if missing_schema or unused_schema:
    raise SystemExit(
        f"Variable schema mismatch. Missing: {missing_schema or '-'}; unused: {unused_schema or '-'}"
    )

data = {
    "format": "winhub-template-library",
    "version": 1,
    "exported_at": "2026-08-04T00:00:00Z",
    "templates": [
        {
            "id": REPORT_ID,
            "name": "VSS WinRAR Backup Report",
            "category": "Backup",
            "action_type": "run_script",
            "type": "report",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {
                "script": report,
                "__template_policy": {
                    "hide_code": False,
                    "lock_edit": False,
                    "lock_delete": False,
                    "disable_run": False,
                },
            },
        },
        {
            "id": ACTION_ID,
            "name": "VSS WinRAR Backup to SMB",
            "category": "Backup",
            "action_type": "run_script",
            "type": "action",
            "is_approved": True,
            "created_by": "Template Pack",
            "payload": {
                "__report_template_id": REPORT_ID,
                "__agent_timeout_seconds": 86400,
                "__variable_schema": variable_schema,
                "__template_policy": {
                    "hide_code": False,
                    "lock_edit": False,
                    "lock_delete": False,
                    "disable_run": False,
                },
                "script": script,
            },
        },
    ],
}

(BASE / "vss_winrar_backup_pack.json").write_text(
    json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
