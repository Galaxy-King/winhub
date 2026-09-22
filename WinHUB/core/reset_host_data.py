"""Erase endpoint-derived operational data while preserving server configuration.

This is intentionally a standalone maintenance command.  It never runs from the
web application and defaults to a read-only inventory.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from flask import Flask
from sqlalchemy import delete, func, select

from core.config import Config
from core.database import db


CONFIRMATION = "ERASE-WINHUB-HOST-DATA"

# Child/derived tables come first so the operation works with SQLite tests and
# PostgreSQL even when a historical installation lacks an expected CASCADE.
RESET_TABLES = (
    "report_deliveries",
    "report_revisions",
    "ai_report_requests",
    "aggregated_jobs",
    "history_search_tokens",
    "agent_tasks",
    "telemetry_history",
    "connection_ip_history",
    "endpoint_metrics",
    "endpoint_duplicate_exceptions",
    "endpoint_group_membership",
    "agent_update_rollouts",
    "scheduled_tasks",
    "trigger_rules",
    "tasks",
    "registration_history",
    "audit_logs",
    "api_key_group_access",
    "user_group_access",
    "endpoints",
    "endpoint_groups",
)


def _tables(metadata):
    missing = [name for name in RESET_TABLES if name not in metadata.tables]
    if missing:
        raise RuntimeError("Database schema is missing reset tables: " + ", ".join(missing))
    return [metadata.tables[name] for name in RESET_TABLES]


def inventory_counts(connection, metadata) -> dict[str, int]:
    return {
        table.name: int(connection.execute(select(func.count()).select_from(table)).scalar_one())
        for table in _tables(metadata)
    }


def erase_host_data(connection, metadata) -> dict[str, int]:
    before = inventory_counts(connection, metadata)
    for table in _tables(metadata):
        connection.execute(delete(table))
    remaining = inventory_counts(connection, metadata)
    not_empty = {name: count for name, count in remaining.items() if count}
    if not_empty:
        raise RuntimeError(f"Host reset verification failed; rows remain: {not_empty}")
    return before


def reset_host_runtime_files(data_dir: str) -> list[str]:
    """Clear active host-targeted JSON state; backups and logs are retained."""
    changed: list[str] = []
    for name in ("infra_scheduled_reports.json",):
        path = Path(data_dir) / name
        if not path.exists():
            continue
        temporary = path.with_name(path.name + ".reset-tmp")
        temporary.write_text("[]\n", encoding="utf-8")
        os.replace(temporary, path)
        changed.append(str(path))
    return changed


def build_app() -> Flask:
    app = Flask("winhub-host-reset")
    app.config.from_object(Config)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory or erase WinHUB endpoints, groups, tasks, telemetry, reports, "
            "schedules, rollouts, registration and audit history. Users, API keys, "
            "task templates, integration profiles, TLS and network config are preserved."
        )
    )
    parser.add_argument("--execute", action="store_true", help="perform the reset; default is read-only")
    parser.add_argument("--confirm", default="", help=f"required with --execute: {CONFIRMATION}")
    args = parser.parse_args(argv)
    if args.execute and args.confirm != CONFIRMATION:
        parser.error(f"--execute requires --confirm {CONFIRMATION}")

    app = build_app()
    with app.app_context():
        if args.execute:
            with db.engine.begin() as connection:
                counts = erase_host_data(connection, db.metadata)
            files = reset_host_runtime_files(Config.DATA_DIR)
            print(json.dumps({"mode": "executed", "deleted_rows": counts, "reset_files": files}, indent=2))
        else:
            with db.engine.connect() as connection:
                counts = inventory_counts(connection, db.metadata)
            print(json.dumps({"mode": "dry-run", "rows_that_would_be_deleted": counts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
