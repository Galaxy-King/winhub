import argparse
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from core.config import Config


def timestamp():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def backup_postgres(output_dir):
    database_uri = Config.SQLALCHEMY_DATABASE_URI
    if not database_uri.startswith("postgresql"):
        raise RuntimeError("PostgreSQL backup requires DATABASE_URI or POSTGRES_* settings.")

    ensure_dir(output_dir)
    dump_path = os.path.join(output_dir, f"winhub_pg_{timestamp()}.dump")
    subprocess.run(
        ["pg_dump", "--format=custom", "--file", dump_path, database_uri],
        check=True,
    )
    return dump_path


def backup_runtime_files(output_dir):
    ensure_dir(output_dir)
    copied = []
    for name in ("master_key.enc", "sys_secret.enc", "infra_smtp_profiles.json", "infra_template_secrets.json"):
        source = os.path.join(Config.DATA_DIR, name)
        if os.path.exists(source):
            destination = os.path.join(output_dir, name)
            shutil.copy2(source, destination)
            copied.append(destination)
    return copied


def production_check():
    checks = []
    rate_limit_ok = bool(Config.RATELIMIT_STORAGE_URI)
    rate_limit_detail = Config.RATELIMIT_STORAGE_URI
    if Config.RATELIMIT_STORAGE_URI == "memory://":
        rate_limit_detail = "memory:// (single-server mode; Redis optional for stricter production)"
    checks.append(("DATABASE_URI", Config.SQLALCHEMY_DATABASE_URI.startswith("postgresql"), Config.SAFE_DATABASE_URI))
    checks.append(("SECRET_KEY", not Config.SECRET_KEY.startswith("default-dev-secret-key"), "set a long random SECRET_KEY"))
    checks.append(("RATELIMIT_STORAGE_URI", rate_limit_ok, rate_limit_detail or "set memory:// or redis://..."))
    checks.append(("AGENT_API_KEY", Config.AGENT_API_KEY != "WinHUB-Secret-Enroll-2026", "set a long random AGENT_API_KEY"))
    checks.append(("AGENT_TASK_HMAC_SECRET", Config.AGENT_TASK_HMAC_SECRET != Config.SECRET_KEY, "set a separate random AGENT_TASK_HMAC_SECRET"))
    checks.append(("AGENT_ENROLLMENT_ALLOWLIST", True, Config.AGENT_ENROLLMENT_ALLOWLIST or "empty: global enrollment, rely on Pending approval and enrollment rate limit"))
    checks.append(("AGENT_ALLOW_REENROLL_EXISTING", not Config.AGENT_ALLOW_REENROLL_EXISTING, "keep false unless intentionally recovering agents"))
    checks.append(("SESSION_COOKIE_SECURE", bool(Config.SESSION_COOKIE_SECURE), "enable secure cookies when serving HTTPS"))
    checks.append(("SESSION_COOKIE_SAMESITE", Config.SESSION_COOKIE_SAMESITE in ("Strict", "Lax"), Config.SESSION_COOKIE_SAMESITE))
    checks.append(("SESSION_IDLE_TIMEOUT_SECONDS", 0 < Config.SESSION_IDLE_TIMEOUT_SECONDS <= 21600, f"{Config.SESSION_IDLE_TIMEOUT_SECONDS}s"))
    checks.append(("DATA_DIR", os.path.isdir(Config.DATA_DIR), Config.DATA_DIR))
    return checks


def main():
    parser = argparse.ArgumentParser(description="WinHUB production helper")
    sub = parser.add_subparsers(dest="command", required=True)
    backup = sub.add_parser("backup", help="Create PostgreSQL dump and copy encrypted runtime files")
    backup.add_argument("--output-dir", default=os.path.join(Config.DATA_DIR, "backups"))
    sub.add_parser("check", help="Print production readiness checks")
    args = parser.parse_args()

    if args.command == "backup":
        db_dump = backup_postgres(args.output_dir)
        files = backup_runtime_files(args.output_dir)
        print(f"Database backup: {db_dump}")
        print("Runtime files:")
        for path in files:
            print(f" - {path}")
    elif args.command == "check":
        failed = False
        for name, ok, detail in production_check():
            print(f"[{'OK' if ok else 'WARN'}] {name}: {detail}")
            failed = failed or not ok
        raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
