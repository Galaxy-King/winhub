#!/usr/bin/env bash
# Canonical updater; also packaged with the Linux agent. No installed-agent CLI dependency.
set -euo pipefail
umask 077

extract_update() {
  python3 - "$1" "$2" <<'PY'
import os
from pathlib import Path
import tarfile
import sys

root = Path(sys.argv[2]).resolve()
if any(root.iterdir()):
    raise ValueError('Staging must be empty')
total = 0
with tarfile.open(sys.argv[1], 'r|gz') as archive:
    for index, member in enumerate(archive, 1):
        name = member.name
        parts = name.split('/')
        total += member.size
        if index > 4096 or member.size > 512 * 1024**2 or total > 2 * 1024**3:
            raise ValueError('Expanded archive limits exceeded')
        if (len(name) > 512 or name.startswith('/') or '\\' in name or ':' in name
                or '..' in parts or member.size < 0
                or any(p.endswith(' ') or (p != '.' and p.endswith('.')) for p in parts)):
            raise ValueError('Unsafe archive path')
        if not (member.isdir() or member.isreg()) or member.issparse():
            raise ValueError('Links and special files are forbidden')
        target = root.joinpath(name).resolve()
        if not target.is_relative_to(root):
            raise ValueError('Archive escapes staging')
        if member.isdir():
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with archive.extractfile(member) as source, target.open('xb') as output:
            remaining = member.size
            while remaining:
                block = source.read(min(remaining, 81920))
                if not block:
                    raise ValueError('Truncated archive')
                output.write(block)
                remaining -= len(block)
            output.flush()
            os.fsync(output.fileno())
PY
}

assert_path() {
  [[ "$(realpath -m -- "$1")" == "$1" && ! -L "$1" ]] || { echo "Unsafe path: $1" >&2; return 1; }
}

main() {
  local package='' expected_sha256='__WINHUB_AUTHORIZED_SHA256__'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --package|-p) package="${2:?Package argument required}"; shift 2 ;;
      --expected-sha256) expected_sha256="${2:?Hash argument required}"; shift 2 ;;
      *) echo "Unknown argument: $1" >&2; return 2 ;;
    esac
  done
  [[ $EUID == 0 ]] || { echo 'Run the updater as root.' >&2; return 1; }
  [[ "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || { echo 'An authorized SHA-256 is required.' >&2; return 1; }
  [[ -f "$package" && ! -L "$package" ]] || { echo 'Package missing or linked.' >&2; return 1; }
  command -v python3 >/dev/null
  command -v flock >/dev/null
  [[ -x /usr/bin/setsid ]] || { echo 'util-linux is required.' >&2; return 1; }
  install_dir=/opt/winhub-linux-agent
  data_dir=/var/lib/winhub-agent
  service_name=winhub-linux-agent.service
  unit_path="/etc/systemd/system/$service_name"
  for directory in "$install_dir" "$data_dir" "$data_dir/updates" "$data_dir/backups"; do
    assert_path "$directory"
    mkdir -p -- "$directory"
    chown root:root "$directory"
    chmod 0700 "$directory"
  done
  assert_path "$unit_path"
  assert_path "$data_dir/updates/updater.lock"
  exec 9>"$data_dir/updates/updater.lock"
  flock -n 9 || { echo 'Another updater is running.' >&2; return 1; }
  work="$(mktemp -d "$data_dir/updates/stage-XXXXXXXX")"
  backup=''
  stopped=0
  backup_complete=0
  trap cleanup EXIT
  [[ $(stat -c %s -- "$package") -le 536870912 ]] || { echo 'Package too large.' >&2; return 1; }
  cp -- "$package" "$work/package.tar.gz"
  local actual
  actual="$(sha256sum -- "$work/package.tar.gz" | cut -d ' ' -f1)"
  [[ "${actual,,}" == "${expected_sha256,,}" ]] || { echo 'Package SHA-256 mismatch.' >&2; return 1; }
  mkdir "$work/files"
  extract_update "$work/package.tar.gz" "$work/files"
  python3 - "$work/files/update-protocol.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    descriptor = json.load(stream)
if descriptor.get('protocol') != 2 or descriptor.get('platform') != 'linux':
    raise ValueError('Package does not support safe update preflight')
PY
  for entry in WinHUBLinuxAgent update-linux-agent.sh "$service_name"; do
    [[ -f "$work/files/$entry" ]] || { echo "Package missing $entry" >&2; return 1; }
  done
  chmod 0700 "$work/files/WinHUBLinuxAgent"
  "$work/files/WinHUBLinuxAgent" --validate-config /etc/winhub-agent/winhub_agent.conf
  "$work/files/WinHUBLinuxAgent" --check-update-server /etc/winhub-agent/winhub_agent.conf
  [[ -z "$(find "$install_dir" -type l -print -quit)" ]] || { echo 'Linked install contents.' >&2; return 1; }
  # All failure-prone package/config/TLS checks above run before stopping the old service.
  systemctl stop "$service_name"
  stopped=1
  if systemctl is-active --quiet "$service_name"; then echo 'Old service is still running.' >&2; return 1; fi
  backup="$(mktemp -d "$data_dir/backups/update-XXXXXXXX")"
  cp -a -- "$install_dir" "$backup/code"
  cp -a -- "$unit_path" "$backup/unit"
  backup_complete=1
  replace_code "$work/files"
  install -m 0644 "$install_dir/$service_name" "$unit_path"
  systemctl daemon-reload
  systemctl start "$service_name"
  sleep 10
  systemctl is-active --quiet "$service_name"
  echo "Update installed. Backup: $backup. Confirm new version and a task in Fleet Center."
}

replace_code() {
  assert_path "$install_dir"
  [[ "$install_dir" == /opt/winhub-linux-agent ]] || return 1
  # Refuse links before deleting anything; keep any legacy runtime config untouched.
  [[ -z "$(find "$install_dir" -type l -print -quit)" ]] || { echo 'Linked install contents.' >&2; return 1; }
  find "$install_dir" -mindepth 1 -maxdepth 1 ! -name winhub_agent.conf ! -name winhub_agent.bootstrap.conf -exec rm -rf -- {} + || return 1
  while IFS= read -r -d '' entry; do cp -a -- "$entry" "$install_dir/" || return 1; done < <(
    find "$1" -mindepth 1 -maxdepth 1 ! -name winhub_agent.conf ! -name winhub_agent.bootstrap.conf -print0
  )
  chmod 0700 "$install_dir/WinHUBLinuxAgent" "$install_dir"/*.sh
}

cleanup() {
  local result=$?
  trap - EXIT
  if [[ $result != 0 && $stopped == 1 ]]; then
    echo 'Update failed; attempting code rollback without rewinding live config/state.' >&2
    # Never copy over a running process. Report failure rather than hide it.
    if systemctl stop "$service_name"; then
      if [[ $backup_complete == 1 ]]; then
        if ! replace_code "$backup/code" || ! cp -a -- "$backup/unit" "$unit_path"; then
          echo "ROLLBACK FAILED. Backup: $backup" >&2
          exit "$result"
        fi
        systemctl daemon-reload || true
      fi
      systemctl start "$service_name" || echo "ROLLBACK START FAILED. Backup: $backup" >&2
    else
      echo "Cannot stop service for rollback. Backup: $backup" >&2
    fi
  fi
  assert_path "$work"
  [[ "$work" == "$data_dir/updates/"stage-* ]] || exit 1
  rm -rf -- "$work"
  exit "$result"
}

# Parse all functions before the updater replaces its own installed source file.
main "$@"
