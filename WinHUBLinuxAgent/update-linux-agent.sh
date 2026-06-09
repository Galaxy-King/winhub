#!/usr/bin/env bash
set -euo pipefail

package_path=""
install_dir="${WINHUB_AGENT_INSTALL_DIR:-/opt/winhub-linux-agent}"
service_name="winhub-linux-agent.service"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package|-p)
      package_path="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./update-linux-agent.sh --package PACKAGE.tar.gz" >&2
  exit 1
fi

if [[ -z "$package_path" || ! -f "$package_path" ]]; then
  echo "Package not found: $package_path" >&2
  exit 1
fi

backup_dir="/var/lib/winhub-agent/backups/$(date +%Y%m%d_%H%M%S)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$backup_dir"
if [[ -d "$install_dir" ]]; then
  cp -a "$install_dir/." "$backup_dir/"
fi

tar -xzf "$package_path" -C "$tmp_dir"
systemctl stop "$service_name" 2>/dev/null || true
mkdir -p "$install_dir"
cp -a "$tmp_dir/." "$install_dir/"
chmod 0755 "$install_dir/WinHUBLinuxAgent" "$install_dir"/*.sh
cp "$install_dir/$service_name" "/etc/systemd/system/$service_name"
systemctl daemon-reload
systemctl enable --now "$service_name"

echo "Updated WinHUB Linux Agent. Backup: $backup_dir"
