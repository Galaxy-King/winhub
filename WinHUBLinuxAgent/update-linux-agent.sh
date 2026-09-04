#!/usr/bin/env bash
set -euo pipefail
umask 077

package_path=""
expected_sha256=""
install_dir="${WINHUB_AGENT_INSTALL_DIR:-/opt/winhub-linux-agent}"
service_name="winhub-linux-agent.service"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package|-p)
      package_path="${2:-}"
      shift 2
      ;;
    --expected-sha256)
      expected_sha256="${2:-}"
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
[[ "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || { echo 'An authorized SHA-256 is required.' >&2; exit 1; }
actual_sha256="$(sha256sum -- "$package_path" | cut -d ' ' -f1)"
[[ "${actual_sha256,,}" == "${expected_sha256,,}" ]] || { echo 'Package SHA-256 mismatch.' >&2; exit 1; }
[[ "$install_dir" == /opt/winhub-linux-agent && ! -L "$install_dir" ]] || { echo 'Unsafe install path.' >&2; exit 1; }
[[ "$(realpath -m "$install_dir")" == "$install_dir" ]] || { echo 'Install path must not contain symlinks.' >&2; exit 1; }
[[ -x /usr/bin/setsid ]] || { echo 'Install util-linux: /usr/bin/setsid is required.' >&2; exit 1; }

backup_dir="/var/lib/winhub-agent/backups/$(date +%Y%m%d_%H%M%S)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$backup_dir"
if [[ -d "$install_dir" ]]; then
  cp -a "$install_dir/." "$backup_dir/"
fi

"$install_dir/WinHUBLinuxAgent" --extract-update "$package_path" "$tmp_dir"
[[ -f "$tmp_dir/WinHUBLinuxAgent" && -f "$tmp_dir/$service_name" ]] || { echo 'Incomplete update package.' >&2; exit 1; }
chmod 0755 "$tmp_dir/WinHUBLinuxAgent"
"$tmp_dir/WinHUBLinuxAgent" --validate-config /etc/winhub-agent/winhub_agent.conf
stopped=0
rollback() {
  result=$?
  if [[ $result -ne 0 && $stopped == 1 ]]; then
    echo "Update failed; restoring executable files from $backup_dir" >&2
    cp -a "$backup_dir/." "$install_dir/"
    cp "$install_dir/$service_name" "/etc/systemd/system/$service_name"
    systemctl daemon-reload
    systemctl start "$service_name" || true
  fi
  rm -rf -- "$tmp_dir"
  exit "$result"
}
trap rollback EXIT
systemctl stop "$service_name" 2>/dev/null || true
stopped=1
mkdir -p "$install_dir"
cp -a "$tmp_dir/." "$install_dir/"
chmod 0755 "$install_dir/WinHUBLinuxAgent" "$install_dir"/*.sh
cp "$install_dir/$service_name" "/etc/systemd/system/$service_name"
systemctl daemon-reload
systemctl enable --now "$service_name"
sleep 3
systemctl is-active --quiet "$service_name"

echo "Updated WinHUB Linux Agent. Backup: $backup_dir"
