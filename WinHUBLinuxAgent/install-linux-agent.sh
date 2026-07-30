#!/usr/bin/env bash
set -euo pipefail

install_dir="${WINHUB_AGENT_INSTALL_DIR:-/opt/winhub-linux-agent}"
config_dir="${WINHUB_AGENT_CONFIG_DIR:-/etc/winhub-agent}"
data_dir="${WINHUB_AGENT_DATA_DIR:-/var/lib/winhub-agent}"
service_name="winhub-linux-agent.service"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./install-linux-agent.sh" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported system: /etc/os-release is missing." >&2
  exit 1
fi
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
  debian:*|ubuntu:*|*:debian*|*:ubuntu*) ;;
  *) echo "Warning: ${PRETTY_NAME:-unknown Linux} is not an officially tested Debian/Ubuntu/Proxmox platform." >&2 ;;
esac

command -v systemctl >/dev/null || { echo "systemd is required." >&2; exit 1; }

systemctl stop "$service_name" 2>/dev/null || true
mkdir -p "$install_dir" "$config_dir" "$data_dir"
cp -a . "$install_dir/"
chmod 0755 "$install_dir"
chmod 0755 "$install_dir/WinHUBLinuxAgent" "$install_dir"/*.sh
chmod 0700 "$data_dir"
chown -R root:root "$install_dir" "$config_dir" "$data_dir"

if [[ ! -f "$config_dir/winhub_agent.conf" ]]; then
  cp "$install_dir/winhub_agent.conf.example" "$config_dir/winhub_agent.conf"
  chmod 0600 "$config_dir/winhub_agent.conf"
fi

if [[ ! -f "$config_dir/winhub_agent.bootstrap.conf" && -f "$install_dir/winhub_agent.bootstrap.conf" ]]; then
  cp "$install_dir/winhub_agent.bootstrap.conf" "$config_dir/winhub_agent.bootstrap.conf"
  chmod 0600 "$config_dir/winhub_agent.bootstrap.conf"
fi

cp "$install_dir/$service_name" "/etc/systemd/system/$service_name"
systemctl daemon-reload
systemctl enable --now "$service_name"

echo "Installed WinHUB Linux Agent."
echo "Edit $config_dir/winhub_agent.conf and create $config_dir/winhub_agent.bootstrap.conf for first enrollment if needed."
echo "Logs: journalctl -u $service_name -f"
