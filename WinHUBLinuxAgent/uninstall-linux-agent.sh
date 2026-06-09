#!/usr/bin/env bash
set -euo pipefail

service_name="winhub-linux-agent.service"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./uninstall-linux-agent.sh" >&2
  exit 1
fi

systemctl disable --now "$service_name" 2>/dev/null || true
rm -f "/etc/systemd/system/$service_name"
systemctl daemon-reload

echo "Service removed. Runtime data remains in /var/lib/winhub-agent and config remains in /etc/winhub-agent."
