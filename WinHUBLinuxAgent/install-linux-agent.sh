#!/usr/bin/env bash
set -euo pipefail
umask 077

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
[[ -x /usr/bin/systemd-run && -f /sys/fs/cgroup/cgroup.controllers ]] || { echo 'systemd-run and cgroup v2 are required for bounded tasks.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required for safe update extraction.' >&2; exit 1; }
command -v flock >/dev/null || { echo 'util-linux/flock is required for safe updates.' >&2; exit 1; }
[[ -x /usr/bin/setsid ]] || { echo 'Install util-linux: /usr/bin/setsid is required for task cleanup.' >&2; exit 1; }
for agent_path in "$install_dir" "$config_dir" "$data_dir"; do
  [[ "$agent_path" == /* && "$(realpath -m "$agent_path")" == "$agent_path" && ! -L "$agent_path" ]] || { echo 'Agent paths must be absolute and contain no symlinks.' >&2; exit 1; }
done

if [[ ! -f "$config_dir/winhub_agent.conf" ]]; then
  echo "Prepare $config_dir/winhub_agent.conf with a trusted certificate pin before installing." >&2
  exit 1
fi
./WinHUBLinuxAgent --validate-config "$config_dir/winhub_agent.conf"

# A bundled public key is first-install bootstrap trust, authenticated by the
# administrator's trusted package transfer/checksum. It never rotates existing trust.
bundled_trust='./release-signing-public.pem'
installed_trust="$data_dir/release-signing-public.pem"
if [[ -e "$bundled_trust" || -L "$bundled_trust" ]]; then
  [[ -f "$bundled_trust" && ! -L "$bundled_trust" ]] || { echo 'Invalid bundled public key.' >&2; exit 1; }
  if [[ -e "$installed_trust" || -L "$installed_trust" ]]; then
    [[ -f "$installed_trust" && ! -L "$installed_trust" ]] && cmp -s "$bundled_trust" "$installed_trust" || { echo 'Existing release trust differs; explicit key rotation required.' >&2; exit 1; }
  fi
  # Read-only: validates public SPKI, publisher signature, inventory and rollback floor.
  ./WinHUBLinuxAgent --verify-release "$PWD" "$bundled_trust" "$data_dir/release-state.json" 0.0.0 ''
fi

systemctl stop "$service_name" 2>/dev/null || true
mkdir -p "$install_dir" "$config_dir" "$data_dir"
cp -a . "$install_dir/"
chmod 0755 "$install_dir"
chmod 0755 "$install_dir/WinHUBLinuxAgent" "$install_dir"/*.sh
chmod 0700 "$data_dir"
chmod 0700 "$config_dir"
chmod 0600 "$config_dir/winhub_agent.conf"
chown -R root:root "$install_dir" "$config_dir" "$data_dir"
if [[ -f "$bundled_trust" && ! -e "$installed_trust" ]]; then
  install -o root -g root -m 0600 "$bundled_trust" "$installed_trust"
fi

if [[ ! -f "$config_dir/winhub_agent.conf" ]]; then
  cp "$install_dir/winhub_agent.conf.example" "$config_dir/winhub_agent.conf"
  chmod 0600 "$config_dir/winhub_agent.conf"
fi

if [[ ! -f "$config_dir/winhub_agent.bootstrap.conf" && -f "$install_dir/winhub_agent.bootstrap.conf" ]]; then
  cp "$install_dir/winhub_agent.bootstrap.conf" "$config_dir/winhub_agent.bootstrap.conf"
  chmod 0600 "$config_dir/winhub_agent.bootstrap.conf"
fi

cp "$install_dir/$service_name" "/etc/systemd/system/$service_name"
chmod 0644 "/etc/systemd/system/$service_name"
systemctl daemon-reload
systemctl enable --now "$service_name"

echo "Installed WinHUB Linux Agent."
echo "Edit $config_dir/winhub_agent.conf and create $config_dir/winhub_agent.bootstrap.conf for first enrollment if needed."
echo "Logs: journalctl -u $service_name -f"
