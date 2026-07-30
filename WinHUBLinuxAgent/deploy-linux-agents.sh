#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hosts_file=""
package_path=""
ssh_user="${WINHUB_DEPLOY_SSH_USER:-root}"
ssh_port="${WINHUB_DEPLOY_SSH_PORT:-22}"
ssh_key="${WINHUB_DEPLOY_SSH_KEY:-}"
force_install=0
sync_config=1
remote_tmp="/tmp/winhub-linux-agent-deploy"

usage() {
  cat <<'EOF'
Usage:
  ./deploy-linux-agents.sh --hosts linux_hosts.txt [options]

Required files next to this script:
  WinHUBLinuxAgent-vX.Y.Z-linux-x64.tar.gz
  winhub_agent.conf
  winhub_agent.bootstrap.conf

Options:
  --hosts FILE          Text file with IPs/hosts, one per line. Lines may be root@host.
  --package FILE        Agent tar.gz package. Defaults to newest WinHUBLinuxAgent-v*-linux-x64.tar.gz next to script.
  --user USER           SSH user for lines without user@host. Default: root.
  --port PORT           SSH port. Default: 22.
  --identity FILE       SSH private key.
  --force               Install even when remote agent version is current or newer.
  --no-config-sync      Do not copy winhub_agent.conf and winhub_agent.bootstrap.conf.
  -h, --help            Show this help.

Example:
  ./deploy-linux-agents.sh --hosts linux_hosts.txt --user root --identity ~/.ssh/id_ed25519
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)
      hosts_file="${2:-}"
      shift 2
      ;;
    --package)
      package_path="${2:-}"
      shift 2
      ;;
    --user)
      ssh_user="${2:-}"
      shift 2
      ;;
    --port)
      ssh_port="${2:-}"
      shift 2
      ;;
    --identity|-i)
      ssh_key="${2:-}"
      shift 2
      ;;
    --force)
      force_install=1
      shift
      ;;
    --no-config-sync)
      sync_config=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$hosts_file" ]]; then
  echo "--hosts is required." >&2
  usage >&2
  exit 2
fi

if [[ ! -f "$hosts_file" ]]; then
  echo "Hosts file not found: $hosts_file" >&2
  exit 1
fi

if [[ -z "$package_path" ]]; then
  package_path="$(find "$script_dir" -maxdepth 1 -type f -name 'WinHUBLinuxAgent-v*-linux-x64.tar.gz' -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {print $2}')"
fi

if [[ -z "$package_path" || ! -f "$package_path" ]]; then
  echo "Agent package not found. Put WinHUBLinuxAgent-vX.Y.Z-linux-x64.tar.gz next to this script or pass --package." >&2
  exit 1
fi

runtime_config="$script_dir/winhub_agent.conf"
bootstrap_config="$script_dir/winhub_agent.bootstrap.conf"
if [[ "$sync_config" -eq 1 ]]; then
  [[ -f "$runtime_config" ]] || { echo "Missing $runtime_config" >&2; exit 1; }
  [[ -f "$bootstrap_config" ]] || { echo "Missing $bootstrap_config" >&2; exit 1; }
fi

package_name="$(basename "$package_path")"
target_version="$(sed -nE 's/^WinHUBLinuxAgent-v([0-9][^-]*)-linux-x64\.tar\.gz$/\1/p' <<< "$package_name")"
if [[ -z "$target_version" ]]; then
  echo "Cannot determine target version from package name: $package_name" >&2
  exit 1
fi

ssh_opts=(-p "$ssh_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
scp_opts=(-P "$ssh_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
if [[ -n "$ssh_key" ]]; then
  ssh_opts+=(-i "$ssh_key")
  scp_opts+=(-i "$ssh_key")
fi

version_is_older() {
  local current="$1"
  local target="$2"
  [[ "$current" != "$target" ]] && [[ "$(printf '%s\n%s\n' "$current" "$target" | sort -V | head -n1)" == "$current" ]]
}

remote_for_host() {
  local item="$1"
  if [[ "$item" == *@* ]]; then
    printf '%s' "$item"
  else
    printf '%s@%s' "$ssh_user" "$item"
  fi
}

deploy_host() {
  local host_line="$1"
  local remote
  remote="$(remote_for_host "$host_line")"
  echo "==> $remote"

  local remote_version
  if ! remote_version="$(ssh "${ssh_opts[@]}" "$remote" "if [ -x /opt/winhub-linux-agent/WinHUBLinuxAgent ]; then /opt/winhub-linux-agent/WinHUBLinuxAgent --version; else echo absent; fi" 2>&1)"; then
    echo "    SSH failed: $remote_version" >&2
    return 1
  fi
  remote_version="$(tr -d '\r' <<< "$remote_version" | tail -n1 | xargs)"
  echo "    current=$remote_version target=$target_version"

  local install_needed=0
  if [[ "$force_install" -eq 1 || "$remote_version" == "absent" ]]; then
    install_needed=1
  elif version_is_older "$remote_version" "$target_version"; then
    install_needed=1
  fi

  ssh "${ssh_opts[@]}" "$remote" "install -d -m 0700 '$remote_tmp'"
  scp "${scp_opts[@]}" "$package_path" "$remote:$remote_tmp/$package_name" >/dev/null
  if [[ "$sync_config" -eq 1 ]]; then
    scp "${scp_opts[@]}" "$runtime_config" "$bootstrap_config" "$remote:$remote_tmp/" >/dev/null
  fi

  if [[ "$install_needed" -eq 1 ]]; then
    ssh "${ssh_opts[@]}" "$remote" "set -euo pipefail
      rm -rf '$remote_tmp/extract'
      mkdir -p '$remote_tmp/extract'
      tar -xzf '$remote_tmp/$package_name' -C '$remote_tmp/extract'
      cd '$remote_tmp/extract'
      if [ '$remote_version' = 'absent' ]; then
        ./install-linux-agent.sh
      else
        ./update-linux-agent.sh --package '$remote_tmp/$package_name'
      fi
    "
    echo "    installed/updated"
  else
    echo "    install skipped; version is current or newer"
  fi

  if [[ "$sync_config" -eq 1 ]]; then
    ssh "${ssh_opts[@]}" "$remote" "set -euo pipefail
      install -d -m 0700 /etc/winhub-agent
      install -m 0600 '$remote_tmp/winhub_agent.conf' /etc/winhub-agent/winhub_agent.conf
      if [ ! -s /var/lib/winhub-agent/agent.token ]; then
        install -m 0600 '$remote_tmp/winhub_agent.bootstrap.conf' /etc/winhub-agent/winhub_agent.bootstrap.conf
      fi
      systemctl restart winhub-linux-agent
    "
    echo "    configs synced and service restarted"
  fi

  local verified_version
  verified_version="$(ssh "${ssh_opts[@]}" "$remote" "systemctl is-active --quiet winhub-linux-agent && /opt/winhub-linux-agent/WinHUBLinuxAgent --version")"
  ssh "${ssh_opts[@]}" "$remote" "rm -rf '$remote_tmp'"
  echo "    verified active, version=$verified_version"
}

mapfile -t hosts < <(sed 's/#.*//' "$hosts_file" | awk '{$1=$1}; NF {print}')
if [[ "${#hosts[@]}" -eq 0 ]]; then
  echo "Hosts file is empty after comments/blank lines are removed." >&2
  exit 1
fi

echo "Package: $package_path"
echo "Target version: $target_version"
echo "Hosts: ${#hosts[@]}"
echo

failures=0
for host in "${hosts[@]}"; do
  if ! deploy_host "$host"; then
    failures=$((failures + 1))
    echo "    FAILED: $host" >&2
  fi
  echo
done

if [[ "$failures" -gt 0 ]]; then
  echo "Completed with $failures failure(s)." >&2
  exit 1
fi

echo "Completed successfully."
