#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly backup_root="/Library/Application Support/WinHUB/Data/backups"
package_path=""

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --package|-p) [[ $# -ge 2 ]] || die "Missing package path."; package_path="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done
[[ ${EUID} -eq 0 ]] || die "Updater must run as root."
[[ -f "${package_path}" ]] || die "Package not found."
[[ $(uname -m) == "arm64" ]] || die "This update is for Apple Silicon only."

tmp_dir="$(/usr/bin/mktemp -d -t winhub-agent-update)"
trap '/bin/rm -rf "${tmp_dir}"' EXIT

# Reject absolute paths, parent traversal, links and device files before extraction.
while IFS= read -r entry; do
  [[ -n "${entry}" ]] || continue
  [[ "${entry}" != /* && "${entry}" != *"../"* && "${entry}" != ".." ]] || die "Unsafe archive path: ${entry}"
done < <(/usr/bin/tar -tzf "${package_path}")
if /usr/bin/tar -tvzf "${package_path}" | /usr/bin/awk '$1 ~ /^[lhbcps]/ { bad=1 } END { exit bad ? 0 : 1 }'; then
  die "Archive contains links or special files."
fi

/usr/bin/tar -xzf "${package_path}" -C "${tmp_dir}" --no-same-owner
[[ -f "${tmp_dir}/WinHUBMacAgent" ]] || die "Update does not contain WinHUBMacAgent."
if [[ ${WINHUB_ALLOW_UNSIGNED:-0} != "1" ]]; then
  /usr/bin/codesign --verify --deep --strict --verbose=2 "${tmp_dir}/WinHUBMacAgent" || die "Updated agent signature is invalid."
fi

backup_dir="${backup_root}/$(/bin/date -u +%Y%m%dT%H%M%SZ)"
/usr/bin/install -d -o root -g wheel -m 0700 "${backup_dir}"
/bin/cp -a "${install_dir}/." "${backup_dir}/"
/bin/launchctl bootout system/"${label}" 2>/dev/null || true

rollback() {
  /bin/rm -rf "${install_dir}"
  /usr/bin/install -d -o root -g wheel -m 0755 "${install_dir}"
  /bin/cp -a "${backup_dir}/." "${install_dir}/"
  /bin/launchctl bootstrap system "/Library/LaunchDaemons/${label}.plist" 2>/dev/null || true
}
trap 'rollback; /bin/rm -rf "${tmp_dir}"' ERR

while IFS= read -r -d '' item; do
  name="${item##*/}"
  case "${name}" in
    WinHUBMacAgent|*.dylib|*.sh) mode=0755 ;;
    *.json|README.md) mode=0644 ;;
    *) continue ;;
  esac
  /usr/bin/install -o root -g wheel -m "${mode}" "${item}" "${install_dir}/${name}"
done < <(/usr/bin/find "${tmp_dir}" -maxdepth 1 -type f -print0)
/bin/launchctl bootstrap system "/Library/LaunchDaemons/${label}.plist"
/bin/launchctl kickstart -k system/"${label}"
trap '/bin/rm -rf "${tmp_dir}"' EXIT
echo "WinHUB macOS Agent updated. Backup: ${backup_dir}"
