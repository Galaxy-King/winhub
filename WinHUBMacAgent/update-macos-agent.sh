#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly newsyslog_path="/etc/newsyslog.d/${label}.conf"
readonly backup_root="/Library/Application Support/WinHUB/Data/backups"
package_path=""
expected_version=""

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

verify_arm64_binary() {
  /usr/bin/file "$1" | /usr/bin/grep -q 'arm64' || die "$1 does not contain the arm64 architecture."
}

signed_team_id() {
  local binary="$1"
  local details
  /usr/bin/codesign --verify --strict --verbose=2 "${binary}" || die "Invalid code signature: ${binary}"
  details="$(/usr/bin/codesign -dvvv "${binary}" 2>&1)"
  printf '%s\n' "${details}" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}'
}

signed_identifier() {
  local binary="$1"
  /usr/bin/codesign -dvvv "${binary}" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}'
}

verify_hardened_runtime() {
  /usr/bin/codesign -dvvv "$1" 2>&1 | /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' \
    || die "Hardened Runtime is missing from $1."
}

verify_launchdaemon_plist() {
  local candidate="$1"
  /usr/bin/plutil -lint "${candidate}" >/dev/null
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "${candidate}")" == "${label}" ]] \
    || die "LaunchDaemon label is invalid."
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "${candidate}")" == "${install_dir}/WinHUBMacAgent" ]] \
    || die "LaunchDaemon executable path is invalid."
}

verify_signed_release() {
  local release_dir="$1"
  local required_team="$2"
  local main_team
  local item
  local item_team
  main_team="$(signed_team_id "${release_dir}/WinHUBMacAgent")"
  [[ -n "${main_team}" && "${main_team}" != "not set" ]] \
    || die "Production update requires a non-ad-hoc Apple code signature."
  [[ "${main_team}" == "${required_team}" ]] \
    || die "Updated agent TeamIdentifier ${main_team} does not match installed TeamIdentifier ${required_team}."
  [[ "$(signed_identifier "${release_dir}/WinHUBMacAgent")" == "${label}" ]] \
    || die "Updated agent code-signing identifier must be ${label}."
  verify_hardened_runtime "${release_dir}/WinHUBMacAgent"
  while IFS= read -r -d '' item; do
    [[ "${item}" == "${release_dir}/WinHUBMacAgent" ]] && continue
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      item_team="$(signed_team_id "${item}")"
      [[ "${item_team}" == "${main_team}" ]] || die "Mach-O files are signed by different Apple teams."
    fi
  done < <(/usr/bin/find "${release_dir}" -maxdepth 1 -type f -print0)
}

while (($#)); do
  case "$1" in
    --package|-p) [[ $# -ge 2 ]] || die "Missing package path."; package_path="$2"; shift 2 ;;
    --expected-version) [[ $# -ge 2 ]] || die "Missing expected version."; expected_version="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "Updater must run as root."
[[ $(uname -s) == "Darwin" ]] || die "Updater supports macOS only."
[[ $(uname -m) == "arm64" ]] || die "This update is for Apple Silicon only."
macos_major="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)"
[[ "${macos_major}" =~ ^[0-9]+$ && "${macos_major}" -ge 14 ]] \
  || die "A .NET 8-supported macOS release (14 or newer) is required."
[[ -f "${package_path}" ]] || die "Package not found."
[[ -f "${install_dir}/WinHUBMacAgent" ]] || die "Installed agent binary was not found."
[[ -f "${plist_path}" ]] || die "Installed LaunchDaemon plist was not found."
if [[ -n "${expected_version}" ]]; then
  [[ "${expected_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] \
    || die "Invalid expected version: ${expected_version}"
fi

tmp_dir="$(/usr/bin/mktemp -d -t winhub-agent-update)"
trap '/bin/rm -rf "${tmp_dir}"' EXIT

# Reject absolute paths, parent traversal, links and device files before extraction.
while IFS= read -r entry; do
  [[ -n "${entry}" ]] || continue
  normalized="${entry}"
  while [[ "${normalized}" == ./* ]]; do normalized="${normalized#./}"; done
  [[ -z "${normalized}" || "${normalized}" == "." ]] && continue
  [[ "${normalized}" != /* && "/${normalized}/" != *"/../"* && "${normalized}" != -* ]] \
    || die "Unsafe archive path: ${entry}"
done < <(/usr/bin/tar -tzf "${package_path}")
if /usr/bin/tar -tvzf "${package_path}" | /usr/bin/awk '$1 ~ /^[lhbcps]/ { bad=1 } END { exit bad ? 0 : 1 }'; then
  die "Archive contains links or special files."
fi

/usr/bin/tar -xzf "${package_path}" -C "${tmp_dir}" --no-same-owner
[[ -f "${tmp_dir}/WinHUBMacAgent" ]] || die "Update does not contain WinHUBMacAgent."
[[ -f "${tmp_dir}/${label}.plist" ]] || die "Update does not contain ${label}.plist."
[[ -f "${tmp_dir}/${label}.newsyslog.conf" ]] || die "Update does not contain ${label}.newsyslog.conf."
verify_arm64_binary "${tmp_dir}/WinHUBMacAgent"
verify_launchdaemon_plist "${tmp_dir}/${label}.plist"

if [[ ${WINHUB_ALLOW_UNSIGNED:-0} != "1" ]]; then
  installed_team="$(signed_team_id "${install_dir}/WinHUBMacAgent")"
  [[ -n "${installed_team}" && "${installed_team}" != "not set" ]] \
    || die "Installed agent does not have a production Apple TeamIdentifier."
  verify_signed_release "${tmp_dir}" "${installed_team}"
fi

actual_version="$("${tmp_dir}/WinHUBMacAgent" --version)"
[[ -n "${actual_version}" ]] || die "Updated agent did not report a version."
if [[ -n "${expected_version}" && "${actual_version}" != "${expected_version}" ]]; then
  die "Update package version ${actual_version} does not match expected ${expected_version}."
fi

stage_dir="${tmp_dir}/stage"
/usr/bin/install -d -o root -g wheel -m 0755 "${stage_dir}"
while IFS= read -r -d '' item; do
  name="${item##*/}"
  case "${name}" in
    WinHUBMacAgent|*.dylib|*.sh) mode=0755 ;;
    *.json|README.md) mode=0644 ;;
    *) continue ;;
  esac
  /usr/bin/install -o root -g wheel -m "${mode}" "${item}" "${stage_dir}/${name}"
done < <(/usr/bin/find "${tmp_dir}" -maxdepth 1 -type f -print0)

if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
  while IFS= read -r -d '' item; do
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --sign - "${item}"
    fi
  done < <(/usr/bin/find "${stage_dir}" -maxdepth 1 -type f -print0)
fi

backup_dir="${backup_root}/$(/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
/usr/bin/install -d -o root -g wheel -m 0700 "${backup_dir}/install"
/bin/cp -a "${install_dir}/." "${backup_dir}/install/"
/bin/cp -p "${plist_path}" "${backup_dir}/${label}.plist"
newsyslog_backup_exists=0
if [[ -f "${newsyslog_path}" ]]; then
  /bin/cp -p "${newsyslog_path}" "${backup_dir}/${label}.newsyslog.conf"
  newsyslog_backup_exists=1
fi

rollback() {
  set +e
  /bin/launchctl bootout system/"${label}" 2>/dev/null
  /bin/rm -rf "${install_dir}"
  /usr/bin/install -d -o root -g wheel -m 0755 "${install_dir}"
  /bin/cp -a "${backup_dir}/install/." "${install_dir}/"
  /usr/bin/install -o root -g wheel -m 0644 "${backup_dir}/${label}.plist" "${plist_path}"
  if [[ ${newsyslog_backup_exists} -eq 1 ]]; then
    /usr/bin/install -o root -g wheel -m 0644 "${backup_dir}/${label}.newsyslog.conf" "${newsyslog_path}"
  else
    /bin/rm -f "${newsyslog_path}"
  fi
  /bin/launchctl bootstrap system "${plist_path}" 2>/dev/null
  /bin/launchctl enable system/"${label}" 2>/dev/null
  /bin/launchctl kickstart -k system/"${label}" 2>/dev/null
}

rollback_on_error() {
  status=$?
  trap - ERR
  rollback
  exit "${status}"
}
trap rollback_on_error ERR

/bin/launchctl bootout system/"${label}" 2>/dev/null || true
/bin/rm -rf "${install_dir}"
/usr/bin/install -d -o root -g wheel -m 0755 "${install_dir}"
/bin/cp -a "${stage_dir}/." "${install_dir}/"
/usr/sbin/chown -R root:wheel "${install_dir}"
/usr/bin/install -o root -g wheel -m 0644 "${tmp_dir}/${label}.plist" "${plist_path}"
/usr/bin/install -o root -g wheel -m 0644 "${tmp_dir}/${label}.newsyslog.conf" "${newsyslog_path}"
/usr/bin/plutil -lint "${plist_path}" >/dev/null

/bin/launchctl bootstrap system "${plist_path}"
/bin/launchctl enable system/"${label}"
/bin/launchctl kickstart -k system/"${label}"

service_running=0
for _ in 1 2 3 4 5; do
  service_state="$(/bin/launchctl print system/"${label}" 2>/dev/null || true)"
  if [[ "${service_state}" == *"state = running"* ]]; then
    service_running=1
    break
  fi
  /bin/sleep 1
done
[[ ${service_running} -eq 1 ]] || die "Updated LaunchDaemon did not stay running."

trap - ERR
/bin/rm -f "${package_path}"
printf 'WinHUB macOS Agent updated. Backup: %s\n' "${backup_dir}"
