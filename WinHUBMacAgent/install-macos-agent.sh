#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly config_dir="/Library/Application Support/WinHUB/Config"
readonly data_dir="/Library/Application Support/WinHUB/Data"
readonly log_dir="/Library/Logs/WinHUB"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly newsyslog_path="/etc/newsyslog.d/${label}.conf"
readonly source_dir="$(cd "$(dirname "$0")" && pwd -P)"
readonly expected_team_id="${WINHUB_EXPECTED_TEAM_ID:-}"
runtime_config_source=""
bootstrap_config_source=""

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
  /usr/bin/codesign -dvvv "$1" 2>&1 | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}'
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

verify_config_source() {
  local candidate="$1"
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || die "Configuration must be a regular file: ${candidate}"
  /usr/bin/plutil -lint "${candidate}" >/dev/null || die "Invalid configuration: ${candidate}"
}

verify_signed_release() {
  local release_dir="$1"
  local main_team
  local item
  local item_team
  main_team="$(signed_team_id "${release_dir}/WinHUBMacAgent")"
  [[ -n "${main_team}" && "${main_team}" != "not set" ]] \
    || die "Production installation requires a non-ad-hoc Apple code signature."
  [[ "$(signed_identifier "${release_dir}/WinHUBMacAgent")" == "${label}" ]] \
    || die "Agent code-signing identifier must be ${label}."
  verify_hardened_runtime "${release_dir}/WinHUBMacAgent"
  if [[ -n "${expected_team_id}" && "${main_team}" != "${expected_team_id}" ]]; then
    die "Agent TeamIdentifier ${main_team} does not match expected ${expected_team_id}."
  fi
  while IFS= read -r -d '' item; do
    [[ "${item}" == "${release_dir}/WinHUBMacAgent" ]] && continue
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      item_team="$(signed_team_id "${item}")"
      [[ "${item_team}" == "${main_team}" ]] || die "Mach-O files are signed by different Apple teams."
    fi
  done < <(/usr/bin/find "${release_dir}" -maxdepth 1 -type f -print0)
  printf '%s' "${main_team}"
}

while (($#)); do
  case "$1" in
    --config) [[ $# -ge 2 ]] || die "Missing --config path."; runtime_config_source="$2"; shift 2 ;;
    --bootstrap-config) [[ $# -ge 2 ]] || die "Missing --bootstrap-config path."; bootstrap_config_source="$2"; shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

adhoc_sign_installed_tree() {
  local item
  while IFS= read -r -d '' item; do
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --sign - "${item}"
    fi
  done < <(/usr/bin/find "${install_dir}" -maxdepth 1 -type f -print0)
}

[[ ${EUID} -eq 0 ]] || die "Run with sudo: sudo ./install-macos-agent.sh"
[[ $(uname -s) == "Darwin" ]] || die "This package supports macOS only."
[[ $(uname -m) == "arm64" ]] || die "This package is for Apple Silicon (arm64)."
macos_major="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)"
[[ "${macos_major}" =~ ^[0-9]+$ && "${macos_major}" -ge 14 ]] \
  || die "A .NET 8-supported macOS release (14 or newer) is required."
[[ -f "${source_dir}/WinHUBMacAgent" ]] || die "WinHUBMacAgent is missing from the package."
[[ -f "${source_dir}/${label}.plist" ]] || die "${label}.plist is missing."
[[ -f "${source_dir}/${label}.newsyslog.conf" ]] || die "${label}.newsyslog.conf is missing."
verify_arm64_binary "${source_dir}/WinHUBMacAgent"
verify_launchdaemon_plist "${source_dir}/${label}.plist"

if [[ -z "${runtime_config_source}" ]]; then
  runtime_config_source="${source_dir}/winhub_agent.conf.example"
  [[ -f "${source_dir}/winhub_agent.conf" ]] && runtime_config_source="${source_dir}/winhub_agent.conf"
fi
if [[ -z "${bootstrap_config_source}" && -f "${source_dir}/winhub_agent.bootstrap.conf" ]]; then
  bootstrap_config_source="${source_dir}/winhub_agent.bootstrap.conf"
fi
verify_config_source "${runtime_config_source}"
if [[ -n "${bootstrap_config_source}" ]]; then verify_config_source "${bootstrap_config_source}"; fi

team_id=""
if [[ ${WINHUB_ALLOW_UNSIGNED:-0} != "1" ]]; then
  team_id="$(verify_signed_release "${source_dir}")"
fi

/bin/launchctl bootout system/"${label}" 2>/dev/null || true
/usr/bin/install -d -o root -g wheel -m 0755 "${install_dir}" "${config_dir}" "${log_dir}"
/usr/bin/install -d -o root -g wheel -m 0700 "${data_dir}"
/bin/rm -f "${install_dir}/WinHUBMacAgent" "${install_dir}"/*.dylib "${install_dir}"/*.sh "${install_dir}"/*.json "${install_dir}/README.md"

while IFS= read -r -d '' item; do
  name="${item##*/}"
  case "${name}" in
    WinHUBMacAgent|*.dylib|*.sh)
      /usr/bin/install -o root -g wheel -m 0755 "${item}" "${install_dir}/${name}"
      ;;
    *.json|README.md)
      /usr/bin/install -o root -g wheel -m 0644 "${item}" "${install_dir}/${name}"
      ;;
  esac
done < <(/usr/bin/find "${source_dir}" -maxdepth 1 -type f -print0)

/usr/bin/install -o root -g wheel -m 0644 "${source_dir}/${label}.plist" "${plist_path}"
/usr/bin/install -o root -g wheel -m 0644 "${source_dir}/${label}.newsyslog.conf" "${newsyslog_path}"
/usr/bin/plutil -lint "${plist_path}" >/dev/null

if [[ ! -f "${config_dir}/winhub_agent.conf" ]]; then
  /usr/bin/install -o root -g wheel -m 0600 "${runtime_config_source}" "${config_dir}/winhub_agent.conf"
fi
if [[ -n "${bootstrap_config_source}" && ! -f "${data_dir}/agent.token" ]]; then
  /usr/bin/install -o root -g wheel -m 0600 "${bootstrap_config_source}" "${config_dir}/winhub_agent.bootstrap.conf"
fi

/usr/sbin/chown -R root:wheel "${install_dir}" "${config_dir}" "${data_dir}" "${log_dir}" "${plist_path}" "${newsyslog_path}"
/bin/chmod 0700 "${data_dir}"
/bin/chmod 0600 "${config_dir}"/*.conf 2>/dev/null || true
/bin/chmod 0755 "${install_dir}/WinHUBMacAgent" "${install_dir}"/*.sh
if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
  adhoc_sign_installed_tree
fi

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
[[ ${service_running} -eq 1 ]] || die "LaunchDaemon did not stay running. Check ${log_dir}/agent-error.log."

printf '%s\n' \
  "WinHUB macOS Agent installed and running." \
  "Apple Team ID: ${team_id:-development-ad-hoc}" \
  "Configuration: ${config_dir}/winhub_agent.conf" \
  "Logs: ${log_dir}/agent.log and agent-error.log"
