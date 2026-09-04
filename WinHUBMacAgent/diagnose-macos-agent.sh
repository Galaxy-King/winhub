#!/bin/bash
set -uo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly config_dir="/Library/Application Support/WinHUB/Config"
readonly data_dir="/Library/Application Support/WinHUB/Data"
readonly log_dir="/Library/Logs/WinHUB"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly newsyslog_path="/etc/newsyslog.d/${label}.conf"
readonly binary="${install_dir}/WinHUBMacAgent"
failures=0
warnings=0

pass() { printf '[PASS] %s\n' "$*"; }
warn() { warnings=$((warnings + 1)); printf '[WARN] %s\n' "$*"; }
fail() { failures=$((failures + 1)); printf '[FAIL] %s\n' "$*"; }

printf 'WinHUB macOS Agent production diagnostics\n'
printf 'Timestamp: %s\n\n' "$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')"

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] && pass 'Operating system is macOS.' || fail 'This host is not macOS.'
[[ "$(/usr/bin/uname -m)" == "arm64" ]] && pass 'Architecture is Apple Silicon arm64.' || fail 'Architecture is not arm64.'
if [[ ${EUID} -ne 0 ]]; then
  warn 'Run with sudo for complete permission, state and network checks.'
fi

if [[ -f "${binary}" ]]; then
  /usr/bin/file "${binary}" | /usr/bin/grep -q 'arm64' && pass 'Agent binary contains arm64 code.' || fail 'Agent binary is not arm64.'
  if /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "${binary}" >/dev/null 2>&1; then
    pass 'Apple code signature is valid.'
    signature_details="$(/usr/bin/codesign -dvvv "${binary}" 2>&1)"
    identifier="$(printf '%s\n' "${signature_details}" | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
    team_id="$(printf '%s\n' "${signature_details}" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "${identifier}" == "${label}" ]] && pass "Code-signing identifier is ${label}." || fail "Unexpected code-signing identifier: ${identifier:-missing}."
    [[ -n "${team_id}" && "${team_id}" != "not set" ]] && pass "Developer Team ID: ${team_id}." || fail 'Production Developer Team ID is missing.'
    printf '%s\n' "${signature_details}" | /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' \
      && pass 'Hardened Runtime is enabled.' || fail 'Hardened Runtime flag is missing.'
  else
    fail 'Apple code signature verification failed.'
  fi
  version="$("${binary}" --version 2>/dev/null || true)"
  [[ -n "${version}" ]] && pass "Agent version: ${version}." || fail 'Agent version check failed.'
else
  fail "Agent binary is missing at ${binary}."
fi

if [[ -f "${plist_path}" ]] && /usr/bin/plutil -lint "${plist_path}" >/dev/null 2>&1; then
  pass 'LaunchDaemon plist is valid.'
  plist_label="$(/usr/libexec/PlistBuddy -c 'Print :Label' "${plist_path}" 2>/dev/null || true)"
  plist_program="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "${plist_path}" 2>/dev/null || true)"
  [[ "${plist_label}" == "${label}" ]] && pass 'LaunchDaemon label is correct.' || fail "Unexpected LaunchDaemon label: ${plist_label:-missing}."
  [[ "${plist_program}" == "${binary}" ]] && pass 'LaunchDaemon executable path is correct.' || fail "Unexpected LaunchDaemon executable: ${plist_program:-missing}."
else
  fail 'LaunchDaemon plist is missing or invalid.'
fi
[[ -f "${newsyslog_path}" ]] && pass 'newsyslog rotation policy is installed.' || warn 'newsyslog rotation policy is missing.'

config_path="${config_dir}/winhub_agent.conf"
if [[ -f "${config_path}" ]] && /usr/bin/plutil -lint "${config_path}" >/dev/null 2>&1; then
  pass 'Runtime configuration is valid JSON.'
  server_url="$(/usr/bin/plutil -extract ServerUrl raw -o - "${config_path}" 2>/dev/null || true)"
  case "${server_url}" in
    https://?*) pass "Server URL uses HTTPS: ${server_url}." ;;
    *) fail "Server URL is missing or not HTTPS: ${server_url:-missing}." ;;
  esac
  ignore_tls="$(/usr/bin/plutil -extract IgnoreTlsCertificateErrors raw -o - "${config_path}" 2>/dev/null || true)"
  [[ "${ignore_tls}" == "false" ]] && pass 'TLS certificate bypass is disabled.' || fail 'IgnoreTlsCertificateErrors must be false.'
  require_signature="$(/usr/bin/plutil -extract RequireTaskSignature raw -o - "${config_path}" 2>/dev/null || true)"
  [[ "${require_signature}" == "true" ]] && pass 'Task signature validation is required.' || fail 'RequireTaskSignature must be true.'
else
  fail 'Runtime configuration is missing or invalid.'
  server_url=""
fi

for protected_path in "${config_dir}" "${data_dir}"; do
  if [[ -e "${protected_path}" ]]; then
    owner="$(/usr/bin/stat -f '%Su:%Sg' "${protected_path}" 2>/dev/null || true)"
    [[ "${owner}" == "root:wheel" ]] && pass "Ownership is root:wheel: ${protected_path}." || fail "Unexpected ownership ${owner:-unknown}: ${protected_path}."
  fi
done
if [[ -s "${data_dir}/agent.token" ]]; then
  pass 'Enrollment token exists.'
elif [[ -s "${config_dir}/winhub_agent.bootstrap.conf" ]]; then
  warn 'Enrollment is pending; bootstrap configuration still exists.'
else
  warn 'Neither an enrollment token nor bootstrap configuration exists.'
fi

service_state="$(/bin/launchctl print system/"${label}" 2>&1 || true)"
if [[ "${service_state}" == *"state = running"* ]]; then
  pass 'LaunchDaemon is running.'
else
  fail 'LaunchDaemon is not running.'
fi

if [[ -n "${server_url}" && ${EUID} -eq 0 ]]; then
  if /usr/bin/curl --silent --show-error --head --max-time 10 "${server_url}" >/dev/null 2>&1; then
    pass 'HTTPS connection to WinHUB completed.'
  else
    warn 'HTTPS connection check failed; inspect DNS, routing, proxy and TLS trust.'
  fi
fi

if [[ -f "${log_dir}/agent-error.log" ]]; then
  error_size="$(/usr/bin/stat -f '%z' "${log_dir}/agent-error.log" 2>/dev/null || printf '0')"
  [[ "${error_size}" == "0" ]] && pass 'Agent error log is empty.' || warn "Agent error log contains ${error_size} bytes; inspect its latest entries."
fi

printf '\nSummary: failures=%d warnings=%d\n' "${failures}" "${warnings}"
[[ ${failures} -eq 0 ]]
