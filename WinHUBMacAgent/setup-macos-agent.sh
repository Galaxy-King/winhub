#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly source_dir="$(cd "$(dirname "$0")" && pwd -P)"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly config_dir="/Library/Application Support/WinHUB/Config"
readonly data_dir="/Library/Application Support/WinHUB/Data"
readonly log_dir="/Library/Logs/WinHUB"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly provisioning_dir="/private/var/tmp/${label}.provisioning"
work_dir="$(/usr/bin/mktemp -d -t winhub-agent-setup)"
runtime_config=""
bootstrap_config=""
package_path=""
provisioning_staged=0

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: ./setup-macos-agent.sh [--pkg PATH] [--config PATH --bootstrap-config PATH]

Without config arguments the script securely prompts for the WinHUB URL and secrets.
If exactly one .pkg is beside this script, the signed installer path is used automatically.
EOF
}

cleanup() {
  /bin/rm -rf "${work_dir}"
  if [[ ${provisioning_staged} -eq 1 ]]; then
    /usr/bin/sudo /bin/rm -rf "${provisioning_dir}" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM
/bin/chmod 0700 "${work_dir}"

while (($#)); do
  case "$1" in
    --pkg) [[ $# -ge 2 ]] || die "Missing --pkg path."; package_path="$2"; shift 2 ;;
    --config) [[ $# -ge 2 ]] || die "Missing --config path."; runtime_config="$2"; shift 2 ;;
    --bootstrap-config) [[ $# -ge 2 ]] || die "Missing --bootstrap-config path."; bootstrap_config="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

validate_config_file() {
  local candidate="$1"
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || die "Configuration must be a regular file: ${candidate}"
  /usr/bin/plutil -lint "${candidate}" >/dev/null || die "Invalid JSON configuration: ${candidate}"
}

create_interactive_config() {
  runtime_config="${work_dir}/winhub_agent.conf"
  bootstrap_config="${work_dir}/winhub_agent.bootstrap.conf"

  printf 'WinHUB HTTPS server URL: '
  IFS= read -r server_url
  case "${server_url}" in
    https://?*) ;;
    *) die "The server URL must start with https://." ;;
  esac
  [[ "${server_url}" != *[[:space:]]* ]] || die "The server URL must not contain whitespace."

  printf 'Enrollment key: '
  IFS= read -r -s enrollment_key
  printf '\nTask HMAC secret: '
  IFS= read -r -s task_secret
  printf '\n'
  [[ -n "${enrollment_key}" && -n "${task_secret}" ]] || die "Both secrets are required."

  /usr/bin/plutil -create xml1 "${runtime_config}"
  /usr/bin/plutil -insert ServerUrl -string "${server_url%/}" "${runtime_config}"
  /usr/bin/plutil -insert PollIntervalSeconds -integer 30 "${runtime_config}"
  /usr/bin/plutil -insert PollJitterSeconds -integer 30 "${runtime_config}"
  /usr/bin/plutil -insert StartupSpreadSeconds -integer 120 "${runtime_config}"
  /usr/bin/plutil -insert DefaultTaskTimeoutSeconds -integer 1800 "${runtime_config}"
  /usr/bin/plutil -insert MaxResultLogBytes -integer 262144 "${runtime_config}"
  /usr/bin/plutil -insert IgnoreTlsCertificateErrors -bool false "${runtime_config}"
  /usr/bin/plutil -insert ServerCertificateSha256 -string "" "${runtime_config}"
  /usr/bin/plutil -insert RequireTaskSignature -bool true "${runtime_config}"
  /usr/bin/plutil -insert ExecutionMode -string "allowlist" "${runtime_config}"
  /usr/bin/plutil -insert AllowedActions -json '["agent_update"]' "${runtime_config}"
  /usr/bin/plutil -insert AllowCrossHostUpdateDownloads -bool false "${runtime_config}"
  /usr/bin/plutil -insert RestartAfterConsecutivePollFailures -integer 10 "${runtime_config}"
  /usr/bin/plutil -convert json "${runtime_config}"

  /usr/bin/plutil -create xml1 "${bootstrap_config}"
  /usr/bin/plutil -insert GlobalApiKey -string "${enrollment_key}" "${bootstrap_config}"
  /usr/bin/plutil -insert TaskHmacSecret -string "${task_secret}" "${bootstrap_config}"
  /usr/bin/plutil -convert json "${bootstrap_config}"
  /bin/chmod 0600 "${runtime_config}" "${bootstrap_config}"
  unset enrollment_key task_secret server_url
}

wait_for_service() {
  local service_running=0
  local service_state=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    service_state="$(/usr/bin/sudo /bin/launchctl print system/"${label}" 2>/dev/null || true)"
    if [[ "${service_state}" == *"state = running"* ]]; then
      service_running=1
      break
    fi
    /bin/sleep 1
  done
  [[ ${service_running} -eq 1 ]] || die "LaunchDaemon did not stay running. Check ${log_dir}/agent-error.log."
}

verify_installed_identity() {
  local details
  local installed_team
  local installed_identifier
  /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "${install_dir}/WinHUBMacAgent" \
    || die "Installed agent code signature is invalid."
  details="$(/usr/bin/codesign -dvvv "${install_dir}/WinHUBMacAgent" 2>&1)"
  installed_team="$(printf '%s\n' "${details}" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  installed_identifier="$(printf '%s\n' "${details}" | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
  [[ "${installed_identifier}" == "${label}" ]] || die "Installed agent identifier is not ${label}."
  printf '%s\n' "${details}" | /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' \
    || die "Installed agent does not use Hardened Runtime."
  if [[ -n ${WINHUB_EXPECTED_TEAM_ID:-} && "${installed_team}" != "${WINHUB_EXPECTED_TEAM_ID}" ]]; then
    die "Installed agent Team ID ${installed_team:-missing} does not match WINHUB_EXPECTED_TEAM_ID."
  fi
}

configure_installed_agent() {
  [[ -f "${install_dir}/WinHUBMacAgent" && -f "${plist_path}" ]] \
    || die "Installed WinHUB agent files are incomplete. Reinstall the signed package."
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 0755 "${config_dir}" "${log_dir}"
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 0700 "${data_dir}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0600 "${runtime_config}" "${config_dir}/winhub_agent.conf"
  if [[ ! -f "${data_dir}/agent.token" ]]; then
    /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0600 "${bootstrap_config}" "${config_dir}/winhub_agent.bootstrap.conf"
  else
    printf 'Existing enrollment token retained; bootstrap secrets were not reinstalled.\n'
  fi
  if ! /usr/bin/sudo /bin/launchctl print system/"${label}" >/dev/null 2>&1; then
    /usr/bin/sudo /bin/launchctl bootstrap system "${plist_path}"
  fi
  /usr/bin/sudo /bin/launchctl enable system/"${label}"
  /usr/bin/sudo /bin/launchctl kickstart -k system/"${label}"
  wait_for_service
}

run_direct_installer() {
  local installer="${source_dir}/install-macos-agent.sh"
  [[ -x "${installer}" ]] || die "install-macos-agent.sh is missing or not executable."
  if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
    /usr/bin/sudo /usr/bin/env WINHUB_ALLOW_UNSIGNED=1 "${installer}" --config "${runtime_config}" --bootstrap-config "${bootstrap_config}"
  elif [[ -n ${WINHUB_EXPECTED_TEAM_ID:-} ]]; then
    /usr/bin/sudo /usr/bin/env WINHUB_EXPECTED_TEAM_ID="${WINHUB_EXPECTED_TEAM_ID}" "${installer}" --config "${runtime_config}" --bootstrap-config "${bootstrap_config}"
  else
    /usr/bin/sudo "${installer}" --config "${runtime_config}" --bootstrap-config "${bootstrap_config}"
  fi
}

verify_installer_package() {
  local signature_details
  [[ -f "${package_path}" && ! -L "${package_path}" ]] || die "Installer package not found: ${package_path}"
  signature_details="$(/usr/sbin/pkgutil --check-signature "${package_path}" 2>&1)" \
    || die "Installer package signature is invalid."
  printf '%s\n' "${signature_details}" | /usr/bin/grep -q 'Developer ID Installer:' \
    || die "The package is not signed with Developer ID Installer."
  if [[ -n ${WINHUB_EXPECTED_TEAM_ID:-} ]]; then
    printf '%s\n' "${signature_details}" | /usr/bin/grep -F "(${WINHUB_EXPECTED_TEAM_ID})" >/dev/null \
      || die "Installer Team ID does not match WINHUB_EXPECTED_TEAM_ID."
  fi
  /usr/sbin/spctl --assess --type install --verbose=2 "${package_path}" \
    || die "Gatekeeper rejected the package. It must be signed and notarized."
}

run_package_installer() {
  verify_installer_package
  /usr/bin/sudo /bin/rm -rf "${provisioning_dir}"
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 0700 "${provisioning_dir}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0600 "${runtime_config}" "${provisioning_dir}/winhub_agent.conf"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0600 "${bootstrap_config}" "${provisioning_dir}/winhub_agent.bootstrap.conf"
  provisioning_staged=1
  /usr/bin/sudo /usr/sbin/installer -pkg "${package_path}" -target /
  provisioning_staged=0
  /usr/bin/sudo /bin/rm -rf "${provisioning_dir}"
  verify_installed_identity
  wait_for_service
}

if [[ -z "${runtime_config}" && -z "${bootstrap_config}" ]]; then
  if [[ -f "${source_dir}/winhub_agent.conf" && -f "${source_dir}/winhub_agent.bootstrap.conf" ]]; then
    runtime_config="${source_dir}/winhub_agent.conf"
    bootstrap_config="${source_dir}/winhub_agent.bootstrap.conf"
    printf 'Using winhub_agent.conf and winhub_agent.bootstrap.conf beside the setup script.\n'
  else
    create_interactive_config
  fi
elif [[ -z "${runtime_config}" || -z "${bootstrap_config}" ]]; then
  die "Both --config and --bootstrap-config must be supplied together."
fi
validate_config_file "${runtime_config}"
validate_config_file "${bootstrap_config}"

if [[ -z "${package_path}" ]]; then
  shopt -s nullglob
  package_candidates=("${source_dir}"/WinHUBMacAgent-v*-macos-arm64.pkg)
  shopt -u nullglob
  if [[ ${#package_candidates[@]} -eq 1 ]]; then
    package_path="${package_candidates[0]}"
  elif [[ ${#package_candidates[@]} -gt 1 ]]; then
    die "More than one installer package is beside the setup script; select one with --pkg."
  fi
fi

if [[ -n "${package_path}" ]]; then
  run_package_installer
elif [[ "${source_dir}" == "${install_dir}" ]]; then
  configure_installed_agent
else
  run_direct_installer
fi

printf '%s\n' \
  "WinHUB macOS Agent is installed, configured and running." \
  "Status: sudo launchctl print system/${label}" \
  "Logs: ${log_dir}/agent.log and agent-error.log"
