#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly config_dir="/Library/Application Support/WinHUB/Config"
readonly data_dir="/Library/Application Support/WinHUB/Data"
readonly log_dir="/Library/Logs/WinHUB"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly source_dir="$(cd "$(dirname "$0")" && pwd -P)"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || die "Run with sudo: sudo ./install-macos-agent.sh"
[[ $(uname -s) == "Darwin" ]] || die "This package supports macOS only."
[[ $(uname -m) == "arm64" ]] || die "This package is for Apple Silicon (arm64)."
[[ -f "${source_dir}/WinHUBMacAgent" ]] || die "WinHUBMacAgent is missing from the package."
[[ -f "${source_dir}/${label}.plist" ]] || die "${label}.plist is missing."

if [[ ${WINHUB_ALLOW_UNSIGNED:-0} != "1" ]]; then
  /usr/bin/codesign --verify --deep --strict --verbose=2 "${source_dir}/WinHUBMacAgent" \
    || die "Agent signature is invalid. For local development only, set WINHUB_ALLOW_UNSIGNED=1."
fi

/bin/launchctl bootout system/"${label}" 2>/dev/null || true
/usr/bin/install -d -o root -g wheel -m 0755 "${install_dir}" "${config_dir}" "${log_dir}"
/usr/bin/install -d -o root -g wheel -m 0700 "${data_dir}"

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
/usr/bin/plutil -lint "${plist_path}" >/dev/null

if [[ ! -f "${config_dir}/winhub_agent.conf" ]]; then
  runtime_config_source="${source_dir}/winhub_agent.conf.example"
  [[ -f "${source_dir}/winhub_agent.conf" ]] && runtime_config_source="${source_dir}/winhub_agent.conf"
  /usr/bin/install -o root -g wheel -m 0600 "${runtime_config_source}" "${config_dir}/winhub_agent.conf"
fi
if [[ -f "${source_dir}/winhub_agent.bootstrap.conf" && ! -f "${data_dir}/agent.token" ]]; then
  /usr/bin/install -o root -g wheel -m 0600 "${source_dir}/winhub_agent.bootstrap.conf" "${config_dir}/winhub_agent.bootstrap.conf"
fi

/usr/sbin/chown -R root:wheel "${install_dir}" "${config_dir}" "${data_dir}" "${log_dir}" "${plist_path}"
/bin/chmod 0700 "${data_dir}"
/bin/chmod 0600 "${config_dir}"/*.conf 2>/dev/null || true
/bin/chmod 0755 "${install_dir}/WinHUBMacAgent" "${install_dir}"/*.sh
if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
  /usr/bin/codesign --force --deep --sign - "${install_dir}/WinHUBMacAgent"
  /usr/bin/codesign --verify --deep --strict "${install_dir}/WinHUBMacAgent"
fi
/bin/launchctl bootstrap system "${plist_path}"
/bin/launchctl enable system/"${label}"
/bin/launchctl kickstart -k system/"${label}"

printf '%s\n' \
  "WinHUB macOS Agent installed." \
  "Configuration: ${config_dir}/winhub_agent.conf" \
  "Logs: ${log_dir}/agent.log and agent-error.log"
