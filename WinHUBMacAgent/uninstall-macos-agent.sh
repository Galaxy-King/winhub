#!/bin/bash
set -euo pipefail

readonly label="com.winhub.agent"
readonly install_dir="/Library/PrivilegedHelperTools/com.winhub.agent"
readonly config_dir="/Library/Application Support/WinHUB/Config"
readonly data_dir="/Library/Application Support/WinHUB/Data"
readonly log_dir="/Library/Logs/WinHUB"
readonly plist_path="/Library/LaunchDaemons/${label}.plist"
readonly newsyslog_path="/etc/newsyslog.d/${label}.conf"
purge=0

while (($#)); do
  case "$1" in
    --purge) purge=1; shift ;;
    --help|-h)
      printf 'Usage: sudo ./uninstall-macos-agent.sh [--purge]\n'
      printf 'Without --purge, enrollment identity, configuration and logs are retained.\n'
      exit 0
      ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
/bin/launchctl bootout system/"${label}" 2>/dev/null || true
/bin/rm -f "${plist_path}"
/bin/rm -f "${newsyslog_path}"
/bin/rm -rf "${install_dir}"
/usr/sbin/pkgutil --forget "${label}" >/dev/null 2>&1 || true

if [[ ${purge} -eq 1 ]]; then
  /bin/rm -rf "${config_dir}" "${data_dir}" "${log_dir}"
  /bin/rmdir "/Library/Application Support/WinHUB" 2>/dev/null || true
  echo "Agent, configuration, enrollment identity, update backups and logs were permanently removed."
else
  echo "Agent removed. Configuration, enrollment identity and logs were retained under /Library."
fi
