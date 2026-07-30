#!/bin/bash
set -euo pipefail

readonly label="com.winhub.agent"
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
/bin/launchctl bootout system/"${label}" 2>/dev/null || true
/bin/rm -f "/Library/LaunchDaemons/${label}.plist"
/bin/rm -rf "/Library/PrivilegedHelperTools/com.winhub.agent"
echo "Agent removed. Configuration, identity and logs were retained under /Library."
