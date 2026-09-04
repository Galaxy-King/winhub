#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT="${BACKUP_ROOT:-/var/lib/winhub/backups}"
BACKUP_DIR="${1:-${BACKUP_ROOT}/latest}"
APP_DIR="${APP_DIR:-/opt/winhub}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/debian/rollback_winhub.sh [backup-dir]"
  exit 1
fi

if [[ -L "${BACKUP_DIR}" ]]; then
  BACKUP_DIR="$(readlink -f "${BACKUP_DIR}")"
fi

echo "[WinHUB] Rolling back using ${BACKUP_DIR}"
"${APP_DIR}/deploy/debian/restore_winhub.sh" "${BACKUP_DIR}"
