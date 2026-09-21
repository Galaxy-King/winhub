#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
EXECUTE=false
CONFIRM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute) EXECUTE=true; shift ;;
    --confirm) CONFIRM="${2:-}"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ${APP_DIR}/deploy/debian/reset_host_data.sh [--execute --confirm ERASE-WINHUB-HOST-DATA]" >&2
  exit 1
fi
if [[ ! -x "${APP_DIR}/venv/bin/python" || ! -f "${APP_DIR}/core/reset_host_data.py" || ! -f "${ENV_FILE}" ]]; then
  echo "WinHUB runtime, reset command or env file is missing." >&2
  exit 1
fi

run_reset() {
  (
    cd "${APP_DIR}"
    set -a
    # This is the same root-owned EnvironmentFile consumed by systemd.
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
    WINHUB_ROLE=maintenance WINHUB_DISABLE_SCHEDULER=true \
      runuser -u winhub --preserve-environment -- \
      "${APP_DIR}/venv/bin/python" -m core.reset_host_data "$@"
  )
}

if [[ "${EXECUTE}" != true ]]; then
  echo "[WinHUB] Read-only host-data reset inventory"
  run_reset
  echo "[WinHUB] No data changed. Execute only after reviewing the documented scope."
  exit 0
fi
if [[ "${CONFIRM}" != "ERASE-WINHUB-HOST-DATA" ]]; then
  echo "Refusing destructive reset. Use: --execute --confirm ERASE-WINHUB-HOST-DATA" >&2
  exit 2
fi

web_was_active=false
agent_was_active=false
newsletter_was_active=false
systemctl is-active --quiet winhub && web_was_active=true
systemctl is-active --quiet winhub-agent && agent_was_active=true
systemctl is-active --quiet winhub-newsletter && newsletter_was_active=true
restart_services() {
  if [[ "${web_was_active}" == true ]]; then systemctl start winhub || true; fi
  if [[ "${agent_was_active}" == true ]]; then systemctl start winhub-agent || true; fi
  if [[ "${newsletter_was_active}" == true ]]; then systemctl start winhub-newsletter || true; fi
}
trap restart_services EXIT

echo "[WinHUB] Stopping API services to freeze host state"
systemctl stop winhub-agent 2>/dev/null || true
systemctl stop winhub-newsletter 2>/dev/null || true
systemctl stop winhub

echo "[WinHUB] Creating the mandatory pre-reset backup"
APP_DIR="${APP_DIR}" ENV_FILE="${ENV_FILE}" "${APP_DIR}/deploy/debian/backup_winhub.sh"

echo "[WinHUB] Erasing active host-derived data in one database transaction"
run_reset --execute --confirm "${CONFIRM}"

restart_services
trap - EXIT
"${APP_DIR}/deploy/debian/healthcheck_winhub.sh"
echo "[WinHUB] Host data reset complete. The backup and service logs still contain historical data by design."
