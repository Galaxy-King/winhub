#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://127.0.0.1:8443/api/health}"
TRIES="${TRIES:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

for attempt in $(seq 1 "${TRIES}"); do
  if curl -fsS --max-time 5 "${URL}" >/tmp/winhub_healthcheck.json; then
    echo "[WinHUB] Healthcheck OK: ${URL}"
    cat /tmp/winhub_healthcheck.json
    echo
    exit 0
  fi
  echo "[WinHUB] Healthcheck attempt ${attempt}/${TRIES} failed; retrying..."
  sleep "${SLEEP_SECONDS}"
done

echo "[WinHUB] Healthcheck failed: ${URL}" >&2
systemctl --no-pager --full status winhub || true
journalctl -u winhub -n 80 --no-pager || true
exit 1
