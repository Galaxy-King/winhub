#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://127.0.0.1:8443/api/health}"
TRIES="${TRIES:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
APP_DIR="${APP_DIR:-/opt/winhub}"
HEALTH_TMP="$(mktemp)"
trap 'rm -f "${HEALTH_TMP}"' EXIT

renderer_healthcheck() {
  local mode socket_path
  mode="$(awk -F= '/^[[:space:]]*REPORT_RENDERER_MODE[[:space:]]*=/{gsub(/[ \047"\r]/, "", $2); print tolower($2); exit}' "${ENV_FILE}" 2>/dev/null || true)"
  if [[ "${mode}" != "service" ]]; then
    return 0
  fi
  socket_path="$(awk -F= '/^[[:space:]]*REPORT_RENDERER_SOCKET[[:space:]]*=/{gsub(/[ \047"\r]/, "", $2); print $2; exit}' "${ENV_FILE}" 2>/dev/null || true)"
  socket_path="${socket_path:-/run/winhub-renderer.sock}"
  systemctl is-active --quiet winhub-renderer.socket || return 1
  "${APP_DIR}/venv/bin/python" - "${socket_path}" <<'PY'
import json
import socket
import sys

request = json.dumps({"template": "{{ value }}", "context": {"value": "renderer-ok"}}).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(10)
    connection.connect(sys.argv[1])
    connection.sendall(request)
    connection.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
response = json.loads(b"".join(chunks).decode())
if not response.get("ok") or response.get("output") != "renderer-ok":
    raise SystemExit("isolated renderer returned an invalid response")
PY
}

for attempt in $(seq 1 "${TRIES}"); do
  if curl -fsS --max-time 5 "${URL}" >"${HEALTH_TMP}"; then
    if renderer_healthcheck; then
      echo "[WinHUB] Healthcheck OK: ${URL}"
      cat "${HEALTH_TMP}"
      echo
      exit 0
    fi
    echo "[WinHUB] Isolated renderer healthcheck failed; retrying..." >&2
  fi
  echo "[WinHUB] Healthcheck attempt ${attempt}/${TRIES} failed; retrying..."
  sleep "${SLEEP_SECONDS}"
done

echo "[WinHUB] Healthcheck failed: ${URL}" >&2
systemctl --no-pager --full status winhub || true
journalctl -u winhub -n 80 --no-pager || true
journalctl -u 'winhub-renderer@*' -n 80 --no-pager || true
exit 1
