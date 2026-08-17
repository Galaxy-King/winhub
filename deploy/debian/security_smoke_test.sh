#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
HTTPS_URL="${HTTPS_URL:-https://127.0.0.1/login}"

env_value() {
  local key="$1"
  awk -F= -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      value=$2
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      gsub(/^["\047]|["\047]$/, "", value)
      print value
      exit
    }
  ' "${ENV_FILE}"
}

require_env() {
  local key="$1" expected="$2" actual
  actual="$(env_value "${key}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "[FAIL] ${key}=${actual:-unset}; expected ${expected}" >&2
    exit 1
  fi
  echo "[OK] ${key}=${actual}"
}

echo "[WinHUB] Strict security smoke test"
"${APP_DIR}/deploy/debian/healthcheck_winhub.sh"

require_env AGENT_REQUIRE_SIGNED_REQUESTS true
require_env AGENT_ALLOW_LEGACY_AGENT_SIGNATURES false
require_env AGENT_TASK_SIGNATURE_MODE v2
require_env OUTBOUND_POLICY_MODE enforce
require_env CSP_NONCE_MODE enforce
require_env REPORT_RENDERER_MODE service

systemctl is-active --quiet winhub-renderer.socket
socket_path="$(env_value REPORT_RENDERER_SOCKET || true)"
socket_path="${socket_path:-/run/winhub-renderer.sock}"
test -S "${socket_path}"

if id -nG winhub-renderer | tr ' ' '\n' | grep -Fxq winhub; then
  echo "[FAIL] winhub-renderer must not be a member of the winhub group" >&2
  exit 1
fi
if runuser -u winhub-renderer -- test -r "${ENV_FILE}"; then
  echo "[FAIL] winhub-renderer can read ${ENV_FILE}" >&2
  exit 1
fi
if runuser -u winhub-renderer -- test -x /var/lib/winhub; then
  echo "[FAIL] winhub-renderer can traverse /var/lib/winhub" >&2
  exit 1
fi
echo "[OK] renderer identity cannot read server secrets or data"

unit_text="$(systemctl cat winhub-renderer@.service)"
for required in \
  'User=winhub-renderer' \
  'PrivateNetwork=true' \
  'ProtectSystem=strict' \
  'InaccessiblePaths=/etc/winhub /var/lib/winhub /var/log/winhub' \
  'RestrictAddressFamilies=AF_UNIX' \
  'SystemCallFilter=~@network-io' \
  'IPAddressDeny=any'; do
  grep -Fq "${required}" <<<"${unit_text}" || {
    echo "[FAIL] active renderer unit is missing: ${required}" >&2
    exit 1
  }
done
unset unit_text
echo "[OK] active renderer unit has filesystem and network isolation"

(cd "${APP_DIR}" && "${APP_DIR}/venv/bin/python" -m unittest tests.test_security_foundation -v)

"${APP_DIR}/venv/bin/python" - "${socket_path}" <<'PY'
import json
import socket
import sys

socket_path = sys.argv[1]

def render(template, context):
    request = json.dumps({"template": template, "context": context}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(12)
        connection.connect(socket_path)
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode())

valid = render("{{ value }}", {"value": '<img src=x onerror="alert(1)">'})
if not valid.get("ok") or "<img" in valid.get("output", "") or "&lt;img" not in valid.get("output", ""):
    raise SystemExit("[FAIL] renderer did not HTML-escape report context")

attack = render("{{ ''.__class__.__mro__ }}", {})
if attack.get("ok"):
    raise SystemExit("[FAIL] renderer accepted a known Jinja sandbox escape")
print("[OK] isolated renderer accepts safe templates and rejects escape payloads")
PY

csp_headers="$(curl -skI "${HTTPS_URL}" | tr -d '\r' | grep -Ei '^content-security-policy')"
grep -Eq "^content-security-policy:.*script-src 'self' 'nonce-[^']+'" <<<"${csp_headers}" || {
  echo "[FAIL] enforced CSP nonce header is missing" >&2
  exit 1
}
echo "[OK] enforced per-response CSP nonce is active"

journalctl -u winhub --since "10 minutes ago" -p warning --no-pager
echo "[WinHUB] All strict security smoke tests passed"
