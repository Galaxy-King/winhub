#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
OUT_FILE="${1:-/etc/nginx/sites-available/winhub}"
BASE_CONF="${APP_DIR}/deploy/debian/nginx-winhub.conf"

if [[ ! -f "${BASE_CONF}" ]]; then
  echo "Base nginx config not found: ${BASE_CONF}" >&2
  exit 1
fi

agent_public_port="443"
if [[ -f "${ENV_FILE}" ]]; then
  raw_port="$(awk -F= '/^[[:space:]]*AGENT_PUBLIC_PORT[[:space:]]*=/{print $2; exit}' "${ENV_FILE}" | tr -d " '\"\r" || true)"
  if [[ -n "${raw_port}" ]]; then
    agent_public_port="${raw_port}"
  fi
fi

if ! [[ "${agent_public_port}" =~ ^[0-9]+$ ]] || (( agent_public_port < 1 || agent_public_port > 65535 )); then
  echo "Invalid AGENT_PUBLIC_PORT: ${agent_public_port}" >&2
  exit 1
fi

if [[ "${agent_public_port}" == "80" ]]; then
  echo "AGENT_PUBLIC_PORT=80 conflicts with the HTTP redirect listener." >&2
  exit 1
fi

install -m 0644 "${BASE_CONF}" "${OUT_FILE}"

if [[ "${agent_public_port}" == "443" ]]; then
  echo "[WinHUB] Nginx agent public port is 443; using the main HTTPS listener for agents."
  exit 0
fi

cat >> "${OUT_FILE}" <<EOF

# Agent-only public listener generated from AGENT_PUBLIC_PORT=${agent_public_port}.
# This port exposes only agent APIs and package downloads; the web UI is blocked.
server {
    listen ${agent_public_port} ssl http2;
    server_name _;

    ssl_certificate /etc/winhub/certs/cert.pem;
    ssl_certificate_key /etc/winhub/certs/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 512m;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;

    location /api/agent/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /api/public/agent-packages/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /api/public/software-packages/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /api/health {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        return 404;
    }
}
EOF

echo "[WinHUB] Added agent-only nginx listener on port ${agent_public_port}."
