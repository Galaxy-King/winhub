#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/debian/install_debian.sh"
  exit 1
fi

APP_DIR="/opt/winhub"
ENV_DIR="/etc/winhub"
DATA_DIR="/var/lib/winhub"
LOG_DIR="/var/log/winhub"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

generate_env_secrets() {
  local env_file="$1"
  local initial_doc="${2:-/root/winhub-initial-secrets.txt}"
  python3 - "${env_file}" "${initial_doc}" <<'PY'
import secrets
import sys
from pathlib import Path

path = Path(sys.argv[1])
doc_path = Path(sys.argv[2])
secret_keys = {
    "SECRET_KEY": 64,
    "AGENT_API_KEY": 48,
    "AGENT_TASK_HMAC_SECRET": 48,
    "POSTGRES_PASSWORD": 32,
}
placeholders = ("replace-with", "change-me", "changeme", "default-dev-secret-key", "WinHUB-Secret-Enroll-2026")

lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
changed = []
generated = {}

def weak(value):
    raw = (value or "").strip().strip("'\"")
    return not raw or any(marker.lower() in raw.lower() for marker in placeholders)

for idx, line in enumerate(lines):
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    if key not in secret_keys or not weak(value):
        continue
    token = secrets.token_urlsafe(secret_keys[key])
    lines[idx] = f"{key}={token}"
    changed.append(key)
    generated[key] = token

if changed:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not doc_path.exists():
        doc = [
            "WinHUB initial server secrets",
            "============================",
            "",
            "This file was created once by install_debian.sh.",
            "Keep it in a password manager or encrypted offline storage.",
            "Do not commit it to Git and do not leave world-readable copies.",
            "",
            "Generated values:",
        ]
        for key in changed:
            doc.append(f"{key}={generated[key]}")
        doc.extend([
            "",
            "Critical restore material:",
            "- /etc/winhub/winhub.env",
            "- /etc/winhub/certs/",
            "- /var/lib/winhub/master_key.enc",
            "- /var/lib/winhub/sys_secret.enc",
            "- PostgreSQL dump from backup_winhub.sh",
            "- /var/lib/winhub/gnupg if Newsletter/GPG is used",
            "",
            "Recommended backup command:",
            "  /opt/winhub/deploy/debian/backup_winhub.sh",
        ])
        doc_path.write_text("\n".join(doc) + "\n", encoding="utf-8")
        doc_path.chmod(0o600)
    print("[WinHUB] Generated strong local secrets in " + str(path) + ": " + ", ".join(changed))
    print("[WinHUB] Initial secret recovery document: " + str(doc_path))
else:
    print("[WinHUB] Env secrets already look initialized")
PY
}

apt-get update
apt-get install -y \
  python3 python3-venv python3-pip \
  postgresql postgresql-contrib \
  nginx openssl gnupg ca-certificates \
  build-essential rsync curl git

if ! id winhub >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin winhub
fi
if ! id winhub-renderer >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin winhub-renderer
fi

mkdir -p "${APP_DIR}" "${ENV_DIR}/certs" "${DATA_DIR}/logs" "${DATA_DIR}/gnupg" "${LOG_DIR}"
rsync -a \
  --exclude venv \
  --exclude data \
  --exclude certs \
  --exclude '*.log' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "${SRC_DIR}/" "${APP_DIR}/"

python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/python" -m pip install --upgrade pip wheel
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

if [[ ! -f "${ENV_DIR}/winhub.env" ]]; then
  install -m 0640 -o root -g winhub "${APP_DIR}/deploy/debian/winhub.env.example" "${ENV_DIR}/winhub.env"
  generate_env_secrets "${ENV_DIR}/winhub.env"
  echo "Created ${ENV_DIR}/winhub.env with generated local secrets."
fi

if [[ ! -f "${ENV_DIR}/certs/cert.pem" || ! -f "${ENV_DIR}/certs/key.pem" ]]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
    -keyout "${ENV_DIR}/certs/key.pem" \
    -out "${ENV_DIR}/certs/cert.pem" \
    -subj "/CN=WinHUB" \
    -addext "subjectAltName=IP:127.0.0.1"
  echo "Created temporary self-signed cert in ${ENV_DIR}/certs. Replace it with your IP/SAN production cert."
fi

install -m 0644 "${APP_DIR}/deploy/debian/winhub.service" /etc/systemd/system/winhub.service
install -m 0644 "${APP_DIR}/deploy/debian/winhub-agent.service" /etc/systemd/system/winhub-agent.service
install -m 0644 "${APP_DIR}/deploy/debian/winhub-renderer.socket" /etc/systemd/system/winhub-renderer.socket
install -m 0644 "${APP_DIR}/deploy/debian/winhub-renderer@.service" /etc/systemd/system/winhub-renderer@.service
ENV_FILE="${ENV_DIR}/winhub.env" APP_DIR="${APP_DIR}" bash "${APP_DIR}/deploy/debian/render_nginx_config.sh" /etc/nginx/sites-available/winhub
ln -sfn /etc/nginx/sites-available/winhub /etc/nginx/sites-enabled/winhub
install -m 0644 "${APP_DIR}/deploy/debian/winhub.logrotate" /etc/logrotate.d/winhub
chmod 0755 "${APP_DIR}/deploy/debian/backup_winhub.sh" "${APP_DIR}/deploy/debian/healthcheck_winhub.sh" "${APP_DIR}/deploy/debian/security_smoke_test.sh" "${APP_DIR}/deploy/debian/migrate_winhub.sh" "${APP_DIR}/deploy/debian/render_nginx_config.sh" "${APP_DIR}/deploy/debian/restore_winhub.sh" "${APP_DIR}/deploy/debian/rollback_winhub.sh" "${APP_DIR}/deploy/debian/update_winhub.sh"

chown -R winhub:winhub "${APP_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 0750 "${DATA_DIR}" "${LOG_DIR}"
chmod 0700 "${DATA_DIR}/gnupg"
chown -R root:winhub "${ENV_DIR}"
chmod 0750 "${ENV_DIR}"
chmod 0750 "${ENV_DIR}/certs"
chmod 0640 "${ENV_DIR}/winhub.env"
chmod 0640 "${ENV_DIR}/certs/"*.pem

systemctl daemon-reload
systemctl enable --now winhub-renderer.socket
nginx -t

if awk -F= '/^[[:space:]]*AGENT_BACKEND_PORT[[:space:]]*=/{gsub(/[ \047"\r]/, "", $2); if ($2 != "") found=1} END{exit found ? 0 : 1}' "${ENV_DIR}/winhub.env"; then
  systemctl enable --now winhub-agent
fi

cat <<'EOF'

WinHUB Debian files installed.

Next:
1. Review /etc/winhub/winhub.env for host/IP/database values.
2. Create PostgreSQL database/user if needed.
3. Replace /etc/winhub/certs/cert.pem and key.pem with your IP/SAN certificate.
4. Run:
   sudo systemctl enable --now winhub
   sudo systemctl reload nginx
   sudo /opt/winhub/deploy/debian/healthcheck_winhub.sh

EOF
