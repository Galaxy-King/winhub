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

apt-get update
apt-get install -y \
  python3 python3-venv python3-pip \
  postgresql postgresql-contrib \
  nginx openssl gnupg ca-certificates \
  build-essential rsync curl git

if ! id winhub >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin winhub
fi

mkdir -p "${APP_DIR}" "${ENV_DIR}/certs" "${DATA_DIR}/logs" "${LOG_DIR}"
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
  echo "Created ${ENV_DIR}/winhub.env. Edit secrets before starting WinHUB."
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
install -m 0644 "${APP_DIR}/deploy/debian/nginx-winhub.conf" /etc/nginx/sites-available/winhub
ln -sfn /etc/nginx/sites-available/winhub /etc/nginx/sites-enabled/winhub
install -m 0644 "${APP_DIR}/deploy/debian/winhub.logrotate" /etc/logrotate.d/winhub
chmod 0755 "${APP_DIR}/deploy/debian/backup_winhub.sh" "${APP_DIR}/deploy/debian/healthcheck_winhub.sh" "${APP_DIR}/deploy/debian/migrate_winhub.sh" "${APP_DIR}/deploy/debian/update_winhub.sh"

chown -R winhub:winhub "${APP_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chown -R root:winhub "${ENV_DIR}"
chmod 0750 "${ENV_DIR}"
chmod 0750 "${ENV_DIR}/certs"
chmod 0640 "${ENV_DIR}/winhub.env"
chmod 0640 "${ENV_DIR}/certs/"*.pem

systemctl daemon-reload
nginx -t

cat <<'EOF'

WinHUB Debian files installed.

Next:
1. Edit /etc/winhub/winhub.env and set real secrets/passwords.
2. Create PostgreSQL database/user if needed.
3. Replace /etc/winhub/certs/cert.pem and key.pem with your IP/SAN certificate.
4. Run:
   sudo systemctl enable --now winhub
   sudo systemctl reload nginx
   sudo /opt/winhub/deploy/debian/healthcheck_winhub.sh

EOF
