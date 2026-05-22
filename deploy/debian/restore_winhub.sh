#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
BACKUP_DIR="${1:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/debian/restore_winhub.sh /var/lib/winhub/backups/<timestamp>"
  exit 1
fi

if [[ -z "${BACKUP_DIR}" || ! -d "${BACKUP_DIR}" ]]; then
  echo "Backup directory not found: ${BACKUP_DIR}" >&2
  exit 1
fi

if [[ ! -f "${BACKUP_DIR}/app.tar.gz" ]]; then
  echo "Backup does not contain app.tar.gz: ${BACKUP_DIR}" >&2
  exit 1
fi

env_value() {
  local key="$1"
  [[ -f "${ENV_FILE}" ]] || return 0
  awk -F= -v key="${key}" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if ((substr(value, 1, 1) == "\"" && substr(value, length(value), 1) == "\"") ||
          (substr(value, 1, 1) == "'"'"'" && substr(value, length(value), 1) == "'"'"'")) {
        value = substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  ' "${ENV_FILE}"
}

echo "[WinHUB] Restoring backup ${BACKUP_DIR}"
systemctl stop winhub || true

TMP_DIR="$(mktemp -d)"
tar -xzf "${BACKUP_DIR}/app.tar.gz" -C "${TMP_DIR}"
rsync -a --delete "${TMP_DIR}/app/" "${APP_DIR}/"
rm -rf "${TMP_DIR}"

if [[ -f "${BACKUP_DIR}/winhub_postgres.dump" ]]; then
  POSTGRES_HOST_VALUE="$(env_value POSTGRES_HOST)"
  POSTGRES_PORT_VALUE="$(env_value POSTGRES_PORT)"
  POSTGRES_DB_VALUE="$(env_value POSTGRES_DB)"
  POSTGRES_USER_VALUE="$(env_value POSTGRES_USER)"
  POSTGRES_PASSWORD_VALUE="$(env_value POSTGRES_PASSWORD)"
  if [[ -n "${POSTGRES_DB_VALUE}" && -n "${POSTGRES_USER_VALUE}" ]]; then
    echo "[WinHUB] Restoring PostgreSQL database ${POSTGRES_DB_VALUE}"
    export PGPASSWORD="${POSTGRES_PASSWORD_VALUE}"
    pg_restore \
      --host "${POSTGRES_HOST_VALUE:-127.0.0.1}" \
      --port "${POSTGRES_PORT_VALUE:-5432}" \
      --username "${POSTGRES_USER_VALUE}" \
      --dbname "${POSTGRES_DB_VALUE}" \
      --clean --if-exists --no-owner \
      "${BACKUP_DIR}/winhub_postgres.dump"
    unset PGPASSWORD
  else
    echo "[WinHUB] POSTGRES_* settings not found; skipped database restore."
  fi
fi

python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/python" -m pip install --upgrade pip wheel
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

install -m 0644 "${APP_DIR}/deploy/debian/winhub.service" /etc/systemd/system/winhub.service
install -m 0644 "${APP_DIR}/deploy/debian/nginx-winhub.conf" /etc/nginx/sites-available/winhub
ln -sfn /etc/nginx/sites-available/winhub /etc/nginx/sites-enabled/winhub
install -m 0644 "${APP_DIR}/deploy/debian/winhub.logrotate" /etc/logrotate.d/winhub

chown -R winhub:winhub "${APP_DIR}" /var/lib/winhub /var/log/winhub
chown -R root:winhub /etc/winhub
chmod 0750 /etc/winhub /etc/winhub/certs
chmod 0640 "${ENV_FILE}"
chmod 0640 /etc/winhub/certs/*.pem 2>/dev/null || true

systemctl daemon-reload
nginx -t
systemctl start winhub
systemctl reload nginx || true

"${APP_DIR}/deploy/debian/healthcheck_winhub.sh"
echo "[WinHUB] Restore complete"
