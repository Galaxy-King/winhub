#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
BACKUP_SCRIPT="${APP_DIR}/deploy/debian/backup_winhub.sh"
HEALTHCHECK_SCRIPT="${APP_DIR}/deploy/debian/healthcheck_winhub.sh"
MIGRATE_SCRIPT="${APP_DIR}/deploy/debian/migrate_winhub.sh"
RELEASE_REF="${1:-}"
RELEASE_ARCHIVE=""
export APP_DIR ENV_FILE

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/debian/update_winhub.sh [git-ref]"
  exit 1
fi

if [[ ! -d "${APP_DIR}" ]]; then
  echo "APP_DIR does not exist: ${APP_DIR}" >&2
  exit 1
fi

if [[ -n "${RELEASE_REF}" && -f "${RELEASE_REF}" ]]; then
  RELEASE_ARCHIVE="$(readlink -f "${RELEASE_REF}")"
fi

cd "${APP_DIR}"

echo "[WinHUB] Starting update in ${APP_DIR}"

if [[ -x "${BACKUP_SCRIPT}" ]]; then
  "${BACKUP_SCRIPT}"
else
  bash "${BACKUP_SCRIPT}"
fi

if [[ -n "${RELEASE_ARCHIVE}" ]]; then
  echo "[WinHUB] Deploying release archive ${RELEASE_ARCHIVE}"
  TMP_DIR="$(mktemp -d)"
  tar -xf "${RELEASE_ARCHIVE}" -C "${TMP_DIR}"
  RELEASE_SRC="${TMP_DIR}"
  mapfile -t entries < <(find "${TMP_DIR}" -mindepth 1 -maxdepth 1)
  if [[ "${#entries[@]}" -eq 1 && -d "${entries[0]}" ]]; then
    RELEASE_SRC="${entries[0]}"
  fi
  rsync -a \
    --delete \
    --exclude venv \
    --exclude data \
    --exclude certs \
    --exclude '*.log' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "${RELEASE_SRC}/" "${APP_DIR}/"
  rm -rf "${TMP_DIR}"
elif [[ -d .git ]]; then
  echo "[WinHUB] Updating Git working tree"
  git fetch --tags --prune
  if [[ -n "${RELEASE_REF}" ]]; then
    git checkout "${RELEASE_REF}"
  else
    git pull --ff-only
  fi
else
  echo "[WinHUB] No .git repository and no release archive argument. Only refreshing dependencies/service."
fi

python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/python" -m pip install --upgrade pip wheel
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

if [[ -f "${APP_DIR}/alembic.ini" && -d "${APP_DIR}/migrations/versions" ]]; then
  echo "[WinHUB] Running database migrations"
  if [[ -x "${MIGRATE_SCRIPT}" ]]; then
    "${MIGRATE_SCRIPT}" upgrade
  else
    bash "${MIGRATE_SCRIPT}" upgrade
  fi
fi

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
systemctl restart winhub
systemctl reload nginx

if [[ -x "${HEALTHCHECK_SCRIPT}" ]]; then
  "${HEALTHCHECK_SCRIPT}"
else
  bash "${HEALTHCHECK_SCRIPT}"
fi

echo "[WinHUB] Update complete"
