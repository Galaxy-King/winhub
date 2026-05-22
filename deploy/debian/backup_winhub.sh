#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/lib/winhub/backups}"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_DIR="${BACKUP_ROOT}/${STAMP}"
VERSION_FILE="${APP_DIR}/VERSION"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/debian/backup_winhub.sh"
  exit 1
fi

mkdir -p "${OUT_DIR}"
chown -R winhub:winhub "${BACKUP_ROOT}" || true

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

POSTGRES_HOST_VALUE="$(env_value POSTGRES_HOST)"
POSTGRES_PORT_VALUE="$(env_value POSTGRES_PORT)"
POSTGRES_DB_VALUE="$(env_value POSTGRES_DB)"
POSTGRES_USER_VALUE="$(env_value POSTGRES_USER)"
POSTGRES_PASSWORD_VALUE="$(env_value POSTGRES_PASSWORD)"

echo "[WinHUB] Creating backup in ${OUT_DIR}"

rsync -a \
  --delete \
  --exclude venv \
  --exclude data \
  --exclude certs \
  --exclude '*.log' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "${APP_DIR}/" "${OUT_DIR}/app/"

tar -C "${OUT_DIR}" -czf "${OUT_DIR}/app.tar.gz" app
rm -rf "${OUT_DIR}/app"

if [[ -n "${POSTGRES_DB_VALUE}" && -n "${POSTGRES_USER_VALUE}" ]]; then
  export PGPASSWORD="${POSTGRES_PASSWORD_VALUE}"
  pg_dump \
    --host "${POSTGRES_HOST_VALUE:-127.0.0.1}" \
    --port "${POSTGRES_PORT_VALUE:-5432}" \
    --username "${POSTGRES_USER_VALUE}" \
    --format custom \
    --file "${OUT_DIR}/winhub_postgres.dump" \
    "${POSTGRES_DB_VALUE}"
  unset PGPASSWORD
else
  echo "[WinHUB] POSTGRES_* settings not found; skipping PostgreSQL dump."
fi

for path in "${ENV_FILE}" /etc/winhub/certs /var/lib/winhub/admin_recovery.txt; do
  if [[ -e "${path}" ]]; then
    rsync -aR "${path}" "${OUT_DIR}/runtime/"
  fi
done

if [[ -d /var/lib/winhub/newsletter ]]; then
  rsync -a /var/lib/winhub/newsletter "${OUT_DIR}/runtime/var/lib/winhub/"
fi

if command -v sha256sum >/dev/null 2>&1; then
  find "${OUT_DIR}" -type f -print0 | sort -z | xargs -0 sha256sum > "${OUT_DIR}/SHA256SUMS"
fi

cat > "${OUT_DIR}/backup.json" <<EOF
{
  "created_at_utc": "${STAMP}",
  "app_dir": "${APP_DIR}",
  "version": "$(test -f "${VERSION_FILE}" && tr -d '[:space:]' < "${VERSION_FILE}" || echo unknown)",
  "has_postgres_dump": $(test -f "${OUT_DIR}/winhub_postgres.dump" && echo true || echo false),
  "has_app_archive": true
}
EOF

ln -sfn "${OUT_DIR}" "${BACKUP_ROOT}/latest"

chown -R winhub:winhub "${OUT_DIR}" || true
chmod -R go-rwx "${OUT_DIR}"

echo "[WinHUB] Backup complete: ${OUT_DIR}"
