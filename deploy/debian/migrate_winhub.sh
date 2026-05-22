#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/winhub}"
ENV_FILE="${ENV_FILE:-/etc/winhub/winhub.env}"
COMMAND="${1:-upgrade}"

export_env_key() {
  local key="$1"
  [[ -f "${ENV_FILE}" ]] || return 0
  local value
  value="$(awk -F= -v key="${key}" '
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
  ' "${ENV_FILE}")"
  if [[ -n "${value}" ]]; then
    export "${key}=${value}"
  fi
}

for key in \
  WINHUB_ENV SECRET_KEY DATA_DIR DATABASE_URI \
  POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD \
  RATELIMIT_STORAGE_URI RATELIMIT_DEFAULT LOGIN_RATE_LIMIT AGENT_ENROLLMENT_RATE_LIMIT; do
  export_env_key "${key}"
done

cd "${APP_DIR}"

case "${COMMAND}" in
  upgrade)
    "${APP_DIR}/venv/bin/alembic" upgrade head
    ;;
  revision)
    shift
    "${APP_DIR}/venv/bin/alembic" revision --autogenerate "$@"
    ;;
  *)
    echo "Usage: sudo deploy/debian/migrate_winhub.sh upgrade" >&2
    echo "   or: sudo deploy/debian/migrate_winhub.sh revision -m 'describe change'" >&2
    exit 2
    ;;
esac
