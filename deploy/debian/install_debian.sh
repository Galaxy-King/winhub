#!/usr/bin/env bash
set -euo pipefail

umask 027

APP_DIR="/opt/winhub"
ENV_DIR="/etc/winhub"
ENV_FILE="${ENV_DIR}/winhub.env"
DATA_DIR="/var/lib/winhub"
LOG_DIR="/var/log/winhub"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RECOVERY_WORK_DIR=""
RECOVERY_ARCHIVE=""
PUBLIC_HOST="${WINHUB_PUBLIC_HOST:-}"
CERT_SAN_TYPE=""
FRESH_INSTALL=false

info() {
  printf '[WinHUB] %s\n' "$*"
}

fail() {
  printf '[WinHUB] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup_recovery_artifacts() {
  if [[ -n "${RECOVERY_ARCHIVE}" && -f "${RECOVERY_ARCHIVE}" ]]; then
    rm -f -- "${RECOVERY_ARCHIVE}"
  fi
  if [[ -n "${RECOVERY_WORK_DIR}" && -d "${RECOVERY_WORK_DIR}" ]]; then
    rm -rf -- "${RECOVERY_WORK_DIR}"
  fi
}

trap cleanup_recovery_artifacts EXIT

pause_for_operator() {
  local message="$1"
  if [[ ! -t 0 ]]; then
    fail "Fresh installation requires an interactive terminal. Re-run from SSH or a local root shell."
  fi
  printf '\n%s\n' "${message}"
  read -r -p "Press Enter to continue... " _
}

env_value() {
  local key="$1"
  [[ -f "${ENV_FILE}" ]] || return 0
  awk -F= -v key="${key}" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if ((substr(value, 1, 1) == "\"" && substr(value, length(value), 1) == "\"") ||
          (substr(value, 1, 1) == "\047" && substr(value, length(value), 1) == "\047")) {
        value = substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  ' "${ENV_FILE}"
}

set_env_value() {
  local key="$1"
  local value="$2"
  python3 - "${ENV_FILE}" "${key}" "${value}" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
replacement = f"{key}={value}"
for index, line in enumerate(lines):
    if pattern.match(line):
        lines[index] = replacement
        break
else:
    lines.append(replacement)
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

generate_env_secrets() {
  python3 - "${ENV_FILE}" <<'PY'
import secrets
import sys
from pathlib import Path

path = Path(sys.argv[1])
secret_sizes = {
    "SECRET_KEY": 64,
    "AGENT_API_KEY": 64,
    "AGENT_TASK_HMAC_SECRET": 64,
    "POSTGRES_PASSWORD": 48,
}
placeholder_markers = (
    "replace-with",
    "change-me",
    "changeme",
    "default-dev-secret-key",
    "winhub-secret-enroll-2026",
)

lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
generated = []

def needs_generation(value):
    normalized = (value or "").strip().strip("'\"")
    return not normalized or any(marker in normalized.lower() for marker in placeholder_markers)

for index, line in enumerate(lines):
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    if key not in secret_sizes or not needs_generation(value):
        continue
    # token_urlsafe uses the operating-system CSPRNG and gives independent,
    # shell-safe values without quotes or whitespace.
    lines[index] = f"{key}={secrets.token_urlsafe(secret_sizes[key])}"
    generated.append(key)

path.write_text("\n".join(lines) + "\n", encoding="utf-8")
if generated:
    print("[WinHUB] Generated independent cryptographic secrets: " + ", ".join(generated))
else:
    print("[WinHUB] Required secrets already exist; they were not rotated.")
PY
}

detect_public_host() {
  local detected
  detected="$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\./ && $i !~ /^127\./) {print $i; exit}}')"
  printf '%s' "${detected:-127.0.0.1}"
}

validate_public_host() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys

value = sys.argv[1].strip()
try:
    address = ipaddress.ip_address(value)
except ValueError:
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?",
        value,
    ):
        raise SystemExit(1)
    print("DNS:" + value.rstrip("."))
else:
    if address.version != 4:
        raise SystemExit(1)
    print("IP:" + str(address))
PY
}

configure_public_host() {
  local default_host validated
  default_host="$(detect_public_host)"
  if [[ -z "${PUBLIC_HOST}" ]]; then
    [[ -t 0 ]] || fail "Set WINHUB_PUBLIC_HOST for a fresh non-interactive environment."
    printf '\nWinHUB needs the DNS name or IPv4 address used by browsers and agents.\n'
    read -r -p "Public DNS name or IPv4 address [${default_host}]: " PUBLIC_HOST
    PUBLIC_HOST="${PUBLIC_HOST:-${default_host}}"
  fi
  validated="$(validate_public_host "${PUBLIC_HOST}")" || fail "Invalid public host: ${PUBLIC_HOST}"
  PUBLIC_HOST="${validated#*:}"
  CERT_SAN_TYPE="${validated%%:*}"
}

create_postgres_database() {
  local database_password
  database_password="$(env_value POSTGRES_PASSWORD)"
  [[ -n "${database_password}" ]] || fail "POSTGRES_PASSWORD is empty after secret generation."

  info "Creating or reconciling the local PostgreSQL role and database"
  WINHUB_DB_PASSWORD="${database_password}" \
    runuser --whitelist-environment WINHUB_DB_PASSWORD -u postgres -- \
      psql --set=ON_ERROR_STOP=1 <<'SQL'
\getenv winhub_db_password WINHUB_DB_PASSWORD
SELECT format('CREATE ROLE winhub LOGIN PASSWORD %L', :'winhub_db_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'winhub') \gexec
ALTER ROLE winhub WITH LOGIN PASSWORD :'winhub_db_password';
SELECT 'CREATE DATABASE winhub OWNER winhub'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'winhub') \gexec
ALTER DATABASE winhub OWNER TO winhub;
REVOKE ALL ON DATABASE winhub FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE winhub TO winhub;
SQL
}

create_tls_certificate() {
  local san
  san="${CERT_SAN_TYPE}:${PUBLIC_HOST}"
  info "Generating a self-signed TLS certificate for ${san}"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
    -keyout "${ENV_DIR}/certs/key.pem" \
    -out "${ENV_DIR}/certs/cert.pem" \
    -subj "/CN=${PUBLIC_HOST}" \
    -addext "subjectAltName=${san}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"
}

certificate_fingerprint() {
  openssl x509 -in "${ENV_DIR}/certs/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':'
}

public_host_from_env() {
  local base_url
  base_url="$(env_value AGENT_PUBLIC_BASE_URL)"
  python3 - "${base_url}" <<'PY'
import socket
import sys
from urllib.parse import urlsplit

value = sys.argv[1].strip()
host = urlsplit(value).hostname if value else None
print(host or socket.getfqdn() or "server-address")
PY
}

create_recovery_archive() {
  local admin_file="${DATA_DIR}/admin_recovery.txt"
  local archive_stamp fingerprint

  [[ -f "${admin_file}" ]] || fail "Admin recovery file was not created. Check the winhub service log."
  [[ -f "${DATA_DIR}/master_key.enc" ]] || fail "master_key.enc was not created."
  [[ -f "${DATA_DIR}/sys_secret.enc" ]] || fail "sys_secret.enc was not created."

  archive_stamp="$(date -u +%Y%m%d_%H%M%S)"
  fingerprint="$(certificate_fingerprint)"
  RECOVERY_WORK_DIR="$(mktemp -d /run/winhub-recovery.XXXXXX)"
  RECOVERY_ARCHIVE="/run/WinHUB-recovery-${archive_stamp}.tar.gz"
  chmod 0700 "${RECOVERY_WORK_DIR}"

  mkdir -p "${RECOVERY_WORK_DIR}/etc/winhub/certs" "${RECOVERY_WORK_DIR}/var/lib/winhub"
  install -m 0600 "${ENV_FILE}" "${RECOVERY_WORK_DIR}/etc/winhub/winhub.env"
  install -m 0600 "${ENV_DIR}/certs/cert.pem" "${RECOVERY_WORK_DIR}/etc/winhub/certs/cert.pem"
  install -m 0600 "${ENV_DIR}/certs/key.pem" "${RECOVERY_WORK_DIR}/etc/winhub/certs/key.pem"
  install -m 0600 "${DATA_DIR}/master_key.enc" "${RECOVERY_WORK_DIR}/var/lib/winhub/master_key.enc"
  install -m 0600 "${DATA_DIR}/sys_secret.enc" "${RECOVERY_WORK_DIR}/var/lib/winhub/sys_secret.enc"
  install -m 0600 "${admin_file}" "${RECOVERY_WORK_DIR}/admin-recovery.txt"

  cat > "${RECOVERY_WORK_DIR}/README.txt" <<EOF
WinHUB one-time recovery bundle
===============================

Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Server URL: https://${PUBLIC_HOST}
TLS certificate SHA-256: ${fingerprint}

Contents:
- admin-recovery.txt: first administrator password and TOTP seed;
- etc/winhub/winhub.env: required server and agent-enrollment secrets;
- etc/winhub/certs/: TLS certificate and private key;
- var/lib/winhub/master_key.enc: payload/report encryption key;
- var/lib/winhub/sys_secret.enc: TOTP/system-secret encryption key.

Store this bundle in an encrypted password manager or encrypted offline storage.
Anyone who obtains it can control or decrypt this WinHUB installation.
Do not put it in Git, Confluence, tickets, chat, ordinary cloud folders, or email.
After the first login, change the admin password and keep MFA enabled.
EOF

  (
    cd "${RECOVERY_WORK_DIR}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  tar -C "${RECOVERY_WORK_DIR}" -czf "${RECOVERY_ARCHIVE}" .
  chmod 0600 "${RECOVERY_ARCHIVE}"
}

confirm_recovery_saved() {
  local archive_hash answer
  archive_hash="$(sha256sum "${RECOVERY_ARCHIVE}" | awk '{print $1}')"

  printf '\n============================================================\n'
  printf 'WINHUB RECOVERY BUNDLE — COPY IT OFF THIS SERVER NOW\n'
  printf '============================================================\n'
  printf 'Bundle: %s\n' "${RECOVERY_ARCHIVE}"
  printf 'SHA-256: %s\n' "${archive_hash}"
  printf 'Server: https://%s\n' "${PUBLIC_HOST}"
  printf 'TLS pin: %s\n' "$(certificate_fingerprint)"
  printf '\nExample from another trusted computer:\n'
  printf '  scp root@%s:%s ./\n' "${PUBLIC_HOST}" "${RECOVERY_ARCHIVE}"
  printf '\nIf root SSH is disabled, copy it to encrypted removable/off-host storage with sudo.\n'
  printf 'The archive and duplicate recovery files will be deleted from the server after confirmation.\n'

  while true; do
    read -r -p "Type SAVED after verifying the off-host copy: " answer
    if [[ "${answer}" == "SAVED" ]]; then
      break
    fi
    printf 'Confirmation was not accepted. Copy the bundle and type SAVED. If the installer exits, the temporary archive is removed and will be recreated on the next run.\n'
  done

  rm -f -- "${DATA_DIR}/admin_recovery.txt" "${DATA_DIR}/MASTER_KEY_BACKUP.txt"
  rm -f -- "${RECOVERY_ARCHIVE}"
  RECOVERY_ARCHIVE=""
  rm -rf -- "${RECOVERY_WORK_DIR}"
  RECOVERY_WORK_DIR=""
  info "One-time recovery copies were removed from the server"
}

if [[ "${EUID}" -ne 0 ]]; then
  fail "Run as root: sudo bash deploy/debian/install_debian.sh"
fi

if [[ ! -f "${SRC_DIR}/requirements.txt" || ! -f "${SRC_DIR}/server_debian.py" ]]; then
  fail "Run the installer from a complete WinHUB Git checkout."
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  FRESH_INSTALL=true
  configure_public_host
  pause_for_operator "A new secure WinHUB installation will be created for https://${PUBLIC_HOST}. No secret is taken from the WiKi or Git repository."
fi

info "Installing operating-system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  python3 python3-venv python3-pip \
  postgresql postgresql-contrib \
  nginx openssl gnupg ca-certificates \
  build-essential rsync curl git
unset DEBIAN_FRONTEND

systemctl enable --now postgresql

if ! id winhub >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin winhub
fi
if ! id winhub-renderer >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin winhub-renderer
fi

mkdir -p "${APP_DIR}" "${ENV_DIR}/certs" "${DATA_DIR}/logs" "${DATA_DIR}/gnupg" "${LOG_DIR}"
if [[ "$(readlink -f "${SRC_DIR}")" != "$(readlink -f "${APP_DIR}")" ]]; then
  info "Copying the Git checkout to ${APP_DIR}"
  rsync -a \
    --exclude venv \
    --exclude .venv \
    --exclude data \
    --exclude certs \
    --exclude '*.log' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "${SRC_DIR}/" "${APP_DIR}/"
else
  info "Git checkout is already located at ${APP_DIR}"
fi

python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/python" -m pip install --upgrade pip wheel
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

if [[ "${FRESH_INSTALL}" == true ]]; then
  install -m 0640 -o root -g winhub "${APP_DIR}/deploy/debian/winhub.env.example" "${ENV_FILE}"
  generate_env_secrets
  set_env_value POSTGRES_HOST 127.0.0.1
  set_env_value POSTGRES_PORT 5432
  set_env_value POSTGRES_DB winhub
  set_env_value POSTGRES_USER winhub
  set_env_value AGENT_PUBLIC_BASE_URL "https://${PUBLIC_HOST}"
  set_env_value AGENT_PACKAGE_URL_MODE relative
  set_env_value CSP_MODE enforce
  set_env_value CSP_NONCE_MODE enforce
  set_env_value OUTBOUND_POLICY_MODE enforce
  set_env_value AGENT_TASK_SIGNATURE_MODE v2
  set_env_value AGENT_REQUIRE_SIGNED_REQUESTS true
  set_env_value AGENT_ALLOW_LEGACY_AGENT_SIGNATURES false
  chmod 0640 "${ENV_FILE}"

  pause_for_operator "Independent secrets for sessions, PostgreSQL, agent enrollment, and task signing have been generated with the operating-system CSPRNG. They will be placed in the one-time recovery bundle at the end; never copy them to the WiKi."
  create_postgres_database
else
  info "Existing ${ENV_FILE} found; secrets and PostgreSQL credentials will not be rotated"
fi

if [[ ! -f "${ENV_DIR}/certs/cert.pem" || ! -f "${ENV_DIR}/certs/key.pem" ]]; then
  if [[ -z "${PUBLIC_HOST}" ]]; then
    configure_public_host
  fi
  create_tls_certificate
fi

install -m 0644 "${APP_DIR}/deploy/debian/winhub.service" /etc/systemd/system/winhub.service
install -m 0644 "${APP_DIR}/deploy/debian/winhub-agent.service" /etc/systemd/system/winhub-agent.service
install -m 0644 "${APP_DIR}/deploy/debian/winhub-renderer.socket" /etc/systemd/system/winhub-renderer.socket
install -m 0644 "${APP_DIR}/deploy/debian/winhub-renderer@.service" /etc/systemd/system/winhub-renderer@.service
ENV_FILE="${ENV_FILE}" APP_DIR="${APP_DIR}" bash "${APP_DIR}/deploy/debian/render_nginx_config.sh" /etc/nginx/sites-available/winhub
ln -sfn /etc/nginx/sites-available/winhub /etc/nginx/sites-enabled/winhub
install -m 0644 "${APP_DIR}/deploy/debian/winhub.logrotate" /etc/logrotate.d/winhub
chmod 0755 \
  "${APP_DIR}/deploy/debian/backup_winhub.sh" \
  "${APP_DIR}/deploy/debian/healthcheck_winhub.sh" \
  "${APP_DIR}/deploy/debian/security_smoke_test.sh" \
  "${APP_DIR}/deploy/debian/migrate_winhub.sh" \
  "${APP_DIR}/deploy/debian/render_nginx_config.sh" \
  "${APP_DIR}/deploy/debian/restore_winhub.sh" \
  "${APP_DIR}/deploy/debian/rollback_winhub.sh" \
  "${APP_DIR}/deploy/debian/update_winhub.sh"

chown -R root:winhub "${APP_DIR}"
chmod -R u=rwX,g=rX,o= "${APP_DIR}"
chmod 0751 "${APP_DIR}"
chmod -R u=rwX,go=rX "${APP_DIR}/static"
chmod -R u=rwX,go=rX "${APP_DIR}/venv"
chmod 0751 "${APP_DIR}/core"
chmod 0644 "${APP_DIR}/core/report_renderer.py"
chown -R winhub:winhub "${DATA_DIR}" "${LOG_DIR}"
chown -R root:winhub "${ENV_DIR}"
chmod 0750 "${DATA_DIR}" "${LOG_DIR}" "${ENV_DIR}" "${ENV_DIR}/certs"
chmod 0700 "${DATA_DIR}/gnupg"
chmod 0640 "${ENV_FILE}" "${ENV_DIR}/certs/cert.pem" "${ENV_DIR}/certs/key.pem"

systemctl daemon-reload
systemctl enable --now winhub-renderer.socket
nginx -t

if [[ -f "${APP_DIR}/alembic.ini" && -d "${APP_DIR}/migrations/versions" ]]; then
  info "Applying database migrations"
  "${APP_DIR}/deploy/debian/migrate_winhub.sh" upgrade
fi

systemctl enable winhub
systemctl restart winhub
if awk -F= '/^[[:space:]]*AGENT_BACKEND_PORT[[:space:]]*=/{gsub(/[ \047"\r]/, "", $2); if ($2 != "") found=1} END{exit found ? 0 : 1}' "${ENV_FILE}"; then
  systemctl enable --now winhub-agent
fi
systemctl enable --now nginx
systemctl reload nginx
"${APP_DIR}/deploy/debian/healthcheck_winhub.sh"

chmod 0600 "${DATA_DIR}/master_key.enc" "${DATA_DIR}/sys_secret.enc" 2>/dev/null || true

if [[ "${FRESH_INSTALL}" == true || -f "${DATA_DIR}/admin_recovery.txt" ]]; then
  if [[ -z "${PUBLIC_HOST}" ]]; then
    PUBLIC_HOST="$(public_host_from_env)"
  fi
  create_recovery_archive
  confirm_recovery_saved
fi

cat <<EOF

WinHUB installation completed successfully.

URL: https://${PUBLIC_HOST:-server-address}
Services: winhub, winhub-renderer.socket, nginx
Configuration: ${ENV_FILE}
Data: ${DATA_DIR}
Logs: ${LOG_DIR}

The server keeps only secrets required for operation. The one-time recovery archive
and duplicate initial-admin recovery file are no longer present on the server.

Next:
1. Sign in and change the initial admin password.
2. Keep MFA enabled.
3. Trust the internal CA or replace the generated certificate with a trusted certificate.
4. Install an agent and approve it in Review Center.
5. Configure encrypted off-host backups.

EOF
