#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/dist}"
ARCHIVE="${OUT_DIR}/winhub-v${VERSION}.tar.gz"
MANIFEST="${OUT_DIR}/winhub-v${VERSION}.manifest.json"

mkdir -p "${OUT_DIR}"

tar \
  --exclude-vcs \
  --exclude-from="${ROOT_DIR}/deploy/server-excludes.txt" \
  -czf "${ARCHIVE}" \
  -C "${ROOT_DIR}" \
  --files-from="${ROOT_DIR}/deploy/server-files.txt"

SHA256="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
cat > "${MANIFEST}" <<EOF
{
  "version": "${VERSION}",
  "created_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "server_archive": "$(basename "${ARCHIVE}")",
  "server_archive_sha256": "${SHA256}"
}
EOF

echo "${ARCHIVE}"
