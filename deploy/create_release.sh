#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/dist}"
ARCHIVE="${OUT_DIR}/winhub-v${VERSION}.tar.gz"

mkdir -p "${OUT_DIR}"

tar \
  --exclude-vcs \
  --exclude='./dist' \
  --exclude='./venv' \
  --exclude='./.venv' \
  --exclude='./data' \
  --exclude='./certs' \
  --exclude='./*.log' \
  --exclude='./WinHUBAgent/bin' \
  --exclude='./WinHUBAgent/obj' \
  --exclude='./WinHUBAgent/publish' \
  -czf "${ARCHIVE}" \
  -C "${ROOT_DIR}" .

echo "${ARCHIVE}"
