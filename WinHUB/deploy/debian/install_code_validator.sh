#!/usr/bin/env bash
# Called by install/update after source permissions are set. Never installs model-supplied code.
set -euo pipefail
APP_DIR="${APP_DIR:-/opt/winhub}"
if [[ "${EUID}" -ne 0 ]]; then
  echo 'Installing the validator unit requires root.' >&2
  exit 1
fi
if ! id winhub-validator >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin winhub-validator
fi
if id -nG winhub-validator | tr ' ' '\n' | grep -Fxq winhub; then
  echo 'winhub-validator must not belong to the winhub group.' >&2
  exit 1
fi
for name in code_validator.py validate_powershell.ps1 ai_template_contract.py report_renderer.py; do
  chown root:root "${APP_DIR}/core/${name}"
  chmod 0644 "${APP_DIR}/core/${name}"
done
install -m 0644 "${APP_DIR}/deploy/debian/winhub-code-validator.socket" /etc/systemd/system/winhub-code-validator.socket
install -m 0644 "${APP_DIR}/deploy/debian/winhub-code-validator@.service" /etc/systemd/system/winhub-code-validator@.service
systemctl daemon-reload
systemctl enable --now winhub-code-validator.socket
if ! command -v pwsh >/dev/null 2>&1; then
  echo '[WinHUB] AI PowerShell validation needs pwsh. Generation remains available, but apply/save requires successful validation.'
fi
if ! command -v shellcheck >/dev/null 2>&1; then
  echo '[WinHUB] Optional ShellCheck missing; Bash syntax validation remains available.'
fi
