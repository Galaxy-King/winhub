"""Runtime-only updater assets and dependency checks (no agent source checkout needed)."""

import base64
import json
from pathlib import Path
import re


UPDATERS = Path(__file__).resolve().parents[1] / "deploy" / "agent-updaters"
SHA_PLACEHOLDER = "__WINHUB_AUTHORIZED_SHA256__"


def updater_bootstrap_script(platform, sha256):
    if platform not in {"windows", "linux"}:
        raise ValueError("No bootstrap updater for this platform")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(sha256 or "")):
        raise ValueError("An authorized package SHA-256 is required")
    name = "update-service.ps1" if platform == "windows" else "update-linux-agent.sh"
    source = (UPDATERS / name).read_text(encoding="utf-8")
    if source.count(SHA_PLACEHOLDER) != 1:
        raise ValueError("Invalid updater bootstrap asset")
    # Legacy agents pass only PackagePath. This default is delivered inside the
    # signed prepare task, never calculated from the downloaded archive itself.
    encoded = base64.b64encode(source.replace(SHA_PLACEHOLDER, sha256.lower()).encode()).decode()
    if platform == "windows":
        return f'''$ErrorActionPreference = 'Stop'
$install = 'C:\\Program Files\\WinHUBAgent'
$path = Join-Path $install 'update-service.ps1'
$check = $path
while ($check) {{
    if ((Test-Path -LiteralPath $check) -and ((Get-Item -LiteralPath $check -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {{ throw 'Updater path contains a reparse point.' }}
    $check = [IO.Path]::GetDirectoryName($check)
}}
if (-not (Test-Path -LiteralPath (Join-Path $install 'WinHUBAgent.exe'))) {{ throw 'Installed agent is missing.' }}
icacls $install /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Cannot protect updater directory.' }}
$temporary = Join-Path $install ('update-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {{
    [IO.File]::WriteAllBytes($temporary, [Convert]::FromBase64String('{encoded}'))
    Move-Item -LiteralPath $temporary -Destination $path -Force
}} finally {{ if (Test-Path -LiteralPath $temporary) {{ Remove-Item -LiteralPath $temporary -Force }} }}
Write-Output 'WinHUB updater prepared for the authorized package.'
'''
    return f'''#!/bin/bash
set -euo pipefail
umask 077
install=/opt/winhub-linux-agent
path="$install/update-linux-agent.sh"
[[ $EUID == 0 && "$(realpath -m "$install")" == "$install" && ! -L "$path" ]] || exit 1
[[ -f "$install/WinHUBLinuxAgent" ]] || exit 1
command -v python3 >/dev/null
chown root:root "$install"
chmod 0700 "$install"
temporary="$(mktemp "$install/.updater-XXXXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
printf '%s' '{encoded}' | base64 --decode > "$temporary"
chmod 0700 "$temporary"
mv -f -- "$temporary" "$path"
echo 'WinHUB updater prepared for the authorized package.'
'''


def update_preparation_state(task, lookup):
    """Return ready/wait/failed; never deliver update after denied/missing preparation."""
    if task.action_type != "agent_update":
        return "ready"
    try:
        payload = json.loads(task.payload or "{}")
    except (ValueError, TypeError):
        return "failed"
    if not isinstance(payload, dict):
        return "failed"
    dependency = payload.get("__updater_prepare_task_id")
    if dependency is None:
        return "ready"  # Existing/manual update tasks keep their protocol.
    if not isinstance(dependency, str) or not dependency or dependency == task.id:
        return "failed"
    prepare = lookup(dependency)
    if (prepare is None or prepare.endpoint_id != task.endpoint_id
            or prepare.job_id != task.job_id or prepare.action_type != "run_script"):
        return "failed"
    if prepare.status == "Success":
        return "ready"
    if prepare.status in {"Pending", "PickedUp", "Running"}:
        return "wait"
    return "failed"
