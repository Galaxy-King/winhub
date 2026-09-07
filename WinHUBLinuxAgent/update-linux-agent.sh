#!/usr/bin/env bash
# Source-checkout entry point. Published packages contain the full canonical script.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$script_dir/../WinHUB/deploy/agent-updaters/update-linux-agent.sh" "$@"
