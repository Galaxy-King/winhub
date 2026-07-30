# WinHUB macOS Agent

Native AOT endpoint agent for Apple Silicon (`osx-arm64`) and macOS 13 or newer. It uses
the existing WinHUB enrollment, polling, telemetry, result and signed-task protocol.

## Secure defaults

- Valid TLS is mandatory. Certificate bypass is disabled.
- Every task must have a valid WinHUB HMAC signature.
- The default execution policy allows only `agent_update`; remote shell and reboot are denied.
- Every update must include the SHA-256 recorded by WinHUB and a valid Apple code signature.
- Configuration, token, RSA identity and bootstrap secrets use root-only permissions.
- The bootstrap file is deleted after secrets migrate into the protected data directory.
- Update archives are checked for traversal, links and special files before extraction.

The daemon runs as root only because a fleet agent may update its root-owned installation.
Do not change `ExecutionMode` to `full` unless unrestricted remote administration is an
explicit security decision. For inventory-only operation use `"ExecutionMode": "disabled"`.

## Install

The simplest installation asks for the URL and secrets without placing them in shell history:

   `./setup-macos-agent.sh`

If `winhub_agent.conf` and `winhub_agent.bootstrap.conf` are already located beside
the installer, `setup-macos-agent.sh` uses them directly and asks no questions.

The temporary setup files are removed immediately after installation. For unattended
deployment, place `winhub_agent.conf` and `winhub_agent.bootstrap.conf` beside the installer
and run `sudo ./install-macos-agent.sh`.

Unsigned binaries are rejected. For a local development Mac only:

   `sudo WINHUB_ALLOW_UNSIGNED=1 ./install-macos-agent.sh`

Status and logs:

   `sudo launchctl print system/com.winhub.agent`

   `tail -f /Library/Logs/WinHUB/agent.log`

## Build and sign

Build on an Apple Silicon Mac with .NET 8 SDK:

   `WINHUB_CODESIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)" ./create-macos-agent-release.sh`

For public distribution, notarize and staple a signed `.pkg` in the release pipeline.
Never distribute a package built with `WINHUB_ALLOW_UNSIGNED=1`.
