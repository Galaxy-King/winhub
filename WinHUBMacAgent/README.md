# WinHUB macOS Agent

Native AOT endpoint agent for Apple Silicon (`osx-arm64`) and a .NET 8-supported macOS
release (macOS 14 or newer). It uses
the existing WinHUB enrollment, polling, telemetry, result and signed-task protocol.

## Secure defaults

- Valid TLS is mandatory. Certificate bypass is disabled.
- Every task must have a valid WinHUB HMAC signature.
- The default execution policy allows only `agent_update`; remote shell and reboot are denied.
- Every update must include the SHA-256 recorded by WinHUB and a valid Apple code signature from the same Apple Team ID as the installed agent.
- Configuration, token, RSA identity and bootstrap secrets use root-only permissions.
- The bootstrap file is deleted after secrets migrate into the protected data directory.
- Update archives are checked for traversal, links and special files before extraction.
- Updates replace stale runtime files, update and validate the LaunchDaemon plist, verify that the new service stays running, and roll back on failure.

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

Pin the expected Apple signer on the first production installation:

   `WINHUB_EXPECTED_TEAM_ID="TEAMID" ./setup-macos-agent.sh`

Unsigned binaries are rejected. For a local development Mac only:

   `sudo WINHUB_ALLOW_UNSIGNED=1 ./install-macos-agent.sh`

Status and logs:

   `sudo launchctl print system/com.winhub.agent`

   `tail -f /Library/Logs/WinHUB/agent.log`

## Build and sign

Build on an Apple Silicon Mac with the .NET 8 Arm64 SDK and Xcode Command Line Tools:

   `WINHUB_CODESIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)" ./create-macos-agent-release.sh`

The release script performs a Native AOT publish, signs every Mach-O file with hardened
runtime and a secure timestamp, validates the embedded version, runs the WinHUB protocol
self-test, and creates `dist-agent/WinHUBMacAgent-v<VERSION>-macos-arm64.tar.gz` plus SHA-256.

For a local build without a Developer ID certificate:

   `WINHUB_ALLOW_UNSIGNED_BUILD=1 ./create-macos-agent-release.sh`

Never upload an unsigned/ad-hoc build to production WinHUB. For public distribution outside
managed WinHUB updates, also create and notarize a signed `.pkg`.

The complete build-host guide is in `BUILD_MAC_M4_UA.md`.
