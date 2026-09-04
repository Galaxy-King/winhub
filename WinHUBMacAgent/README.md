# WinHUB macOS Agent

Production endpoint agent for Apple Silicon (`osx-arm64`) and macOS 14+. It is a
self-contained .NET 10 LTS Native AOT LaunchDaemon and uses the WinHUB enrollment, signed-request,
Task Signature v2, polling, telemetry, result queue and managed-update protocols.

## Production security model

- HTTPS validation is mandatory; optional SHA-256 certificate pinning is supported.
- The agent has a persistent RSA identity and signs enrollment/poll/result/telemetry requests.
- Task Signature v2 binds the task to the endpoint, payload, timeout, expiry and sequence.
- Local execution defaults to `allowlist` with only `agent_update` permitted.
- Updates require a server-signed task, package SHA-256, expected embedded version, safe
  archive layout, `arm64`, Hardened Runtime, code-signing identifier `com.winhub.agent`, and
  the same Apple Team ID as the installed binary.
- Config, tokens, secrets and identity are root-only. The bootstrap file is removed after
  migration, and the enrollment key is erased from local state after successful enrollment.
- The updater validates the new LaunchDaemon, verifies that it stays running, and rolls back
  the runtime and plist on failure.
- Task output and execution time are bounded; unsent results survive restarts.
- `newsyslog` rotates stdout/stderr logs.

The daemon runs as root because inventory, administrative tasks and replacement of its
root-owned installation require it. macOS TCC/PPPC remains a separate control: Screen
Recording, Accessibility, Full Disk Access and other protected resources are not granted by
the code signature or root alone.

## Recommended production installation

Use the notarized installer bundle produced by the release script. After unzipping it:

```bash
cd WinHUBMacAgent-v<VERSION>-macos-arm64-installer
WINHUB_EXPECTED_TEAM_ID="TEAMID" ./setup-macos-agent.sh
```

The setup script checks the Developer ID Installer signature and Gatekeeper assessment,
prompts for the HTTPS URL and secrets without adding them to shell history, stages them in a
root-only temporary directory, installs the `.pkg`, removes the staging directory and waits
for the LaunchDaemon to remain running.

For MDM/unattended installation, prepare runtime and bootstrap JSON files and run:

```bash
WINHUB_EXPECTED_TEAM_ID="TEAMID" ./setup-macos-agent.sh \
  --pkg ./WinHUBMacAgent-v<VERSION>-macos-arm64.pkg \
  --config ./winhub_agent.conf \
  --bootstrap-config ./winhub_agent.bootstrap.conf
```

Do not put secrets directly in a command argument or a `.pkg`. Protect temporary config
files with mode `0600` and delete the deployment copy after installation.

## Build, sign and notarize on a MacBook M4

```bash
WINHUB_CODESIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)" \
WINHUB_INSTALLER_IDENTITY="Developer ID Installer: Example Corp (TEAMID)" \
WINHUB_NOTARY_PROFILE="winhub-notary" \
  ./create-macos-agent-release.sh
```

The default production build creates:

- `WinHUBMacAgent-v<VERSION>-macos-arm64.tar.gz` and SHA-256 for **WinHUB managed updates**;
- a signed and stapled `WinHUBMacAgent-v<VERSION>-macos-arm64.pkg` and SHA-256;
- an installer `.zip` containing the notarized package and interactive setup wrapper.

An explicitly limited signed update-only build is available with `WINHUB_UPDATE_ONLY=1`.
An ad-hoc local test build requires `WINHUB_ALLOW_UNSIGNED_BUILD=1` and must never be uploaded
to production WinHUB.

The complete host preparation, certificate, notarization, build, rollout, MDM, PPPC and
incident procedures are in [BUILD_MAC_M4_UA.md](docs/BUILD_MAC_M4_UA.md).

## Operations

```bash
sudo launchctl print system/com.winhub.agent
sudo /Library/PrivilegedHelperTools/com.winhub.agent/diagnose-macos-agent.sh
tail -f /Library/Logs/WinHUB/agent.log
```

Uninstall while retaining identity/config/logs:

```bash
sudo /Library/PrivilegedHelperTools/com.winhub.agent/uninstall-macos-agent.sh
```

Permanently remove all local WinHUB Agent state:

```bash
sudo /Library/PrivilegedHelperTools/com.winhub.agent/uninstall-macos-agent.sh --purge
```
