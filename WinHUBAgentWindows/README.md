# WinHUBAgentWindows

Source project: `WinHUBAgentWindows.csproj`. The executable, service and update archives retain the name `WinHUBAgent` for compatibility with installed agents.

Windows endpoint agent for WinHUB.

Current strict-pin changes are a **release candidate**, not completion of the full production hardening plan. [Implemented controls, migration requirements and remaining release gates](../WinHUB-WiKi/guides/agents/PRODUCTION_PIN_AGENTS_UA.md). Build from the full repository: this project links `../WinHUBLinuxAgent/Security/*.cs`.

## Production build

Build on a machine with the .NET 8 SDK installed:

```powershell
cd C:\Path\To\WinHUB_Project\WinHUBAgentWindows
dotnet restore
dotnet publish .\WinHUBAgentWindows.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishAot=true `
  -o .\publish
```

Do not combine `PublishAot=true` with `PublishSingleFile=true`; .NET does not allow those two publish modes together.

If you specifically want a non-AOT single-file build, use this alternative:

```powershell
dotnet publish .\WinHUBAgentWindows.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishAot=false `
  -p:PublishSingleFile=true `
  -o .\publish
```

Copy the contents of `.\publish` to each endpoint, for example:

```text
C:\Program Files\WinHUBAgent
```

Do not deploy `WinHUBAgent.pdb` to production endpoints. Keep it on the build server for diagnostics.

Package a release build:

```powershell
.\create-agent-release.ps1 -Version 1.2.0
```

The release script builds NativeAOT by default. Use `-ManagedSingleFile` only when you explicitly need a non-AOT managed single-file package:

```powershell
.\create-agent-release.ps1 -Version 1.2.0 -ManagedSingleFile
```

## Agent configs

Use two config files:

- `winhub_agent.conf` is the runtime config. It does not contain secrets.
- `winhub_agent.bootstrap.conf` is used only for first enrollment. It contains secrets and is deleted by the agent after migration to DPAPI.

Runtime config:

```json
{
  "ServerUrl": "https://192.168.37.223:8443",
  "GlobalApiKey": "",
  "PollIntervalSeconds": 30,
  "PollJitterSeconds": 30,
  "StartupSpreadSeconds": 120,
  "TaskHmacSecret": "",
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "SERVER_CERT_SHA256_WITHOUT_COLONS",
  "ServerCertificateSha256Next": "",
  "RequireTaskSignature": true,
  "RestartAfterConsecutivePollFailures": 10
}
```

Polling cadence:

- `PollIntervalSeconds` is the base polling interval.
- `PollJitterSeconds` adds a random `0..N` second delay after every poll, preventing many agents from polling in the same second.
- `StartupSpreadSeconds` adds a stable per-host startup delay before the first poll, so GPO deployments, service restarts, and mass updates do not create a synchronized request burst.
- `RestartAfterConsecutivePollFailures` exits the agent after N failed polls in a row so Windows Service Recovery can restart it. Use `0` to disable this self-heal.
- Newer servers can return `next_poll_after`, `poll_jitter_seconds`, and `telemetry_after` in `/api/agent/poll`; the agent treats those as bounded scheduling hints and falls back to the local config when they are absent.

Bootstrap config:

```json
{
  "GlobalApiKey": "ADMINISTRATOR_PROVISIONED_ENROLLMENT_TOKEN"
}
```

Production uses an administrator-provisioned SHA-256 certificate pin. Only HTTPS is accepted; TLS bypass and legacy/unsigned task execution are forbidden. An optional `ServerCertificateSha256Next` supports planned certificate rotation. The leaf certificate must be within its validity dates.

Obtain the fingerprint locally on the trusted WinHUB server, not from an unverified network connection:

```bash
openssl x509 -in /etc/winhub/certs/cert.pem -noout -fingerprint -sha256 -dates
```

Use the actual Nginx leaf certificate if its path differs. Never send the private `key.pem` to an endpoint. See the [strict pin rollout and release gates](../WinHUB-WiKi/guides/agents/PRODUCTION_PIN_AGENTS_UA.md).

During initial enrollment the agent migrates `GlobalApiKey` into DPAPI-protected storage under:

```text
C:\ProgramData\WinHUB\agent.secrets
```

After successful migration the bootstrap config is removed. After enrollment succeeds, `GlobalApiKey` is removed from local DPAPI storage; an already enrolled agent also removes a leftover bootstrap key on upgrade. The agent retains only its per-host token and identity key. Tasks require per-agent RSA-PSS v2; legacy `TaskHmacSecret` is discarded at startup. The pinned task key and replay counter are persisted separately in `C:\ProgramData\WinHUB\task-signing-state.json` before execution.

`C:\ProgramData\WinHUB\execution-journal` retains task claims and undelivered results. After a crash, interrupted execution is reported as UNKNOWN (it may have had side effects), never silently rerun. See the release gates for journal capacity, archival and rollback limitations.

The agent checks local ACLs on startup and when it writes sensitive files. It restricts the install folder, data folder, logs, token, hardware ID, identity key, and secret store to `SYSTEM` and local `Administrators`.

Local service logs are written to:

```text
C:\ProgramData\WinHUB\logs\agent.log
```

Logs rotate at 1 MiB, keep up to 7 rotated files, and files older than 14 days are removed automatically.

If deployment tooling keeps copying `winhub_agent.bootstrap.conf` back to endpoints, fix the deployment rule after first rollout.

## Server enrollment hardening

For production, set these values on the WinHUB server:

```env
AGENT_API_KEY=long-random-bootstrap-secret
AGENT_TASK_HMAC_SECRET=another-long-random-task-signing-secret
AGENT_ENROLLMENT_ENABLED=true
AGENT_ENROLLMENT_ALLOWLIST=
AGENT_ALLOW_REENROLL_EXISTING=false
AGENT_TASK_SIGNATURE_MODE=v2
AGENT_REQUIRE_SIGNED_REQUESTS=true
AGENT_ALLOW_LEGACY_AGENT_SIGNATURES=false
AGENT_ENROLLMENT_RATE_LIMIT=10 per minute
RATELIMIT_STORAGE_URI=memory://
RATELIMIT_DEFAULT=
```

The HMAC value above remains a server configuration requirement for compatibility; do not distribute it to strict-v2 Windows/Linux agents. This release does not yet add single-use scoped enrollment tokens on the server.

For a global server, leave `AGENT_ENROLLMENT_ALLOWLIST` empty and rely on:

- manual approval;
- Pending quarantine;
- enrollment-only rate limit;
- TLS pinning;
- per-agent RSA-PSS v2 task signatures;
- blocked re-enrollment for already approved hosts.

If enrollment should be closed after a rollout window, set:

```env
AGENT_ENROLLMENT_ENABLED=false
```

Then restart WinHUB. Existing approved agents continue to poll with their per-host `auth_token`; new enrollments are blocked until enrollment is enabled again.

## Install service

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd "C:\Program Files\WinHUBAgent"
.\install-service.ps1
```

The install script locks down ACLs for:

```text
C:\Program Files\WinHUBAgent
C:\ProgramData\WinHUB
```

Only `SYSTEM` and local `Administrators` get access.

Check logs:

```powershell
Get-Content "C:\ProgramData\WinHUB\logs\agent.log" -Tail 100

Get-EventLog -LogName Application -Source WinHUBAgent -Newest 30 |
  Select-Object TimeGenerated, EntryType, Message
```

## Update service

Copy a versioned agent package to the endpoint and run PowerShell as Administrator:

```powershell
cd "C:\Program Files\WinHUBAgent"
.\update-service.ps1 -PackagePath "C:\Temp\WinHUBAgent-PACKAGE.zip" -ExpectedSha256 "AUTHORIZED_64_HEX_SHA256"
```

The update script backs up the current install under:

```text
C:\ProgramData\WinHUB\backups
```

It preserves `winhub_agent.conf` and does not delete DPAPI secrets from:

```text
C:\ProgramData\WinHUB\agent.secrets
```

## Remote self-update task

Approved agents can update themselves when WinHUB dispatches an `agent_update` task.

WinHUB seeds an `Agent Self Update` template in the Infrastructure module. Approve it only for users who are allowed to update endpoint software.

Task payload:

```json
{
  "package_url": "https://SERVER_IP/downloads/WinHUBAgent-v0.1.0-win-x64.zip",
  "sha256": "PACKAGE_SHA256_WITHOUT_COLONS"
}
```

`package_url` may be relative or use the same HTTPS origin as `ServerUrl`. `sha256` is mandatory. Redirects, cross-host downloads, packages above 512 MiB and mismatching hashes are refused. SHA-256 from a signed task is not an independent publisher signature; see the remaining release gates before deployment.

The agent downloads the package to:

```text
C:\ProgramData\WinHUB\updates
```

Then it launches `update-service.ps1` as a detached PowerShell process, reports that the update was launched, and the updater restarts the Windows service.

## Enrollment flow

1. Agent posts enrollment to `/api/agent/enroll`.
2. Server creates the host as `Pending`.
3. Admin approves the host in Infrastructure.
4. Only approved hosts receive tasks.
5. Tasks are signed by the server with a separate per-endpoint RSA-PSS key.
6. The agent refuses unsigned, legacy, invalid or replayed tasks. Production cannot disable these checks.

## Uninstall service

Run PowerShell as Administrator:

```powershell
cd "C:\Program Files\WinHUBAgent"
.\uninstall-service.ps1
```
