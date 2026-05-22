# WinHUBAgent

Windows endpoint agent for WinHUB.

## Production build

Build on a machine with the .NET 8 SDK installed:

```powershell
cd C:\Path\To\WinHUBAgent
dotnet restore
dotnet publish .\WinHUBAgent.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishAot=true `
  -o .\publish
```

Do not combine `PublishAot=true` with `PublishSingleFile=true`; .NET does not allow those two publish modes together.

If you specifically want a non-AOT single-file build, use this alternative:

```powershell
dotnet publish .\WinHUBAgent.csproj `
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
  "TaskHmacSecret": "",
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "SERVER_CERT_SHA256_WITHOUT_COLONS",
  "RequireTaskSignature": true
}
```

Bootstrap config:

```json
{
  "GlobalApiKey": "same-value-as-server-AGENT_API_KEY",
  "TaskHmacSecret": "same-value-as-server-AGENT_TASK_HMAC_SECRET"
}
```

Because WinHUB is reached by IP address, production TLS should use one of these approaches:

- Certificate with an IP Subject Alternative Name for the server IP.
- Internal CA trusted by endpoints.
- Certificate pinning with `ServerCertificateSha256`.

Do not use `IgnoreTlsCertificateErrors=true` in production.

To get the SHA256 thumbprint from the WinHUB server certificate on a Windows machine:

```powershell
$tcp = New-Object Net.Sockets.TcpClient("192.168.37.223", 8443)
$ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient("192.168.37.223")
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
$cert.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
$ssl.Dispose()
$tcp.Dispose()
```

Paste the returned value into `ServerCertificateSha256` without spaces or colons.

After the first successful start, the agent migrates `GlobalApiKey` and `TaskHmacSecret` into DPAPI-protected storage under:

```text
C:\ProgramData\WinHUB\agent.secrets
```

The plaintext bootstrap config is removed after migration. If deployment tooling keeps copying `winhub_agent.bootstrap.conf` back to endpoints, fix the deployment rule after first rollout.

## Server enrollment hardening

For production, set these values on the WinHUB server:

```env
AGENT_API_KEY=long-random-bootstrap-secret
AGENT_TASK_HMAC_SECRET=another-long-random-task-signing-secret
AGENT_ENROLLMENT_ENABLED=true
AGENT_ENROLLMENT_ALLOWLIST=
AGENT_ALLOW_REENROLL_EXISTING=false
AGENT_ENROLLMENT_RATE_LIMIT=10 per minute
RATELIMIT_STORAGE_URI=memory://
RATELIMIT_DEFAULT=
```

For a global server, leave `AGENT_ENROLLMENT_ALLOWLIST` empty and rely on:

- manual approval;
- Pending quarantine;
- enrollment-only rate limit;
- TLS pinning;
- task HMAC;
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
Get-EventLog -LogName Application -Source WinHUBAgent -Newest 30 |
  Select-Object TimeGenerated, EntryType, Message
```

## Update service

Copy a versioned agent package to the endpoint and run PowerShell as Administrator:

```powershell
cd "C:\Program Files\WinHUBAgent"
.\update-service.ps1 -PackagePath "C:\Temp\WinHUBAgent-v0.1.0-win-x64.zip"
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

`package_url` may be absolute or relative to `ServerUrl`. `sha256` is strongly recommended; if provided, the agent refuses to launch the updater when the package hash does not match.

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
5. Tasks are signed by the server with `AGENT_TASK_HMAC_SECRET`.
6. Agent refuses unsigned/invalid tasks when `RequireTaskSignature=true`.

## Uninstall service

Run PowerShell as Administrator:

```powershell
cd "C:\Program Files\WinHUBAgent"
.\uninstall-service.ps1
```
