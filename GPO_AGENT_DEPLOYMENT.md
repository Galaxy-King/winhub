# WinHUB Agent Deployment Through GPO

This guide describes the tested way to deploy WinHUB Agent to domain computers through Group Policy.

The recommended method is:

- GPO is linked to the domain or target OU.
- Security Filtering limits the GPO to an AD security group containing computer accounts.
- A Computer Startup `.cmd` wrapper runs the PowerShell installer.
- Agent files and configs are stored in `NETLOGON`.

## 1. Deployment Folder

Create this folder on the domain controller:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy
```

Local path on the domain controller:

```text
C:\Windows\SYSVOL\sysvol\sot01.aditsot.com\scripts\WinHUBAgentDeploy
```

Expected files:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\
  WinHUBAgent-v1.2.6-win-x64.zip
  winhub_agent.conf
  winhub_agent.bootstrap.conf
  install-winhub-agent.ps1
  install-winhub-agent.cmd
```

The ZIP should contain agent binaries and service scripts only:

```text
WinHUBAgent.exe
install-service.ps1
update-service.ps1
uninstall-service.ps1
appsettings.json
```

Do not put real secrets directly inside the ZIP. Keep real configs beside the ZIP in the protected deployment folder.

## 2. Config Files

`winhub_agent.conf` contains runtime connection settings:

```json
{
  "ServerUrl": "https://130.0.234.89:55555",
  "PollIntervalSeconds": 30,
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "SERVER_CERT_SHA256_WITHOUT_COLONS",
  "RequireTaskSignature": true
}
```

`winhub_agent.bootstrap.conf` contains enrollment/signing secrets:

```json
{
  "GlobalApiKey": "SERVER_AGENT_API_KEY",
  "TaskHmacSecret": "SERVER_AGENT_TASK_HMAC_SECRET"
}
```

On the WinHUB server, values are in:

```bash
/etc/winhub/winhub.env
```

Useful commands:

```bash
grep -E '^(AGENT_API_KEY|AGENT_TASK_HMAC_SECRET)=' /etc/winhub/winhub.env
```

`ServerCertificateSha256` is the SHA256 hash of the TLS certificate as seen by agents through the public agent endpoint.

Example from Windows:

```powershell
$HostName = "130.0.234.89"
$Port = 55555

$tcp = New-Object Net.Sockets.TcpClient($HostName, $Port)
$ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient($HostName)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
$sha = [System.Security.Cryptography.SHA256]::Create()
([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace("-", "").ToLower()
$ssl.Dispose()
$tcp.Close()
```

## 3. Folder Permissions

Startup scripts run as the computer account, not the interactive user.

The deployment folder must be readable by target computer accounts.

On the domain controller:

```powershell
icacls "C:\Windows\SYSVOL\sysvol\sot01.aditsot.com\scripts\WinHUBAgentDeploy" /grant "Domain Computers:(OI)(CI)RX"
```

Recommended:

- `Domain Computers`: Read & Execute
- Domain/Enterprise admins: Full Control
- Avoid broad write access.

If you later move files to a dedicated share, grant both share and NTFS read permissions to the target computer group or `Domain Computers`.

## 4. AD Group For Target Hosts

Create a security group for test deployment:

```text
WinHUB_Agent_Deploy_Test
```

Add computer accounts to the group, not user accounts.

Example:

```text
FEMMELISE-PC$
SERVER01$
TERMINAL01$
```

PowerShell example on the domain controller:

```powershell
Add-ADGroupMember -Identity "WinHUB_Agent_Deploy_Test" -Members "FEMMELISE-PC$"
```

Important: after adding a computer to an AD group, reboot the computer so its machine token contains the new group membership.

## 5. GPO Security Filtering

Create or use GPO:

```text
Deploy WinHUB Agent
```

Link it to the domain or to the OU containing target computers.

In `Scope -> Security Filtering`:

- Remove `Authenticated Users`.
- Add `WinHUB_Agent_Deploy_Test`.

In `Delegation -> Advanced`:

- `WinHUB_Agent_Deploy_Test`: Allow `Read` and `Apply group policy`.
- `Domain Computers`: Allow `Read` only.

This means only computers in `WinHUB_Agent_Deploy_Test` apply the GPO, while domain computers can still read the GPO metadata.

## 6. GPO Settings

Set the startup script:

```text
Computer Configuration
-> Policies
-> Windows Settings
-> Scripts (Startup/Shutdown)
-> Startup
-> Scripts
```

Add:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Use the `.cmd` wrapper instead of directly adding the PowerShell script. It writes a clear wrapper log and avoids silent PowerShell startup-script issues.

Enable network wait:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> System
-> Logon
-> Always wait for the network at computer startup and logon = Enabled
```

Recommended script settings:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> System
-> Scripts
-> Run Windows PowerShell scripts first = Enabled
-> Specify maximum wait time for Group Policy scripts = 600 seconds
```

If PowerShell execution is restricted, enable:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> Windows Components
-> Windows PowerShell
-> Turn on Script Execution = Enabled
-> Allow all scripts
```

## 7. CMD Wrapper

Create:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Content:

```cmd
@echo off
mkdir "C:\ProgramData\WinHUB\gpo-install" 2>nul

echo [%date% %time%] Starting WinHUB GPO wrapper >> "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1" >> "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" 2>&1

echo [%date% %time%] Finished with exit code %ERRORLEVEL% >> "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log"

exit /b %ERRORLEVEL%
```

## 8. PowerShell Installer

Create:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1
```

Content:

```powershell
$ErrorActionPreference = "Stop"

$PackageVersion = "1.2.6"
$SourceDir = "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy"
$ZipName = "WinHUBAgent-v$PackageVersion-win-x64.zip"

$ServiceName = "WinHUBAgent"
$InstallDir = "C:\Program Files\WinHUBAgent"
$DataDir = "C:\ProgramData\WinHUB"
$TempDir = Join-Path $DataDir "gpo-install"
$ExtractDir = Join-Path $TempDir "extract"
$ZipPath = Join-Path $TempDir $ZipName
$LogFile = Join-Path $TempDir "install.log"
$VersionMarker = Join-Path $InstallDir ".deployed_version"

$RuntimeConfigSource = Join-Path $SourceDir "winhub_agent.conf"
$BootstrapSource = Join-Path $SourceDir "winhub_agent.bootstrap.conf"

$RuntimeConfigTarget = Join-Path $InstallDir "winhub_agent.conf"
$BootstrapTarget = Join-Path $InstallDir "winhub_agent.bootstrap.conf"

function Write-DeployLog {
    param([string]$Message)

    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

try {
    Write-DeployLog "Starting WinHUB Agent deployment. Target version: $PackageVersion"

    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $sourceZip = Join-Path $SourceDir $ZipName

    if (-not (Test-Path -LiteralPath $sourceZip)) {
        throw "Package not found: $sourceZip"
    }

    if (-not (Test-Path -LiteralPath $RuntimeConfigSource)) {
        throw "Runtime config not found: $RuntimeConfigSource"
    }

    if (-not (Test-Path -LiteralPath $BootstrapSource)) {
        throw "Bootstrap config not found: $BootstrapSource"
    }

    $installedVersion = ""
    if (Test-Path -LiteralPath $VersionMarker) {
        $installedVersion = (Get-Content -LiteralPath $VersionMarker -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    }

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($service -and $installedVersion -eq $PackageVersion) {
        Write-DeployLog "WinHUB Agent $PackageVersion already installed."

        if ($service.Status -ne "Running") {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
            Write-DeployLog "Service start requested."
        }

        exit 0
    }

    Copy-Item -LiteralPath $sourceZip -Destination $ZipPath -Force
    Write-DeployLog "Package copied to $ZipPath"

    if (Test-Path -LiteralPath $ExtractDir) {
        Remove-Item -LiteralPath $ExtractDir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

    Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractDir -Force
    Write-DeployLog "Package extracted to $ExtractDir"

    if ($service) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-DeployLog "Existing service stopped."
    }

    Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notin @(
            "winhub_agent.conf",
            "winhub_agent.bootstrap.conf",
            ".deployed_version"
        )
    } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Copy-Item -Path (Join-Path $ExtractDir "*") -Destination $InstallDir -Recurse -Force
    Write-DeployLog "Agent files copied to $InstallDir"

    if (-not (Test-Path -LiteralPath $RuntimeConfigTarget)) {
        Copy-Item -LiteralPath $RuntimeConfigSource -Destination $RuntimeConfigTarget -Force
        Write-DeployLog "Runtime config copied to $RuntimeConfigTarget"
    } else {
        Write-DeployLog "Runtime config already exists, copy skipped."
    }

    if (-not (Test-Path -LiteralPath $BootstrapTarget)) {
        Copy-Item -LiteralPath $BootstrapSource -Destination $BootstrapTarget -Force
        Write-DeployLog "Bootstrap config copied to $BootstrapTarget"
    } else {
        Write-DeployLog "Bootstrap config already exists, copy skipped."
    }

    $installScript = Join-Path $InstallDir "install-service.ps1"
    if (-not (Test-Path -LiteralPath $installScript)) {
        throw "install-service.ps1 not found in $InstallDir"
    }

    Set-ExecutionPolicy Bypass -Scope Process -Force

    & $installScript -InstallDir $InstallDir -ServiceName $ServiceName
    Write-DeployLog "install-service.ps1 executed."

    Set-Content -LiteralPath $VersionMarker -Value $PackageVersion -Encoding ASCII
    Write-DeployLog "Version marker updated: $PackageVersion"

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-DeployLog "Service start requested after install."
    }

    Write-DeployLog "WinHUB Agent deployment completed successfully."
} catch {
    Write-DeployLog "ERROR: $($_.Exception.Message)"
    throw
}
```

## 9. Client Verification

On a test computer:

```powershell
gpupdate /force
Restart-Computer
```

After reboot:

```powershell
gpresult /r /scope computer
```

Expected in `Applied Group Policy Objects`:

```text
Deploy WinHUB Agent
```

Check wrapper log:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" -Tail 80
```

Check installer log:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\install.log" -Tail 80
```

Check installed files:

```powershell
Get-ChildItem "C:\Program Files\WinHUBAgent"
```

Check service:

```powershell
Get-Service WinHUBAgent
Get-CimInstance Win32_Service -Filter "Name='WinHUBAgent'" |
  Select Name, State, StartMode, PathName
```

Check service recovery:

```powershell
sc.exe qfailure WinHUBAgent
```

Expected recovery actions:

```text
RESTART
RESTART
RESTART
```

Check network:

```powershell
Test-NetConnection 130.0.234.89 -Port 55555
```

In WinHUB:

```text
Endpoint Management -> Nodes -> Pending Approval
```

Approve the new node. After the next poll or service restart, it should become online.

## 10. Troubleshooting

If GPO is applied but no agent folder exists:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" -Tail 80
Get-Content "C:\ProgramData\WinHUB\gpo-install\install.log" -Tail 80
```

If logs do not exist, startup scripts are not running or the GPO did not run at boot.

Check applied GPOs:

```powershell
gpresult /h C:\gp.html
start C:\gp.html
```

Look for:

```text
Computer Configuration -> Windows Settings -> Scripts -> Startup
```

Check Group Policy operational log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 120 |
Where-Object { $_.Message -match "script|startup|WinHUB|PowerShell|error|fail" } |
Select TimeCreated, Id, LevelDisplayName, Message |
Format-List
```

Check access to deployment files:

```powershell
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1"
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\WinHUBAgent-v1.2.6-win-x64.zip"
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\winhub_agent.conf"
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\winhub_agent.bootstrap.conf"
```

If the user can open the folder but startup script fails, test as LocalSystem:

```powershell
psexec -i -s powershell.exe
```

Inside the SYSTEM PowerShell:

```powershell
whoami
Test-Path "\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
```

Expected:

```text
nt authority\system
True
```

## 11. Production Rollout

After test deployment works:

1. Keep `WinHUB_Agent_Deploy_Test` for testing.
2. Create a production group, for example:

```text
WinHUB_Agent_Deploy_Prod
```

3. Add target computer accounts gradually.
4. Replace Security Filtering on the GPO with the production group, or keep separate GPOs for test/prod.
5. Reboot target computers after adding them to the group.
6. Approve nodes in WinHUB Pending Approval.

For a controlled rollout, add computers in small batches.

## 12. Updating Agent Version Through GPO

When a new agent package is ready:

1. Copy the new ZIP to:

```text
\\sot01.aditsot.com\NETLOGON\WinHUBAgentDeploy
```

2. Change in `install-winhub-agent.ps1`:

```powershell
$PackageVersion = "1.2.7"
```

3. Reboot target machines.

The script compares:

```text
C:\Program Files\WinHUBAgent\.deployed_version
```

If the marker differs from `$PackageVersion`, it updates the agent files and reinstalls the service. Existing local `winhub_agent.conf` is not overwritten.
