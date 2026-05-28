# WinHUB Agent Deployment Through GPO

This guide describes the tested way to deploy WinHUB Agent to domain computers through Group Policy.

Українська версія починається нижче: [Українська інструкція](#ukrainian-guide).

Use the placeholders below and replace them with your environment values:

```text
<DOMAIN_FQDN>          example: corp.example.com
<DC_FQDN>              example: dc01.corp.example.com
<PUBLIC_AGENT_HOST>    example: 203.0.113.10
<AGENT_PUBLIC_PORT>    example: 55555
<AGENT_VERSION>        example: 1.2.6
```

## English Guide

### 1. Recommended Deployment Model

- Link the GPO to the domain or the OU containing target computers.
- Limit application through Security Filtering to an AD security group containing computer accounts.
- Run a Computer Startup `.cmd` wrapper.
- Let the `.cmd` wrapper call the PowerShell installer.
- Store deployment files in `NETLOGON`.
- Keep real agent configs beside the ZIP, not inside the ZIP.

### 2. Deployment Folder

Create this folder on the domain controller:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy
```

Local path on the domain controller:

```text
C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy
```

Expected files:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\
  WinHUBAgent-v<AGENT_VERSION>-win-x64.zip
  winhub_agent.conf
  winhub_agent.bootstrap.conf
  install-winhub-agent.ps1
  install-winhub-agent.cmd
```

The ZIP should contain only agent binaries and service scripts:

```text
WinHUBAgent.exe
install-service.ps1
update-service.ps1
uninstall-service.ps1
appsettings.json
```

Do not put real `winhub_agent.conf` or `winhub_agent.bootstrap.conf` inside the ZIP. Future agent updates may replace files from the ZIP, so configs should live beside the archive and be copied only during first install.

### 3. Agent Config Files

`winhub_agent.conf` contains runtime connection settings:

```json
{
  "ServerUrl": "https://<PUBLIC_AGENT_HOST>:<AGENT_PUBLIC_PORT>",
  "PollIntervalSeconds": 30,
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "SERVER_CERT_SHA256_WITHOUT_COLONS",
  "RequireTaskSignature": true
}
```

`winhub_agent.bootstrap.conf` contains enrollment and task signing secrets:

```json
{
  "GlobalApiKey": "SERVER_AGENT_API_KEY",
  "TaskHmacSecret": "SERVER_AGENT_TASK_HMAC_SECRET"
}
```

On the WinHUB server, the values are usually stored in:

```bash
/etc/winhub/winhub.env
```

Useful command:

```bash
grep -E '^(AGENT_API_KEY|AGENT_TASK_HMAC_SECRET)=' /etc/winhub/winhub.env
```

`ServerCertificateSha256` must be the SHA256 hash of the TLS certificate as seen by agents through the public agent endpoint.

Example from Windows:

```powershell
$HostName = "<PUBLIC_AGENT_HOST>"
$Port = <AGENT_PUBLIC_PORT>

$tcp = New-Object Net.Sockets.TcpClient($HostName, $Port)
$ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient($HostName)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
$sha = [System.Security.Cryptography.SHA256]::Create()
([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace("-", "").ToLower()
$ssl.Dispose()
$tcp.Close()
```

### 4. Folder Permissions

Startup scripts run as the computer account, not as the logged-in user.

The deployment folder must be readable by target computer accounts.

On the domain controller:

```powershell
icacls "C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy" /grant "Domain Computers:(OI)(CI)RX"
```

Recommended permissions:

- `Domain Computers`: Read & Execute
- Domain/Enterprise admins: Full Control
- No broad write permissions for regular users

If files are moved to a dedicated SMB share, configure both share permissions and NTFS permissions. Target computer accounts must be able to read the files.

### 5. AD Group For Target Hosts

Create a security group for test deployment:

```text
WinHUB_Agent_Deploy_Test
```

Add computer accounts, not user accounts:

```text
CLIENT01$
SERVER01$
TERMINAL01$
```

PowerShell example on the domain controller:

```powershell
Add-ADGroupMember -Identity "WinHUB_Agent_Deploy_Test" -Members "CLIENT01$"
```

After adding a computer to an AD group, reboot the computer so its machine token contains the new group membership.

### 6. GPO Security Filtering

Create or use a GPO:

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

### 7. GPO Settings

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
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Use the `.cmd` wrapper instead of directly adding the PowerShell script. The wrapper writes a clear startup log and avoids silent PowerShell startup-script issues.

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

If PowerShell execution is restricted:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> Windows Components
-> Windows PowerShell
-> Turn on Script Execution = Enabled
-> Allow all scripts
```

### 8. CMD Wrapper

Create:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Content:

```cmd
@echo off
set SOURCE=\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy
set LOGDIR=C:\ProgramData\WinHUB\gpo-install
mkdir "%LOGDIR%" 2>nul

echo [%date% %time%] Starting WinHUB GPO wrapper >> "%LOGDIR%\startup-wrapper.log"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SOURCE%\install-winhub-agent.ps1" >> "%LOGDIR%\startup-wrapper.log" 2>&1

echo [%date% %time%] Finished with exit code %ERRORLEVEL% >> "%LOGDIR%\startup-wrapper.log"

exit /b %ERRORLEVEL%
```

### 9. PowerShell Installer

Create:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1
```

Content:

```powershell
$ErrorActionPreference = "Stop"

$PackageVersion = "<AGENT_VERSION>"
$SourceDir = "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy"
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

### 10. Client Verification

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

Check logs:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" -Tail 80
Get-Content "C:\ProgramData\WinHUB\gpo-install\install.log" -Tail 80
```

Check installed files and service:

```powershell
Get-ChildItem "C:\Program Files\WinHUBAgent"
Get-Service WinHUBAgent
Get-CimInstance Win32_Service -Filter "Name='WinHUBAgent'" |
  Select Name, State, StartMode, PathName
sc.exe qfailure WinHUBAgent
```

Expected service recovery actions:

```text
RESTART
RESTART
RESTART
```

Check network:

```powershell
Test-NetConnection <PUBLIC_AGENT_HOST> -Port <AGENT_PUBLIC_PORT>
```

In WinHUB:

```text
Endpoint Management -> Nodes -> Pending Approval
```

Approve the new node. After the next poll or service restart, it should become online.

### 11. Troubleshooting

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

Check access to deployment files:

```powershell
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\WinHUBAgent-v<AGENT_VERSION>-win-x64.zip"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\winhub_agent.conf"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\winhub_agent.bootstrap.conf"
```

If the interactive user can open the folder but startup script still fails, test access as LocalSystem:

```powershell
psexec -i -s powershell.exe
```

Inside the SYSTEM PowerShell:

```powershell
whoami
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
```

Expected:

```text
nt authority\system
True
```

### 12. Production Rollout

After test deployment works:

1. Keep `WinHUB_Agent_Deploy_Test` for testing.
2. Create a production group, for example `WinHUB_Agent_Deploy_Prod`.
3. Add target computer accounts gradually.
4. Replace Security Filtering on the GPO with the production group, or keep separate GPOs for test/prod.
5. Reboot target computers after adding them to the group.
6. Approve nodes in WinHUB Pending Approval.

For a controlled rollout, add computers in small batches.

### 13. Updating Agent Version Through GPO

When a new agent package is ready:

1. Copy the new ZIP to `\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy`.
2. Change `$PackageVersion` in `install-winhub-agent.ps1`.
3. Reboot target machines.

The script compares:

```text
C:\Program Files\WinHUBAgent\.deployed_version
```

If the marker differs from `$PackageVersion`, it updates the agent files and reinstalls the service. Existing local `winhub_agent.conf` is not overwritten.

---

## Ukrainian Guide

Ця інструкція описує перевірений спосіб розгортання WinHUB Agent на доменні комп'ютери через Group Policy.

Використовуй ці змінні та заміни їх під своє середовище:

```text
<DOMAIN_FQDN>          приклад: corp.example.com
<DC_FQDN>              приклад: dc01.corp.example.com
<PUBLIC_AGENT_HOST>    приклад: 203.0.113.10
<AGENT_PUBLIC_PORT>    приклад: 55555
<AGENT_VERSION>        приклад: 1.2.6
```

### 1. Рекомендована схема

- GPO прив'язується до домену або OU з потрібними комп'ютерами.
- Security Filtering обмежує застосування політики до AD-групи з computer accounts.
- На старті комп'ютера запускається `.cmd` wrapper.
- `.cmd` wrapper запускає PowerShell installer.
- Файли агента лежать у `NETLOGON`.
- Реальні конфіги лежать поруч із ZIP, а не всередині ZIP.

### 2. Папка для розгортання

Створи папку на контролері домену:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy
```

Локальний шлях на контролері домену:

```text
C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy
```

Очікувані файли:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\
  WinHUBAgent-v<AGENT_VERSION>-win-x64.zip
  winhub_agent.conf
  winhub_agent.bootstrap.conf
  install-winhub-agent.ps1
  install-winhub-agent.cmd
```

У ZIP мають бути тільки файли агента і service scripts:

```text
WinHUBAgent.exe
install-service.ps1
update-service.ps1
uninstall-service.ps1
appsettings.json
```

Не клади реальні `winhub_agent.conf` або `winhub_agent.bootstrap.conf` всередину ZIP. Під час майбутніх оновлень файли з ZIP можуть замінювати вміст папки агента, тому конфіги краще тримати поруч з архівом і копіювати тільки при першому встановленні.

### 3. Конфіги агента

`winhub_agent.conf` містить параметри підключення:

```json
{
  "ServerUrl": "https://<PUBLIC_AGENT_HOST>:<AGENT_PUBLIC_PORT>",
  "PollIntervalSeconds": 30,
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "SERVER_CERT_SHA256_WITHOUT_COLONS",
  "RequireTaskSignature": true
}
```

`winhub_agent.bootstrap.conf` містить секрети enrollment/signing:

```json
{
  "GlobalApiKey": "SERVER_AGENT_API_KEY",
  "TaskHmacSecret": "SERVER_AGENT_TASK_HMAC_SECRET"
}
```

На WinHUB сервері ці значення зазвичай у:

```bash
/etc/winhub/winhub.env
```

Команда для перегляду:

```bash
grep -E '^(AGENT_API_KEY|AGENT_TASK_HMAC_SECRET)=' /etc/winhub/winhub.env
```

`ServerCertificateSha256` має бути SHA256 сертифіката, який агент бачить через публічний agent endpoint.

Приклад з Windows:

```powershell
$HostName = "<PUBLIC_AGENT_HOST>"
$Port = <AGENT_PUBLIC_PORT>

$tcp = New-Object Net.Sockets.TcpClient($HostName, $Port)
$ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient($HostName)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
$sha = [System.Security.Cryptography.SHA256]::Create()
([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace("-", "").ToLower()
$ssl.Dispose()
$tcp.Close()
```

### 4. Права на папку

Startup scripts виконуються від імені computer account, а не від імені залогіненого користувача.

Цільові комп'ютери мають мати право читати deployment folder.

На контролері домену:

```powershell
icacls "C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy" /grant "Domain Computers:(OI)(CI)RX"
```

Рекомендовано:

- `Domain Computers`: Read & Execute
- Domain/Enterprise admins: Full Control
- Не давати широкі write permissions звичайним користувачам

Якщо переносиш файли на окрему SMB-share, налаштуй і share permissions, і NTFS permissions. Computer accounts цільових хостів мають читати файли.

### 5. AD-група для цільових хостів

Створи security group для тесту:

```text
WinHUB_Agent_Deploy_Test
```

Додавай саме computer accounts, не user accounts:

```text
CLIENT01$
SERVER01$
TERMINAL01$
```

PowerShell приклад на контролері домену:

```powershell
Add-ADGroupMember -Identity "WinHUB_Agent_Deploy_Test" -Members "CLIENT01$"
```

Після додавання комп'ютера в AD-групу перезавантаж комп'ютер, щоб його machine token отримав нове членство в групі.

### 6. Security Filtering у GPO

Створи або використовуй GPO:

```text
Deploy WinHUB Agent
```

Прив'яжи GPO до домену або OU з потрібними комп'ютерами.

У `Scope -> Security Filtering`:

- Видали `Authenticated Users`.
- Додай `WinHUB_Agent_Deploy_Test`.

У `Delegation -> Advanced`:

- `WinHUB_Agent_Deploy_Test`: Allow `Read` і `Apply group policy`.
- `Domain Computers`: Allow `Read` only.

Так політика буде застосовуватися тільки до комп'ютерів у `WinHUB_Agent_Deploy_Test`, але доменні комп'ютери зможуть читати metadata GPO.

### 7. Налаштування GPO

Додай startup script:

```text
Computer Configuration
-> Policies
-> Windows Settings
-> Scripts (Startup/Shutdown)
-> Startup
-> Scripts
```

Додай:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Використовуй `.cmd` wrapper, а не прямий запуск `.ps1`. Wrapper пише зрозумілий лог і прибирає частину silent-проблем із PowerShell startup scripts.

Увімкни очікування мережі:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> System
-> Logon
-> Always wait for the network at computer startup and logon = Enabled
```

Рекомендовані script settings:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> System
-> Scripts
-> Run Windows PowerShell scripts first = Enabled
-> Specify maximum wait time for Group Policy scripts = 600 seconds
```

Якщо PowerShell execution policy блокує запуск:

```text
Computer Configuration
-> Policies
-> Administrative Templates
-> Windows Components
-> Windows PowerShell
-> Turn on Script Execution = Enabled
-> Allow all scripts
```

### 8. CMD wrapper

Створи:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd
```

Вміст:

```cmd
@echo off
set SOURCE=\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy
set LOGDIR=C:\ProgramData\WinHUB\gpo-install
mkdir "%LOGDIR%" 2>nul

echo [%date% %time%] Starting WinHUB GPO wrapper >> "%LOGDIR%\startup-wrapper.log"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SOURCE%\install-winhub-agent.ps1" >> "%LOGDIR%\startup-wrapper.log" 2>&1

echo [%date% %time%] Finished with exit code %ERRORLEVEL% >> "%LOGDIR%\startup-wrapper.log"

exit /b %ERRORLEVEL%
```

### 9. PowerShell installer

Створи:

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1
```

Вміст такий самий, як в англійській секції [PowerShell Installer](#9-powershell-installer). Заміни:

```powershell
$PackageVersion = "<AGENT_VERSION>"
$SourceDir = "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy"
```

на свої значення.

### 10. Перевірка на клієнті

На тестовому комп'ютері:

```powershell
gpupdate /force
Restart-Computer
```

Після перезавантаження:

```powershell
gpresult /r /scope computer
```

У `Applied Group Policy Objects` має бути:

```text
Deploy WinHUB Agent
```

Перевір логи:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" -Tail 80
Get-Content "C:\ProgramData\WinHUB\gpo-install\install.log" -Tail 80
```

Перевір файли і службу:

```powershell
Get-ChildItem "C:\Program Files\WinHUBAgent"
Get-Service WinHUBAgent
Get-CimInstance Win32_Service -Filter "Name='WinHUBAgent'" |
  Select Name, State, StartMode, PathName
sc.exe qfailure WinHUBAgent
```

Очікувані recovery actions:

```text
RESTART
RESTART
RESTART
```

Перевір мережу:

```powershell
Test-NetConnection <PUBLIC_AGENT_HOST> -Port <AGENT_PUBLIC_PORT>
```

У WinHUB:

```text
Endpoint Management -> Nodes -> Pending Approval
```

Approve new node. Після наступного poll або restart service агент має стати online.

### 11. Troubleshooting

Якщо GPO застосувалась, але папки агента немає:

```powershell
Get-Content "C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log" -Tail 80
Get-Content "C:\ProgramData\WinHUB\gpo-install\install.log" -Tail 80
```

Якщо логів немає, startup scripts не запустились або GPO не виконалась при boot.

Перевір applied GPOs:

```powershell
gpresult /h C:\gp.html
start C:\gp.html
```

Перевір доступ до файлів:

```powershell
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.ps1"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\WinHUBAgent-v<AGENT_VERSION>-win-x64.zip"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\winhub_agent.conf"
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\winhub_agent.bootstrap.conf"
```

Якщо користувач відкриває папку, але startup script не працює, перевір доступ від LocalSystem:

```powershell
psexec -i -s powershell.exe
```

Всередині SYSTEM PowerShell:

```powershell
whoami
Test-Path "\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\install-winhub-agent.cmd"
```

Очікувано:

```text
nt authority\system
True
```

### 12. Production rollout

Коли тест пройшов:

1. Залиш `WinHUB_Agent_Deploy_Test` для тестів.
2. Створи production group, наприклад `WinHUB_Agent_Deploy_Prod`.
3. Додавай computer accounts поступово.
4. Заміни Security Filtering у GPO на production group або тримай окремі GPO для test/prod.
5. Перезавантаж комп'ютери після додавання в групу.
6. Approve nodes у WinHUB Pending Approval.

Для контрольованого rollout додавай комп'ютери невеликими групами.

### 13. Оновлення агента через GPO

Коли готовий новий agent package:

1. Скопіюй новий ZIP у `\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy`.
2. Зміни `$PackageVersion` в `install-winhub-agent.ps1`.
3. Перезавантаж цільові машини.

Скрипт порівнює:

```text
C:\Program Files\WinHUBAgent\.deployed_version
```

Якщо marker відрізняється від `$PackageVersion`, агент оновиться і служба буде перевстановлена. Існуючий локальний `winhub_agent.conf` не перезаписується.
