#requires -Version 5.1
#requires -RunAsAdministrator
param(
    [ValidateSet('Audit','Install','Repair','Uninstall')][string]$Action = 'Audit',
    [ValidateSet('Blocked','Allowed')][string]$AutoUpdate = 'Blocked'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$InstallDir = Join-Path $env:ProgramFiles 'Telegram Desktop'
$TelegramExe = Join-Path $InstallDir 'Telegram.exe'
$UpdaterPath = Join-Path $InstallDir 'Updater.exe'
$PublicShortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Telegram.lnk'
$StartMenuDir = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Telegram Desktop'
$StartMenuLink = Join-Path $StartMenuDir 'Telegram.lnk'
$LauncherPath = Join-Path $InstallDir 'WinHUB-Telegram-Launcher.ps1'

function Assert-ManagedPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($InstallDir)
    if ($full -ne $root -and -not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Path outside managed installation directory.'
    }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point is not supported: $cursor"
            }
        }
        $cursor = Split-Path -Parent $cursor
    }
    if (Test-Path -LiteralPath $full -PathType Container) {
        foreach ($item in Get-ChildItem -LiteralPath $full -Recurse -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in managed directory.' }
        }
    }
}

function Stop-ManagedProcesses {
    # Do not stop unrelated applications named Updater.
    foreach ($process in Get-CimInstance Win32_Process -Filter "Name='Telegram.exe' OR Name='Updater.exe'") {
        if ($process.ExecutablePath -and ([IO.Path]::GetFullPath($process.ExecutablePath)).StartsWith($InstallDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        }
    }
}

function Set-ReadOnlyInstallation {
    Assert-ManagedPath $InstallDir
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-32-545','ReadAndExecute'))) {
        $sid = New-Object Security.Principal.SecurityIdentifier($entry[0])
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $InstallDir -AclObject $acl
    foreach ($child in Get-ChildItem -LiteralPath $InstallDir -Force) {
        & icacls.exe $child.FullName /reset /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to reset child ACLs.' }
    }
}

function Write-IsolatedLauncher {
    # Resolve AppData at launch in the interactive user's context, never in LocalSystem.
    $launch = @'
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($sid.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) { throw 'Telegram must be launched by an interactive user.' }
$appData = [Environment]::GetFolderPath('ApplicationData')
if ([string]::IsNullOrWhiteSpace($appData) -or -not [IO.Path]::IsPathRooted($appData)) { throw 'No absolute user AppData directory.' }
$work = Join-Path $appData ('WinHUB Telegram-' + $sid.Value)
$cursor = $work
while ($cursor) {
    if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Profile path contains a reparse point.' }
    $cursor = Split-Path -Parent $cursor
}
if (Test-Path -LiteralPath $work) {
    if (-not (Test-Path -LiteralPath $work -PathType Container)) { throw 'Profile path is not a directory.' }
    $owner = (Get-Acl -LiteralPath $work).GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $sid.Value) { throw 'Profile belongs to another identity; refusing to reuse it.' }
}
New-Item -ItemType Directory -Path $work -Force | Out-Null
# Check one level at a time so junctions are rejected before traversal/reset.
$pending = New-Object 'System.Collections.Generic.Queue[string]'
$pending.Enqueue($work)
while ($pending.Count -gt 0) {
    foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile contains a reparse point.' }
        if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
    }
}
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($sid)
foreach ($owner in @($sid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($owner, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[IO.Directory]::SetAccessControl($work, $acl)
foreach ($child in Get-ChildItem -LiteralPath $work -Force) {
    & icacls.exe $child.FullName /reset /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to protect profile contents.' }
}
$exe = '__TELEGRAM_EXE__'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Telegram executable is missing.' }
Start-Process -FilePath $exe -ArgumentList ('-workdir "{0}"' -f $work) -WorkingDirectory $work
'@
    $launch = $launch.Replace('__TELEGRAM_EXE__', $TelegramExe.Replace("'", "''"))
    Set-Content -LiteralPath $LauncherPath -Value $launch -Encoding UTF8
}

function New-IsolatedShortcut([string]$Path) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $shortcut = $shell.CreateShortcut($Path)
        $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $shortcut.Arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $LauncherPath + '"'
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.IconLocation = "$TelegramExe,0"
        $shortcut.Save()
    } finally {
        if ($shortcut) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

try {
    if (-not [Environment]::Is64BitProcess) { throw 'Requires 64-bit PowerShell.' }
    if ($Action -ne 'Audit') {
        Assert-ManagedPath $InstallDir
        if (Test-Path -LiteralPath (Join-Path $InstallDir 'tdata')) { throw 'Shared tdata detected. Preserve and review it manually before changing the installation.' }
        Stop-ManagedProcesses
        if ($Action -eq 'Install') {
            $installer = Join-Path ([IO.Path]::GetTempPath()) ('telegram-' + [guid]::NewGuid().ToString('N') + '.exe')
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri 'https://telegram.org/dl/desktop/win64' -OutFile $installer -UseBasicParsing
                $signature = Get-AuthenticodeSignature -LiteralPath $installer
                if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Telegram (FZ-LLC|Messenger LLP)(,|$)') {
                    throw 'Installer must have a valid Telegram publisher signature.'
                }
                if (Test-Path -LiteralPath $UpdaterPath -PathType Container) { Remove-Item -LiteralPath $UpdaterPath -Recurse -Force }
                $proc = Start-Process -FilePath $installer -WindowStyle Hidden -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS /MERGETASKS="!desktopicon,!autostart" /DIR="{0}"' -f $InstallDir) -Wait -PassThru
                if ($proc.ExitCode -ne 0) { throw "Installer exit code: $($proc.ExitCode)" }
            } finally { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }
        }
        if ($Action -in @('Install','Repair')) {
            if (-not (Test-Path -LiteralPath $TelegramExe -PathType Leaf)) { throw 'Telegram is not installed. Use Install first.' }
            # Shared tdata could contain an old shared session. Never delete or distribute it.
            if (Test-Path -LiteralPath (Join-Path $InstallDir 'tdata')) { throw 'Shared tdata detected in Program Files. Review and move it manually before continuing.' }
            if ($AutoUpdate -eq 'Blocked') {
                if (Test-Path -LiteralPath $UpdaterPath -PathType Leaf) { Remove-Item -LiteralPath $UpdaterPath -Force }
                New-Item -ItemType Directory -Path $UpdaterPath -Force | Out-Null
            } elseif (Test-Path -LiteralPath $UpdaterPath -PathType Container) {
                throw 'To restore Updater.exe choose Install with AutoUpdate=Allowed.'
            }
            Write-IsolatedLauncher
            Set-ReadOnlyInstallation
            New-IsolatedShortcut $PublicShortcut
            New-IsolatedShortcut $StartMenuLink
        }
        if ($Action -eq 'Uninstall') {
            $uninstaller = Join-Path $InstallDir 'unins000.exe'
            if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
                $proc = Start-Process -FilePath $uninstaller -WindowStyle Hidden -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait -PassThru
                if ($proc.ExitCode -ne 0) { throw "Uninstaller exit code: $($proc.ExitCode)" }
            }
            Stop-ManagedProcesses
            Assert-ManagedPath $InstallDir
            if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
            foreach ($link in @($PublicShortcut,$StartMenuLink)) { Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue }
        }
    }
    [ordered]@{
        action = $Action; status = 'Success'; scope = 'AllUsers'; installed = (Test-Path -LiteralPath $TelegramExe)
        auto_update_blocked = (Test-Path -LiteralPath $UpdaterPath -PathType Container)
        shared_tdata_detected = (Test-Path -LiteralPath (Join-Path $InstallDir 'tdata'))
        desktop_shortcut = (Test-Path -LiteralPath $PublicShortcut)
        start_menu_shortcut = (Test-Path -LiteralPath $StartMenuLink)
        profile = '%APPDATA%\WinHUB Telegram-<Windows SID>'; profiles_preserved = $true
    } | ConvertTo-Json -Compress
    exit 0
} catch {
    @{ action = $Action; status = 'Failed'; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
