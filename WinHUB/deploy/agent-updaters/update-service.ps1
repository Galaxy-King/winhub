param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [string]$ExpectedSha256 = '__WINHUB_AUTHORIZED_SHA256__',
    [string]$InstallDir = 'C:\Program Files\WinHUBAgent',
    [ValidateSet('WinHUBAgent')][string]$ServiceName = 'WinHUBAgent'
)
$ErrorActionPreference = 'Stop'

function Assert-WinHubPath([string]$Path) {
    $check = [IO.Path]::GetFullPath($Path)
    while ($check) {
        if ((Test-Path -LiteralPath $check) -and ((Get-Item -LiteralPath $check -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse points are forbidden: $check"
        }
        $check = [IO.Path]::GetDirectoryName($check)
    }
}

function Protect-WinHubDirectory([string]$Path) {
    Assert-WinHubPath $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Expand-WinHubUpdate([string]$Archive, [string]$Destination) {
    # PowerShell 5.1/.NET Framework compatible. Never execute the installed old EXE.
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Assert-WinHubPath $Archive
    Assert-WinHubPath $Destination
    if (@(Get-ChildItem -LiteralPath $Destination -Force).Count) { throw 'Staging must be empty.' }
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -gt 4096) { throw 'Too many archive entries.' }
        [long]$total = 0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            $kind = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ($kind -notin @(0, 0x8000, 0x4000)) { throw 'Archive links/special files are forbidden.' }
            if ($name.Length -gt 512 -or $name.StartsWith('/') -or $name.Contains(':')) { throw 'Unsafe archive path.' }
            foreach ($part in $name.Split('/')) {
                if ($part -eq '..' -or $part.EndsWith(' ') -or ($part -ne '.' -and $part.EndsWith('.')) -or
                    $part -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)') { throw 'Unsafe archive component.' }
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $name))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Archive escapes staging.' }
            $total += $entry.Length
            if ($entry.Length -gt 512MB -or $total -gt 2GB) { throw 'Archive exceeds expanded size limits.' }
            if ($name.EndsWith('/')) { [IO.Directory]::CreateDirectory($target) | Out-Null; continue }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            $inputStream = $entry.Open()
            try {
                $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = New-Object byte[] 81920
                    [long]$written = 0
                    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $written += $count
                        if ($written -gt $entry.Length) { throw 'Archive entry exceeds declared size.' }
                        $output.Write($buffer, 0, $count)
                    }
                    if ($written -ne $entry.Length) { throw 'Truncated archive entry.' }
                    $output.Flush($true)
                } finally { $output.Dispose() }
            } finally { $inputStream.Dispose() }
        }
    } finally { $zip.Dispose() }
}

function Clear-WinHubCode([string]$Path) {
    # Only explicit, checked agent directories. Preserve live identity/replay config.
    Assert-WinHubPath $Path
    if ([IO.Path]::GetFileName($Path) -ne 'WinHUBAgent') { throw 'Unsafe code directory.' }
    foreach ($entry in Get-ChildItem -LiteralPath $Path -Force -Recurse) { Assert-WinHubPath $entry.FullName }
    Get-ChildItem -LiteralPath $Path -Force |
        Where-Object { $_.Name -notin @('winhub_agent.conf', 'winhub_agent.bootstrap.conf') } |
        Remove-Item -Recurse -Force
}

function Copy-WinHubCode([string]$Source, [string]$Destination) {
    Get-ChildItem -LiteralPath $Source -Force |
        Where-Object { $_.Name -notin @('winhub_agent.conf', 'winhub_agent.bootstrap.conf') } |
        Copy-Item -Destination $Destination -Recurse -Force
}

if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'An authorized package SHA-256 is required.' }
$InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
if ([IO.Path]::GetFileName($InstallDir) -ne 'WinHUBAgent') { throw 'Unsafe installation path.' }
Assert-WinHubPath $InstallDir
Assert-WinHubPath $PackagePath
if ((Get-Item -LiteralPath $PackagePath).Length -gt 512MB) { throw 'Package exceeds 512 MiB.' }
$dataDir = Join-Path $env:ProgramData 'WinHUB'
Protect-WinHubDirectory $dataDir
Protect-WinHubDirectory (Join-Path $dataDir 'updates')
Protect-WinHubDirectory (Join-Path $dataDir 'backups')
$lockPath = Join-Path $dataDir 'updates\updater.lock'
Assert-WinHubPath $lockPath
$lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$work = Join-Path $dataDir ('updates\stage-' + [Guid]::NewGuid().ToString('N'))
$backup = Join-Path $dataDir ('backups\' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
$stopped = $false
$backupComplete = $false
try {
    Protect-WinHubDirectory $work
    $archive = Join-Path $work 'package.zip'
    # Verify a private snapshot: later writes to the downloaded path cannot change extraction.
    Copy-Item -LiteralPath $PackagePath -Destination $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Package SHA-256 mismatch.' }
    $stage = Join-Path $work 'files'
    Protect-WinHubDirectory $stage
    Expand-WinHubUpdate $archive $stage
    $candidate = Join-Path $stage 'WinHUBAgent.exe'
    $descriptor = Get-Content -LiteralPath (Join-Path $stage 'update-protocol.json') -Raw | ConvertFrom-Json
    if ($descriptor.protocol -ne 2 -or $descriptor.platform -ne 'windows') { throw 'Package does not support safe update preflight.' }
    if ((Get-Item -LiteralPath $candidate).VersionInfo.FileMajorPart -lt 2) { throw 'Legacy binary does not support update preflight.' }
    foreach ($required in @('update-service.ps1', 'install-service.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw "Package missing $required" }
    }
    & $candidate --validate-config (Join-Path $InstallDir 'winhub_agent.conf')
    if ($LASTEXITCODE -ne 0) { throw 'Configuration preflight failed; service was not stopped.' }
    & $candidate --check-update-server (Join-Path $InstallDir 'winhub_agent.conf')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned HTTPS preflight failed; service was not stopped.' }
    foreach ($entry in Get-ChildItem -LiteralPath $InstallDir -Force -Recurse) { Assert-WinHubPath $entry.FullName }
    $existing = Get-Service -Name $ServiceName -ErrorAction Stop
    # Pre-existing recovery/watchdog settings remain unchanged.
    Stop-Service -Name $ServiceName -ErrorAction Stop
    $stopped = $true
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    # Every copied item inherits the protected installation directory.
    Protect-WinHubDirectory $InstallDir
    Protect-WinHubDirectory $backup
    Copy-Item -LiteralPath $InstallDir -Destination (Join-Path $backup 'WinHUBAgent') -Recurse
    $backupComplete = $true
    Clear-WinHubCode $InstallDir
    Copy-WinHubCode $stage $InstallDir
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 10
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'New service did not remain running.' }
    Write-Host "[WinHUBAgent] Update installed. Backup: $backup. Confirm new version and a task in Fleet Center."
} catch {
    Write-Warning "[WinHUBAgent] Update failed: $_"
    if ($stopped) {
        try {
            $service = Get-Service -Name $ServiceName
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            if ($backupComplete) {
                Clear-WinHubCode $InstallDir
                Copy-WinHubCode (Join-Path $backup 'WinHUBAgent') $InstallDir
            }
            Start-Service -Name $ServiceName
            Write-Warning 'Previous code restored; live config, secrets and journal were NOT rewound.'
        } catch { Write-Warning "ROLLBACK FAILED: $_. Backup: $backup" }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $work) {
        Assert-WinHubPath $work
        if ([IO.Path]::GetDirectoryName($work) -ne (Join-Path $dataDir 'updates')) { throw 'Unsafe staging cleanup path.' }
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    $lock.Dispose()
}
