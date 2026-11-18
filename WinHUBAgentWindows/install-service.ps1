param(
    [string]$InstallDir = "C:\Program Files\WinHUBAgent",
    [string]$ServiceName = "WinHUBAgent"
)

$ErrorActionPreference = "Stop"

function Install-WinHUBReleaseTrust {
    param([string]$SourceDir, [string]$DataDir)

    $bundled = Join-Path $SourceDir 'release-signing-public.pem'
    if (-not (Test-Path -LiteralPath $bundled)) {
        Write-Warning 'Package has no publisher public key. Existing trust is unchanged; signed updates require provisioned trust.'
        return
    }
    $target = Join-Path $DataDir 'release-signing-public.pem'
    $state = Join-Path $DataDir 'release-state.json'
    if (Test-Path -LiteralPath $target) {
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($bundled))) {
            throw 'Bundled publisher key differs from existing trust. Explicit key rotation is required; existing key was preserved.'
        }
    } elseif (Test-Path -LiteralPath $state) {
        throw 'Publisher trust is missing but release state exists. Restore trusted public key before reinstalling.'
    }

    # Runtime configs may already be beside the installer. Verify only the fixed
    # release inventory in an isolated directory; never copy runtime secrets.
    $stage = Join-Path $DataDir ('trust-check-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        foreach ($name in @('appsettings.json', 'install-service.ps1', 'release-manifest.json',
                'uninstall-service.ps1', 'update-protocol.json', 'update-service.ps1',
                'WinHUBAgent.exe', 'release-signing-public.pem')) {
            $source = Get-Item -LiteralPath (Join-Path $SourceDir $name) -Force
            if ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package links are forbidden.' }
            Copy-Item -LiteralPath $source.FullName -Destination (Join-Path $stage $name)
        }
        $verifier = Join-Path $stage 'WinHUBAgent.exe'
        $version = (& $verifier --version | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Cannot read bundled agent version.' }
        $trust = if (Test-Path -LiteralPath $target) { $target } else { Join-Path $stage 'release-signing-public.pem' }
        & $verifier --verify-release $stage $trust $state $version $version
        if ($LASTEXITCODE -ne 0) { throw 'Publisher signature, inventory or rollback verification failed. Service was not changed.' }
        if (-not (Test-Path -LiteralPath $target)) {
            # No overwrite: a concurrent provisioner cannot have its key replaced.
            [IO.File]::Copy((Join-Path $stage 'release-signing-public.pem'), $target, $false)
        }
        icacls $target /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not secure publisher trust.' }
        Write-Host 'Publisher public key verified and provisioned; existing trust was preserved.'
    } finally {
        $stageRoot = [IO.Path]::GetFullPath($DataDir).TrimEnd('\') + '\'
        if (-not [IO.Path]::GetFullPath($stage).StartsWith($stageRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Trust staging cleanup escaped data directory.'
        }
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}

function Ensure-WinHUBAgentRecovery {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    sc.exe failureflag $ServiceName 1 | Out-Null
}

function Ensure-WinHUBAgentWatchdog {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName
    )

    $taskName = "WinHUBAgent Watchdog"
    $command = "`$svc = Get-Service -Name '$ServiceName' -ErrorAction SilentlyContinue; if (`$svc -and `$svc.Status -ne 'Running') { Start-Service -Name '$ServiceName' }"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command $command"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}

$exe = Join-Path $InstallDir "WinHUBAgent.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "WinHUBAgent.exe was not found in $InstallDir"
}

$config = Join-Path $InstallDir "winhub_agent.conf"
if (-not (Test-Path -LiteralPath $config)) {
    throw "winhub_agent.conf was not found in $InstallDir"
}

$dataDir = Join-Path $env:ProgramData "WinHUB"
& $exe --validate-config $config
if ($LASTEXITCODE -ne 0) { throw 'Production pin configuration is invalid. Existing service was not changed.' }
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

icacls $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure installation directory.' }
icacls $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure data directory.' }

Install-WinHUBReleaseTrust -SourceDir $PSScriptRoot -DataDir $dataDir

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

New-Service `
    -Name $ServiceName `
    -BinaryPathName "`"$exe`"" `
    -DisplayName "WinHUB Agent" `
    -Description "WinHUB endpoint agent service" `
    -StartupType Automatic | Out-Null

Ensure-WinHUBAgentRecovery -ServiceName $ServiceName
Ensure-WinHUBAgentWatchdog -ServiceName $ServiceName

Start-Service -Name $ServiceName
Write-Host "WinHUBAgent service installed and started."
