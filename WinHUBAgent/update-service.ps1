param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [string]$InstallDir = "C:\Program Files\WinHUBAgent",
    [string]$ServiceName = "WinHUBAgent"
)

$ErrorActionPreference = "Stop"

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

if (-not (Test-Path -LiteralPath $PackagePath)) {
    throw "Package was not found: $PackagePath"
}

$dataDir = Join-Path $env:ProgramData "WinHUB"
$backupRoot = Join-Path $dataDir "backups"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $backupRoot $stamp
$tempDir = Join-Path $env:TEMP "WinHUBAgentUpdate_$stamp"
$stageDir = Join-Path $env:TEMP "WinHUBAgentStage_$stamp"
$rollbackDir = Join-Path $backupDir "WinHUBAgent"

New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

try {
    Write-Host "[WinHUBAgent] Extracting package"
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $tempDir -Force

    $packageRoot = $tempDir
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "WinHUBAgent.exe"))) {
        $candidateRoots = Get-ChildItem -LiteralPath $tempDir -Directory -Recurse -Force |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "WinHUBAgent.exe") } |
            Sort-Object { $_.FullName.Length }
        if ($candidateRoots -and $candidateRoots.Count -gt 0) {
            $packageRoot = $candidateRoots[0].FullName
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "WinHUBAgent.exe"))) {
        throw "Package does not contain WinHUBAgent.exe in a supported layout."
    }
    foreach ($runtimeConfigName in @("winhub_agent.conf", "winhub_agent.bootstrap.conf")) {
        $packageRuntimeConfig = Join-Path $packageRoot $runtimeConfigName
        if (Test-Path -LiteralPath $packageRuntimeConfig) {
            Remove-Item -LiteralPath $packageRuntimeConfig -Force
        }
    }
    Write-Host "[WinHUBAgent] Package root: $packageRoot"

    Copy-Item -Path (Join-Path $packageRoot "*") -Destination $stageDir -Recurse -Force
    if (-not (Test-Path -LiteralPath (Join-Path $stageDir "WinHUBAgent.exe"))) {
        throw "Staged package is invalid: WinHUBAgent.exe is missing."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $stageDir "update-service.ps1"))) {
        throw "Staged package is invalid: update-service.ps1 is missing."
    }

    Write-Host "[WinHUBAgent] Backing up current install to $backupDir"
    if (Test-Path -LiteralPath $InstallDir) {
        Copy-Item -LiteralPath $InstallDir -Destination $rollbackDir -Recurse -Force
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[WinHUBAgent] Stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    $runtimeConfig = Join-Path $InstallDir "winhub_agent.conf"
    $savedRuntimeConfig = Join-Path $backupDir "winhub_agent.conf"
    if (Test-Path -LiteralPath $runtimeConfig) {
        Copy-Item -LiteralPath $runtimeConfig -Destination $savedRuntimeConfig -Force
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Get-ChildItem -LiteralPath $InstallDir -Force |
        Where-Object { $_.Name -notin @("winhub_agent.conf", "winhub_agent.bootstrap.conf") } |
        Remove-Item -Recurse -Force

    Copy-Item -Path (Join-Path $stageDir "*") -Destination $InstallDir -Recurse -Force

    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir "WinHUBAgent.exe"))) {
        throw "Updated install is invalid: WinHUBAgent.exe is missing."
    }

    if ((Test-Path -LiteralPath $savedRuntimeConfig) -and -not (Test-Path -LiteralPath $runtimeConfig)) {
        Copy-Item -LiteralPath $savedRuntimeConfig -Destination $runtimeConfig -Force
    }

    icacls $InstallDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    icacls $dataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

    if (-not $existing) {
        & (Join-Path $InstallDir "install-service.ps1") -InstallDir $InstallDir -ServiceName $ServiceName
    } else {
        Set-Service -Name $ServiceName -StartupType Automatic
        Ensure-WinHUBAgentRecovery -ServiceName $ServiceName
        Ensure-WinHUBAgentWatchdog -ServiceName $ServiceName
        Start-Service -Name $ServiceName
    }

    Start-Sleep -Seconds 3
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne "Running") {
        throw "Service did not start after update. Current status: $($service.Status)"
    }

    Write-Host "[WinHUBAgent] Update complete."
} catch {
    Write-Error "[WinHUBAgent] Update failed: $_"
    try {
        if (Test-Path -LiteralPath $rollbackDir) {
            Write-Host "[WinHUBAgent] Attempting rollback from $rollbackDir"
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Get-ChildItem -LiteralPath $InstallDir -Force |
                Where-Object { $_.Name -notin @("winhub_agent.conf", "winhub_agent.bootstrap.conf") } |
                Remove-Item -Recurse -Force
            Copy-Item -Path (Join-Path $rollbackDir "*") -Destination $InstallDir -Recurse -Force
            Start-Service -Name $ServiceName
            Write-Host "[WinHUBAgent] Rollback complete."
        }
    } catch {
        Write-Error "[WinHUBAgent] Rollback failed: $_"
    }
    throw
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
}
