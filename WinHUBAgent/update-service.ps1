param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [string]$InstallDir = "C:\Program Files\WinHUBAgent",
    [string]$ServiceName = "WinHUBAgent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $PackagePath)) {
    throw "Package was not found: $PackagePath"
}

$dataDir = Join-Path $env:ProgramData "WinHUB"
$backupRoot = Join-Path $dataDir "backups"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $backupRoot $stamp
$tempDir = Join-Path $env:TEMP "WinHUBAgentUpdate_$stamp"

New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    Write-Host "[WinHUBAgent] Backing up current install to $backupDir"
    if (Test-Path -LiteralPath $InstallDir) {
        Copy-Item -LiteralPath $InstallDir -Destination (Join-Path $backupDir "WinHUBAgent") -Recurse -Force
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[WinHUBAgent] Stopping service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    Write-Host "[WinHUBAgent] Extracting package"
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $tempDir -Force

    $runtimeConfig = Join-Path $InstallDir "winhub_agent.conf"
    $savedRuntimeConfig = Join-Path $backupDir "winhub_agent.conf"
    if (Test-Path -LiteralPath $runtimeConfig) {
        Copy-Item -LiteralPath $runtimeConfig -Destination $savedRuntimeConfig -Force
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Get-ChildItem -LiteralPath $InstallDir -Force |
        Where-Object { $_.Name -notin @("winhub_agent.conf", "winhub_agent.bootstrap.conf") } |
        Remove-Item -Recurse -Force

    Copy-Item -Path (Join-Path $tempDir "*") -Destination $InstallDir -Recurse -Force

    if ((Test-Path -LiteralPath $savedRuntimeConfig) -and -not (Test-Path -LiteralPath $runtimeConfig)) {
        Copy-Item -LiteralPath $savedRuntimeConfig -Destination $runtimeConfig -Force
    }

    icacls $InstallDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    icacls $dataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

    if (-not $existing) {
        & (Join-Path $InstallDir "install-service.ps1") -InstallDir $InstallDir -ServiceName $ServiceName
    } else {
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
    throw
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
