# Source-checkout entry point. Published packages contain the full canonical script.
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [string]$InstallDir = 'C:\Program Files\WinHUBAgent',
    [string]$ServiceName = 'WinHUBAgent'
)
& (Join-Path $PSScriptRoot '../WinHUB/deploy/agent-updaters/update-service.ps1') @PSBoundParameters
if (-not $?) { throw 'WinHUB agent update failed.' }
