param(
    [string]$InstallDir = "C:\Program Files\WinHUBAgent",
    [string]$ServiceName = "WinHUBAgent"
)

$ErrorActionPreference = "Stop"

$exe = Join-Path $InstallDir "WinHUBAgent.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "WinHUBAgent.exe was not found in $InstallDir"
}

$config = Join-Path $InstallDir "winhub_agent.conf"
if (-not (Test-Path -LiteralPath $config)) {
    throw "winhub_agent.conf was not found in $InstallDir"
}

$dataDir = Join-Path $env:ProgramData "WinHUB"
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

icacls $InstallDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
icacls $dataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

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

Start-Service -Name $ServiceName
Write-Host "WinHUBAgent service installed and started."
