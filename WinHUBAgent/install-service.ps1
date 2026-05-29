param(
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

Ensure-WinHUBAgentRecovery -ServiceName $ServiceName
Ensure-WinHUBAgentWatchdog -ServiceName $ServiceName

Start-Service -Name $ServiceName
Write-Host "WinHUBAgent service installed and started."
