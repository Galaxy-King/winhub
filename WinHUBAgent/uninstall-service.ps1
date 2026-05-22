param(
    [string]$ServiceName = "WinHUBAgent"
)

$ErrorActionPreference = "Stop"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Write-Host "WinHUBAgent service removed."
} else {
    Write-Host "WinHUBAgent service is not installed."
}
