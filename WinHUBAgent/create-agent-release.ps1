param(
    [string]$Version = "1.2.0",
    [string]$OutputDir = ".\dist-agent"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$publishDir = Join-Path $OutputDir "publish"
$zipPath = Join-Path $OutputDir "WinHUBAgent-v$Version-win-x64.zip"
$manifestPath = Join-Path $OutputDir "WinHUBAgent-v$Version-win-x64.manifest.json"

dotnet publish .\WinHUBAgent.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishAot=true `
  -o $publishDir

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force

$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
$manifest = [ordered]@{
    version = $Version
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    agent_package = (Split-Path -Leaf $zipPath)
    agent_package_sha256 = $hash
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host $zipPath
Write-Host $manifestPath
Write-Host "SHA256: $hash"
