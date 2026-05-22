param(
    [string]$Version = "1.2.0",
    [string]$OutputDir = ".\dist-agent",
    [switch]$Aot
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$publishDir = Join-Path $OutputDir "publish"
$zipPath = Join-Path $OutputDir "WinHUBAgent-v$Version-win-x64.zip"
$manifestPath = Join-Path $OutputDir "WinHUBAgent-v$Version-win-x64.manifest.json"

if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}

$publishArgs = @(
    "publish", ".\WinHUBAgent.csproj",
    "-c", "Release",
    "-r", "win-x64",
    "--self-contained", "true",
    "-o", $publishDir
)

if ($Aot) {
    $publishArgs += "-p:PublishAot=true"
} else {
    $publishArgs += "-p:PublishAot=false"
    $publishArgs += "-p:PublishSingleFile=true"
}

dotnet @publishArgs

Get-ChildItem -LiteralPath $publishDir -Filter "*.pdb" -Force | Remove-Item -Force
foreach ($runtimeConfigName in @("winhub_agent.conf", "winhub_agent.bootstrap.conf")) {
    $runtimeConfigPath = Join-Path $publishDir $runtimeConfigName
    if (Test-Path -LiteralPath $runtimeConfigPath) {
        Remove-Item -LiteralPath $runtimeConfigPath -Force
    }
}

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
    publish_mode = $(if ($Aot) { "self-contained-aot" } else { "self-contained-single-file" })
    aot = [bool]$Aot
    pdb_included = $false
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host $zipPath
Write-Host $manifestPath
Write-Host "SHA256: $hash"
