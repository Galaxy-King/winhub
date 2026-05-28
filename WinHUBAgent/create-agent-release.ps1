param(
    [string]$Version = "1.2.0",
    [string]$OutputDir = ".\dist-agent",
    [switch]$Aot,
    [switch]$ManagedSingleFile
)

$ErrorActionPreference = "Stop"

if ($Aot -and $ManagedSingleFile) {
    throw "Use either -Aot or -ManagedSingleFile, not both."
}

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
    "-o", $publishDir,
    "-p:Version=$Version",
    "-p:AssemblyVersion=$Version.0",
    "-p:FileVersion=$Version.0",
    "-p:InformationalVersion=$Version"
)

if ($ManagedSingleFile) {
    $publishArgs += "-p:PublishAot=false"
    $publishArgs += "-p:PublishSingleFile=true"
} else {
    $publishArgs += "-p:PublishAot=true"
}

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

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
    publish_mode = $(if ($ManagedSingleFile) { "self-contained-single-file" } else { "self-contained-aot" })
    aot = -not [bool]$ManagedSingleFile
    pdb_included = $false
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host $zipPath
Write-Host $manifestPath
Write-Host "SHA256: $hash"
