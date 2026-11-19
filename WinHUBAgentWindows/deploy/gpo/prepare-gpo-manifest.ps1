param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [string]$SourceDir = ''
)

# Preparation only: endpoint deployment still verifies publisher signature and inventory.
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    $SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-NormalizedGpoPath([string]$Path) {
    $native = $Path -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
    return [IO.Path]::GetFullPath($native).TrimEnd([char[]]'\/')
}
$source = Get-NormalizedGpoPath ((Get-Item -LiteralPath $SourceDir).FullName)
$package = Get-Item -LiteralPath $PackagePath
if ($package.PSIsContainer -or $package.Extension -ne '.zip') {
    throw 'PackagePath must identify a ZIP file.'
}
$packageDirectory = Get-NormalizedGpoPath $package.Directory.FullName
if (-not [string]::Equals($packageDirectory, $source, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ZIP directory '$packageDirectory' differs from SourceDir '$source'. Place the signed ZIP beside the deployment files."
}
$keyPath = Join-Path $source 'release-signing-public.pem'
$keyHash = (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash
$zip = [IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    $entry = $zip.GetEntry('release-manifest.json')
    if (-not $entry -or $entry.Length -gt 2MB) { throw 'Missing or oversized root release-manifest.json.' }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { $envelope = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    if ($envelope.algorithm -ne 'rsa-pss-sha256' -or -not $envelope.signature) { throw 'Expected a signed release envelope.' }
    $release = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envelope.payload)) | ConvertFrom-Json
    $pem = [IO.File]::ReadAllText($keyPath)
    $der = [Convert]::FromBase64String(($pem.Replace('-----BEGIN PUBLIC KEY-----','').Replace('-----END PUBLIC KEY-----','') -replace '\s',''))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $keyId = ([BitConverter]::ToString($sha.ComputeHash($der))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($release.key_id -ne $keyId) { throw 'The selected public key does not match the release key ID.' }
    if ($release.schema -ne 1 -or $release.platform -ne 'windows' -or $release.architecture -ne 'x64' -or
        [string]$release.version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
        throw 'Expected a Windows x64 release with a semantic version.'
    }
    foreach ($name in @('WinHUBAgent.exe','install-service.ps1','uninstall-service.ps1','update-service.ps1','update-protocol.json','appsettings.json')) {
        if (-not $zip.GetEntry($name)) { throw "Missing file at ZIP root: $name" }
    }
} finally { $zip.Dispose() }

$manifestPath = Join-Path $source 'deployment-manifest.json'
$epoch = ''
if (Test-Path -LiteralPath $manifestPath) {
    $existing = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $epoch = [string]$existing.server_identity_epoch
    if ($existing.publisher_public_key_sha256 -and $existing.publisher_public_key_sha256 -ne $keyHash) {
        throw 'Publisher key differs from the existing deployment manifest. Key rotation is a separate operation.'
    }
    Copy-Item -LiteralPath $manifestPath -Destination ($manifestPath + '.backup-' + [guid]::NewGuid().ToString('N'))
}
$manifest = [ordered]@{
    schema = 1
    version = [string]$release.version
    package = $package.Name
    sha256 = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash
    publisher_public_key = 'release-signing-public.pem'
    publisher_public_key_sha256 = $keyHash
    server_identity_epoch = $epoch
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json) + "`r`n", [Text.UTF8Encoding]::new($false))
Write-Output "Prepared $manifestPath for $($release.version). Existing server_identity_epoch preserved."
Write-Output 'Publisher signature, inventory and anti-rollback state are verified by the deployment script on the endpoint.'
