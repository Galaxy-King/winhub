param([Parameter(Mandatory=$true)][string]$DescriptorPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$stage = $null
$phase = 'preflight'
try {
    $descriptor = Get-Content -LiteralPath $DescriptorPath -Raw | ConvertFrom-Json
    $installDir = 'C:\Program Files\WinHUBAgent'
    $dataDir = 'C:\ProgramData\WinHUB'
    if ((Test-Path -LiteralPath (Join-Path $installDir 'WinHUBAgent.exe')) -or
        (Get-Service WinHUBAgent -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath (Join-Path $dataDir 'agent.token'))) {
        throw 'Existing WinHUB installation/identity found; bootstrap does not reinstall.'
    }
    $origin = [Uri]$descriptor.runtime_config.ServerUrl
    $url = [Uri]$descriptor.url
    if ($url.Scheme -ne 'https' -or $url.Authority -ne $origin.Authority -or $url.AbsolutePath -notlike '/api/public/software-delivery/bootstrap/*') {
        throw 'Invalid bootstrap delivery origin.'
    }
    $stage = Join-Path $env:ProgramData ('WinHUB-Bootstrap-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    icacls $stage /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect staging directory.' }
    $phase = 'download'
    $package = Join-Path $stage 'agent.zip'
    $pins = @($descriptor.runtime_config.ServerCertificateSha256, $descriptor.runtime_config.ServerCertificateSha256Next)
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public sealed class WinHubPinnedTls {
    readonly HashSet<string> pins;
    public WinHubPinnedTls(string[] values) { pins = new HashSet<string>(values, StringComparer.OrdinalIgnoreCase); }
    public RemoteCertificateValidationCallback Callback { get { return Validate; } }
    bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (certificate == null) return false;
        using (var cert = new X509Certificate2(certificate)) {
            if (DateTime.UtcNow < cert.NotBefore.ToUniversalTime() || DateTime.UtcNow > cert.NotAfter.ToUniversalTime()) return false;
            using (var sha = SHA256.Create()) return pins.Contains(BitConverter.ToString(sha.ComputeHash(cert.RawData)).Replace("-", ""));
        }
    }
}
"@
    $pinnedTls = New-Object WinHubPinnedTls -ArgumentList (,[string[]]$pins)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [Net.HttpWebRequest]::Create($url)
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $request.ServerCertificateValidationCallback = $pinnedTls.Callback
    $request.Headers['Authorization'] = 'Bearer ' + $descriptor.token
    $response = $request.GetResponse()
    try {
        if ([int]$response.StatusCode -ne 200) { throw 'Download requires HTTP 200 without redirect.' }
        $inputStream = $response.GetResponseStream()
        $output = [IO.File]::Open($package, [IO.FileMode]::CreateNew)
        try {
            $buffer = New-Object byte[] 81920
            [long]$count = 0
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $count += $read
                if ($count -gt [long]$descriptor.size -or $clock.Elapsed.TotalSeconds -gt 300) { throw 'Download bounds exceeded.' }
                $output.Write($buffer, 0, $read)
            }
        } finally { $output.Dispose(); $inputStream.Dispose() }
    } finally { $response.Dispose() }
    if ((Get-Item -LiteralPath $package).Length -ne [long]$descriptor.size -or
        (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $descriptor.sha256) { throw 'Package hash/size mismatch.' }
    $phase = 'signature'
    $extract = Join-Path $stage 'release'
    Expand-Archive -LiteralPath $package -DestinationPath $extract
    $trust = Join-Path $stage 'trusted-public.pem'
    [IO.File]::WriteAllText($trust, [string]$descriptor.public_key, (New-Object Text.UTF8Encoding $false))
    $binary = Join-Path $extract 'WinHUBAgent.exe'
    & $binary --verify-release $extract $trust (Join-Path $dataDir 'release-state.json') $descriptor.version $descriptor.version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Release signature verification failed.' }
    $phase = 'install'
    New-Item -ItemType Directory -Path $installDir | Out-Null
    icacls $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect install directory.' }
    Copy-Item -Path (Join-Path $extract '*') -Destination $installDir -Recurse
    $encoding = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText((Join-Path $installDir 'winhub_agent.conf'), ($descriptor.runtime_config | ConvertTo-Json -Depth 8), $encoding)
    [IO.File]::WriteAllText((Join-Path $installDir 'winhub_agent.bootstrap.conf'), (@{GlobalApiKey=$descriptor.enrollment_token} | ConvertTo-Json), $encoding)
    & ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $installDir 'install-service.ps1')))) -InstallDir $installDir *> $null
    if ((Get-Service WinHUBAgent).Status -ne 'Running') { throw 'Agent service not running.' }
    $phase = 'enrollment'
    $registration = $null
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        $statusRequest = [Net.HttpWebRequest]::Create([string]$descriptor.url + '/status')
        $statusRequest.Proxy = $null
        $statusRequest.AllowAutoRedirect = $false
        $statusRequest.Timeout = 10000
        $statusRequest.ServerCertificateValidationCallback = $pinnedTls.Callback
        $statusRequest.Headers['Authorization'] = 'Bearer ' + $descriptor.token
        $statusResponse = $statusRequest.GetResponse()
        try {
            $reader = New-Object IO.StreamReader ($statusResponse.GetResponseStream())
            try { $registration = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        } finally { $statusResponse.Dispose() }
        if ($registration.registered) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $registration.registered) { throw 'Service started but enrollment was not confirmed within five minutes.' }
    @{installed=$true; registered=$true; endpoint_id=$registration.endpoint_id; approval_status=$registration.approval_status; agent_version=$registration.agent_version} | ConvertTo-Json -Compress
    exit 0
} catch {
    # Exception text can contain credentials. Return only a category.
    @{installed=$false; phase=$phase; error_type=$_.Exception.GetType().Name} | ConvertTo-Json -Compress
    exit 1
} finally {
    if (Test-Path -LiteralPath $DescriptorPath) { Remove-Item -LiteralPath $DescriptorPath -Force }
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
