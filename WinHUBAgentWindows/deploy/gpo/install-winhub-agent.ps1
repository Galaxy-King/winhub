param(
    [string]$SourceDir = '\\DC_FQDN\NETLOGON\WinHUBAgentDeploy',
    [string]$InstallDir = 'C:\Program Files\WinHUBAgent',
    [string]$DataDir = "$env:ProgramData\WinHUB",
    [ValidateSet('WinHUBAgent')][string]$ServiceName = 'WinHUBAgent'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$TempDir = Join-Path $DataDir 'gpo-install'
$LogFile = Join-Path $TempDir 'install.log'
$VersionMarker = Join-Path $InstallDir '.deployed_version'
$RuntimeConfigTarget = Join-Path $InstallDir 'winhub_agent.conf'
$BootstrapTarget = Join-Path $InstallDir 'winhub_agent.bootstrap.conf'
$ReleaseTrustTarget = Join-Path $DataDir 'release-signing-public.pem'
$ReleaseState = Join-Path $DataDir 'release-state.json'
$mutex = $null

function Write-DeployLog([string]$Message) {
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 5MB) {
        Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force
    }
    Add-Content -LiteralPath $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" -Encoding UTF8
}

function Protect-Directory([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure directory: $Path" }
}

function Assert-OrdinaryPath([string]$Path) {
    $check = [IO.Path]::GetFullPath($Path)
    while ($check) {
        if ((Test-Path -LiteralPath $check) -and ((Get-Item -LiteralPath $check -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse points are forbidden in deployment paths: $check"
        }
        $check = [IO.Path]::GetDirectoryName($check)
    }
}

function Get-SemanticVersion([string]$Value) {
    $clean = ([string]$Value).Trim().Split('+')[0]
    if ($clean -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?$') {
        return $null
    }
    return $clean
}

function Compare-SemanticVersion([string]$Left, [string]$Right) {
    $leftClean = Get-SemanticVersion $Left
    $rightClean = Get-SemanticVersion $Right
    if (-not $leftClean -or -not $rightClean) { throw 'Cannot compare invalid semantic versions.' }
    $leftParts = $leftClean.Split('-', 2); $rightParts = $rightClean.Split('-', 2)
    $leftCore = $leftParts[0].Split('.'); $rightCore = $rightParts[0].Split('.')
    for ($i = 0; $i -lt 3; $i++) {
        $a = [Numerics.BigInteger]::Parse($leftCore[$i]); $b = [Numerics.BigInteger]::Parse($rightCore[$i])
        if ($a -lt $b) { return -1 }; if ($a -gt $b) { return 1 }
    }
    if ($leftParts.Count -eq 1 -and $rightParts.Count -eq 1) { return 0 }
    if ($leftParts.Count -eq 1) { return 1 }; if ($rightParts.Count -eq 1) { return -1 }
    $aParts = $leftParts[1].Split('.'); $bParts = $rightParts[1].Split('.')
    for ($i = 0; $i -lt [Math]::Min($aParts.Count, $bParts.Count); $i++) {
        $aNumeric = $aParts[$i] -match '^[0-9]+$'; $bNumeric = $bParts[$i] -match '^[0-9]+$'
        if ($aNumeric -and $bNumeric) {
            $a = [Numerics.BigInteger]::Parse($aParts[$i]); $b = [Numerics.BigInteger]::Parse($bParts[$i])
            if ($a -lt $b) { return -1 }; if ($a -gt $b) { return 1 }
        } elseif ($aNumeric -ne $bNumeric) { return $(if ($aNumeric) { -1 } else { 1 }) }
        else { $comparison = [String]::CompareOrdinal($aParts[$i], $bParts[$i]); if ($comparison -ne 0) { return [Math]::Sign($comparison) } }
    }
    return [Math]::Sign($aParts.Count - $bParts.Count)
}

function Get-InstalledVersion {
    $exe = Join-Path $InstallDir 'WinHUBAgent.exe'
    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        foreach ($candidate in @((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion, (Get-Item -LiteralPath $exe).VersionInfo.FileVersion)) {
            $version = Get-SemanticVersion $candidate
            if ($version) { return $version }
        }
    }
    if (Test-Path -LiteralPath $VersionMarker -PathType Leaf) {
        $version = Get-SemanticVersion ((Get-Content -LiteralPath $VersionMarker -First 1 -ErrorAction SilentlyContinue))
        if ($version) { return $version }
    }
    return ''
}

function Ensure-ServiceProtection {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return }
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure delayed automatic service start.' }
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure service recovery.' }
    & sc.exe failureflag $ServiceName 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure non-crash recovery.' }

    $watchdog = Join-Path $TempDir 'ensure-service.ps1'
    @'
$ErrorActionPreference = 'Stop'
$lockPath = Join-Path $env:ProgramData 'WinHUB\updates\updater.lock'
$lock = $null
try {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $lockPath) | Out-Null
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $service = Get-Service -Name 'WinHUBAgent' -ErrorAction SilentlyContinue
    if ($service) {
        & sc.exe config WinHUBAgent start= delayed-auto | Out-Null
        if ($service.Status -ne 'Running') { Start-Service -Name 'WinHUBAgent' }
    }
} catch [IO.IOException] {
    # The transactional updater owns the lock; do not race its deliberate stop.
} finally {
    if ($lock) { $lock.Dispose() }
}

function Reset-ServerBoundIdentity([string]$Epoch, [string]$BootstrapSource) {
    if ([string]::IsNullOrWhiteSpace($Epoch)) { return }
    if ($Epoch -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$') {
        throw 'server_identity_epoch must be empty or a canonical UUID.'
    }
    $epochFile = Join-Path $DataDir 'server-identity-epoch.txt'
    $currentEpoch = if (Test-Path -LiteralPath $epochFile -PathType Leaf) { (Get-Content -LiteralPath $epochFile -First 1).Trim() } else { '' }
    if ($currentEpoch -eq $Epoch) { return }
    if (-not (Test-Path -LiteralPath $BootstrapSource -PathType Leaf)) {
        throw 'A new server identity epoch requires winhub_agent.bootstrap.conf.'
    }

    Write-DeployLog "Applying one-time server identity epoch $Epoch; endpoint hardware and RSA identity are preserved."
    Protect-Directory (Join-Path $DataDir 'updates')
    $identityLockPath = Join-Path $DataDir 'updates\updater.lock'
    $identityLock = [IO.File]::Open($identityLockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        $backupRoot = Join-Path $DataDir 'server-reset-backups'
        Protect-Directory $backupRoot
        $backup = Join-Path $backupRoot ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $backup | Out-Null
        foreach ($name in @('agent.token', 'task-signing-state.json', 'execution-journal')) {
            $path = Join-Path $DataDir $name
            if (Test-Path -LiteralPath $path) { Move-Item -LiteralPath $path -Destination $backup }
        }
        Protect-Directory $InstallDir
        Copy-Item -LiteralPath $BootstrapSource -Destination $BootstrapTarget -Force
        $epochTemp = "$epochFile.tmp"
        Set-Content -LiteralPath $epochTemp -Value $Epoch -Encoding ASCII
        Move-Item -LiteralPath $epochTemp -Destination $epochFile -Force
        Write-DeployLog "Server-bound token/task state archived to $backup; fresh enrollment is required."
    } finally {
        $identityLock.Dispose()
    }
}
'@ | Set-Content -LiteralPath $watchdog -Encoding UTF8
    & schtasks.exe /Create /TN 'WinHUBAgent Watchdog' /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /TR "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$watchdog`"" /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not register the service watchdog task.' }
    $service.Refresh()
    if ($service.Status -ne 'Running') { Start-Service -Name $ServiceName }
}

try {
    $mutex = New-Object Threading.Mutex($false, 'Global\WinHUBAgentGpoDeploy')
    try { $hasMutex = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $hasMutex = $true }
    if (-not $hasMutex) { Write-DeployLog 'Another deployment instance is active; exiting successfully.'; exit 0 }

    Protect-Directory $DataDir
    Protect-Directory $TempDir
    Assert-OrdinaryPath $InstallDir
    Assert-OrdinaryPath $DataDir
    Write-DeployLog "Starting deployment from $SourceDir"

    $manifestPath = Join-Path $SourceDir 'deployment-manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $targetVersion = Get-SemanticVersion ([string]$manifest.version)
    if ($manifest.schema -ne 1 -or -not $targetVersion) { throw 'Deployment manifest schema/version is invalid.' }
    if ([string]$manifest.package -ne [IO.Path]::GetFileName([string]$manifest.package)) { throw 'Package must be a plain filename.' }
    if ([string]$manifest.publisher_public_key -ne [IO.Path]::GetFileName([string]$manifest.publisher_public_key)) { throw 'Publisher key must be a plain filename.' }
    $expectedHash = ([string]$manifest.sha256).ToUpperInvariant()
    $expectedKeyHash = ([string]$manifest.publisher_public_key_sha256).ToUpperInvariant()
    $serverIdentityEpoch = ([string]$manifest.server_identity_epoch).Trim()
    if ($expectedHash -notmatch '^[0-9A-F]{64}$' -or $expectedKeyHash -notmatch '^[0-9A-F]{64}$') { throw 'Manifest SHA-256 values are invalid.' }

    $packageSource = Join-Path $SourceDir ([string]$manifest.package)
    $trustSource = Join-Path $SourceDir ([string]$manifest.publisher_public_key)
    foreach ($required in @($packageSource, $trustSource, (Join-Path $SourceDir 'winhub_agent.conf'))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required deployment file is missing: $required" }
    }
    if ((Get-FileHash -LiteralPath $trustSource -Algorithm SHA256).Hash -ne $expectedKeyHash) { throw 'Publisher public key SHA-256 mismatch.' }
    if (Test-Path -LiteralPath $ReleaseTrustTarget) {
        if ((Get-FileHash -LiteralPath $ReleaseTrustTarget -Algorithm SHA256).Hash -ne $expectedKeyHash) {
            throw 'The endpoint trusts a different release publisher; key rotation must be performed separately.'
        }
    } else {
        Copy-Item -LiteralPath $trustSource -Destination $ReleaseTrustTarget
    }

    $work = Join-Path $TempDir ('stage-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $packageCopy = Join-Path $work 'package.zip'
    Copy-Item -LiteralPath $packageSource -Destination $packageCopy
    if ((Get-Item -LiteralPath $packageCopy).Length -gt 512MB) { throw 'Agent package exceeds 512 MiB.' }
    if ((Get-FileHash -LiteralPath $packageCopy -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Agent package SHA-256 mismatch.' }
    $stage = Join-Path $work 'files'
    New-Item -ItemType Directory -Path $stage | Out-Null
    Expand-Archive -LiteralPath $packageCopy -DestinationPath $stage
    $candidate = Join-Path $stage 'WinHUBAgent.exe'
    foreach ($required in @($candidate, (Join-Path $stage 'install-service.ps1'), (Join-Path $stage 'update-service.ps1'), (Join-Path $stage 'release-manifest.json'))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Signed package is incomplete: $required" }
    }

    $installedVersion = Get-InstalledVersion
    $comparison = if ($installedVersion) { Compare-SemanticVersion $installedVersion $targetVersion } else { -1 }
    if ($comparison -gt 0) { throw "Installed version $installedVersion is newer than GPO target $targetVersion; downgrade refused." }

    $candidateVersionOutput = @(& $candidate --version 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Candidate version probe failed.' }
    $candidateVersion = Get-SemanticVersion ([string]($candidateVersionOutput | Select-Object -Last 1))
    if (-not $candidateVersion -or (Compare-SemanticVersion $candidateVersion $targetVersion) -ne 0) {
        throw "Signed package version '$candidateVersion' does not match deployment target '$targetVersion'."
    }

    $runtimeConfigSource = Join-Path $SourceDir 'winhub_agent.conf'
    $configForValidation = if (Test-Path -LiteralPath $RuntimeConfigTarget) { $RuntimeConfigTarget } else { $runtimeConfigSource }
    & $candidate --verify-release $stage $ReleaseTrustTarget $ReleaseState $(if ($installedVersion) { $installedVersion } else { '0.0.0' }) $targetVersion
    if ($LASTEXITCODE -ne 0) { throw 'Publisher signature or signed file inventory verification failed.' }
    & $candidate --validate-config $configForValidation
    if ($LASTEXITCODE -ne 0) { throw 'Runtime configuration validation failed.' }
    & $candidate --check-update-server $configForValidation
    if ($LASTEXITCODE -ne 0) { throw 'Pinned HTTPS server preflight failed.' }

    Reset-ServerBoundIdentity -Epoch $serverIdentityEpoch -BootstrapSource (Join-Path $SourceDir 'winhub_agent.bootstrap.conf')

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $installedExe = Join-Path $InstallDir 'WinHUBAgent.exe'
    $binaryMatches = (Test-Path -LiteralPath $installedExe -PathType Leaf) -and
        ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash)
    if (-not $service -and (Test-Path -LiteralPath $installedExe -PathType Leaf) -and (Test-Path -LiteralPath $RuntimeConfigTarget -PathType Leaf)) {
        Write-DeployLog 'Installed code has no service; recreating a stopped service so transactional repair/update can run.'
        Protect-Directory $InstallDir
        New-Service -Name $ServiceName -BinaryPathName "`"$installedExe`"" -DisplayName 'WinHUB Agent' -Description 'WinHUB endpoint agent service' -StartupType Automatic | Out-Null
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
    }
    if ($service -and $comparison -eq 0 -and $binaryMatches -and (Test-Path -LiteralPath $RuntimeConfigTarget -PathType Leaf)) {
        Write-DeployLog "Version $targetVersion is installed; repairing service policy and start state."
        Ensure-ServiceProtection
        Set-Content -LiteralPath $VersionMarker -Value $targetVersion -Encoding ASCII
        exit 0
    }

    if ($service -and (Test-Path -LiteralPath $RuntimeConfigTarget)) {
        Write-DeployLog "Updating agent from $installedVersion to $targetVersion with the transactional updater."
        & (Join-Path $stage 'update-service.ps1') -PackagePath $packageCopy -ExpectedSha256 $expectedHash -InstallDir $InstallDir -ServiceName $ServiceName
        if ($LASTEXITCODE -ne 0) { throw 'Transactional agent update failed.' }
    } else {
        Write-DeployLog 'Performing first install or service repair.'
        Protect-Directory $InstallDir
        if (-not (Test-Path -LiteralPath $RuntimeConfigTarget)) {
            Copy-Item -LiteralPath $runtimeConfigSource -Destination $RuntimeConfigTarget
        }
        $secretStore = Join-Path $DataDir 'agent.secrets'
        $bootstrapSource = Join-Path $SourceDir 'winhub_agent.bootstrap.conf'
        if (-not (Test-Path -LiteralPath $secretStore) -and -not (Test-Path -LiteralPath $BootstrapTarget)) {
            if (-not (Test-Path -LiteralPath $bootstrapSource -PathType Leaf)) { throw 'Bootstrap config is required only for this first enrollment, but is missing.' }
            Copy-Item -LiteralPath $bootstrapSource -Destination $BootstrapTarget
        }
        Get-ChildItem -LiteralPath $InstallDir -Force | Where-Object { $_.Name -notin @('winhub_agent.conf', 'winhub_agent.bootstrap.conf') } | Remove-Item -Recurse -Force
        Get-ChildItem -LiteralPath $stage -Force | Where-Object { $_.Name -notin @('winhub_agent.conf', 'winhub_agent.bootstrap.conf') } | Copy-Item -Destination $InstallDir -Recurse -Force
        & (Join-Path $InstallDir 'install-service.ps1') -InstallDir $InstallDir -ServiceName $ServiceName
        if ($LASTEXITCODE -ne 0) { throw 'Service installation failed.' }
    }

    Ensure-ServiceProtection
    $installedAfter = Get-InstalledVersion
    if (-not $installedAfter -or (Compare-SemanticVersion $installedAfter $targetVersion) -ne 0) {
        throw "Installed binary version '$installedAfter' does not match target '$targetVersion'."
    }
    Set-Content -LiteralPath $VersionMarker -Value $targetVersion -Encoding ASCII
    Write-DeployLog "Deployment completed successfully: $targetVersion"
} catch {
    try { Write-DeployLog "ERROR: $($_.Exception.Message)" } catch { }
    throw
} finally {
    if ($work -and (Test-Path -LiteralPath $work)) {
        $resolvedTemp = [IO.Path]::GetFullPath($TempDir).TrimEnd('\') + '\'
        $resolvedWork = [IO.Path]::GetFullPath($work)
        if ($resolvedWork.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($mutex) { try { $mutex.ReleaseMutex() } catch { }; $mutex.Dispose() }
}
