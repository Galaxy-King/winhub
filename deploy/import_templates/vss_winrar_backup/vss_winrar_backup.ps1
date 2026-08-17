$ErrorActionPreference = 'Stop'

try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$StartedAt = Get-Date
$Stage = 'initialization'
$RunTemp = $null
$SmbDriveName = $null
$ShadowMappings = @()
$ArchiveResults = @()
$DeletedByRetention = @()
$Warnings = New-Object System.Collections.Generic.List[string]
$Succeeded = $false
$ErrorMessage = $null
$ArchivePassword = $null
$SmbPassword = $null

function Split-WinHubLines {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @(
        $Text -split "`r?`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

function ConvertFrom-WinHubBase64Secret {
    param(
        [string]$EncodedValue,
        [string]$SecretName
    )

    try {
        $bytes = [Convert]::FromBase64String($EncodedValue.Trim())
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        throw "Template Secret '$SecretName' is not valid UTF-8 Base64."
    }
}

function ConvertTo-WinHubBoolean {
    param([string]$Value)
    return @('1', 'true', 'yes', 'on', 'enabled') -contains ([string]$Value).Trim().ToLowerInvariant()
}

function ConvertTo-SafeFileToken {
    param(
        [string]$Value,
        [string]$Fallback = 'backup'
    )

    $safe = ([string]$Value -replace '[^A-Za-z0-9._-]+', '_').Trim(' ', '.', '_')
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = $Fallback }
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80).TrimEnd('.', '_') }
    return $safe
}

function Resolve-WinHubSourceFolder {
    param([string]$Path)

    $candidate = ([string]$Path).Trim()
    if ($candidate -notmatch '^[A-Za-z]:\\') {
        throw "Source '$candidate' must be an absolute local Windows path such as C:\\Data. UNC sources cannot be protected with local VSS."
    }

    $fullPath = [System.IO.Path]::GetFullPath($candidate)
    if ($fullPath -match '^[A-Za-z]:\\$') { return $fullPath }
    return $fullPath.TrimEnd('\\')
}

function Get-WinHubSmbDestination {
    param([string]$Path)

    $normalized = ([string]$Path).Trim().TrimEnd('\\')
    if ($normalized -notmatch '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$') {
        throw "Backup destination '$normalized' must be a UNC path such as \\\\nas\\backups\\server01."
    }

    return [pscustomobject][ordered]@{
        server = $Matches[1]
        share = $Matches[2]
        share_root = "\\$($Matches[1])\$($Matches[2])"
        sub_path = [string]$Matches[3]
        original = $normalized
    }
}

function Remove-WinHubShadowSet {
    param(
        [array]$Mappings,
        [string]$WorkingDirectory,
        [string]$DiskShadowPath,
        [System.Collections.Generic.List[string]]$WarningList
    )

    if (-not $Mappings -or [string]::IsNullOrWhiteSpace($WorkingDirectory) -or -not (Test-Path -LiteralPath $WorkingDirectory)) {
        return
    }

    try {
        $cleanupFile = Join-Path $WorkingDirectory 'diskshadow_cleanup.dsh'
        $cleanupLines = @($Mappings | ForEach-Object { "delete shadows exposed $($_.drive):" })
        if ($cleanupLines.Count -eq 0) { return }
        [System.IO.File]::WriteAllLines($cleanupFile, $cleanupLines, [System.Text.Encoding]::ASCII)
        $cleanupOutput = @(& $DiskShadowPath /s $cleanupFile 2>&1)
        $cleanupExitCode = $LASTEXITCODE
        if ($cleanupExitCode -ne 0) {
            $WarningList.Add("VSS cleanup returned exit code ${cleanupExitCode}: $($cleanupOutput -join ' ')")
        }
    } catch {
        $WarningList.Add("VSS cleanup failed: $($_.Exception.Message)")
    }
}

$ProjectNameText = @'
{{project_name}}
'@
$TaskNameText = @'
{{task_name}}
'@
$BackupDestinationText = @'
{{backup_destination}}
'@
$RecursiveFoldersText = @'
{{recursive_folders}}
'@
$SingleFoldersText = @'
{{single_folders}}
'@
$ArchivePrefixText = @'
{{archive_prefix}}
'@
$WinRarPathText = @'
{{winrar_path}}
'@
$TempRootText = @'
{{temp_root}}
'@
$CompressionLevelText = @'
{{compression_level}}
'@
$VerifyModeText = @'
{{verify_mode}}
'@
$RetentionDaysText = @'
{{retention_days}}
'@
$FailOnMissingSourceText = @'
{{fail_on_missing_source}}
'@

$SmbUsernameBase64 = @'
{{secret:vss_backup_smb_username_b64}}
'@
$SmbPasswordBase64 = @'
{{secret:vss_backup_smb_password_b64}}
'@
$ArchivePasswordBase64 = @'
{{secret:vss_backup_archive_password_b64}}
'@

$ProjectName = $ProjectNameText.Trim()
$TaskName = $TaskNameText.Trim()
$BackupDestination = $BackupDestinationText.Trim()
$ArchivePrefix = $ArchivePrefixText.Trim()
$WinRarPath = $WinRarPathText.Trim()
$TempRoot = $TempRootText.Trim()
$VerifyMode = $VerifyModeText.Trim()
$FailOnMissingSource = ConvertTo-WinHubBoolean $FailOnMissingSourceText

try {
    $Stage = 'validating configuration'

    if ([string]::IsNullOrWhiteSpace($ProjectName)) { $ProjectName = 'Backup' }
    if ([string]::IsNullOrWhiteSpace($TaskName)) { $TaskName = 'VSS WinRAR backup' }
    if ([string]::IsNullOrWhiteSpace($ArchivePrefix)) { $ArchivePrefix = 'WinHUB' }
    if ([string]::IsNullOrWhiteSpace($WinRarPath)) { $WinRarPath = 'C:\Program Files\WinRAR\WinRAR.exe' }
    if ([string]::IsNullOrWhiteSpace($TempRoot)) { $TempRoot = 'C:\ProgramData\WinHUB\BackupTemp' }
    if ([string]::IsNullOrWhiteSpace($VerifyMode)) { $VerifyMode = 'Size' }

    $CompressionLevel = 0
    if (-not [int]::TryParse($CompressionLevelText.Trim(), [ref]$CompressionLevel) -or $CompressionLevel -lt 0 -or $CompressionLevel -gt 5) {
        throw 'Compression level must be an integer from 0 through 5.'
    }

    $RetentionDays = 0
    if (-not [int]::TryParse($RetentionDaysText.Trim(), [ref]$RetentionDays) -or $RetentionDays -lt 0 -or $RetentionDays -gt 3650) {
        throw 'Retention days must be an integer from 0 through 3650.'
    }

    if (@('None', 'Size', 'SHA256') -notcontains $VerifyMode) {
        throw "Verify mode must be None, Size, or SHA256. Received '$VerifyMode'."
    }
    if (-not (Test-Path -LiteralPath $WinRarPath -PathType Leaf)) {
        throw "WinRAR was not found at '$WinRarPath'."
    }

    $DiskShadowPath = Join-Path $env:SystemRoot 'System32\diskshadow.exe'
    if (-not (Test-Path -LiteralPath $DiskShadowPath -PathType Leaf)) {
        throw "DiskShadow was not found at '$DiskShadowPath'."
    }

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The backup task must run elevated. The WinHUB Agent service should run as LocalSystem or another local administrator.'
    }

    if ($TempRoot -notmatch '^[A-Za-z]:\\' -or $TempRoot -match '^[A-Za-z]:\\?$') {
        throw "Temp root '$TempRoot' must be a dedicated absolute local folder, not a volume root."
    }

    $SmbDestination = Get-WinHubSmbDestination $BackupDestination
    $SmbUsername = ConvertFrom-WinHubBase64Secret $SmbUsernameBase64 'vss_backup_smb_username_b64'
    $SmbPassword = ConvertFrom-WinHubBase64Secret $SmbPasswordBase64 'vss_backup_smb_password_b64'
    $ArchivePassword = ConvertFrom-WinHubBase64Secret $ArchivePasswordBase64 'vss_backup_archive_password_b64'
    if ([string]::IsNullOrWhiteSpace($SmbUsername)) { throw 'The decoded SMB username is empty.' }
    if ([string]::IsNullOrEmpty($SmbPassword)) { throw 'The decoded SMB password is empty.' }
    if ([string]::IsNullOrEmpty($ArchivePassword)) { throw 'The decoded archive password is empty.' }

    $RecursiveFolders = @(
        Split-WinHubLines $RecursiveFoldersText |
            ForEach-Object { Resolve-WinHubSourceFolder $_ } |
            Select-Object -Unique
    )
    $SingleFolders = @(
        Split-WinHubLines $SingleFoldersText |
            ForEach-Object { Resolve-WinHubSourceFolder $_ } |
            Where-Object { $RecursiveFolders -notcontains $_ } |
            Select-Object -Unique
    )
    if (($RecursiveFolders.Count + $SingleFolders.Count) -eq 0) {
        throw 'No source folders were provided.'
    }

    $ExistingRecursiveFolders = New-Object System.Collections.Generic.List[string]
    $ExistingSingleFolders = New-Object System.Collections.Generic.List[string]
    foreach ($folder in $RecursiveFolders) {
        if (Test-Path -LiteralPath $folder -PathType Container) {
            $ExistingRecursiveFolders.Add($folder)
        } elseif ($FailOnMissingSource) {
            throw "Recursive source folder does not exist: $folder"
        } else {
            $Warnings.Add("Recursive source folder does not exist and was skipped: $folder")
        }
    }
    foreach ($folder in $SingleFolders) {
        if (Test-Path -LiteralPath $folder -PathType Container) {
            $ExistingSingleFolders.Add($folder)
        } elseif ($FailOnMissingSource) {
            throw "Single-level source folder does not exist: $folder"
        } else {
            $Warnings.Add("Single-level source folder does not exist and was skipped: $folder")
        }
    }
    if (($ExistingRecursiveFolders.Count + $ExistingSingleFolders.Count) -eq 0) {
        throw 'None of the configured source folders exists.'
    }

    $Stage = 'preparing local workspace'
    [System.IO.Directory]::CreateDirectory($TempRoot) | Out-Null
    $RunTemp = Join-Path $TempRoot ("run_{0}_{1}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), [guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($RunTemp) | Out-Null

    $AllExistingFolders = @($ExistingRecursiveFolders.ToArray()) + @($ExistingSingleFolders.ToArray())
    $Volumes = @($AllExistingFolders | ForEach-Object { $_.Substring(0, 2).ToUpperInvariant() } | Select-Object -Unique)
    $CandidateLetters = @('R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Q', 'P', 'O', 'N')
    $UsedLetters = @(
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[A-Za-z]$' } |
            ForEach-Object { $_.Name.ToUpperInvariant() }
    )
    $FreeLetters = @($CandidateLetters | Where-Object { $UsedLetters -notcontains $_ -and -not (Test-Path -LiteralPath "$_`:\") })
    if ($FreeLetters.Count -lt $Volumes.Count) {
        throw "Not enough free drive letters for VSS. Needed $($Volumes.Count), available $($FreeLetters.Count)."
    }

    $ScriptFile = Join-Path $RunTemp 'diskshadow_create.dsh'
    $MetaFile = Join-Path $RunTemp 'vss_metadata.cab'
    $DiskShadowLines = New-Object System.Collections.Generic.List[string]
    $DiskShadowLines.Add('set context persistent')
    $DiskShadowLines.Add('set verbose on')
    $DiskShadowLines.Add("set metadata `"$MetaFile`"")

    for ($index = 0; $index -lt $Volumes.Count; $index++) {
        $alias = "WinHubVol$index"
        $mapping = [pscustomobject][ordered]@{
            volume = $Volumes[$index]
            alias = $alias
            drive = $FreeLetters[$index]
        }
        $ShadowMappings += $mapping
        $DiskShadowLines.Add("add volume $($mapping.volume) alias $alias")
    }
    $DiskShadowLines.Add('create')
    foreach ($mapping in $ShadowMappings) {
        $DiskShadowLines.Add("expose %$($mapping.alias)% $($mapping.drive):")
    }
    [System.IO.File]::WriteAllLines($ScriptFile, $DiskShadowLines, [System.Text.Encoding]::ASCII)

    $Stage = 'creating VSS snapshot set'
    $DiskShadowOutput = @(& $DiskShadowPath /s $ScriptFile 2>&1)
    $DiskShadowExitCode = $LASTEXITCODE
    $MissingShadowDrives = @($ShadowMappings | Where-Object { -not (Test-Path -LiteralPath "$($_.drive):\") })
    if ($DiskShadowExitCode -ne 0 -or $MissingShadowDrives.Count -gt 0) {
        throw "VSS snapshot set was not created or exposed correctly. DiskShadow exit code: $DiskShadowExitCode. Output: $($DiskShadowOutput -join ' ')"
    }

    $Stage = 'creating encrypted RAR archives'
    $SafePrefix = ConvertTo-SafeFileToken $ArchivePrefix 'WinHUB'
    $SafeComputerName = ConvertTo-SafeFileToken $env:COMPUTERNAME 'WindowsHost'
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $RunToken = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $LocalArchives = New-Object System.Collections.Generic.List[object]
    $ArchiveIndex = 0

    $ArchiveRequests = @()
    $ArchiveRequests += @($ExistingRecursiveFolders.ToArray() | ForEach-Object { [pscustomobject]@{ path = $_; mode = 'recursive'; switch = '-r' } })
    $ArchiveRequests += @($ExistingSingleFolders.ToArray() | ForEach-Object { [pscustomobject]@{ path = $_; mode = 'single-level'; switch = '-r-' } })

    foreach ($request in $ArchiveRequests) {
        $ArchiveIndex++
        $mapping = $ShadowMappings | Where-Object { $_.volume -eq $request.path.Substring(0, 2).ToUpperInvariant() } | Select-Object -First 1
        if (-not $mapping) { throw "No VSS mapping was found for '$($request.path)'." }

        $relativePath = $request.path.Substring(2).TrimStart('\\')
        $shadowRoot = "$($mapping.drive):\"
        $shadowSource = if ([string]::IsNullOrWhiteSpace($relativePath)) { $shadowRoot } else { Join-Path $shadowRoot $relativePath }
        if (-not (Test-Path -LiteralPath $shadowSource -PathType Container)) {
            throw "Source '$($request.path)' is not visible inside the VSS snapshot at '$shadowSource'."
        }

        $sourceToken = ConvertTo-SafeFileToken ($request.path -replace ':', '') 'source'
        $modeToken = if ($request.mode -eq 'recursive') { 'rec' } else { 'single' }
        $archiveName = '{0}_{1}_{2:D2}_{3}_{4}_{5}_{6}.rar' -f $SafePrefix, $SafeComputerName, $ArchiveIndex, $sourceToken, $modeToken, $Timestamp, $RunToken
        $localArchivePath = Join-Path $RunTemp $archiveName
        $winRarArguments = @(
            'a',
            '-idq',
            $request.switch,
            '-ep1',
            "-m$CompressionLevel",
            "-hp$ArchivePassword",
            $localArchivePath,
            $shadowSource
        )
        $WinRarOutput = @(& $WinRarPath @winRarArguments 2>&1)
        $WinRarExitCode = $LASTEXITCODE
        if ($WinRarExitCode -ne 0 -or -not (Test-Path -LiteralPath $localArchivePath -PathType Leaf)) {
            throw "WinRAR failed for '$($request.path)' with exit code $WinRarExitCode. Output: $($WinRarOutput -join ' ')"
        }

        $localItem = Get-Item -LiteralPath $localArchivePath
        if ($localItem.Length -le 0) { throw "WinRAR created an empty archive for '$($request.path)'." }
        $LocalArchives.Add([pscustomobject][ordered]@{
            name = $archiveName
            local_path = $localArchivePath
            source = $request.path
            mode = $request.mode
            size_bytes = [int64]$localItem.Length
        })
    }

    if ($LocalArchives.Count -eq 0) { throw 'No archives were created.' }

    $Stage = 'connecting to SMB destination'
    $secureSmbPassword = ConvertTo-SecureString $SmbPassword -AsPlainText -Force
    $smbCredential = New-Object System.Management.Automation.PSCredential($SmbUsername, $secureSmbPassword)
    $SmbDriveName = 'WBK' + (Get-Random -Minimum 100000 -Maximum 999999)
    try {
        New-PSDrive -Name $SmbDriveName -PSProvider FileSystem -Root $SmbDestination.share_root -Credential $smbCredential -Scope Script -ErrorAction Stop | Out-Null
    } catch {
        throw "Cannot connect to SMB share '$($SmbDestination.share_root)' as '$SmbUsername'. Check TCP 445, share/NTFS permissions, and conflicting SMB sessions. $($_.Exception.Message)"
    }

    $destinationRoot = "$SmbDriveName`:\"
    $destinationPath = if ([string]::IsNullOrWhiteSpace($SmbDestination.sub_path)) {
        $destinationRoot
    } else {
        Join-Path $destinationRoot $SmbDestination.sub_path
    }
    if (-not (Test-Path -LiteralPath $destinationPath -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationPath -Force -ErrorAction Stop | Out-Null
    }

    $Stage = 'copying and verifying archives'
    foreach ($archive in $LocalArchives) {
        $destinationFile = Join-Path $destinationPath $archive.name
        if (Test-Path -LiteralPath $destinationFile) {
            throw "Destination archive already exists and will not be overwritten: '$destinationFile'."
        }
        Copy-Item -LiteralPath $archive.local_path -Destination $destinationFile -ErrorAction Stop
        $destinationItem = Get-Item -LiteralPath $destinationFile -ErrorAction Stop

        $verification = 'none'
        if ($VerifyMode -eq 'Size') {
            if ([int64]$destinationItem.Length -ne [int64]$archive.size_bytes) {
                throw "Size verification failed for '$($archive.name)'. Local: $($archive.size_bytes), destination: $($destinationItem.Length)."
            }
            $verification = 'size-ok'
        } elseif ($VerifyMode -eq 'SHA256') {
            $sourceHash = (Get-FileHash -LiteralPath $archive.local_path -Algorithm SHA256).Hash
            $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash
            if ($sourceHash -ne $destinationHash) {
                throw "SHA256 verification failed for '$($archive.name)'."
            }
            $verification = 'sha256-ok'
        }

        $ArchiveResults += [pscustomobject][ordered]@{
            name = $archive.name
            source = $archive.source
            mode = $archive.mode
            size_bytes = [int64]$archive.size_bytes
            size_mb = [math]::Round($archive.size_bytes / 1MB, 2)
            destination = Join-Path $SmbDestination.original $archive.name
            verification = $verification
        }
    }

    if ($RetentionDays -gt 0) {
        $Stage = 'applying retention policy'
        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        $retentionPattern = "${SafePrefix}_${SafeComputerName}_*.rar"
        $oldArchives = @(
            Get-ChildItem -LiteralPath $destinationPath -Filter $retentionPattern -File -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff }
        )
        foreach ($oldArchive in $oldArchives) {
            Remove-Item -LiteralPath $oldArchive.FullName -Force -ErrorAction Stop
            $DeletedByRetention += $oldArchive.Name
        }
    }

    $Succeeded = $true
} catch {
    $ErrorMessage = "[$Stage] $($_.Exception.Message)"
} finally {
    $Stage = 'cleanup'
    if ($SmbDriveName) {
        try {
            Remove-PSDrive -Name $SmbDriveName -Scope Script -Force -ErrorAction Stop
        } catch {
            $Warnings.Add("SMB cleanup failed for PSDrive '$SmbDriveName': $($_.Exception.Message)")
        }
    }

    if ($ShadowMappings.Count -gt 0 -and $RunTemp) {
        Remove-WinHubShadowSet -Mappings $ShadowMappings -WorkingDirectory $RunTemp -DiskShadowPath $DiskShadowPath -WarningList $Warnings
    }

    if ($RunTemp -and (Test-Path -LiteralPath $RunTemp)) {
        try {
            Remove-Item -LiteralPath $RunTemp -Recurse -Force -ErrorAction Stop
        } catch {
            $Warnings.Add("Temporary workspace cleanup failed for '$RunTemp': $($_.Exception.Message)")
        }
    }

    $ArchivePassword = $null
    $SmbPassword = $null
    $SmbUsername = $null
    $secureSmbPassword = $null
    $smbCredential = $null
    [System.GC]::Collect()
}

$FinishedAt = Get-Date
$Result = [ordered]@{
    winhub_report_type = 'vss_winrar_backup'
    success = $Succeeded
    project = $ProjectName
    task = $TaskName
    endpoint = $env:COMPUTERNAME
    backup_destination = $BackupDestination
    recursive_folders = @($RecursiveFolders)
    single_folders = @($SingleFolders)
    archives = @($ArchiveResults)
    retention_days = $RetentionDays
    deleted_by_retention = @($DeletedByRetention)
    warnings = @($Warnings)
    started_at = $StartedAt.ToString('yyyy-MM-dd HH:mm:ss')
    finished_at = $FinishedAt.ToString('yyyy-MM-dd HH:mm:ss')
    duration_seconds = [int]($FinishedAt - $StartedAt).TotalSeconds
}
if (-not $Succeeded) { $Result['error'] = $ErrorMessage }

Write-Output ($Result | ConvertTo-Json -Depth 10 -Compress)
if (-not $Succeeded) { exit 1 }
