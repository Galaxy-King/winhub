$ErrorActionPreference = "Stop"

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$Action = "{{Action}}"
$Browser = "{{Browser}}"
$Scope = "{{Scope}}"
$ExtensionInput = @"
{{ExtensionIds}}
"@
$TargetUsersInput = @"
{{TargetUsers}}
"@
$UpdateUrl = "{{UpdateUrl}}"
$BlockOthers = "{{BlockOthers}}"
$PinExtension = "{{PinExtension}}"

function ConvertTo-BoolValue {
    param($Value)
    $text = ([string]$Value).Trim().ToLowerInvariant()
    return @("1", "true", "yes", "y", "on", "enabled") -contains $text
}

function ConvertTo-SafeText {
    param($Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [array]) {
        $text = (($Value | Where-Object { $null -ne $_ } | ForEach-Object { [System.Convert]::ToString($_) }) -join [Environment]::NewLine)
        if ($null -eq $text) { return "" }
        return $text.Trim()
    }

    $single = [System.Convert]::ToString($Value)
    if ($null -eq $single) { return "" }
    return $single.Trim()
}

function ConvertTo-PlainObject {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $plain = [ordered]@{}
        foreach ($key in $Value.Keys) { $plain[[string]$key] = ConvertTo-PlainObject $Value[$key] }
        return $plain
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and -not ($Value -is [pscustomobject])) {
        $items = New-Object System.Collections.ArrayList
        foreach ($item in $Value) { [void]$items.Add((ConvertTo-PlainObject $item)) }
        return ,$items
    }

    $properties = $Value.PSObject.Properties | Where-Object { $_.MemberType -in @("NoteProperty", "Property") -and $_.Name -notmatch "^PS" }
    if ($properties.Count -gt 0) {
        $plain = [ordered]@{}
        foreach ($property in $properties) { $plain[$property.Name] = ConvertTo-PlainObject $property.Value }
        return $plain
    }

    return [string]$Value
}

function Split-MultilineList {
    param([string]$Text)
    if (-not $Text) { return @() }
    @($Text -split "[,\r\n]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-ExtensionIdFromValue {
    param([string]$Value)
    if (-not $Value) { return "" }
    return (($Value -split ";", 2)[0]).Trim().ToLowerInvariant()
}

function Normalize-ExtensionRequest {
    param([string]$Item, [string]$DefaultUpdateUrl)

    $text = ([string]$Item).Trim()
    if (-not $text) { return $null }

    $extensionId = Get-ExtensionIdFromValue $text
    $valid = ($extensionId -match "^[a-p]{32}$")
    $forceValue = $text

    if ($text -notmatch ";") {
        $forceValue = "$extensionId;$DefaultUpdateUrl"
    }

    [pscustomobject][ordered]@{
        extension_id = $extensionId
        force_value = $forceValue
        valid = $valid
        raw = $text
    }
}

function Ensure-RegistryKey {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Get-PolicyList {
    param([string]$BasePath, [string]$SubKey)

    $path = Join-Path $BasePath $SubKey
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $key) { return @() }

    @($key.GetValueNames() | Where-Object { $_ -match "^\d+$" } | Sort-Object { [int]$_ } | ForEach-Object {
        $value = [string]$key.GetValue($_)
        [pscustomobject][ordered]@{
            index = [int]$_
            value = $value
            extension_id = Get-ExtensionIdFromValue $value
        }
    })
}

function Set-PolicyList {
    param([string]$BasePath, [string]$SubKey, [string[]]$Values)

    $path = Join-Path $BasePath $SubKey
    Ensure-RegistryKey $path
    $key = Get-Item -LiteralPath $path -ErrorAction Stop

    foreach ($name in $key.GetValueNames()) {
        if ($name -match "^\d+$") {
            Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction SilentlyContinue
        }
    }

    $index = 1
    foreach ($value in @($Values | Where-Object { $_ } | Select-Object -Unique)) {
        New-ItemProperty -LiteralPath $path -Name ([string]$index) -PropertyType String -Value $value -Force | Out-Null
        $index++
    }
}

function Add-PolicyValues {
    param([string]$BasePath, [string]$SubKey, [string[]]$Values)

    $current = @(Get-PolicyList -BasePath $BasePath -SubKey $SubKey)
    $currentValues = @($current | ForEach-Object { $_.value })
    $currentIds = @($current | ForEach-Object { $_.extension_id })
    $changed = $false
    $added = @()

    foreach ($value in $Values) {
        $id = Get-ExtensionIdFromValue $value
        if ($value -eq "*") {
            if ($currentValues -notcontains "*") {
                $currentValues += "*"
                $added += "*"
                $changed = $true
            }
            continue
        }

        if ($currentIds -notcontains $id) {
            $currentValues += $value
            $currentIds += $id
            $added += $id
            $changed = $true
        }
    }

    if ($changed) {
        Set-PolicyList -BasePath $BasePath -SubKey $SubKey -Values $currentValues
    }

    [pscustomobject][ordered]@{ changed = $changed; added = @($added) }
}

function Remove-PolicyItems {
    param([string]$BasePath, [string]$SubKey, [string[]]$ExtensionIds, [bool]$RemoveWildcard)

    $current = @(Get-PolicyList -BasePath $BasePath -SubKey $SubKey)
    $removed = @()
    $remaining = @()

    foreach ($item in $current) {
        if ($RemoveWildcard -and $item.value -eq "*") {
            $removed += "*"
            continue
        }
        if ($ExtensionIds -contains $item.extension_id) {
            $removed += $item.extension_id
            continue
        }
        $remaining += $item.value
    }

    if ($removed.Count -gt 0) {
        Set-PolicyList -BasePath $BasePath -SubKey $SubKey -Values $remaining
    }

    [pscustomobject][ordered]@{ changed = ($removed.Count -gt 0); removed = @($removed) }
}

function Get-ExtensionSettingsText {
    param([string]$BasePath)
    if (-not (Test-Path -LiteralPath $BasePath)) { return "" }
    try {
        return [string]((Get-ItemProperty -LiteralPath $BasePath -Name "ExtensionSettings" -ErrorAction SilentlyContinue).ExtensionSettings)
    } catch {
        return ""
    }
}

function Convert-JsonObjectToHashtable {
    param($Object)

    if ($null -eq $Object) { return [ordered]@{} }
    if ($Object -is [string] -or $Object -is [bool] -or $Object -is [int] -or $Object -is [long] -or $Object -is [double] -or $Object -is [decimal]) { return $Object }
    if ($Object -is [System.Collections.IDictionary]) {
        $table = [ordered]@{}
        foreach ($key in $Object.Keys) { $table[$key] = Convert-JsonObjectToHashtable $Object[$key] }
        return $table
    }
    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string]) -and -not ($Object -is [pscustomobject])) {
        $items = New-Object System.Collections.ArrayList
        foreach ($item in $Object) { [void]$items.Add((Convert-JsonObjectToHashtable $item)) }
        return ,$items
    }
    if ($Object.PSObject.Properties.Count -gt 0) {
        $table = [ordered]@{}
        foreach ($property in $Object.PSObject.Properties) { $table[$property.Name] = Convert-JsonObjectToHashtable $property.Value }
        return $table
    }
    return $Object
}

function Test-DictionaryHasKey {
    param($Dictionary, [string]$Key)

    if ($null -eq $Dictionary -or $Dictionary -isnot [System.Collections.IDictionary]) { return $false }
    if ($Dictionary.Contains($Key)) { return $true }
    try { return $Dictionary.ContainsKey($Key) } catch { return $false }
}

function Repair-ToolbarPinValue {
    param($Value)

    if ($null -eq $Value -or $Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        if ((Test-DictionaryHasKey -Dictionary $Value -Key "Length") -and [int]$Value["Length"] -eq "force_pinned".Length) {
            return "force_pinned"
        }
    }
    if ($Value.PSObject.Properties["Length"] -and [int]$Value.PSObject.Properties["Length"].Value -eq "force_pinned".Length) {
        return "force_pinned"
    }
    return $Value
}

function Normalize-ExtensionSettings {
    param([System.Collections.IDictionary]$Settings)

    $changed = $false
    foreach ($extensionId in @($Settings.Keys)) {
        $entry = $Settings[$extensionId]
        if ($entry -is [System.Collections.IDictionary] -and (Test-DictionaryHasKey -Dictionary $entry -Key "toolbar_pin")) {
            $current = $entry["toolbar_pin"]
            $fixed = Repair-ToolbarPinValue -Value $current
            if ($fixed -ne $current) {
                $entry["toolbar_pin"] = $fixed
                $changed = $true
            }
        }
    }

    [pscustomobject][ordered]@{ settings = $Settings; changed = $changed }
}

function Set-ToolbarPin {
    param([string]$BasePath, [string[]]$ExtensionIds)

    $warnings = @()
    $changed = $false
    Ensure-RegistryKey $BasePath
    $settingsText = Get-ExtensionSettingsText -BasePath $BasePath
    $settings = [ordered]@{}

    if ($settingsText) {
        try {
            $settings = Convert-JsonObjectToHashtable ($settingsText | ConvertFrom-Json)
        } catch {
            $warnings += "ExtensionSettings contains invalid JSON. Pinning skipped to avoid overwriting existing policy."
            return [pscustomobject][ordered]@{ changed = $false; warnings = @($warnings) }
        }
    }

    $normalized = Normalize-ExtensionSettings -Settings $settings
    $settings = $normalized.settings
    if ($normalized.changed) {
        $changed = $true
        $warnings += "Repaired invalid ExtensionSettings toolbar_pin values created by an older template version."
    }

    foreach ($extensionId in $ExtensionIds) {
        if (-not (Test-DictionaryHasKey -Dictionary $settings -Key $extensionId) -or $settings[$extensionId] -isnot [System.Collections.IDictionary]) {
            $settings[$extensionId] = [ordered]@{}
        }
        if ($settings[$extensionId]["toolbar_pin"] -ne "force_pinned") {
            $settings[$extensionId]["toolbar_pin"] = "force_pinned"
            $changed = $true
        }
    }

    if ($changed) {
        $json = ($settings | ConvertTo-Json -Depth 16 -Compress)
        New-ItemProperty -LiteralPath $BasePath -Name "ExtensionSettings" -PropertyType String -Value $json -Force | Out-Null
    }

    [pscustomobject][ordered]@{ changed = $changed; warnings = @($warnings) }
}

function Get-PolicySnapshot {
    param([string]$BasePath)

    $settingsText = Get-ExtensionSettingsText -BasePath $BasePath
    [pscustomobject][ordered]@{
        forcelist = @(Get-PolicyList -BasePath $BasePath -SubKey "ExtensionInstallForcelist")
        blocklist = @(Get-PolicyList -BasePath $BasePath -SubKey "ExtensionInstallBlocklist")
        allowlist = @(Get-PolicyList -BasePath $BasePath -SubKey "ExtensionInstallAllowlist")
        extension_settings_present = [bool]$settingsText
        extension_settings_conflict_hint = if ($settingsText -match '"\*"\s*:' -and $settingsText -match 'blocked|removed') { "Wildcard ExtensionSettings may block installations" } else { $null }
    }
}

function Find-PolicyConflicts {
    param($Snapshot, [string[]]$ExtensionIds, [string]$Label)

    $conflicts = @()
    $warnings = @()
    $blockValues = @($Snapshot.blocklist | ForEach-Object { $_.value })
    $blockIds = @($Snapshot.blocklist | ForEach-Object { $_.extension_id })
    $allowIds = @($Snapshot.allowlist | ForEach-Object { $_.extension_id })

    if ($blockValues -contains "*") {
        $warnings += "$Label has ExtensionInstallBlocklist=*; extensions not in allowlist may be blocked."
        foreach ($extensionId in $ExtensionIds) {
            if ($allowIds.Count -gt 0 -and $allowIds -notcontains $extensionId) {
                $conflicts += "$Label blocks all extensions and allowlist does not contain $extensionId."
            }
        }
    }

    foreach ($extensionId in $ExtensionIds) {
        if ($blockIds -contains $extensionId) {
            $conflicts += "$Label explicitly blocks $extensionId."
        }
    }

    if ($Snapshot.extension_settings_conflict_hint) {
        $warnings += "$Label $($Snapshot.extension_settings_conflict_hint)."
    }

    [pscustomobject][ordered]@{ conflicts = @($conflicts); warnings = @($warnings) }
}

function Invoke-PolicyAction {
    param(
        [string]$BasePath,
        [string]$Label,
        [string]$ActionName,
        [object[]]$ExtensionRequests,
        [bool]$ShouldBlockOthers,
        [bool]$ShouldPinExtension
    )

    Ensure-RegistryKey $BasePath
    $extensionIds = @($ExtensionRequests | ForEach-Object { $_.extension_id })
    $forceValues = @($ExtensionRequests | ForEach-Object { $_.force_value })
    $changed = $false
    $operations = @()
    $warnings = @()
    $conflicts = @()

    $before = Get-PolicySnapshot -BasePath $BasePath
    $analysis = Find-PolicyConflicts -Snapshot $before -ExtensionIds $extensionIds -Label $Label
    $warnings += $analysis.warnings
    $conflicts += $analysis.conflicts

    switch ($ActionName) {
        "Audit" { }
        "Install" {
            if ($forceValues.Count -eq 0) {
                $warnings += "$Label install requested but no extension IDs were provided."
            } else {
                $result = Add-PolicyValues -BasePath $BasePath -SubKey "ExtensionInstallForcelist" -Values $forceValues
                if ($result.changed) {
                    $changed = $true
                    $operations += "$Label added to force-install list: $($result.added -join ', ')"
                }
                if ($ShouldBlockOthers) {
                    $blockResult = Add-PolicyValues -BasePath $BasePath -SubKey "ExtensionInstallBlocklist" -Values @("*")
                    if ($blockResult.changed) {
                        $changed = $true
                        $operations += "$Label enabled ExtensionInstallBlocklist=*."
                    }
                    $warnings += "$Label BlockOthers=true means Chrome/Edge will block extensions that are not explicitly allowed or force-installed."
                }
                if ($ShouldPinExtension) {
                    $pin = Set-ToolbarPin -BasePath $BasePath -ExtensionIds $extensionIds
                    if ($pin.changed) {
                        $changed = $true
                        $operations += "$Label added toolbar_pin=force_pinned for target extensions."
                    }
                    $warnings += $pin.warnings
                }
            }
        }
        "Remove" {
            $result = Remove-PolicyItems -BasePath $BasePath -SubKey "ExtensionInstallForcelist" -ExtensionIds $extensionIds -RemoveWildcard $false
            if ($result.changed) {
                $changed = $true
                $operations += "$Label removed from force-install list: $($result.removed -join ', ')"
            }
        }
        "Block" {
            $values = @()
            if ($ShouldBlockOthers) { $values += "*" }
            $values += $extensionIds
            $result = Add-PolicyValues -BasePath $BasePath -SubKey "ExtensionInstallBlocklist" -Values $values
            if ($result.changed) {
                $changed = $true
                $operations += "$Label added to blocklist: $($result.added -join ', ')"
            }
        }
        "Unblock" {
            $result = Remove-PolicyItems -BasePath $BasePath -SubKey "ExtensionInstallBlocklist" -ExtensionIds $extensionIds -RemoveWildcard $ShouldBlockOthers
            if ($result.changed) {
                $changed = $true
                $operations += "$Label removed from blocklist: $($result.removed -join ', ')"
            }
        }
        default {
            $warnings += "$Label unknown action '$ActionName'. Audit mode was used."
        }
    }

    $after = Get-PolicySnapshot -BasePath $BasePath
    [pscustomobject][ordered]@{
        label = $Label
        base_path = $BasePath
        changed = $changed
        warnings = @($warnings | Where-Object { $_ } | Select-Object -Unique)
        conflicts = @($conflicts | Where-Object { $_ } | Select-Object -Unique)
        operations = @($operations)
        before = $before
        after = $after
    }
}

function Get-ProfileUsers {
    $profileRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $items = @()

    if (Test-Path -LiteralPath $profileRoot) {
        foreach ($profileKey in (Get-ChildItem -LiteralPath $profileRoot -ErrorAction SilentlyContinue)) {
            $sid = $profileKey.PSChildName
            if ($sid -notmatch "^S-1-5-21-") { continue }
            $profile = Get-ItemProperty -LiteralPath $profileKey.PSPath -ErrorAction SilentlyContinue
            $profilePath = [string]$profile.ProfileImagePath
            if (-not $profilePath -or $profilePath -match "\\(Default|Public|All Users)$") { continue }

            $account = $sid
            try {
                $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $account = Split-Path $profilePath -Leaf
            }

            $items += [pscustomobject][ordered]@{
                sid = $sid
                account = $account
                username = Split-Path $profilePath -Leaf
                profile_path = $profilePath
                ntuser_dat = Join-Path $profilePath "NTUSER.DAT"
                profile_source = "ProfileList"
                local_user_enabled = $null
            }
        }
    }

    $knownSids = @($items | ForEach-Object { [string]$_.sid })
    foreach ($localUser in @(Get-LocalAccountUsers)) {
        if (-not $localUser.sid -or $knownSids -contains $localUser.sid) { continue }

        $profilePath = Join-Path $env:SystemDrive "Users\$($localUser.username)"
        $items += [pscustomobject][ordered]@{
            sid = $localUser.sid
            account = $localUser.account
            username = $localUser.username
            profile_path = $profilePath
            ntuser_dat = Join-Path $profilePath "NTUSER.DAT"
            profile_source = "LocalUsers"
            local_user_enabled = $localUser.enabled
        }
    }

    @($items | Sort-Object account)
}

function Get-LocalAccountUsers {
    $items = @()

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        foreach ($user in @(Get-LocalUser -ErrorAction SilentlyContinue)) {
            if (-not $user.SID) { continue }
            $sid = [string]$user.SID
            if ($sid -notmatch "^S-1-5-21-") { continue }
            $items += [pscustomobject][ordered]@{
                sid = $sid
                account = "$env:COMPUTERNAME\$($user.Name)"
                username = [string]$user.Name
                enabled = [bool]$user.Enabled
            }
        }
        return @($items)
    }

    try {
        $computer = [ADSI]"WinNT://$env:COMPUTERNAME"
        foreach ($child in @($computer.Children | Where-Object { $_.SchemaClassName -eq "User" })) {
            $name = [string]$child.Name
            $sid = ""
            try {
                $sidBytes = [byte[]]$child.Properties["objectSid"].Value
                $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            } catch { }
            if (-not $sid -or $sid -notmatch "^S-1-5-21-") { continue }
            $disabled = $false
            try { $disabled = [bool]$child.AccountDisabled } catch { }
            $items += [pscustomobject][ordered]@{
                sid = $sid
                account = "$env:COMPUTERNAME\$name"
                username = $name
                enabled = (-not $disabled)
            }
        }
    } catch { }

    @($items)
}

function Get-DefaultUserProfile {
    $defaultHive = Join-Path $env:SystemDrive "Users\Default\NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $defaultHive)) { return $null }

    [pscustomobject][ordered]@{
        sid = "DEFAULT_USER_TEMPLATE"
        account = "Default User Template"
        username = "Default"
        profile_path = (Split-Path $defaultHive -Parent)
        ntuser_dat = $defaultHive
    }
}

function Select-TargetUsers {
    param([object[]]$Users, [string]$ScopeName, [string[]]$Targets)

    if ($ScopeName -eq "AllUsers" -or $ScopeName -eq "AllUsersAndDefault") { return @($Users) }
    if ($ScopeName -ne "SpecificUsers") { return @() }

    $normalizedTargets = @($Targets | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    @($Users | Where-Object {
        $account = ([string]$_.account).ToLowerInvariant()
        $username = ([string]$_.username).ToLowerInvariant()
        $sid = ([string]$_.sid).ToLowerInvariant()
        ($normalizedTargets -contains $account) -or ($normalizedTargets -contains $username) -or ($normalizedTargets -contains $sid)
    })
}

function Get-MachinePrecedenceWarnings {
    param($MachineSnapshot, [string]$ScopeName)

    $items = @()
    if (-not $MachineSnapshot) { return @() }

    $machineForcelist = @($MachineSnapshot.forcelist)
    $machineBlocklist = @($MachineSnapshot.blocklist)
    $machineAllowlist = @($MachineSnapshot.allowlist)
    $hasMachinePolicies = ($machineForcelist.Count -gt 0) -or ($machineBlocklist.Count -gt 0) -or ($machineAllowlist.Count -gt 0) -or $MachineSnapshot.extension_settings_present

    if ($ScopeName -eq "Machine") {
        $items += "MACHINE SCOPE SELECTED: Chrome/Edge machine policies have higher priority than per-user extension policies. Existing user-level forced extensions may be ignored for the same policy keys."
    } elseif ($hasMachinePolicies) {
        $items += "MACHINE POLICY PRECEDENCE: machine-level Chrome/Edge policies are present and can override or hide per-user extension policies used by Scope=$ScopeName."
    }

    if (@($machineBlocklist | Where-Object { $_.value -eq "*" }).Count -gt 0) {
        $items += "MACHINE BLOCKLIST WARNING: ExtensionInstallBlocklist=* is set at machine level. User extensions not allowed or force-installed by effective policy may be blocked."
    }
    if ($machineForcelist.Count -gt 0 -and $ScopeName -ne "Machine") {
        $items += "MACHINE FORCELIST WARNING: machine-level ExtensionInstallForcelist is present. Chrome may prefer it over user-level ExtensionInstallForcelist entries."
    }
    if ($MachineSnapshot.extension_settings_present) {
        $items += "MACHINE EXTENSIONSETTINGS WARNING: machine-level ExtensionSettings is present. It can override user-level extension settings."
    }

    @($items | Where-Object { $_ } | Select-Object -Unique)
}

function Invoke-QuietRegExe {
    param([string[]]$Arguments)

    $id = [guid]::NewGuid().ToString("N")
    $stdoutPath = Join-Path $env:TEMP "winhub_reg_$id.out"
    $stderrPath = Join-Path $env:TEMP "winhub_reg_$id.err"

    try {
        $process = Start-Process -FilePath "reg.exe" -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $stdoutRaw = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue } else { "" }
        $stderrRaw = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue } else { "" }
        $stdout = ConvertTo-SafeText $stdoutRaw
        $stderr = ConvertTo-SafeText $stderrRaw

        [pscustomobject][ordered]@{
            exit_code = $process.ExitCode
            stdout = $stdout
            stderr = $stderr
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-UserPolicyAction {
    param(
        [object]$User,
        [string]$BrowserPolicyRoot,
        [string]$ActionName,
        [object[]]$ExtensionRequests,
        [bool]$ShouldBlockOthers,
        [bool]$ShouldPinExtension
    )

    $loadedByScript = $false
    $hiveName = $User.sid
    $result = $null

    try {
        if (-not (Test-Path -LiteralPath "Registry::HKEY_USERS\$hiveName")) {
            if (-not (Test-Path -LiteralPath $User.ntuser_dat)) {
                $profileHint = if ($User.profile_source -eq "LocalUsers") {
                    "Local account exists, but its profile hive was not found at $($User.ntuser_dat). User-level Chrome policy can be written only after this user logs on at least once; Default User Template covers future newly-created profiles."
                } else {
                    "User profile hive is not loaded and NTUSER.DAT was not found at $($User.ntuser_dat)."
                }
                return [pscustomobject][ordered]@{
                    label = if ($User.sid -eq "DEFAULT_USER_TEMPLATE") { "Default User Template" } else { "User $($User.account)" }
                    account = $User.account
                    sid = $User.sid
                    profile_path = $User.profile_path
                    profile_source = $User.profile_source
                    local_user_enabled = $User.local_user_enabled
                    changed = $false
                    warnings = @($profileHint)
                    conflicts = @()
                    operations = @()
                    after = $null
                }
            }
            $hiveName = "WinHUBChromeExt_$($User.sid.Replace('-', '_'))"
            $reg = Invoke-QuietRegExe -Arguments @("load", "HKU\$hiveName", $User.ntuser_dat)
            if ($reg.exit_code -ne 0) {
                $regMessage = @($reg.stderr, $reg.stdout) | Where-Object { $_ } | Select-Object -Unique
                return [pscustomobject][ordered]@{
                    label = if ($User.sid -eq "DEFAULT_USER_TEMPLATE") { "Default User Template" } else { "User $($User.account)" }
                    account = $User.account
                    sid = $User.sid
                    profile_path = $User.profile_path
                    profile_source = $User.profile_source
                    local_user_enabled = $User.local_user_enabled
                    changed = $false
                    warnings = @("Unable to load user hive. reg.exe exit code $($reg.exit_code). $($regMessage -join ' ')".Trim())
                    conflicts = @()
                    operations = @()
                    after = $null
                }
            }
            $loadedByScript = $true
        }

        $basePath = "Registry::HKEY_USERS\$hiveName\$BrowserPolicyRoot"
        $label = if ($User.sid -eq "DEFAULT_USER_TEMPLATE") { "Default User Template" } else { "User $($User.account)" }
        $result = Invoke-PolicyAction -BasePath $basePath -Label $label -ActionName $ActionName -ExtensionRequests $ExtensionRequests -ShouldBlockOthers $ShouldBlockOthers -ShouldPinExtension $ShouldPinExtension
        $result | Add-Member -NotePropertyName account -NotePropertyValue $User.account -Force
        $result | Add-Member -NotePropertyName sid -NotePropertyValue $User.sid -Force
        $result | Add-Member -NotePropertyName profile_path -NotePropertyValue $User.profile_path -Force
        $result | Add-Member -NotePropertyName profile_source -NotePropertyValue $User.profile_source -Force
        $result | Add-Member -NotePropertyName local_user_enabled -NotePropertyValue $User.local_user_enabled -Force
        return $result
    }
    finally {
        if ($loadedByScript) {
            $unloaded = $false
            $lastUnload = $null
            for ($attempt = 1; $attempt -le 5; $attempt++) {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()
                Start-Sleep -Milliseconds (200 * $attempt)

                $lastUnload = Invoke-QuietRegExe -Arguments @("unload", "HKU\$hiveName")
                if ($lastUnload.exit_code -eq 0) {
                    $unloaded = $true
                    break
                }
            }

            if (-not $unloaded -and $result) {
                $unloadMessage = @($lastUnload.stderr, $lastUnload.stdout) | Where-Object { $_ } | Select-Object -Unique
                $result.warnings = @($result.warnings + "Temporary user hive HKU\$hiveName was updated, but reg unload failed after retries. Reboot or logoff usually releases it. $($unloadMessage -join ' ')".Trim() | Where-Object { $_ } | Select-Object -Unique)
            }
        }
    }
}

try {
    $validActions = @("Audit", "Install", "Remove", "Block", "Unblock")
    if ($validActions -notcontains $Action) { $Action = "Audit" }
    if (@("Chrome", "Edge") -notcontains $Browser) { $Browser = "Chrome" }
    if (@("Machine", "AllUsers", "SpecificUsers", "DefaultUser", "AllUsersAndDefault") -notcontains $Scope) { $Scope = "Machine" }
    if (-not $UpdateUrl -or $UpdateUrl -like "{{*") { $UpdateUrl = "https://clients2.google.com/service/update2/crx" }

    $extensionRequests = @(Split-MultilineList $ExtensionInput | ForEach-Object { Normalize-ExtensionRequest -Item $_ -DefaultUpdateUrl $UpdateUrl } | Where-Object { $_ })
    $targetUsers = @(Split-MultilineList $TargetUsersInput)
    $invalidExtensions = @($extensionRequests | Where-Object { -not $_.valid } | ForEach-Object { $_.raw })
    $validExtensionRequests = @($extensionRequests | Where-Object { $_.valid })
    $extensionIds = @($validExtensionRequests | ForEach-Object { $_.extension_id })
    $shouldBlockOthers = ConvertTo-BoolValue $BlockOthers
    $shouldPinExtension = ConvertTo-BoolValue $PinExtension

    $browserPolicyRoot = if ($Browser -eq "Edge") { "Software\Policies\Microsoft\Edge" } else { "Software\Policies\Google\Chrome" }
    $machineBasePath = "Registry::HKEY_LOCAL_MACHINE\$browserPolicyRoot"
    $warnings = @()
    $conflicts = @()
    $operations = @()
    $policyResults = @()

    if ($invalidExtensions.Count -gt 0) {
        $warnings += "Invalid extension IDs were ignored: $($invalidExtensions -join ', '). Chrome/Edge extension IDs must be 32 lowercase characters a-p."
    }
    if ($validExtensionRequests.Count -eq 0 -and @("Install", "Remove", "Block", "Unblock") -contains $Action) {
        $warnings += "$Action requested without valid extension IDs. Only wildcard unblock/block can work when BlockOthers=true."
    }

    $machineAction = "Audit"
    if ($Scope -eq "Machine") {
        $machineAction = $Action
    }
    $machineResult = Invoke-PolicyAction -BasePath $machineBasePath -Label "Machine $Browser policy" -ActionName $machineAction -ExtensionRequests $validExtensionRequests -ShouldBlockOthers $shouldBlockOthers -ShouldPinExtension $shouldPinExtension
    $precedenceWarnings = @(Get-MachinePrecedenceWarnings -MachineSnapshot $machineResult.after -ScopeName $Scope)
    if ($precedenceWarnings.Count -gt 0) {
        $machineResult.warnings = @($machineResult.warnings + $precedenceWarnings | Where-Object { $_ } | Select-Object -Unique)
    }
    $policyResults += $machineResult

    if (@("AllUsers", "AllUsersAndDefault", "SpecificUsers") -contains $Scope) {
        $users = @(Get-ProfileUsers)
        $selectedUsers = @(Select-TargetUsers -Users $users -ScopeName $Scope -Targets $targetUsers)
        if ($Scope -eq "SpecificUsers" -and $selectedUsers.Count -eq 0) {
            $warnings += "SpecificUsers scope was selected, but no matching local profiles were found for: $($targetUsers -join ', ')."
        }
        foreach ($user in $selectedUsers) {
            $policyResults += Invoke-UserPolicyAction -User $user -BrowserPolicyRoot $browserPolicyRoot -ActionName $Action -ExtensionRequests $validExtensionRequests -ShouldBlockOthers $shouldBlockOthers -ShouldPinExtension $shouldPinExtension
        }
    }

    if (@("DefaultUser", "AllUsersAndDefault") -contains $Scope) {
        $defaultUser = Get-DefaultUserProfile
        if ($null -eq $defaultUser) {
            $warnings += "Default User Template was requested, but C:\Users\Default\NTUSER.DAT was not found."
        } else {
            $policyResults += Invoke-UserPolicyAction -User $defaultUser -BrowserPolicyRoot $browserPolicyRoot -ActionName $Action -ExtensionRequests $validExtensionRequests -ShouldBlockOthers $shouldBlockOthers -ShouldPinExtension $shouldPinExtension
        }
    }

    if ($Scope -ne "SpecificUsers" -and $targetUsers.Count -gt 0) {
        $warnings += "TargetUsers was provided but Scope=$Scope ignores per-user targets."
    }

    foreach ($item in $policyResults) {
        $warnings += @($item.warnings)
        $conflicts += @($item.conflicts)
        $operations += @($item.operations)
    }

    $changed = (@($policyResults | Where-Object { $_.changed }).Count -gt 0)
    $status = if ($conflicts.Count -gt 0) { "Conflicts detected" } elseif ($warnings.Count -gt 0) { "Completed with warnings" } elseif ($changed) { "Changed" } else { "No changes" }

    $result = [pscustomobject][ordered]@{
        schema = "winhub.chrome_extension_policy.v1"
        computer_name = $env:COMPUTERNAME
        checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        browser = $Browser
        action = $Action
        scope = $Scope
        status = $status
        changed = $changed
        requested_extensions = @($extensionIds)
        invalid_extensions = @($invalidExtensions)
        block_others = $shouldBlockOthers
        pin_extension = $shouldPinExtension
        update_url = $UpdateUrl
        warnings = @($warnings | Where-Object { $_ } | Select-Object -Unique)
        conflicts = @($conflicts | Where-Object { $_ } | Select-Object -Unique)
        operations = @($operations | Where-Object { $_ })
        policies = @($policyResults)
    }

    ConvertTo-PlainObject $result | ConvertTo-Json -Depth 16 -Compress
}
catch {
    $errorDetails = @("Script failed before completion: $($_.Exception.Message)")
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        $errorDetails += $_.InvocationInfo.PositionMessage
    }
    $errorResult = [pscustomobject][ordered]@{
        schema = "winhub.chrome_extension_policy.v1"
        computer_name = $env:COMPUTERNAME
        checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        browser = $Browser
        action = $Action
        scope = $Scope
        status = "Script error"
        changed = $false
        requested_extensions = @()
        warnings = @()
        conflicts = @($errorDetails)
        operations = @()
        policies = @()
    }
    ConvertTo-PlainObject $errorResult | ConvertTo-Json -Depth 10 -Compress
    exit 1
}
