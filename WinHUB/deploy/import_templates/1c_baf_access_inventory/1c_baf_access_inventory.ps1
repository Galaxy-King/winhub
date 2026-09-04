$ErrorActionPreference = 'Stop'

try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$Warnings = New-Object System.Collections.Generic.List[string]

function ConvertTo-WinHubIpSortKey {
    param([string]$Address)

    $parsed = $null
    if ($Address -and [System.Net.IPAddress]::TryParse($Address, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $octets = $parsed.GetAddressBytes()
        return ('{0:D3}.{1:D3}.{2:D3}.{3:D3}' -f $octets[0], $octets[1], $octets[2], $octets[3])
    }

    return '999.999.999.999'
}

function Get-WinHubPrivateIPv4 {
    $items = New-Object System.Collections.Generic.List[string]

    try {
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            foreach ($address in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)) {
                $value = [string]$address.IPAddress
                if ($value -like '192.168.*' -and -not $items.Contains($value)) {
                    $items.Add($value)
                }
            }
        }
    } catch {
        $Warnings.Add("Get-NetIPAddress failed: $($_.Exception.Message)")
    }

    if ($items.Count -eq 0) {
        try {
            foreach ($adapter in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)) {
                foreach ($value in @($adapter.IPAddress)) {
                    $text = [string]$value
                    if ($text -like '192.168.*' -and -not $items.Contains($text)) {
                        $items.Add($text)
                    }
                }
            }
        } catch {
            $Warnings.Add("Fallback IPv4 lookup failed: $($_.Exception.Message)")
        }
    }

    return @($items | Sort-Object { ConvertTo-WinHubIpSortKey $_ })
}

function Test-WinHubProductName {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return $Text -match '(?i)(1\s*[c\u0441]\s*[:\-]?\s*(enterprise|\u043f\u0456\u0434\u043f\u0440\u0438\u0454\u043c\u0441\u0442\u0432\u043e|\u043f\u0440\u0435\u0434\u043f\u0440\u0438\u044f\u0442\u0438\u0435)|business\s+automation\s+framework|(^|[\s._\-])ba[fs]([\s._\-]|$))'
}

function Get-WinHubSoftwareEvidence {
    $evidence = New-Object System.Collections.Generic.List[object]
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($root in $uninstallRoots) {
        try {
            foreach ($entry in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
                $displayName = [string]$entry.DisplayName
                if (-not (Test-WinHubProductName $displayName)) { continue }
                $evidence.Add([pscustomobject][ordered]@{
                    kind = 'Installed program'
                    name = $displayName.Trim()
                    version = ([string]$entry.DisplayVersion).Trim()
                    path = ([string]$entry.InstallLocation).Trim()
                    state = 'Installed'
                })
            }
        } catch {
            $Warnings.Add("Unable to read uninstall registry '$root': $($_.Exception.Message)")
        }
    }

    try {
        foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $serviceText = "$($service.Name) $($service.DisplayName) $($service.PathName)"
            if ($serviceText -notmatch '(?i)(1cv[78]|(?:^|[\\/"\s])(?:ragent|rmngr|ras)(?:\.exe)?(?:["\s]|$)|1\s*[c\u0441]\s*[:\-]?\s*(enterprise|\u043f\u0456\u0434\u043f\u0440\u0438\u0454\u043c\u0441\u0442\u0432\u043e|\u043f\u0440\u0435\u0434\u043f\u0440\u0438\u044f\u0442\u0438\u0435)|business\s+automation\s+framework)') { continue }
            $evidence.Add([pscustomobject][ordered]@{
                kind = 'Windows service'
                name = ([string]$service.DisplayName).Trim()
                version = ''
                path = ([string]$service.PathName).Trim()
                state = ([string]$service.State).Trim()
            })
        }
    } catch {
        $Warnings.Add("Unable to inspect Windows services: $($_.Exception.Message)")
    }

    $programRoots = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        Select-Object -Unique
    $directoryNames = @('1cv8', '1cv8_x86', '1cv7', '1C', 'BAF', 'BAS')
    $executableNames = @('1cv8.exe', '1cv8c.exe', '1cv8s.exe', '1cv7.exe', '1cestart.exe', 'ragent.exe', 'rmngr.exe', 'ras.exe')

    foreach ($programRoot in $programRoots) {
        foreach ($directoryName in $directoryNames) {
            $candidateRoot = Join-Path $programRoot $directoryName
            if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) { continue }
            try {
                foreach ($file in @(Get-ChildItem -LiteralPath $candidateRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $executableNames -contains $_.Name.ToLowerInvariant() })) {
                    $productName = [string]$file.VersionInfo.ProductName
                    if ([string]::IsNullOrWhiteSpace($productName)) { $productName = $file.Name }
                    $version = [string]$file.VersionInfo.ProductVersion
                    if ([string]::IsNullOrWhiteSpace($version)) { $version = [string]$file.VersionInfo.FileVersion }
                    $evidence.Add([pscustomobject][ordered]@{
                        kind = 'Executable'
                        name = $productName.Trim()
                        version = $version.Trim()
                        path = $file.FullName
                        state = 'Present'
                    })
                }
            } catch {
                $Warnings.Add("Unable to inspect '$candidateRoot': $($_.Exception.Message)")
            }
        }
    }

    $unique = @{}
    foreach ($item in $evidence) {
        $key = ("$($item.kind)|$($item.name)|$($item.path)".ToLowerInvariant())
        if (-not $unique.ContainsKey($key)) { $unique[$key] = $item }
    }

    return @($unique.Values | Sort-Object kind, name, path)
}

function Get-WinHubLocalUserStates {
    $bySid = @{}
    $byName = @{}
    $accounts = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($user in @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)) {
            $state = [pscustomobject][ordered]@{
                name = if ($user.Caption) { [string]$user.Caption } else { "$env:COMPUTERNAME\$($user.Name)" }
                sid = [string]$user.SID
                enabled = (-not [bool]$user.Disabled)
                locked_out = [bool]$user.Lockout
                verified = $true
                source = 'Win32_UserAccount'
            }
            $accounts.Add($state)
            if ($user.SID) { $bySid[[string]$user.SID] = $state }
            if ($user.Name) { $byName[([string]$user.Name).ToLowerInvariant()] = $state }
            if ($user.Caption) { $byName[([string]$user.Caption).ToLowerInvariant()] = $state }
        }
    } catch {
        $Warnings.Add("Win32_UserAccount failed: $($_.Exception.Message)")
    }

    if ($bySid.Count -eq 0) {
        try {
            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                foreach ($user in @(Get-LocalUser -ErrorAction Stop)) {
                    $lockedOut = $null
                    try {
                        $entry = [ADSI]("WinNT://./" + $user.Name + ',user')
                        $flags = [int]$entry.UserFlags.Value
                        $lockedOut = (($flags -band 0x10) -ne 0)
                    } catch { }
                    $state = [pscustomobject][ordered]@{
                        name = "$env:COMPUTERNAME\$($user.Name)"
                        sid = [string]$user.SID
                        enabled = [bool]$user.Enabled
                        locked_out = $lockedOut
                        verified = ($null -ne $lockedOut)
                        source = 'Get-LocalUser/ADSI'
                    }
                    $accounts.Add($state)
                    if ($user.SID) { $bySid[[string]$user.SID] = $state }
                    if ($user.Name) {
                        $byName[([string]$user.Name).ToLowerInvariant()] = $state
                        $byName[("$env:COMPUTERNAME\$($user.Name)").ToLowerInvariant()] = $state
                    }
                }
            }
        } catch {
            $Warnings.Add("Fallback local-user status lookup failed: $($_.Exception.Message)")
        }
    }

    return [pscustomobject][ordered]@{
        by_sid = $bySid
        by_name = $byName
        accounts = $accounts.ToArray()
    }
}

function ConvertFrom-WinHubAdsiMember {
    param(
        $RawMember,
        [string]$GrantedBy
    )

    $name = [string]$RawMember.GetType().InvokeMember('Name', 'GetProperty', $null, $RawMember, $null)
    $className = [string]$RawMember.GetType().InvokeMember('Class', 'GetProperty', $null, $RawMember, $null)
    $adsPath = [string]$RawMember.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $RawMember, $null)
    $accountName = (($adsPath -replace '^WinNT://', '') -replace '/', '\')
    if ([string]::IsNullOrWhiteSpace($accountName)) { $accountName = $name }
    $sid = ''
    try {
        $sidBytes = [byte[]]$RawMember.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $RawMember, $null)
        if ($sidBytes.Count -gt 0) {
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
        }
    } catch { }

    return [pscustomobject][ordered]@{
        name = $accountName
        sid = $sid
        object_class = $className
        granted_by = $GrantedBy
    }
}

function Get-WinHubGroupMembers {
    param(
        [string]$GroupSid,
        [string]$CanonicalName
    )

    $members = New-Object System.Collections.Generic.List[object]
    $sidObject = New-Object System.Security.Principal.SecurityIdentifier($GroupSid)

    try {
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            foreach ($member in @(Get-LocalGroupMember -SID $sidObject -ErrorAction Stop)) {
                $members.Add([pscustomobject][ordered]@{
                    name = [string]$member.Name
                    sid = [string]$member.SID
                    object_class = [string]$member.ObjectClass
                    granted_by = $CanonicalName
                })
            }
            return $members.ToArray()
        }
    } catch {
        $Warnings.Add("Get-LocalGroupMember failed for $CanonicalName; ADSI fallback will be used: $($_.Exception.Message)")
    }

    try {
        $translated = $sidObject.Translate([System.Security.Principal.NTAccount]).Value
        $localizedName = ($translated -split '\\')[-1]
        $group = [ADSI]("WinNT://./" + $localizedName + ',group')
        foreach ($rawMember in @($group.psbase.Invoke('Members'))) {
            $members.Add((ConvertFrom-WinHubAdsiMember -RawMember $rawMember -GrantedBy $CanonicalName))
        }
    } catch {
        $Warnings.Add("Unable to enumerate ${CanonicalName}: $($_.Exception.Message)")
    }

    return $members.ToArray()
}

function Get-WinHubNestedGroupMembers {
    param(
        [object]$Group,
        [string]$GrantedBy
    )

    $members = New-Object System.Collections.Generic.List[object]
    $accountName = ([string]$Group.name).Trim()
    if ($accountName -notmatch '^([^\\]+)\\(.+)$') {
        throw "Group name '$accountName' cannot be resolved through the WinNT provider."
    }

    $authority = $Matches[1]
    $groupName = $Matches[2]
    $entry = [ADSI]("WinNT://$authority/$groupName,group")
    foreach ($rawMember in @($entry.psbase.Invoke('Members'))) {
        $members.Add((ConvertFrom-WinHubAdsiMember -RawMember $rawMember -GrantedBy $GrantedBy))
    }
    return $members.ToArray()
}

function Get-WinHubUserState {
    param(
        [object]$User,
        [object]$LocalStates
    )

    $sid = [string]$User.sid
    $name = ([string]$User.name).Trim()
    if ($sid -and $LocalStates.by_sid.ContainsKey($sid)) {
        return $LocalStates.by_sid[$sid]
    }
    if ($name -and $LocalStates.by_name.ContainsKey($name.ToLowerInvariant())) {
        return $LocalStates.by_name[$name.ToLowerInvariant()]
    }

    if ($name -match '^([^\\]+)\\(.+)$') {
        $authority = $Matches[1]
        $userName = $Matches[2]
        try {
            $entry = [ADSI]("WinNT://$authority/$userName,user")
            $flags = [int]$entry.UserFlags.Value
            return [pscustomobject][ordered]@{
                enabled = (($flags -band 0x2) -eq 0)
                locked_out = (($flags -band 0x10) -ne 0)
                verified = $true
                source = 'WinNT ADSI'
            }
        } catch {
            $Warnings.Add("Unable to verify Enabled/Locked state for '$name': $($_.Exception.Message)")
        }
    }

    return [pscustomobject][ordered]@{
        enabled = $null
        locked_out = $null
        verified = $false
        source = 'Unavailable'
    }
}

function Expand-WinHubAccessMember {
    param(
        [object]$Member,
        [string]$GrantedBy,
        [object]$LocalStates,
        [hashtable]$VisitedGroups,
        [int]$Depth = 0
    )

    $className = ([string]$Member.object_class).Trim()
    if ($className -match '(?i)group') {
        $groupKey = "$GrantedBy|$(([string]$Member.name).ToLowerInvariant())"
        if ($VisitedGroups.ContainsKey($groupKey)) { return }
        $VisitedGroups[$groupKey] = $true
        if ($Depth -ge 6) {
            $Warnings.Add("Nested group expansion stopped at depth 6 for '$($Member.name)'.")
            return
        }

        try {
            foreach ($nestedMember in @(Get-WinHubNestedGroupMembers -Group $Member -GrantedBy $GrantedBy)) {
                Expand-WinHubAccessMember -Member $nestedMember -GrantedBy $GrantedBy -LocalStates $LocalStates -VisitedGroups $VisitedGroups -Depth ($Depth + 1)
            }
        } catch {
            $Warnings.Add("Unable to expand access group '$($Member.name)'; its users were not included because their status cannot be verified: $($_.Exception.Message)")
        }
        return
    }

    if ($className -and $className -notmatch '(?i)user') { return }
    $state = Get-WinHubUserState -User $Member -LocalStates $LocalStates
    return [pscustomobject][ordered]@{
        name = ([string]$Member.name).Trim()
        sid = [string]$Member.sid
        enabled = $state.enabled
        locked_out = $state.locked_out
        status_verified = [bool]$state.verified
        status_source = [string]$state.source
        granted_by = @($GrantedBy)
    }
}

function Get-WinHubActiveAccessAccounts {
    $localStates = Get-WinHubLocalUserStates
    $rawMembers = @(
        Get-WinHubGroupMembers -GroupSid 'S-1-5-32-544' -CanonicalName 'Administrators'
        Get-WinHubGroupMembers -GroupSid 'S-1-5-32-555' -CanonicalName 'Remote Desktop Users'
    )
    $visitedGroups = @{}
    $merged = @{}

    foreach ($state in @($localStates.accounts)) {
        $name = ([string]$state.name).Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $merged[$name.ToLowerInvariant()] = [pscustomobject][ordered]@{
            name = $name
            sid = [string]$state.sid
            enabled = $state.enabled
            locked_out = $state.locked_out
            status_verified = [bool]$state.verified
            status_source = [string]$state.source
            granted_by = @('Local Windows account')
        }
    }

    foreach ($member in $rawMembers) {
        foreach ($account in @(Expand-WinHubAccessMember -Member $member -GrantedBy $member.granted_by -LocalStates $localStates -VisitedGroups $visitedGroups)) {
            $name = ([string]$account.name).Trim()
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $key = $name.ToLowerInvariant()
            if ($merged.ContainsKey($key)) {
                $merged[$key].granted_by = @($merged[$key].granted_by + $account.granted_by | Select-Object -Unique)
            } else {
                $merged[$key] = $account
            }
        }
    }

    $allAccounts = @($merged.Values)
    $activeAccounts = @($allAccounts | Where-Object { $_.status_verified -and $_.enabled -and -not $_.locked_out } | Sort-Object name)
    return [pscustomobject][ordered]@{
        accounts = @($activeAccounts)
        summary = [pscustomobject][ordered]@{
            discovered_users = $allAccounts.Count
            active_enabled_unlocked = $activeAccounts.Count
            disabled = @($allAccounts | Where-Object { $_.status_verified -and -not $_.enabled }).Count
            locked_out = @($allAccounts | Where-Object { $_.status_verified -and $_.enabled -and $_.locked_out }).Count
            unverified = @($allAccounts | Where-Object { -not $_.status_verified }).Count
        }
    }
}

try {
    $addresses = @(Get-WinHubPrivateIPv4)
    $primaryAddress = if ($addresses.Count -gt 0) { $addresses[0] } else { '' }
    if (-not $primaryAddress) {
        $Warnings.Add('No IPv4 address in the 192.168.0.0/16 range was found.')
    }

    $software = @(Get-WinHubSoftwareEvidence)
    $softwareInstalled = ($software.Count -gt 0)
    $activeAccessAccounts = @()
    $accessSummary = [pscustomobject][ordered]@{
        discovered_users = 0
        active_enabled_unlocked = 0
        disabled = 0
        locked_out = 0
        unverified = 0
    }

    if ($softwareInstalled) {
        $accessResult = Get-WinHubActiveAccessAccounts
        $activeAccessAccounts = @($accessResult.accounts)
        $accessSummary = $accessResult.summary
        if ($activeAccessAccounts.Count -eq 0) {
            $Warnings.Add('No enabled and unlocked user accounts with verified access were found.')
        }
    }

    $result = [pscustomobject][ordered]@{
        schema = 'winhub.1c_baf_access_inventory.v1'
        computer_name = $env:COMPUTERNAME
        checked_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        primary_ip = $primaryAddress
        ipv4_192_168 = @($addresses)
        ip_sort_key = "$(ConvertTo-WinHubIpSortKey $primaryAddress)|$($env:COMPUTERNAME.ToLowerInvariant())"
        software_installed = $softwareInstalled
        software = @($software)
        active_access_accounts = @($activeAccessAccounts)
        access_summary = $accessSummary
        access_definition = 'Only user accounts with verified Enabled=true and LockedOut=false that receive access through local Administrators or Remote Desktop Users. Nested groups are expanded up to six levels when the directory is reachable.'
        warnings = @($Warnings.ToArray())
    }

    Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
} catch {
    $errorResult = [pscustomobject][ordered]@{
        schema = 'winhub.1c_baf_access_inventory.v1'
        computer_name = $env:COMPUTERNAME
        checked_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        error = "Inventory failed: $($_.Exception.Message)"
        error_line = [int]$_.InvocationInfo.ScriptLineNumber
    }
    Write-Output ($errorResult | ConvertTo-Json -Depth 5 -Compress)
    exit 1
}
