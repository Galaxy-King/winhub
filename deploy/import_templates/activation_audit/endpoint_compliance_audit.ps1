$ErrorActionPreference = "Stop"

function Convert-LicenseStatus {
    param($Status)

    $statusCode = $null
    try {
        if ($null -ne $Status) {
            $statusCode = [int]$Status
        }
    }
    catch {
        $statusCode = $null
    }

    switch ($statusCode) {
        0 { "Unlicensed" }
        1 { "Licensed" }
        2 { "Out-of-box grace" }
        3 { "Out-of-tolerance grace" }
        4 { "Non-genuine grace" }
        5 { "Notification" }
        6 { "Extended grace" }
        default { "Unknown" }
    }
}

function Invoke-QueryWithTimeout {
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 12
    )

    $job = $null
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $completed) {
            try { Stop-Job -Job $job -ErrorAction SilentlyContinue } catch { }
            throw "Query timeout after $TimeoutSeconds seconds"
        }
        Receive-Job -Job $job -ErrorAction Stop
    }
    finally {
        if ($job) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-ProcessOutputWithTimeout {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 10
    )

    $stdoutPath = Join-Path $env:TEMP ("winhub_proc_stdout_" + [guid]::NewGuid().ToString("N") + ".txt")
    $stderrPath = Join-Path $env:TEMP ("winhub_proc_stderr_" + [guid]::NewGuid().ToString("N") + ".txt")
    $process = $null

    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            throw "Process timeout after $TimeoutSeconds seconds"
        }

        $stdout = ""
        $stderr = ""
        if (Test-Path -LiteralPath $stdoutPath) {
            $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stderrPath) {
            $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        }

        if ($process.ExitCode -ne 0 -and -not $stdout) {
            throw "Process exited with code $($process.ExitCode): $stderr"
        }

        return [string]$stdout
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-WindowsActivationFallback {
    param([string]$Reason)

    try {
        $slmgrPath = Join-Path $env:WINDIR "System32\slmgr.vbs"
        $output = Invoke-ProcessOutputWithTimeout -FilePath "cscript.exe" -Arguments @("//Nologo", $slmgrPath, "/xpr") -TimeoutSeconds 10
        $activated = $false
        $statusText = "Unknown"
        $recognized = $false

        if ($output -match "permanently activated") {
            $activated = $true
            $statusText = "Licensed (permanently activated)"
            $recognized = $true
        }
        elseif ($output -match "will expire\s+(.+)$") {
            $activated = $true
            $statusText = "Licensed (KMS activation expires $($Matches[1].Trim()))"
            $recognized = $true
        }
        elseif ($output -match "notification|unlicensed|not activated") {
            $activated = $false
            $statusText = "Not activated"
            $recognized = $true
        }

        if (-not $recognized) {
            return [pscustomobject][ordered]@{
                detected = $false
                activated = $false
                check_failed = $true
                product_name = "Windows"
                os_caption = $null
                os_version = $null
                license_status = $null
                license_status_text = "Check failed"
                partial_product_key = $null
                description = "Fallback check via slmgr.vbs /xpr"
                fallback_output = (($output -replace "`r", "") -replace "`n+", " ").Trim()
                error = "$Reason; fallback output was not recognized"
            }
        }

        return [pscustomobject][ordered]@{
            detected = $true
            activated = $activated
            check_failed = $false
            product_name = "Windows"
            os_caption = $null
            os_version = $null
            license_status = $null
            license_status_text = $statusText
            partial_product_key = $null
            description = "Fallback check via slmgr.vbs /xpr"
            fallback_output = (($output -replace "`r", "") -replace "`n+", " ").Trim()
            error = $Reason
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            detected = $false
            activated = $false
            check_failed = $true
            product_name = "Windows"
            os_caption = $null
            os_version = $null
            license_status = $null
            license_status_text = "Check failed"
            partial_product_key = $null
            description = $null
            fallback_output = $null
            error = "$Reason; fallback failed: $($_.Exception.Message)"
        }
    }
}

function Get-WindowsActivation {
    try {
        $os = Invoke-QueryWithTimeout -TimeoutSeconds 8 -ScriptBlock {
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        }
        $products = Invoke-QueryWithTimeout -TimeoutSeconds 12 -ScriptBlock {
            Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop
        } |
            Where-Object {
                $_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" -and
                $_.PartialProductKey
            } |
            Sort-Object @{ Expression = { if ($_.LicenseStatus -eq 1) { 0 } else { 1 } } }, Name

        $product = @($products | Select-Object -First 1)[0]

        if (-not $product) {
            return [pscustomobject][ordered]@{
                detected = $false
                activated = $false
                check_failed = $false
                product_name = $os.Caption
                os_caption = $os.Caption
                os_version = $os.Version
                license_status = $null
                license_status_text = "No licensed Windows product entry found"
                partial_product_key = $null
                description = $null
                fallback_output = $null
                error = $null
            }
        }

        return [pscustomobject][ordered]@{
            detected = $true
            activated = ([int]$product.LicenseStatus -eq 1)
            check_failed = $false
            product_name = $product.Name
            os_caption = $os.Caption
            os_version = $os.Version
            license_status = [int]$product.LicenseStatus
            license_status_text = Convert-LicenseStatus $product.LicenseStatus
            partial_product_key = $product.PartialProductKey
            description = $product.Description
            fallback_output = $null
            error = $null
        }
    }
    catch {
        return Get-WindowsActivationFallback -Reason $_.Exception.Message
    }
}

function Find-OsppVbs {
    $roots = @(
        ${env:ProgramFiles},
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    $candidates = @()
    foreach ($root in $roots) {
        foreach ($version in 14..19) {
            $knownPaths = @(
                (Join-Path $root "Microsoft Office\Office$version\ospp.vbs"),
                (Join-Path $root "Microsoft Office\root\Office$version\ospp.vbs")
            )
            foreach ($path in $knownPaths) {
                if (Test-Path -LiteralPath $path) {
                    $candidates += (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue)
                }
            }
        }
    }

    @($candidates | Sort-Object FullName -Unique)
}

function Parse-OsppStatus {
    param([string[]]$Lines, [string]$Source)

    $items = @()
    $current = [ordered]@{}

    foreach ($line in $Lines) {
        $text = ($line -replace "`0", "").Trim()
        if (-not $text) { continue }

        if ($text -match "^---") {
            if ($current.Count -gt 0) {
                $items += [pscustomobject]$current
                $current = [ordered]@{}
            }
            continue
        }

        if ($text -match "^LICENSE NAME:\s*(.+)$") {
            if ($current.Count -gt 0 -and $current.license_name) {
                $items += [pscustomobject]$current
                $current = [ordered]@{}
            }
            $current.source = $Source
            $current.license_name = $Matches[1].Trim()
            continue
        }

        if ($text -match "^LICENSE DESCRIPTION:\s*(.+)$") {
            $current.license_description = $Matches[1].Trim()
            continue
        }

        if ($text -match "^LICENSE STATUS:\s*(.+)$") {
            $statusText = ($Matches[1].Trim() -replace "^---", "" -replace "---$", "").Trim()
            $current.license_status_text = $statusText
            $current.activated = ($statusText -eq "LICENSED")
            continue
        }

        if ($text -match "^Last 5 characters of installed product key:\s*(.+)$") {
            $current.partial_product_key = $Matches[1].Trim()
            continue
        }

        if ($text -match "^ERROR CODE:\s*(.+)$") {
            $current.error_code = $Matches[1].Trim()
            continue
        }
    }

    if ($current.Count -gt 0) {
        $items += [pscustomobject]$current
    }

    @($items)
}

function Get-OfficeFromSoftwareLicensing {
    try {
        $officeProducts = Invoke-QueryWithTimeout -TimeoutSeconds 12 -ScriptBlock {
            Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop
        } |
            Where-Object {
                $_.Name -match "Office|Microsoft 365|O365" -and
                ($_.PartialProductKey -or $_.LicenseStatus -eq 1)
            } |
            Sort-Object Name

        @($officeProducts | ForEach-Object {
            [pscustomobject][ordered]@{
                source = "SoftwareLicensingProduct"
                license_name = $_.Name
                license_description = $_.Description
                license_status = [int]$_.LicenseStatus
                license_status_text = Convert-LicenseStatus $_.LicenseStatus
                activated = ([int]$_.LicenseStatus -eq 1)
                partial_product_key = $_.PartialProductKey
                error_code = $null
            }
        })
    }
    catch {
        @()
    }
}

function Get-OfficeActivation {
    $products = @()
    $errors = @()

    foreach ($ospp in Find-OsppVbs) {
        try {
            $output = & cscript.exe //NoLogo $ospp.FullName /dstatus 2>&1
            foreach ($item in Parse-OsppStatus -Lines $output -Source $ospp.FullName) {
                $products += $item
            }
        }
        catch {
            $errors += "ospp.vbs failed at $($ospp.FullName): $($_.Exception.Message)"
        }
    }

    foreach ($item in Get-OfficeFromSoftwareLicensing) {
        $duplicate = $false
        foreach ($existing in $products) {
            if (($existing.license_name -eq $item.license_name) -and ($existing.partial_product_key -eq $item.partial_product_key)) {
                $duplicate = $true
                break
            }
        }
        if (-not $duplicate) {
            $products += [pscustomobject]$item
        }
    }

    $detected = ($products.Count -gt 0)
    $activated = (@($products | Where-Object { $_.activated }).Count -gt 0)

    [pscustomobject][ordered]@{
        detected = $detected
        activated = $activated
        products = @($products)
        errors = @($errors)
    }
}

function Get-RegionCodeFromCulture {
    param([string]$CultureName)

    try {
        if (-not $CultureName -or $CultureName -notmatch "-") {
            return $null
        }
        $region = New-Object System.Globalization.RegionInfo($CultureName)
        return $region.TwoLetterISORegionName
    }
    catch {
        return $null
    }
}

function Convert-UtcOffsetToMinutes {
    param([string]$Offset)

    if (-not $Offset) {
        return $null
    }

    $text = ([string]$Offset).Trim()
    if ($text -match "^([+-])(\d{2}):?(\d{2})$") {
        $sign = 1
        if ($Matches[1] -eq "-") {
            $sign = -1
        }
        return $sign * (([int]$Matches[2] * 60) + [int]$Matches[3])
    }

    return $null
}

function Get-SystemUtcOffsetMinutes {
    try {
        return [int]([System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalMinutes)
    }
    catch {
        return $null
    }
}

function ConvertTo-PlainObject {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $plain = @{}
        foreach ($key in $Value.Keys) {
            $plain[[string]$key] = ConvertTo-PlainObject $Value[$key]
        }
        return $plain
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = New-Object System.Collections.ArrayList
        foreach ($item in $Value) {
            [void]$items.Add((ConvertTo-PlainObject $item))
        }
        return $items
    }

    $properties = $Value.PSObject.Properties | Where-Object {
        $_.MemberType -in @("NoteProperty", "Property") -and
        $_.Name -notmatch "^PS"
    }

    if ($properties.Count -gt 0) {
        $plain = @{}
        foreach ($property in $properties) {
            $plain[$property.Name] = ConvertTo-PlainObject $property.Value
        }
        return $plain
    }

    return [string]$Value
}

function Invoke-JsonEndpoint {
    param(
        [string]$Uri,
        [string]$Source
    )

    try {
        $response = Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        return [pscustomobject][ordered]@{
            ok = $true
            source = $Source
            data = $response
            error = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            ok = $false
            source = $Source
            data = $null
            error = $_.Exception.Message
        }
    }
}

function Get-InternetLocation {
    $attempts = @(
        @{ Uri = "https://ipapi.co/json/"; Source = "ipapi.co" },
        @{ Uri = "https://ipinfo.io/json"; Source = "ipinfo.io" }
    )

    $errors = @()

    foreach ($attempt in $attempts) {
        $result = Invoke-JsonEndpoint -Uri $attempt.Uri -Source $attempt.Source
        if (-not $result.ok) {
            $errors += "$($result.source): $($result.error)"
            continue
        }

        $data = $result.data
        if ($attempt.Source -eq "ipapi.co") {
            return [pscustomobject][ordered]@{
                detected = $true
                source = $result.source
                ip = $data.ip
                country_code = $data.country_code
                country_name = $data.country_name
                region = $data.region
                city = $data.city
                postal = $data.postal
                latitude = $data.latitude
                longitude = $data.longitude
                timezone = $data.timezone
                utc_offset = $data.utc_offset
                utc_offset_minutes = Convert-UtcOffsetToMinutes $data.utc_offset
                org = $data.org
                asn = $data.asn
                errors = @($errors)
            }
        }

        $latitude = $null
        $longitude = $null
        if ($data.loc -match "^([^,]+),([^,]+)$") {
            $latitude = $Matches[1]
            $longitude = $Matches[2]
        }

        return [pscustomobject][ordered]@{
            detected = $true
            source = $result.source
            ip = $data.ip
            country_code = $data.country
            country_name = $data.country
            region = $data.region
            city = $data.city
            postal = $data.postal
            latitude = $latitude
            longitude = $longitude
            timezone = $data.timezone
            utc_offset = $null
            utc_offset_minutes = $null
            org = $data.org
            asn = $null
            errors = @($errors)
        }
    }

    [pscustomobject][ordered]@{
        detected = $false
        source = $null
        ip = $null
        country_code = $null
        country_name = $null
        region = $null
        city = $null
        postal = $null
        latitude = $null
        longitude = $null
        timezone = $null
        utc_offset = $null
        utc_offset_minutes = $null
        org = $null
        asn = $null
        errors = @($errors)
    }
}

function Get-RegionalSettings {
    $timeZone = Get-TimeZone
    $culture = Get-Culture
    $systemLocale = $null
    $homeLocation = $null
    $uiCulture = Get-UICulture
    $userLanguages = @()

    try { $systemLocale = Get-WinSystemLocale } catch { }
    try { $homeLocation = Get-WinHomeLocation } catch { }
    try { $userLanguages = @((Get-WinUserLanguageList | ForEach-Object { $_.LanguageTag })) } catch { }

    $systemLocaleName = $null
    $systemLocaleDisplayName = $null
    $systemLocaleCountryCode = $null
    if ($systemLocale) {
        $systemLocaleName = $systemLocale.Name
        $systemLocaleDisplayName = $systemLocale.DisplayName
        $systemLocaleCountryCode = Get-RegionCodeFromCulture $systemLocale.Name
    }

    $homeLocationGeoId = $null
    $homeLocationName = $null
    if ($homeLocation) {
        $homeLocationGeoId = $homeLocation.GeoId
        $homeLocationName = $homeLocation.HomeLocation
    }

    $userLanguageCountryCodes = @($userLanguages | ForEach-Object { Get-RegionCodeFromCulture $_ } | Where-Object { $_ } | Select-Object -Unique)

    [pscustomobject][ordered]@{
        timezone_id = $timeZone.Id
        timezone_display_name = $timeZone.DisplayName
        culture_name = $culture.Name
        culture_display_name = $culture.DisplayName
        culture_country_code = Get-RegionCodeFromCulture $culture.Name
        system_locale_name = $systemLocaleName
        system_locale_display_name = $systemLocaleDisplayName
        system_locale_country_code = $systemLocaleCountryCode
        home_location_geo_id = $homeLocationGeoId
        home_location_name = $homeLocationName
        ui_language = $uiCulture.Name
        ui_language_country_code = Get-RegionCodeFromCulture $uiCulture.Name
        user_languages = @($userLanguages)
        user_language_country_codes = @($userLanguageCountryCodes)
        utc_offset_minutes = Get-SystemUtcOffsetMinutes
    }
}

function Get-NetworkLocationSignals {
    $adapterPattern = "vpn|wireguard|openvpn|tap|tun|tailscale|zerotier|nord|proton|surfshark|expressvpn|anyconnect|fortinet|globalprotect"
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject][ordered]@{
            name = $_.Name
            interface_description = $_.InterfaceDescription
            status = $_.Status
            mac_address = $_.MacAddress
            link_speed = $_.LinkSpeed
            looks_like_vpn = (("$($_.Name) $($_.InterfaceDescription)" -match $adapterPattern))
        }
    })
    $vpnLikeAdapters = @($adapters | Where-Object { $_.looks_like_vpn })

    $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject][ordered]@{
            interface_alias = $_.InterfaceAlias
            server_addresses = @($_.ServerAddresses)
        }
    })

    $winHttpProxy = ""
    try {
        $winHttpProxy = ((netsh winhttp show proxy) -join "`n").Trim()
    }
    catch {
        $winHttpProxy = "Unable to read WinHTTP proxy: $($_.Exception.Message)"
    }

    [pscustomobject][ordered]@{
        adapter_count = @($adapters).Count
        vpn_like_adapter_count = @($vpnLikeAdapters).Count
        vpn_like_adapters = @($vpnLikeAdapters | ForEach-Object {
            [pscustomobject][ordered]@{
                name = $_.name
                interface_description = $_.interface_description
                status = $_.status
            }
        })
        dns_servers = @($dnsServers)
        winhttp_proxy = $winHttpProxy
    }
}

function Test-LocationConsistency {
    param(
        $Internet,
        $Regional,
        $Network
    )

    $findings = @()
    $publicCountry = ([string]$Internet.country_code).ToUpperInvariant()
    $systemCountrySignals = @(
        $Regional.culture_country_code,
        $Regional.system_locale_country_code,
        $Regional.ui_language_country_code
    ) + @($Regional.user_language_country_codes)
    $systemCountrySignals = @($systemCountrySignals | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpperInvariant() } | Select-Object -Unique)

    if (-not $Internet.detected) {
        $findings += "Public internet location could not be detected"
    }

    if ($Internet.detected -and $publicCountry -and $systemCountrySignals.Count -gt 0 -and ($systemCountrySignals -notcontains $publicCountry)) {
        $findings += "Windows regional country signals do not match public IP country: public $publicCountry, Windows signals $($systemCountrySignals -join ', ')"
    }

    if ($Internet.detected -and $null -ne $Internet.utc_offset_minutes -and $null -ne $Regional.utc_offset_minutes -and ([int]$Internet.utc_offset_minutes -ne [int]$Regional.utc_offset_minutes)) {
        $findings += "Public IP UTC offset differs from Windows UTC offset: public $($Internet.utc_offset), Windows $($Regional.utc_offset_minutes) minutes"
    }

    if ($Network.vpn_like_adapters.Count -gt 0) {
        $findings += "VPN-like network adapters are present: $(@($Network.vpn_like_adapters | ForEach-Object { $_.name }) -join ', ')"
    }

    [pscustomobject][ordered]@{
        public_country_code = $publicCountry
        windows_country_signals = @($systemCountrySignals)
        public_timezone = $Internet.timezone
        public_utc_offset = $Internet.utc_offset
        public_utc_offset_minutes = $Internet.utc_offset_minutes
        windows_timezone_id = $Regional.timezone_id
        windows_utc_offset_minutes = $Regional.utc_offset_minutes
        consistent = ($findings.Count -eq 0)
        findings = @($findings)
    }
}

$windows = Get-WindowsActivation
$office = Get-OfficeActivation
$internetLocation = Get-InternetLocation
$regionalSettings = Get-RegionalSettings
$networkSignals = Get-NetworkLocationSignals
$locationConsistency = Test-LocationConsistency -Internet $internetLocation -Regional $regionalSettings -Network $networkSignals
$needsAttention = @()
$checkErrors = @()

if ($windows.check_failed) {
    $checkErrors += "Windows activation check failed: $($windows.error)"
}
elseif (-not $windows.activated) {
    $needsAttention += "Windows is not activated"
}

if ($office.detected -and -not $office.activated) {
    $needsAttention += "Office is detected but not activated"
}
elseif (-not $office.detected) {
    $needsAttention += "Office was not detected"
}

foreach ($finding in $locationConsistency.findings) {
    $needsAttention += $finding
}

$overallStatus = "Compliant"
if ($needsAttention.Count -gt 0) {
    $overallStatus = "Needs attention"
}

$result = [pscustomobject][ordered]@{
    schema = "winhub.endpoint_compliance_audit.v1"
    computer_name = $env:COMPUTERNAME
    checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    overall_status = $overallStatus
    windows_activated = [bool]$windows.activated
    office_detected = [bool]$office.detected
    office_activated = [bool]$office.activated
    public_location_detected = [bool]$internetLocation.detected
    location_consistent = [bool]$locationConsistency.consistent
    windows_check_failed = [bool]$windows.check_failed
    check_errors = @($checkErrors)
    needs_attention = @($needsAttention)
    windows = $windows
    office = $office
    public_internet_location = $internetLocation
    regional_settings = $regionalSettings
    network_location_signals = $networkSignals
    location_consistency = $locationConsistency
}

ConvertTo-PlainObject $result | ConvertTo-Json -Depth 8 -Compress
