$ErrorActionPreference = 'Stop'
try {
    # Query only the local SAM, never enumerate the domain directory.
    $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    $active = @()
    foreach ($user in $users) {
        # Unknown flags must fail the audit rather than silently undercount users.
        if ($null -eq $user.Disabled -or $null -eq $user.Lockout) {
            throw 'Account state is unavailable.'
        }
        if (-not $user.Disabled -and -not $user.Lockout) {
            $login = ([string]$user.Name).Trim()
            if (-not $login) { throw 'Account login is unavailable.' }
            $active += $login.ToLowerInvariant()
        }
    }
    $active = @($active | Sort-Object -Unique)
    [ordered]@{
        audit = 'winhub-local-active-accounts-v1'
        active_logins = $active
        active_count = $active.Count
        collected_at_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Depth 4 -Compress
} catch {
    [ordered]@{ audit = 'winhub-local-active-accounts-v1'; error = $_.Exception.Message } |
        ConvertTo-Json -Depth 4 -Compress
    exit 1
}
