param([Parameter(Mandatory=$true)][string]$InputPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $tokens = $null
    $parseErrors = $null
    # Parse as data. Never dot-source, invoke, or import the submitted script.
    $null = [System.Management.Automation.Language.Parser]::ParseFile($InputPath, [ref]$tokens, [ref]$parseErrors)
    $diagnostics = @()
    foreach ($item in @($parseErrors | Select-Object -First 20)) {
        $diagnostics += @{ severity='error'; message="Line $($item.Extent.StartLineNumber): $($item.Message)" }
    }
    if (@($parseErrors).Count -eq 0) {
        if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
            try {
                Import-Module PSScriptAnalyzer -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                # Only reviewed built-in rules; no per-script settings or custom rules.
                $rules = @('PSAvoidUsingInvokeExpression','PSAvoidUsingPlainTextForPassword','PSAvoidUsingConvertToSecureStringWithPlainText','PSUseDeclaredVarsMoreThanAssignments')
                $analysis = @(Invoke-ScriptAnalyzer -Path $InputPath -IncludeRule $rules -ErrorAction Stop -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Select-Object -First 20)
                foreach ($item in $analysis) {
                    $diagnostics += @{ severity='warning'; message="$($item.RuleName) line $($item.Line): $($item.Message)" }
                }
            } catch {
                # PSScriptAnalyzer is optional. Its own module/runtime failure must not
                # corrupt the JSON protocol or invalidate a successful parser result.
                $diagnostics += @{ severity='warning'; message='PSScriptAnalyzer could not complete; only PowerShell syntax was checked' }
            }
        } else {
            $diagnostics += @{ severity='warning'; message='PSScriptAnalyzer unavailable; only PowerShell syntax was checked' }
        }
    }
    $json = @{ syntax_ok=(@($parseErrors).Count -eq 0); diagnostics=@($diagnostics) } | ConvertTo-Json -Depth 4 -Compress
    [Console]::Out.WriteLine($json)
} catch {
    # Keep the transport valid even if the fixed parser helper itself fails.
    # The submitted script is never executed and is not copied into this message.
    $message = [string]$_.Exception.Message
    $message = ($message -replace '[\x00-\x1F]+', ' ').Trim()
    if ($message.Length -gt 500) { $message = $message.Substring(0, 500) }
    $json = @{
        syntax_ok=$false
        diagnostics=@(@{ severity='error'; message="PowerShell parser helper failed: $message" })
    } | ConvertTo-Json -Depth 4 -Compress
    [Console]::Out.WriteLine($json)
    exit 2
}
