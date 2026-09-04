param([Parameter(Mandatory=$true)][string]$InputPath)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
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
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        # Only reviewed built-in rules; no per-script settings or custom rules.
        $rules = @('PSAvoidUsingInvokeExpression','PSAvoidUsingPlainTextForPassword','PSAvoidUsingConvertToSecureStringWithPlainText','PSUseDeclaredVarsMoreThanAssignments')
        foreach ($item in @(Invoke-ScriptAnalyzer -Path $InputPath -IncludeRule $rules | Select-Object -First 20)) {
            $diagnostics += @{ severity='warning'; message="$($item.RuleName) line $($item.Line): $($item.Message)" }
        }
    } else {
        $diagnostics += @{ severity='warning'; message='PSScriptAnalyzer unavailable; only PowerShell syntax was checked' }
    }
}
@{ syntax_ok=(@($parseErrors).Count -eq 0); diagnostics=@($diagnostics) } | ConvertTo-Json -Depth 4 -Compress
