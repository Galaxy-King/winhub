$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$s = @{}
$s['Operation'] = @'
{{Operation}}
'@
$s['CheckMode'] = @'
{{CheckMode}}
'@
$s['PassiveServers'] = @'
{{PassiveServers}}
'@
$s['ActiveServers'] = @'
{{ActiveServers}}
'@
$s['HostnameMode'] = @'
{{HostnameMode}}
'@
$s['CustomHostname'] = @'
{{CustomHostname}}
'@
$s['MetadataMode'] = @'
{{MetadataMode}}
'@
$s['MetadataValue'] = @'
{{MetadataValue}}
'@
$s['PSKIdentity'] = @'
{{PSKIdentity}}
'@
$psk = @'
{{PSKSecretValue}}
'@
$s['AgentDirectory'] = @'
{{AgentDirectory}}
'@
$s['ServiceName'] = @'
{{ServiceName}}
'@
$s['PSKFile'] = @'
{{PSKFile}}
'@

$s['TLSMode'] = 'PSK'

$candidate=$null; $backup=$null; $changed=$false; $newKey=$false
$wasRunning=$false; $stage='validation'; $old=$null
$failureCode='UNEXPECTED_ERROR'; $failureMessage='Operation failed. Check permissions and the indicated validation step.'; $failureField=''
$check='inputs'
function Fail([string]$code,[string]$message,[string]$field='') {
    $script:failureCode=$code; $script:failureMessage=$message; $script:failureField=$field
    throw 'Zabbix configuration check failed.'
}
$utf8=New-Object Text.UTF8Encoding($false)
function Need([string]$name) {
    $v=[string]$s[$name]
    if ([string]::IsNullOrWhiteSpace($v)) { Fail 'REQUIRED_FIELD' 'Fill in the required field.' $name }
    return $v
}
function Protect([string]$path,[string]$account) {
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $id=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')
        $acl.AddAccessRule($rule)
    }
    if($account -and $account -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($account,'Read','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
try {
    foreach($k in $s.Keys) {
        if($s[$k] -match '[\r\n\x00]') { Fail 'INVALID_LINE_BREAK' 'This field must be a single line.' $k }
    }
    if($s.Operation -notin @('Preview','Apply')) { Fail 'INVALID_OPERATION' 'Choose Preview or Apply.' 'Operation' }
    if($s.CheckMode -notin @('Active','Passive','Both')) { Fail 'INVALID_CHECK_MODE' 'Choose Active, Passive or Both.' 'CheckMode' }
    if($s.HostnameMode -notin @('ComputerName','Custom')) { Fail 'INVALID_HOSTNAME_MODE' 'Choose ComputerName or Custom.' 'HostnameMode' }
    if($s.MetadataMode -notin @('Disabled','List')) { Fail 'INVALID_METADATA_MODE' 'Choose Disabled or List.' 'MetadataMode' }
    if($s.TLSMode -notin @('PSK')) { Fail 'INVALID_TLS_MODE' 'This template requires PSK.' }
    $check='agent_paths'; $failureField='AgentDirectory'
    $dir=[IO.Path]::GetFullPath((Need 'AgentDirectory'))
    $config=Join-Path $dir 'zabbix_agent2.conf'
    $exe=Join-Path $dir 'zabbix_agent2.exe'
    if(!(Test-Path -LiteralPath $exe -PathType Leaf)) { Fail 'AGENT_EXECUTABLE_MISSING' 'zabbix_agent2.exe was not found in AgentDirectory. Install the agent first.' 'AgentDirectory' }
    if(!(Test-Path -LiteralPath $config -PathType Leaf)) { Fail 'AGENT_CONFIG_MISSING' 'zabbix_agent2.conf was not found in AgentDirectory. Restore the installed agent config first.' 'AgentDirectory' }
    $serviceName=Need 'ServiceName'
    $check='service_lookup'; $failureField='ServiceName'
    $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if(!$svc) { Fail 'SERVICE_NOT_FOUND' 'The Windows service was not found. Check ServiceName.' 'ServiceName' }
    $info=Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $serviceName }
    if(!$info -or $info.PathName -notlike "*$exe*") { Fail 'SERVICE_EXECUTABLE_MISMATCH' 'The selected service does not use the executable in AgentDirectory.' 'ServiceName' }
    if($info.PathName -match '(?i)(?:--config(?:=|\s+)|-c\s+)(?:"([^"]+)"|(\S+))') {
        $svcConfig=if($Matches[1]){$Matches[1]}else{$Matches[2]}
        if([IO.Path]::GetFullPath($svcConfig) -ne $config) { Fail 'SERVICE_CONFIG_MISMATCH' 'The service uses another config path. Match AgentDirectory to the service configuration.' 'AgentDirectory' }
    }
    $check='read_config'; $failureField='AgentDirectory'
    $old=[IO.File]::ReadAllBytes($config)
    $text=[IO.File]::ReadAllText($config)
    $check='configuration_fields'; $failureField=''
    $u=[ordered]@{}
    $u.Server=if($s.CheckMode -in @('Passive','Both')){Need 'PassiveServers'}else{$null}
    $u.ServerActive=if($s.CheckMode -in @('Active','Both')){Need 'ActiveServers'}else{$null}
    $u.Hostname=$null; $u.HostnameItem=$null
    switch($s.HostnameMode) {
        'ComputerName' {$u.Hostname=$env:COMPUTERNAME}
        'Custom' {$u.Hostname=Need 'CustomHostname'}
    }
    $u.HostMetadata=$null; $u.HostMetadataItem=$null
    switch($s.MetadataMode) {
        'List' {
            $v=Need 'MetadataValue'
            if($v -eq 'UNCONFIGURED' -or [Text.Encoding]::UTF8.GetByteCount($v) -gt 2034) { Fail 'INVALID_METADATA' 'Select valid metadata, up to 2034 UTF-8 bytes.' 'MetadataValue' }
            $u.HostMetadata=$v
        }
    }
    switch($s.TLSMode) {
        'PSK' {
            if($psk -notmatch '\A(?:[0-9a-fA-F]{2}){16,256}\z'){Fail 'INVALID_PSK_FORMAT' 'Enter 32-512 hexadecimal characters in pairs, without spaces or line breaks.' 'PSKSecretValue'}
            $u.TLSConnect='psk'; $u.TLSAccept='psk'; $u.TLSPSKIdentity=Need 'PSKIdentity'
            $check='psk_file'; $failureField='PSKFile'
            $keyPath=[IO.Path]::GetFullPath((Need 'PSKFile'))
            if(![IO.Path]::IsPathRooted($s.PSKFile) -or !(Test-Path -LiteralPath (Split-Path $keyPath -Parent) -PathType Container)){Fail 'INVALID_PSK_PATH' 'Use an absolute PSK file path in an existing directory.' 'PSKFile'}
            $u.TLSPSKFile=$keyPath
            if(Test-Path -LiteralPath $keyPath) {
                if([IO.File]::ReadAllText($keyPath).Trim() -cne $psk){Fail 'PSK_FILE_CONFLICT' 'The existing PSK file contains another key. Use a new PSKFile path for rotation.' 'PSKFile'}
            }
        }
    }
    $check='build_config'; $failureField=''
    $lines=New-Object 'Collections.Generic.List[string]'
    foreach($line in ($text -split '\r?\n')) {
        if($line -match '^\s*([^#\s=]+)\s*=' -and $u.Contains($Matches[1])){continue}
        $lines.Add($line)
    }
    foreach($k in $u.Keys) {
        foreach($v in @($u[$k])) {
            if($null -eq $v -or [string]$v -eq ''){continue}
            if([string]$v -match '[\r\n\x00]'){Fail 'INVALID_CONFIG_VALUE' 'Configuration values must not contain line breaks or NUL.' $k}
            $lines.Add($k+'='+[string]$v)
        }
    }
    $newText=($lines -join "`r`n")+"`r`n"
    if($s.Operation -eq 'Preview') {
        @{status='Preview'; changed=$false; mode=$s.CheckMode; tls=$s.TLSMode; metadata_mode=$s.MetadataMode; parameters=@($u.Keys); note='No files changed; full agent -T validation happens only on Apply.'}|ConvertTo-Json -Depth 8 -Compress
        exit 0
    }
    $check='backup_and_psk'; $failureField=''
    $stage='apply'; $wasRunning=$svc.Status -eq 'Running'
    $id=[Guid]::NewGuid().ToString('N')
    $backup=Join-Path $dir ('zabbix_agent2.conf.winhub-'+$id+'.bak')
    $candidate=Join-Path $dir ('winhub-candidate-'+$id+'.tmp')
    [IO.File]::WriteAllBytes($backup,[byte[]]@()); Protect $backup $info.StartName
    [IO.File]::WriteAllBytes($backup,$old)
    if($s.TLSMode -eq 'PSK') {
        if(!(Test-Path -LiteralPath $keyPath)) {
            $stream=[IO.File]::Open($keyPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $stream.Dispose(); $newKey=$true
            Protect $keyPath $info.StartName
            [IO.File]::WriteAllText($keyPath,$psk+"`r`n",$utf8)
        } else {Protect $keyPath $info.StartName}
    }
    [IO.File]::WriteAllBytes($candidate,[byte[]]@()); Protect $candidate $info.StartName
    [IO.File]::WriteAllText($candidate,$newText,$utf8)
    $check='agent_config_test'
    Push-Location $dir
    try{$null=& $exe '-T' '-c' $candidate 2>&1; $valid=$LASTEXITCODE}finally{Pop-Location}
    if($valid -ne 0){Fail 'AGENT_CONFIG_TEST_FAILED' 'The agent rejected the candidate config or does not support -T. Check Include paths and agent version.'}
    if([Convert]::ToBase64String([IO.File]::ReadAllBytes($config)) -cne [Convert]::ToBase64String($old)){Fail 'CONCURRENT_CONFIG_EDIT' 'The config changed during this task. Review it and retry.'}
    $check='service_restart'; $failureField='ServiceName'
    Stop-Service -Name $serviceName
    $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    $changed=$true
    [IO.File]::WriteAllText($config,$newText,$utf8)
    Start-Service -Name $serviceName
    $svc.Refresh(); $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 3; $svc.Refresh()
    if($svc.Status -ne 'Running'){Fail 'SERVICE_START_FAILED' 'The agent stopped after startup. Check the local Zabbix log.' 'ServiceName'}
    @{status='Success'; changed=$true; mode=$s.CheckMode; tls=$s.TLSMode; metadata_mode=$s.MetadataMode; backup=$backup; note='Service running; Zabbix host/server TLS settings must be configured separately.'}|ConvertTo-Json -Depth 8 -Compress
} catch {
    $rollback='NotNeeded'
    if($changed) {
        try {
            Stop-Service -Name $serviceName
            [IO.File]::WriteAllBytes($config,$old)
            if($wasRunning){Start-Service -Name $serviceName}
            $rollback='Restored'
        } catch {$rollback='Failed'}
    } elseif($stage -eq 'apply' -and $wasRunning) {
        try{Start-Service -Name $serviceName}catch{}
    }
    if($newKey -and $rollback -ne 'Failed') {Remove-Item -LiteralPath $keyPath -Force -ErrorAction SilentlyContinue}
    @{status='Error'; stage=$stage; rollback=$rollback; error_code=$failureCode; check=$check; field=$failureField; message=$failureMessage}|ConvertTo-Json -Depth 8 -Compress
    exit 1
} finally {
    $psk=$null
    if($candidate -and (Test-Path -LiteralPath $candidate)){Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue}
}
