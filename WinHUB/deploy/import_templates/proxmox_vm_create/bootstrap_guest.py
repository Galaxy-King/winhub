"""QEMU Guest Agent orchestration; secret descriptor travels over stdin, not argv/code."""
import base64
import json
import re
import subprocess
import time

BOOTSTRAP_INSTALLER_B64 = ""

READINESS = r"""
$ErrorActionPreference='Stop'
try {
 $service=Get-Service cloudbase-init
 $path='C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log'
 $log=[IO.File]::ReadAllText($path)
 $index=$log.LastIndexOf('Cloudbase-Init version:')
 if ($index -ge 0) { $log=$log.Substring($index) } else { $log='' }
 $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
 $fresh=(Get-Item -LiteralPath $path).LastWriteTime -ge $boot
 $done=$fresh -and $service.Status -eq 'Stopped' -and $log.Contains('Plugins execution done')
 $failed=$done -and $log.Contains(' ERROR ')
 $ip=Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '__IP__'
 $ready=$done -and (-not $failed) -and $log.Contains("Executing plugin 'SetUserPasswordPlugin'") -and
   ([Environment]::MachineName -ieq '__HOSTNAME__') -and [bool]$ip
 @{ready=[bool]$ready; failed=[bool]$failed} | ConvertTo-Json -Compress
} catch { '{"ready":false,"failed":false}' }
"""


def guest_exec(vmid, script, *, stdin=None, asynchronous=False):
    encoded = base64.b64encode(script.encode('utf-16-le')).decode()
    args = ['qm', 'guest', 'exec', str(vmid)]
    args += ['--synchronous', '0'] if asynchronous else ['--timeout', '25']
    if stdin is not None:
        args += ['--pass-stdin', '1']
    args += ['--', 'powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=40)
    if result.returncode:
        raise ValueError('QEMU Guest Agent command failed; inspect guest locally (details withheld)')
    data = json.loads(result.stdout)
    return data.get('result', data)


def install_agent(vmid, hostname, ip, descriptor, *, deadline_seconds=900):
    if not re.fullmatch('[a-fA-F0-9-]{36}', str(descriptor.get('grant_id', ''))):
        raise ValueError('Invalid bootstrap descriptor')
    until = time.monotonic() + deadline_seconds
    check = READINESS.replace('__HOSTNAME__', hostname).replace('__IP__', ip)
    print('Agent bootstrap: waiting for Cloudbase-Init completion and guest network', flush=True)
    while time.monotonic() < until:
        try:
            result = guest_exec(vmid, check)
            state = json.loads(result.get('out-data', '{}')) if result.get('exited') and not result.get('exitcode') else {}
        except (ValueError, subprocess.TimeoutExpired):
            state = {}
        if state.get('failed'):
            raise ValueError('Cloudbase-Init failed; agent installation was not started')
        if state.get('ready'):
            break
        time.sleep(10)
    else:
        raise ValueError('Windows readiness timeout; VM preserved and agent not installed')
    directory = 'C:\\ProgramData\\WinHUB-Provision-' + descriptor['grant_id']
    # This command is fixed code. Only the input stream contains capabilities.
    receiver = r"""
$ErrorActionPreference='Stop'
$dir='__DIR__'
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect bootstrap directory' }
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$utf8=New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText((Join-Path $dir 'descriptor.json'), ($data.descriptor | ConvertTo-Json -Depth 10), $utf8)
[IO.File]::WriteAllBytes((Join-Path $dir 'install.ps1'), [Convert]::FromBase64String($data.script))
'{"received":true}'
""".replace('__DIR__', directory)
    result = guest_exec(vmid, receiver, stdin=json.dumps(dict(descriptor=descriptor, script=BOOTSTRAP_INSTALLER_B64)))
    if not result.get('exited') or result.get('exitcode'):
        raise ValueError('Could not stage agent bootstrap files in Windows')
    launcher = r"""
$dir='__DIR__'
try {
 & ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $dir 'install.ps1')))) -DescriptorPath (Join-Path $dir 'descriptor.json')
} finally {
 if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
""".replace('__DIR__', directory)
    started = guest_exec(vmid, launcher, asynchronous=True)
    pid = int(started['pid'])
    until = time.monotonic() + 660
    print('Agent bootstrap: installing signed package from Software', flush=True)
    while time.monotonic() < until:
        result = subprocess.run(['qm', 'guest', 'exec-status', str(vmid), str(pid)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Lost bootstrap process status; inspect VM before retry')
        status = json.loads(result.stdout)
        status = status.get('result', status)
        if status.get('exited'):
            if status.get('exitcode'):
                # Never echo guest command output: third-party installer errors may include secrets.
                try:
                    failure = json.loads(status.get('out-data', '').strip())
                    phase = failure.get('phase')
                except ValueError:
                    phase = None
                if phase not in ('preflight', 'download', 'signature', 'install', 'enrollment'):
                    phase = 'unknown'
                raise ValueError('Agent bootstrap failed during ' + phase + '; inspect service/logs locally')
            try:
                registered = json.loads(status.get('out-data', '').strip())
            except ValueError:
                raise ValueError('Bootstrap completed without a registration confirmation') from None
            if not registered.get('registered'):
                raise ValueError('Agent service installed but enrollment was not confirmed')
            print(json.dumps(dict(agent_installed=True, agent_registered=True,
                                  endpoint_id=registered.get('endpoint_id'), approval_status=registered.get('approval_status'),
                                  agent_version=registered.get('agent_version'), bootstrap_package_id=descriptor.get('package_id'))))
            return
        time.sleep(5)
    raise ValueError('Agent installation timeout; VM/process preserved, inspect before retry')
