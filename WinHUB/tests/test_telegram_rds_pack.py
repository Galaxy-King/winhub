import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BASE = Path(__file__).resolve().parents[1] / 'deploy/import_templates/telegram_rds'


class TelegramRdsPackTests(unittest.TestCase):
    def test_pack_matches_source(self):
        pack = json.loads((BASE / 'telegram_rds_pack.json').read_text(encoding='utf-8'))
        source = (BASE / 'telegram_rds.ps1').read_text(encoding='utf-8')
        imported = pack['templates'][0]['payload']['script']
        self.assertEqual(imported.split("$ErrorActionPreference = 'Stop'", 1)[1],
                         source.split("$ErrorActionPreference = 'Stop'", 1)[1])
        self.assertNotIn('param(', imported.split("$ErrorActionPreference = 'Stop'", 1)[0])
        self.assertFalse(pack['templates'][0]['is_approved'])

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires PowerShell parser')
    def test_import_with_actual_agent_preamble(self):
        worker = (BASE.parents[3] / 'WinHUBAgentWindows/Worker.cs').read_text(encoding='utf-8')
        preamble = re.search(r'string encodingPreamble = @"(.*?)";', worker, re.S).group(1).replace('""', '"')
        pack = json.loads((BASE / 'telegram_rds_pack.json').read_text(encoding='utf-8'))
        action = pack['templates'][0]['payload']
        with tempfile.TemporaryDirectory(prefix='winhub-telegram-parser-') as temp:
            for mode in action['__variable_schema']['Action']['options']:
                for update in action['__variable_schema']['AutoUpdate']['options']:
                    script = preamble + '\n' + action['script'].replace('{{Action}}', mode).replace('{{AutoUpdate}}', update)
                    candidate = Path(temp) / 'candidate.ps1'
                    candidate.write_text(script, encoding='utf-8-sig')
                    command = "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('" + str(candidate).replace("'", "''") + "',[ref]$tokens,[ref]$errors) | Out-Null; if($errors.Count) { $errors | Out-String | Write-Output; exit 1 }"
                    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, f'{mode}/{update}: {result.stdout}{result.stderr}')

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows ACLs and PowerShell')
    def test_launcher_isolates_and_refuses_unprotected_profile(self):
        source = (BASE / 'telegram_rds.ps1').read_text(encoding='utf-8')
        launcher = source.split("$launch = @'\n", 1)[1].split("\n'@", 1)[0]
        with tempfile.TemporaryDirectory(prefix='winhub-telegram-test-') as temp:
            temp_path = Path(temp)
            def literal(value):
                return "'" + str(value).replace("'", "''") + "'"
            launcher = launcher.replace("[Environment]::GetFolderPath('ApplicationData')", literal(temp_path))
            launcher = launcher.replace("'__TELEGRAM_EXE__'", literal(temp_path / 'Telegram.exe'))
            (temp_path / 'Telegram.exe').write_bytes(b'not executable; Start-Process is mocked')
            harness = """
$ErrorActionPreference = 'Stop'
$script:calls = @()
function Start-Process { param($FilePath, $ArgumentList, $WorkingDirectory)
    $script:calls += @{ exe=$FilePath; args=$ArgumentList; work=$WorkingDirectory }
}
""" + '$launcher = ' + literal(launcher) + """
& ([scriptblock]::Create($launcher))
if ($script:calls.Count -ne 1) { throw 'Expected exactly one launch' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$expected = Join-Path """ + literal(temp_path) + """ ('WinHUB Telegram-' + $sid)
if ($script:calls[0].work -ne $expected -or $script:calls[0].args -ne ('-workdir "{0}"' -f $expected)) { throw 'Wrong user workdir' }
$data = Join-Path $expected 'tdata'
New-Item -ItemType Directory -Path $data | Out-Null
$acl = Get-Acl -LiteralPath $data
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'FullControl', 'Allow')))
Set-Acl -LiteralPath $data -AclObject $acl
& ([scriptblock]::Create($launcher))
$acl = Get-Acl -LiteralPath $data
foreach ($ace in $acl.Access) {
    if ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0') { throw 'Everyone access survived repair' }
}
# An ACL error must stop the launch, never fall back to the common/default profile.
$broken = $launcher.Replace('[IO.Directory]::SetAccessControl($work, $acl)', "throw 'Simulated ACL failure'")
$failed = $false
try { & ([scriptblock]::Create($broken)) } catch { $failed = $true }
if (-not $failed -or $script:calls.Count -ne 2) { throw 'Launched after ACL failure' }
'Launcher isolation/ACL checks passed'
"""
            script = temp_path / 'test.ps1'
            script.write_text(harness, encoding='utf-8-sig')
            env = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script)], capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
