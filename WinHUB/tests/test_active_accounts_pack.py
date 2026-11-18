import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'WinHUB/deploy/import_templates/active_accounts'


class ActiveAccountsPackTests(unittest.TestCase):
    def test_pack_and_aggregate(self):
        pack = json.loads((BASE / 'active_accounts_pack.json').read_text(encoding='utf-8'))
        action, report = pack['templates']
        self.assertEqual(action['payload']['__report_template_id'], report['id'])
        self.assertEqual(action['payload']['script'], (BASE / 'active_accounts.ps1').read_text(encoding='utf-8'))
        template = (BASE / 'active_accounts_report.jinja').read_text(encoding='utf-8')
        self.assertEqual(report['payload']['script'], template)
        spec = importlib.util.spec_from_file_location('accounts_renderer', ROOT / 'WinHUB/core/report_renderer.py')
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        def row(host, logins):
            return dict(host=host, status='Success', data=dict(
                audit='winhub-local-active-accounts-v1', active_logins=logins))
        output = renderer.render_report(template, dict(all_results=[
            row('A', ['Olena', 'ivan']), row('B', ['olena', '<admin>']), row('C', []),
            dict(host='D', status='Failed', data=None),
            dict(host='E', status='Success', data={'error': 'old result'})]))
        for expected in ['кількості хостів — 3', 'активних облікових записів — 4',
                         'активних унікальних облікових записів — 3',
                         'без успішного аудиту — 2', 'підсумок неповний', '&lt;admin&gt;']:
            self.assertIn(expected, output)
        self.assertIn('Результатів немає', renderer.render_report(template, {'all_results': []}))

    @unittest.skipUnless(shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_collector_selection_and_failure(self):
        source = (BASE / 'active_accounts.ps1').read_text(encoding='utf-8')
        parser = "$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('" + str(BASE / 'active_accounts.ps1') + "',[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw ($e|Out-String)}"
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', parser], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        fixtures = [
            ("[pscustomobject]@{Name='Olena';Disabled=$false;Lockout=$false};[pscustomobject]@{Name='disabled';Disabled=$true;Lockout=$false};[pscustomobject]@{Name='locked';Disabled=$false;Lockout=$true}", 0, ['olena']),
            ('', 0, []),
            ("[pscustomobject]@{Name='unknown';Disabled=$false;Lockout=$null}", 1, None),
            ("throw 'Access denied'", 1, None),
        ]
        for body, code, expected in fixtures:
            mock = "function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) " + body + " }\n"
            result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', mock + source], capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            data = json.loads(result.stdout)
            if expected is None:
                self.assertIn('error', data)
            else:
                self.assertEqual(data['active_logins'], expected)
                self.assertEqual(data['active_count'], len(expected))
