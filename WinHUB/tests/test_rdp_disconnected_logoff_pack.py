import json
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'WinHUB/deploy/import_templates/rdp_disconnected_logoff'


class RdpDisconnectedLogoffTests(unittest.TestCase):
    def test_pack_matches_source(self):
        pack = json.loads((BASE / 'rdp_disconnected_logoff_pack.json').read_text(encoding='utf-8'))
        source = (BASE / 'rdp_disconnected_logoff.ps1').read_text(encoding='utf-8')
        self.assertEqual(pack['templates'][0]['payload']['script'], source.replace("[string]$Mode = 'Audit'", "[string]$Mode = '{{Mode}}'"))
        report = pack['templates'][1]
        self.assertEqual(pack['templates'][0]['payload']['__report_template_id'], report['id'])
        self.assertEqual(report['type'], 'report')
        self.assertEqual(report['payload']['script'], (BASE / 'rdp_disconnected_logoff_report.jinja').read_text(encoding='utf-8'))

    def test_structured_report_partial_failure_and_escaping(self):
        spec = importlib.util.spec_from_file_location('rdp_report_renderer', ROOT / 'WinHUB/core/report_renderer.py')
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        rows = [dict(session_id=i, user=f'user-{status}', status=status, connection_state=4,
                     message='<script>unsafe</script>') for i, status in enumerate(
                         ['Active', 'LoggedOff', 'WouldLogoff', 'Skipped', 'Failed'], 1)]
        data = dict(mode='Audit', status='PartialFailure', active=1, logged_off=1, would_logoff=1, failed=1, sessions=rows)
        context = dict(job_title='RDP <test>', all_results=[
            dict(host='SERVER-01', status='Failed', data=data),
            dict(host='SERVER-02', status='Failed', data=None, log='Endpoint unavailable'),
        ])
        template = (BASE / 'rdp_disconnected_logoff_report.jinja').read_text(encoding='utf-8')
        output = renderer.render_report(template, context)
        self.assertIn('<table>', output)
        self.assertIn('RDP Session Report', output)
        self.assertNotRegex(template, r'[\u0400-\u04ff]')
        for row in rows:
            self.assertIn(row['user'], output)
        self.assertIn('Endpoint unavailable', output)
        self.assertIn('Not available in older result', output)
        self.assertIn('&lt;script&gt;', output)
        self.assertNotIn('<script>', output)
        self.assertIn('Audit only', output)
        self.assertIn('No results', renderer.render_report(template, dict(job_title='Empty', all_results=[])))

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_agent_wrapper_and_native_compilation(self):
        source = (BASE / 'rdp_disconnected_logoff.ps1').read_text(encoding='utf-8')
        worker = (ROOT / 'WinHUBAgentWindows/Worker.cs').read_text(encoding='utf-8')
        preamble = re.search(r'string encodingPreamble = @"(.*?)";', worker, re.S).group(1)
        native = source.split("$native = @'\n", 1)[1].split("\n'@", 1)[0]
        # Compile P/Invoke declarations only; no WTS calls or logoff.
        self.run_ps("Add-Type -TypeDefinition @'\n" + native + "\n'@ -Language CSharp\n")
        for mode in ('Audit', 'LogoffDisconnected'):
            with tempfile.TemporaryDirectory(prefix='winhub-rdp-parse-') as temp:
                path = Path(temp) / 'candidate.ps1'
                path.write_text(preamble + '\n' + source.replace("$Mode = 'Audit'", f"$Mode = '{mode}'"), encoding='utf-8-sig')
                self.run_ps("$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('" + str(path).replace("'", "''") + "',[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw ($e|Out-String)}")

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_selection_and_reconnect_with_mock_wts(self):
        source = (BASE / 'rdp_disconnected_logoff.ps1').read_text(encoding='utf-8')
        # Session 1 eligible; 2 active; 3 reconnects; 4 console; 5 no user;
        # 6 changes identity; 7 fails to query; 8 is disconnected protocol 0;
        # 9 becomes console before logoff. Session 0 must never be logged off.
        mock = '''
using System;
namespace WinHUBRdp {
 public class Session { public int Id; public int State=4; public short Protocol=2; public string User="user"; public string Domain="DOMAIN"; public string Station=""; public bool IsConsole=false; }
 public static class Native {
  static int[] reads=new int[10];
  public static int[] SessionIds(){return new int[]{0,1,2,3,4,5,6,7,8,9};}
  public static Session Read(int id){
   if(id==7)throw new Exception("Query failed");
   var s=new Session{Id=id};reads[id]++;
   if(id==2 || (id==3 && reads[id]>1))s.State=0;
   if(id==4){s.Protocol=0;s.IsConsole=true;s.Station="Console";}
   if(id==8)s.Protocol=0;
   if(id==9 && reads[id]>1)s.IsConsole=true;if(id==5)s.User="";
   if(id==6 && reads[id]>1)s.User="other";
   return s;
  }
  public static void Logoff(int id){if(id!=1 && id!=8)throw new Exception("Unsafe session selected");}
 }
}
'''
        source = re.sub(r"\$native = @'\n.*?\n'@", lambda _: "$native = @'\n" + mock + "\n'@", source, count=1, flags=re.S)
        source = source.replace('#requires -RunAsAdministrator\n', '')
        for mode, expected in [('Audit', 5), ('LogoffDisconnected', 2)]:
            result = self.run_ps(source.replace("$Mode = 'Audit'", f"$Mode = '{mode}'"), expected_code=1)
            data = json.loads(result.stdout)
            self.assertEqual(data['failed'], 1)
            self.assertEqual(data['logged_off'], expected if mode == 'LogoffDisconnected' else 0)
            self.assertEqual(data['would_logoff'], expected if mode == 'Audit' else 0)
            rows = {row['session_id']: row for row in data['sessions']}
            self.assertEqual(rows[2]['status'], 'Active')
            self.assertEqual(data['active'], 1)
            for session_id in (0, 4, 5):
                self.assertEqual(rows[session_id]['status'], 'Skipped')
            if mode == 'LogoffDisconnected':
                self.assertEqual(rows[3]['status'], 'Skipped')
                self.assertEqual(rows[6]['status'], 'Skipped')
                self.assertEqual(rows[9]['status'], 'Skipped')
            self.assertEqual(rows[8]['status'], 'WouldLogoff' if mode == 'Audit' else 'LoggedOff')

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_win_ter412_disconnected_protocol_zero(self):
        source = (BASE / 'rdp_disconnected_logoff.ps1').read_text(encoding='utf-8')
        mock = '''
namespace WinHUBRdp {
 public class Session {
  public int Id; public int State=4; public short Protocol=0;
  public string User; public string Domain="WIN-TER412"; public string Station=""; public bool IsConsole=false;
 }
 public static class Native {
  public static int[] SessionIds(){return new int[]{3,4,5,6,7};}
  public static Session Read(int id){
   var s=new Session{Id=id,User=new string[]{"ptashka","rudicorn","vstp","mariam","Administrator"}[id-3]};
   if(id==3){s.State=0;s.Protocol=2;}return s;
  }
  public static void Logoff(int id){if(id==3)throw new System.Exception("Active user selected");}
 }
}
'''
        source = re.sub(r"\$native = @'\n.*?\n'@", lambda _: "$native = @'\n" + mock + "\n'@", source, count=1, flags=re.S)
        source = source.replace('#requires -RunAsAdministrator\n', '')
        for mode in ('Audit', 'LogoffDisconnected'):
            data = json.loads(self.run_ps(source.replace("$Mode = 'Audit'", f"$Mode = '{mode}'")).stdout)
            self.assertEqual(data['active'], 1)
            self.assertEqual(data['would_logoff'], 4 if mode == 'Audit' else 0)
            self.assertEqual(data['logged_off'], 4 if mode == 'LogoffDisconnected' else 0)
            self.assertEqual(data['failed'], 0)

    def run_ps(self, source, expected_code=0):
        with tempfile.TemporaryDirectory(prefix='winhub-rdp-test-') as temp:
            path = Path(temp) / 'test.ps1'
            path.write_text("$ErrorActionPreference='Stop'\n" + source, encoding='utf-8-sig')
            env = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(path)], capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
            return result


if __name__ == '__main__':
    unittest.main()
