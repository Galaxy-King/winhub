import json
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / 'deploy/import_templates/zabbix_agent2'

class ZabbixPackTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('powershell.exe'), 'Requires Windows PowerShell')
    def test_safe_validation_diagnostics(self):
        template = json.loads((BASE / 'zabbix_agent2_winhub_pack.json').read_text(encoding='utf-8'))['templates'][0]
        cases = [('missing_config', 'AGENT_CONFIG_MISSING', 'AgentDirectory'),
                 ('invalid_key', 'INVALID_PSK_FORMAT', 'PSKSecretValue'),
                 ('conflict', 'PSK_FILE_CONFLICT', 'PSKFile'),
                 ('missing_service', 'SERVICE_NOT_FOUND', 'ServiceName'),
                 ('exception', 'UNEXPECTED_ERROR', 'ServiceName')]
        for case, code, field in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='winhub-zabbix-errors-') as temp:
                directory = Path(temp)
                exe = directory / 'zabbix_agent2.exe'
                exe.touch()
                config = directory / 'zabbix_agent2.conf'
                if case != 'missing_config':
                    config.write_text('Server=original\n', encoding='utf-8')
                key = directory / 'test.key'
                if case == 'conflict':
                    key.write_text('cd'*32, encoding='utf-8')
                values = {k: v['default'] for k, v in template['payload']['__variable_schema'].items()}
                values.update(AgentDirectory=temp, PSKFile=str(key), PSKIdentity='test-only', PSKSecretValue='ab'*32)
                if case == 'invalid_key':
                    values['PSKSecretValue'] = 'private-invalid-key'
                prefix = "function Get-Service { [pscustomobject]@{Status='Running'} }\nfunction Get-CimInstance { [pscustomobject]@{Name='Zabbix Agent 2';PathName='" + str(exe) + "';StartName='LocalSystem'} }\n"
                if case == 'missing_service':
                    prefix = 'function Get-Service {}\n'
                if case == 'exception':
                    prefix = "function Get-Service { throw 'private-invalid-key' }\n"
                rendered = re.sub(r'{{(\w+)}}', lambda m: values[m[1]], template['payload']['script'])
                path = directory / 'validation.ps1'
                path.write_text(prefix + rendered, encoding='utf-8-sig')
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(data['stage'], 'validation')
                self.assertEqual(data['rollback'], 'NotNeeded')
                self.assertEqual(data['error_code'], code)
                self.assertEqual(data['field'], field)
                self.assertNotIn('ab'*32, result.stdout + result.stderr)
                self.assertNotIn('private-invalid-key', result.stdout + result.stderr)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)

    def test_incomplete_source_is_not_an_import_pack(self):
        definition = json.loads((BASE / 'template_definition.json').read_text(encoding='utf-8'))
        self.assertNotIn('templates', definition)
        self.assertFalse((BASE / 'template_manifest.json').exists())

    def test_import_rejects_schema_without_script(self):
        from flask import Flask
        from modules.Infrastructure import routes
        app = Flask(__name__)
        app.secret_key = 'test-only'
        with app.test_request_context(json={'templates': [{
            'name': 'Incomplete test', 'payload': {'__variable_schema': {}}
        }]}), mock.patch.object(routes, 'require_permission', return_value=None), \
                mock.patch.object(routes.db.session, 'rollback') as rollback:
            response, status = routes.import_templates()
        self.assertEqual(status, 400)
        self.assertIn('non-empty payload.script', response.get_json()['message'])
        rollback.assert_called_once()

    @unittest.skipUnless(shutil.which('node'), 'Requires Node.js')
    def test_editor_never_uses_metadata_object_as_code(self):
        source = (BASE.parents[3] / 'WinHUB/static/js/infrastructure.js').read_text(encoding='utf-8')
        helper = 'function templateEditorCode(' + source.split('function templateEditorCode(', 1)[1].split('function loadTemplate(', 1)[0]
        fixture = helper + """
const assert = require('node:assert/strict');
assert.equal(templateEditorCode('{"__variable_schema":{}}'), '');
assert.equal(templateEditorCode('{"__variable_schema":{},"script":"Write-Output 1"}'), 'Write-Output 1');
assert.equal(templateEditorCode('{"script":""}'), '');
assert.equal(templateEditorCode('Write-Output 1'), 'Write-Output 1');
assert.equal(templateEditorCode('{"command":"echo test"}'), 'echo test');
assert.equal(templateEditorCode('{"url":"test"}', 'agent_update'), '{"url":"test"}');
"""
        subprocess.run(['node', '-e', fixture], check=True, capture_output=True, text=True)

    def test_only_psk_template_and_priority(self):
        pack = json.loads((BASE / 'zabbix_agent2_winhub_pack.json').read_text(encoding='utf-8'))
        self.assertEqual(len(pack['templates']), 1)
        schema = pack['templates'][0]['payload']['__variable_schema']
        self.assertIn('PSKSecretValue', schema)
        self.assertEqual(set(schema), {
            'Operation', 'CheckMode', 'PassiveServers', 'ActiveServers',
            'HostnameMode', 'CustomHostname', 'MetadataMode', 'MetadataValue',
            'PSKIdentity', 'PSKSecretValue', 'AgentDirectory', 'ServiceName',
            'PSKFile'})
        self.assertNotRegex(json.dumps(schema, ensure_ascii=False), r'[\u0400-\u04ff]')
        self.assertEqual(schema['HostnameMode']['options'], ['ComputerName', 'Custom'])
        self.assertEqual(schema['MetadataMode']['options'], ['Disabled', 'List'])
        self.assertEqual(schema['MetadataMode']['default'], 'List')
        expected = ['Operation', 'CheckMode', 'PassiveServers', 'ActiveServers',
                    'HostnameMode', 'CustomHostname', 'MetadataMode', 'MetadataValue',
                    'PSKIdentity', 'PSKSecretValue']
        self.assertEqual(sorted(schema, key=lambda name: schema[name]['order'])[:10], expected)

    @unittest.skipUnless(shutil.which('node'), 'Requires Node.js')
    def test_form_field_order(self):
        root = BASE.parents[3]
        for file in ['infrastructure.js', 'mobile_operator.js']:
            source = (root / 'WinHUB/static/js' / file).read_text(encoding='utf-8')
            helper = re.search(r'function orderTemplateVariables\(.*?\n\s*}\n(?=\n)', source, re.S).group(0)
            fixture = helper + """
const assert = require('node:assert/strict');
const names = ['Advanced', 'Server', 'PSK', 'Other', 'Invalid'];
const schema = {PSK: {order: 1}, Server: {order: 0}, Invalid: {order: 'invalid'}};
assert.deepEqual(orderTemplateVariables(names, schema), ['Server', 'PSK', 'Advanced', 'Other', 'Invalid']);
assert.deepEqual(orderTemplateVariables(names), names);
assert.deepEqual(names, ['Advanced', 'Server', 'PSK', 'Other', 'Invalid']);
"""
            subprocess.run(['node', '-e', fixture], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("powershell.exe"), "Requires Windows PowerShell")
    def test_schema_sources_and_preview(self):
        pack = json.loads((BASE / 'zabbix_agent2_winhub_pack.json').read_text(encoding='utf-8'))
        self.assertEqual(pack['format'], 'winhub-template-library')
        self.assertEqual(pack['version'], 1)
        for template in pack['templates']:
            self.assertFalse(template['is_approved'])
            schema = template['payload']['__variable_schema']
            script = template['payload']['script']
            source = 'configure_psk.ps1' if 'PSKSecretValue' in schema else 'configure.ps1'
            self.assertEqual(script, (BASE / source).read_text(encoding='utf-8'))
            self.assertEqual(set(re.findall(r'{{(\w+)}}', script)), set(schema))
            self.assertIn('Windows_2P', schema['MetadataValue']['options'])
            self.assertEqual(schema['Operation']['default'], 'Preview')
            if 'PSKSecretValue' in schema:
                self.assertEqual(schema['PSKSecretValue']['default'], '')
            with tempfile.TemporaryDirectory(prefix='winhub-zabbix-test-') as temp:
                directory = Path(temp)
                config = directory / 'zabbix_agent2.conf'
                config.write_text('Server=old.example\nHostMetadata=old\n', encoding='utf-8')
                original = config.read_bytes()
                exe = directory / 'zabbix_agent2.exe'
                exe.touch()
                values = {k: v['default'] for k,v in schema.items()}
                values.update(AgentDirectory=temp, PSKFile=str(directory / 'test.key'), PSKIdentity='test-only', PSKSecretValue='ab'*32, MetadataMode='List')
                rendered = re.sub(r'{{(\w+)}}', lambda m: values[m[1]], script)
                prefix = "function Get-Service { [pscustomobject]@{Status='Running'} }\nfunction Get-CimInstance { [pscustomobject]@{Name='Zabbix Agent 2';PathName='" + str(exe).replace("'", "''") + "';StartName='LocalSystem'} }\n"
                path = directory / 'preview.ps1'
                path.write_text(prefix+rendered, encoding='utf-8-sig')
                parse = "$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile('"+str(path).replace("'", "''")+"',[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw ($e|Out-String)}"
                subprocess.run(['powershell.exe','-NoProfile','-Command',parse],check=True,capture_output=True,text=True)
                result = subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(path)],check=False,capture_output=True,text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                data=json.loads(result.stdout)
                self.assertEqual(data['status'], 'Preview')
                self.assertFalse(data['changed'])
                self.assertEqual(config.read_bytes(), original)
                self.assertFalse((directory / 'test.key').exists())
                self.assertNotIn('ab'*32,result.stdout)

if __name__ == '__main__':
    unittest.main()
