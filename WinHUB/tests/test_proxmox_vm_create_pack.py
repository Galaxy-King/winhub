import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1] / 'deploy/import_templates/proxmox_vm_create'


def load(name):
    spec = importlib.util.spec_from_file_location(name, BASE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProxmoxCreatePackTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'Requires fcntl')
    def test_windows_metadata_includes_credentials_when_dump_omits_them(self):
        from unittest.mock import mock_open
        module = load('create_vm')
        values = {k: v[1] for k, v in load('build_pack').FIELDS.items()}
        values.update(Mode='Create', VMID='', Name='term-192.168.38.234', WindowsHostname='term-38-234', IP='192.168.38.234', Mask='24', Gateway='192.168.38.1', DNS='8.8.8.8')
        with tempfile.TemporaryDirectory() as directory:
            snippet = Path(directory) / 'meta.json'
            calls = []
            def command(*args):
                calls.append(args)
                if args[:3] == ('pvesh', 'get', '/cluster/resources'): return '[]'
                if args[:2] == ('qm', 'config'): return 'template: 1\ncitype: configdrive2\nide2: local:cloudinit\nostype: win11\n'
                if args[:3] == ('pvesh', 'get', '/storage'): return '[{"storage":"local","content":"images,snippets","type":"dir"}]'
                if args[:3] == ('qm', 'cloudinit', 'dump'): return '{"uuid":"original-id","network_config":{"content_path":"/content/0000"}}'
                if args[:2] == ('pvesm', 'path'): return str(snippet)
                return ''
            with patch.object(module.os, 'geteuid', return_value=0), patch('builtins.open', mock_open()), patch.object(module.fcntl, 'flock'), patch.object(module, 'run', side_effect=command), patch.object(module, 'generate_password', return_value='Synthetic!Password123456'):
                module.main(values)
            metadata = json.loads(snippet.read_text())
            self.assertEqual(metadata['admin_pass'], 'Synthetic!Password123456')
            self.assertEqual(metadata['admin_username'], 'Administrator')
            self.assertEqual(metadata['hostname'], 'term-38-234')
            self.assertEqual(metadata['uuid'], 'original-id')
            self.assertEqual(metadata['network_config']['content_path'], '/content/0000')
            self.assertEqual(calls[-1], ('qm', 'start', '100'))
            volume = next(c[2] for c in calls if c[:2] == ('pvesm', 'path'))
            self.assertRegex(volume, r'^local:snippets/winhub-vm-100-[0-9a-f]{24}-meta\.json$')

    @unittest.skipUnless(os.name == 'posix', 'Requires fcntl')
    def test_generated_credentials_are_distinct_and_windows_complex(self):
        module = load('create_vm')
        passwords = {module.generate_password() for _ in range(100)}
        self.assertEqual(len(passwords), 100)
        for password in passwords:
            self.assertEqual(len(password), 24)
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(c in '!@#%+-_' for c in password))

    @unittest.skipUnless(os.name == 'posix', 'Requires fcntl')
    def test_auto_id_first_gap_and_clone_failure_never_configures_existing_vm(self):
        from unittest.mock import mock_open
        module = load('create_vm')
        values = {k: v[1] for k, v in load('build_pack').FIELDS.items()}
        values.update(Mode='Create', VMID='', Name='term-192.168.38.234', WindowsHostname='', IP='192.168.38.234', Mask='24', Gateway='192.168.38.1', DNS='8.8.8.8', AdminPassword='Temporary!12345')
        config = 'template: 1\ncitype: configdrive2\nide2: local:cloudinit\nostype: win11\n'
        for occupied, expected in [([], '100'), ([100, 102, 114], '101'), ([100, 101, 102], '103')]:
            with self.subTest(occupied=occupied), patch.object(module.os, 'geteuid', return_value=0), patch('builtins.open', mock_open()), patch.object(module.fcntl, 'flock'), patch.object(module, 'run', side_effect=[json.dumps([{'vmid': n} for n in occupied]), config, '[{"storage":"local","content":"images,snippets","type":"dir"}]', ValueError('clone collision')]) as run:
                with self.assertRaisesRegex(ValueError, 'clone collision'):
                    module.main(values)
                self.assertEqual(run.call_count, 4)
                self.assertEqual(run.call_args.args[:4], ('qm', 'clone', '9006', expected))

    def test_generated_pack_matches(self):
        self.assertEqual(json.loads((BASE / 'proxmox_vm_create_pack.json').read_text(encoding='utf-8')), load('build_pack').build())

    @unittest.skipUnless(os.name == 'posix', 'Requires Linux Bash/fcntl')
    def test_parameter_injection_is_data_even_with_agent_preamble(self):
        pack = load('build_pack').build()
        payload = pack['templates'][0]['payload']
        for attack in ["$(touch ATTACK)", "'; touch ATTACK; #", "WINHUB_PYTHON\ntouch ATTACK\n#"]:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                script = payload['script']
                values = {k.split('_', 1)[1]: v['default'] for k, v in payload['__variable_schema'].items()}
                values.update(Mode=attack, VMID='115', Name='TEST', WindowsHostname='TEST', IP='192.168.38.234', Mask='24', Gateway='192.168.38.1', DNS='8.8.8.8', AdminPassword='Temporary!12345')
                for field in payload['__variable_schema']:
                    script = script.replace('{{' + field + '}}', values[field.split('_', 1)[1]])
                candidate = Path(directory) / 'task.sh'
                candidate.write_text('#!/usr/bin/env bash\nset -o pipefail\nexport LANG=C.UTF-8\n' + script)
                result = subprocess.run(['/bin/bash', str(candidate)], cwd=directory, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(directory) / 'ATTACK').exists())

    @unittest.skipUnless(os.name == 'posix', 'Requires fcntl')
    def test_invalid_inputs_and_occupied_vmid_never_mutate(self):
        module = load('create_vm')
        values = {k: v[1] for k, v in load('build_pack').FIELDS.items()}
        values.update(VMID='115', Name='TEST', WindowsHostname='TEST', IP='192.168.38.234', Mask='255.255.255.0', Gateway='192.168.38.1', DNS='8.8.8.8', AdminPassword='Temporary!12345')
        for changes in [dict(Name='x;reboot'), dict(IP='invalid'), dict(Gateway='10.0.0.1'), dict(Cores='-1'), dict(Mode='Delete')]:
            with self.subTest(changes=changes), patch.object(module, 'run') as run:
                with self.assertRaises(ValueError):
                    module.main(dict(values, **changes))
                run.assert_not_called()
        from unittest.mock import mock_open
        with patch.object(module.os, 'geteuid', return_value=0), patch('builtins.open', mock_open()), patch.object(module.fcntl, 'flock'), patch.object(module, 'run', return_value='[{"vmid":115}]') as run:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                module.main(values)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], 'pvesh')


if __name__ == '__main__':
    unittest.main()
