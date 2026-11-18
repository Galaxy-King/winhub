import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/proxmox/register_omv_template.py'
SPEC = importlib.util.spec_from_file_location('omv_register', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OmvRegistrationTests(unittest.TestCase):
    def test_hosts_bom_comments_duplicates_and_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            hosts = Path(temp) / 'hosts.txt'
            hosts.write_bytes(b'\xef\xbb\xbf#33\r\n192.0.2.1\r\n#44192.0.2.1\r\n192.0.2.1 # duplicate\r\nroot@192.0.2.2\r\n')
            self.assertEqual(MODULE.read_hosts(hosts), ['root@192.0.2.1', 'root@192.0.2.2'])
            hosts.write_text('$(reboot)\n')
            with self.assertRaises(ValueError):
                MODULE.read_hosts(hosts)

    @unittest.skipUnless(os.name == 'posix', 'Requires fcntl')
    def test_register_idempotent_and_conflicts_never_overwrite(self):
        real_path = Path
        real_open = open
        with tempfile.TemporaryDirectory() as temp:
            root = real_path(temp)
            node = root / 'etc/pve/nodes/node1'
            (node / 'qemu-server').mkdir(parents=True)
            (root / 'etc/pve/local').symlink_to(node, target_is_directory=True)
            (root / 'etc/pve/qemu-server').symlink_to(node / 'qemu-server', target_is_directory=True)
            (root / 'sys/class/net/vmbr1').mkdir(parents=True)
            mount = root / 'mount'
            mount.mkdir()
            volumes = {}
            for name in ['base-9006-disk-0.qcow2', 'base-9006-disk-1.qcow2', 'vm-9006-cloudinit.qcow2']:
                path = mount / name
                path.write_bytes(b'synthetic disk')
                volumes['OMV:9006/' + name] = path
            config = node / 'qemu-server/9006.conf'
            storage = dict(storage='OMV', type='cifs', server='10.97.197.100', share='Proxmox', username='proxmox', content='images', path=str(mount))
            calls = []
            def path_factory(value, *args):
                value = str(value)
                if value.startswith('/etc/pve') or value.startswith('/sys/class/net') or value.startswith('/var/lib/winhub-proxmox-admin'):
                    return real_path(root / value.lstrip('/'), *args)
                return real_path(value, *args)
            def open_factory(path, *args, **kwargs):
                return real_open(root / 'lock' if str(path).startswith('/run/lock/') else path, *args, **kwargs)
            def command(argv, **kwargs):
                calls.append(argv)
                text = ''
                if argv[:3] == ('pvesh', 'get', '/nodes'): text = '[{"node":"node1"}]'
                elif argv[:3] == ('pvesh', 'get', '/cluster/resources'):
                    text = json.dumps([dict(vmid=9006, node='node1', type='qemu')] if config.exists() else [])
                elif argv[:3] == ('pvesh', 'get', '/storage'): text = json.dumps([storage] if storage.get('storage') else [])
                elif argv[:3] == ('pvesh', 'get', '/storage/OMV'): text = json.dumps(storage)
                elif argv[:2] == ('pvesm', 'status'): text = 'Name Type Status\nOMV cifs active 100 20 80\n'
                elif argv[:2] == ('pvesm', 'path'): text = str(volumes[argv[2]])
                elif argv[0] == 'findmnt': text = json.dumps({'filesystems': [dict(fstype='cifs', source='//10.97.197.100/Proxmox')]})
                elif argv[:2] == ('qm', 'config'):
                    text = config.read_text()
                    if 'ms-cert=2023k' in text:
                        text = '\n'.join(line for line in text.splitlines() if not line.startswith('efidisk0:'))
                elif argv[:2] == ('pvesm', 'add'): return subprocess.CompletedProcess(argv, 1, '', 'synthetic secret: ' + p['password'])
                else: raise AssertionError('Unexpected mutation: ' + repr(argv))
                return subprocess.CompletedProcess(argv, 0, text, '')
            p = dict(server=storage['server'], share='Proxmox', username='proxmox', domain='', password='synthetic', storage='OMV', vmid=9006, template=MODULE.TEMPLATE, content='images')
            with patch('pathlib.Path', side_effect=path_factory), patch('builtins.open', side_effect=open_factory), patch('os.geteuid', return_value=0), patch('subprocess.run', side_effect=command):
                MODULE.remote_main(p)
                self.assertEqual(config.read_text(), MODULE.TEMPLATE)
                # Proxmox normalizes option ordering while retaining semantics.
                config.write_text(MODULE.TEMPLATE.replace(
                    'efitype=4m,pre-enrolled-keys=1,size=528K',
                    'size=528K,pre-enrolled-keys=1,efitype=4m'))
                MODULE.remote_main(p)
                config.write_text(MODULE.TEMPLATE.replace('efitype=4m,', 'efitype=4m,ms-cert=2023k,'))
                MODULE.remote_main(p)
                self.assertNotIn('ms-cert=', config.read_text())
                backups = list((root / 'var/lib/winhub-proxmox-admin/config-backups').glob('*.conf'))
                self.assertEqual(len(backups), 1)
                self.assertIn('ms-cert=2023k', backups[0].read_text())
                config.write_text(MODULE.TEMPLATE.replace('base-9006-disk-0.qcow2', 'wrong-disk.qcow2'))
                with self.assertRaisesRegex(ValueError, 'different efidisk0'):
                    MODULE.remote_main(p)
                config.write_text('name: occupied\ntemplate: 0\n')
                with self.assertRaisesRegex(ValueError, 'exists with different'):
                    MODULE.remote_main(p)
                self.assertEqual(config.read_text(), 'name: occupied\ntemplate: 0\n')
                config.unlink()
                storage['server'] = '192.0.2.55'
                with self.assertRaisesRegex(ValueError, 'different server'):
                    MODULE.remote_main(p)
                self.assertFalse(config.exists())
                storage['server'] = p['server']
                volumes['OMV:9006/base-9006-disk-1.qcow2'].unlink()
                with self.assertRaises(FileNotFoundError):
                    MODULE.remote_main(p)
                self.assertFalse(config.exists())
                storage['storage'] = ''
                with self.assertRaisesRegex(ValueError, 'pvesm add failed') as error:
                    MODULE.remote_main(p)
                self.assertNotIn(p['password'], str(error.exception))
                self.assertFalse(config.exists())
            self.assertFalse(any(c[:2] in [('qm', 'start'), ('qm', 'template'), ('pvesm', 'set')] for c in calls))


if __name__ == '__main__':
    unittest.main()
