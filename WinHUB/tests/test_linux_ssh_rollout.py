import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'WinHUBLinuxAgent/deploy-linux-agents.sh'


@unittest.skipUnless(os.name == 'posix', 'Requires WSL/Linux Bash')
class LinuxSshRolloutTests(unittest.TestCase):
    def test_windows_hosts_file_deduplicates_and_continues_after_failed_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hosts = root / 'hosts.txt'
            hosts.write_bytes(b'\xef\xbb\xbf# test\r\n192.0.2.1\r\n192.0.2.1\r\n\r\n192.0.2.2 # next\r\n')
            ssh = root / 'ssh'
            ssh.write_text('''#!/bin/bash
if [[ "$*" == *192.0.2.1* ]]; then exit 1; fi
if [[ "$*" == *__WINHUB_PREFLIGHT__* ]]; then
  printf '__WINHUB_PREFLIGHT__0|debian||x86_64\\n'
else
  cat >/dev/null
fi
''')
            ssh.chmod(0o755)
            result = subprocess.run(['bash', str(SCRIPT), '--action', 'uninstall', '--hosts', str(hosts), '--yes'],
                                    env=dict(os.environ, PATH=str(root) + ':' + os.environ['PATH']),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout.count('==> root@192.0.2.1'), 1)
            self.assertIn('==> root@192.0.2.2', result.stdout)
            self.assertIn('успішно=1, помилок=1, всього=2', result.stdout)

    def test_wrong_package_checksum_blocks_before_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hosts = root / 'hosts.txt'
            hosts.write_text('192.0.2.1\n')
            package = root / 'WinHUBLinuxAgent-v2.0.1-rc.3-linux-x64.tar.gz'
            package.write_bytes(b'synthetic invalid package')
            result = subprocess.run(['bash', str(SCRIPT), '--action', 'install', '--hosts', str(hosts),
                                     '--package', str(package), '--sha256', '0' * 64, '--yes'],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SHA-256 mismatch', result.stderr)
            self.assertNotIn('==>', result.stdout)


if __name__ == '__main__':
    unittest.main()
