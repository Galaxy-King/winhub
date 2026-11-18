"""Run installer trust preflight in isolation, without changing services or /etc."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == 'posix', 'Requires Bash')
class LinuxBundledTrustTests(unittest.TestCase):
    def test_existing_key_is_preserved_and_verification_failure_blocks_install(self):
        installer = (ROOT / 'WinHUBLinuxAgent/install-linux-agent.sh').read_text()
        preflight = installer.split("bundled_trust='./release-signing-public.pem'", 1)[1].split('systemctl stop', 1)[0]
        for existing, verifier, expected in [(None, 0, 0), ('same', 0, 0), ('different', 0, 1), (None, 1, 1)]:
            with self.subTest(existing=existing, verifier=verifier), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                data = directory / 'data'
                data.mkdir()
                (directory / 'release-signing-public.pem').write_text('same')
                installed = data / 'release-signing-public.pem'
                if existing is not None:
                    installed.write_text(existing)
                binary = directory / 'WinHUBLinuxAgent'
                binary.write_text('#!/bin/bash\nexit ' + str(verifier) + '\n')
                binary.chmod(0o755)
                script = "set -euo pipefail\ndata_dir=\"$PWD/data\"\nbundled_trust='./release-signing-public.pem'" + preflight
                result = subprocess.run(['/bin/bash', '-c', script], cwd=directory, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected == 0, result.stderr)
                if existing is not None:
                    self.assertEqual(installed.read_text(), existing)
                else:
                    self.assertFalse(installed.exists(), 'Preflight must not provision trust before verification')


if __name__ == '__main__':
    unittest.main()
