"""Exercise manual installer trust provisioning without touching real services."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('windows_release_signer', ROOT / 'WinHUBLinuxAgent/tools/sign-release.py')
SIGNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNER)


@unittest.skipUnless(os.name == 'nt', 'Requires Windows and a NativeAOT publish')
class WindowsBundledTrustTests(unittest.TestCase):
    def test_provision_preserve_and_reject_before_service_changes(self):
        binaries = list((ROOT / 'WinHUBAgentWindows/dist-agent').glob('publish-*/WinHUBAgent.exe'))
        if not binaries:
            self.skipTest('Build a Windows NativeAOT release first')
        binary = max(binaries, key=lambda p: p.stat().st_mtime)
        version = subprocess.check_output([str(binary), '--version'], text=True).strip()
        installer = (ROOT / 'WinHUBAgentWindows/install-service.ps1').read_text(encoding='utf-8-sig')
        function = 'function Install-WinHUBReleaseTrust' + installer.split('function Install-WinHUBReleaseTrust', 1)[1].split('function Ensure-WinHUBAgentRecovery', 1)[0]
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        for case in ('new', 'same', 'different', 'tamper', 'missing-file', 'orphan-state', 'legacy'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='winhub-win-trust-') as tmp:
                root = Path(tmp)
                source = root / 'source'
                source.mkdir()
                for name in ('appsettings.json', 'install-service.ps1', 'uninstall-service.ps1', 'update-protocol.json', 'update-service.ps1'):
                    shutil.copyfile(ROOT / 'WinHUBAgentWindows' / name, source / name)
                shutil.copyfile(binary, source / 'WinHUBAgent.exe')
                archive = root / 'signed.zip'
                SIGNER.create_package(source, archive, key, 'windows', 'x64', version, 2026111801, bundle_public_key=True)
                package = root / 'package'
                with zipfile.ZipFile(archive) as zipped:
                    zipped.extractall(package)
                # Existing runtime config must not break release verification.
                (package / 'winhub_agent.conf').write_text('{}')
                data = root / 'data'
                data.mkdir()
                target = data / 'release-signing-public.pem'
                if case in ('same', 'different'):
                    target.write_bytes(public if case == 'same' else b'existing trust must survive')
                if case == 'tamper':
                    (package / 'appsettings.json').write_text('tampered')
                if case == 'missing-file':
                    (package / 'update-service.ps1').unlink()
                if case == 'orphan-state':
                    (data / 'release-state.json').write_text('{}')
                if case == 'legacy':
                    (package / 'release-signing-public.pem').unlink()
                runner = root / 'test.ps1'
                runner.write_text("$ErrorActionPreference='Stop'\n" + function + "\nfunction icacls { $global:LASTEXITCODE=0 }\nInstall-WinHUBReleaseTrust -SourceDir '" + str(package) + "' -DataDir '" + str(data) + "'\n", encoding='utf-8-sig')
                result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(runner)], capture_output=True, text=True)
                success = case in ('new', 'same', 'legacy')
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if case in ('new', 'same'):
                    self.assertEqual(target.read_bytes(), public)
                elif case == 'different':
                    self.assertEqual(target.read_bytes(), b'existing trust must survive')
                else:
                    self.assertFalse(target.exists())
                self.assertFalse(list(data.glob('trust-check-*')))
