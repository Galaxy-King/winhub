import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == 'nt', 'Requires Windows PowerShell')
class GpoManifestTests(unittest.TestCase):
    def test_unc_normalization_without_network_access(self):
        helper = (ROOT / 'WinHUBAgentWindows/deploy/gpo/prepare-gpo-manifest.ps1').read_text()
        function = 'function Get-NormalizedGpoPath' + helper.split('function Get-NormalizedGpoPath', 1)[1].split('\n$source =', 1)[0]
        script = function + r'''
$a = Get-NormalizedGpoPath 'Microsoft.PowerShell.Core\FileSystem::\\server\netlogon\WinHUBAgentDeploy\'
$b = Get-NormalizedGpoPath '\\SERVER\netlogon\WinHUBAgentDeploy\.'
if (-not [string]::Equals($a, $b, [StringComparison]::OrdinalIgnoreCase)) { throw 'UNC normalization mismatch' }
'''
        env = {k: v for k, v in os.environ.items() if k.lower() != 'psmodulepath'}
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_metadata_epoch_and_failure_preservation(self):
        with tempfile.TemporaryDirectory(prefix='winhub-gpo-') as temp:
            folder = Path(temp)
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key()
            pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            (folder / 'release-signing-public.pem').write_bytes(pem)
            manifest = folder / 'deployment-manifest.json'
            manifest.write_text(json.dumps({'server_identity_epoch': 'existing-epoch',
                'publisher_public_key_sha256': hashlib.sha256(pem).hexdigest()}))
            package = folder / 'signed package.zip'
            payload = dict(schema=1, platform='windows', architecture='x64', version='2.0.1-rc.3',
                key_id=hashlib.sha256(der).hexdigest())
            # Metadata preparation does not execute the archive or verify signatures.
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('release-manifest.json', json.dumps(dict(algorithm='rsa-pss-sha256',
                    signature='fixture', payload=base64.b64encode(json.dumps(payload).encode()).decode())))
                for name in ('WinHUBAgent.exe', 'install-service.ps1', 'uninstall-service.ps1',
                             'update-service.ps1', 'update-protocol.json', 'appsettings.json'):
                    archive.writestr(name, 'test fixture; never executed')
            command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                str(ROOT / 'WinHUBAgentWindows/deploy/gpo/prepare-gpo-manifest.ps1'),
                '-PackagePath', str(package), '-SourceDir', str(folder)]
            env = {k: v for k, v in os.environ.items() if k.lower() != 'psmodulepath'}
            result = subprocess.run(command, capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(manifest.read_text())
            self.assertEqual(data['version'], '2.0.1-rc.3')
            self.assertEqual(data['package'], package.name)
            self.assertEqual(data['sha256'].lower(), hashlib.sha256(package.read_bytes()).hexdigest())
            self.assertEqual(data['server_identity_epoch'], 'existing-epoch')
            self.assertEqual(len(list(folder.glob('deployment-manifest.json.backup-*'))), 1)
            helper = folder / 'prepare-gpo-manifest.ps1'
            helper.write_bytes((ROOT / 'WinHUBAgentWindows/deploy/gpo/prepare-gpo-manifest.ps1').read_bytes())
            default_source = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(helper), '-PackagePath', str(package)], capture_output=True, text=True, env=env)
            self.assertEqual(default_source.returncode, 0, default_source.stdout + default_source.stderr)
            original = manifest.read_bytes()
            (folder / 'release-signing-public.pem').write_bytes(pem.replace(b'MI', b'NI', 1))
            rejected = subprocess.run(command, capture_output=True, text=True, env=env)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(manifest.read_bytes(), original)
