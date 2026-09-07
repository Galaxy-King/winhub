"""Offline publisher -> actual .NET verifier interoperability; never starts an agent service."""
import base64
import hashlib
import importlib.util
import json
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
SPEC = importlib.util.spec_from_file_location('release_signer', ROOT / 'WinHUBLinuxAgent/tools/sign-release.py')
SIGNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNER)


class ReleaseSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.targets = []
        for platform, path in (
            ('windows', ROOT / 'WinHUBAgentWindows/bin/Release/net8.0-windows/WinHUBAgent.dll'),
            ('linux', ROOT / 'WinHUBLinuxAgent/bin/Release/net8.0/WinHUBLinuxAgent.dll'),
        ):
            if path.exists() and shutil.which('dotnet') and (platform != 'windows' or os.name == 'nt'):
                cls.targets.append((platform, ['dotnet', str(path)]))
        if os.environ.get('WINHUB_TEST_LINUX_BINARY'):
            cls.targets.append(('linux', [os.environ['WINHUB_TEST_LINUX_BINARY']]))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='winhub-release-signing-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.public = self.root / 'public.pem'
        self.public.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def package(self, platform='windows', serial=10, version='2.0.0-rc.3'):
        source = self.root / ('publish-' + platform)
        source.mkdir(exist_ok=True)
        (source / 'update-protocol.json').write_text(json.dumps({'protocol': 2, 'platform': platform}))
        (source / ('WinHUBAgent.exe' if platform == 'windows' else 'WinHUBLinuxAgent')).write_bytes(b'non-executable test fixture')
        suffix = '.zip' if platform == 'windows' else '.tar.gz'
        output = self.root / (platform + suffix)
        SIGNER.create_package(source, output, self.key, platform, 'x64', version, serial)
        return source, output

    def test_signer_inventory_signature_and_no_overwrite(self):
        source, package = self.package()
        with zipfile.ZipFile(package) as archive:
            envelope = json.loads(archive.read(SIGNER.MANIFEST))
            payload = base64.b64decode(envelope['payload'])
            manifest = json.loads(payload)
            self.key.public_key().verify(base64.b64decode(envelope['signature']), payload,
                SIGNER.padding.PSS(mgf=SIGNER.padding.MGF1(SIGNER.hashes.SHA256()), salt_length=32), SIGNER.hashes.SHA256())
            for item in manifest['files']:
                self.assertEqual(hashlib.sha256(archive.read(item['path'])).hexdigest(), item['sha256'])
            self.assertEqual(manifest['key_id'], SIGNER.key_id(self.key))
        with self.assertRaises(ValueError):
            SIGNER.create_package(source, package, self.key, 'windows', 'x64', '2.0.0-rc.3', 10)

    def test_secret_files_and_invalid_versions_rejected(self):
        source, _ = self.package()
        for name in ('agent.secrets', 'private.pem', 'winhub_agent.conf', '.env'):
            secret = source / name
            secret.write_text('synthetic fixture, not a credential')
            with self.assertRaises(ValueError):
                SIGNER.create_package(source, self.root / 'rejected.zip', self.key, 'windows', 'x64', '2.0.0', 11)
            secret.unlink()
        for version in ('v2.0', '2.0.0-rc.01', '2.0.0+metadata', '1' * 129):
            with self.assertRaises(ValueError):
                SIGNER.create_package(source, self.root / 'invalid.zip', self.key, 'windows', 'x64', version, 11)

    def test_private_key_location_policy_before_generation(self):
        for directory in (ROOT / 'never-create-signing-key', self.root / 'OpenCloud' / 'never-create'):
            with self.assertRaises(ValueError):
                SIGNER.create_key(directory, b'synthetic-test-passphrase')
            self.assertFalse(directory.exists())

    def verify(self, command, folder, state, expected_ok=True, installed='2.0.0-rc.2'):
        result = subprocess.run(command + ['--verify-release', str(folder), str(self.public), str(state), installed, '2.0.0-rc.3'],
                                text=True, capture_output=True, timeout=30)
        if expected_ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_agent_verification_adversarial_cases(self):
        if not self.targets:
            self.skipTest('Build agent first for actual verifier interoperability')
        for index, (platform, command) in enumerate(self.targets):
            with self.subTest(platform=platform, executable=command[0]):
                source, package = self.package(platform)
                folder = self.root / ('extracted-' + str(index))
                result = subprocess.run(command + ['--extract-update', str(package), str(folder)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                state = self.root / 'state.json'
                self.verify(command, folder, state)
                self.assertFalse(state.exists(), 'read-only verification must not reserve a release')
                manifest_path = folder / SIGNER.MANIFEST
                original = manifest_path.read_bytes()
                envelope = json.loads(original)
                manifest = json.loads(base64.b64decode(envelope['payload']))
                for field, value in (('platform', 'wrong'), ('architecture', 'arm64'), ('version', '1.0.0'), ('serial', 0)):
                    altered = dict(manifest, **{field: value})
                    manifest_path.write_bytes(SIGNER.signed_envelope(self.key, altered))
                    self.verify(command, folder, state, False)
                manifest_path.write_bytes(SIGNER.signed_envelope(self.other, manifest))
                self.verify(command, folder, state, False)
                envelope['payload'] = base64.b64encode(SIGNER.canonical(dict(manifest, serial=12))).decode()
                manifest_path.write_text(json.dumps(envelope))
                self.verify(command, folder, state, False)
                manifest_path.write_bytes(original)
                binary = folder / ('WinHUBAgent.exe' if platform == 'windows' else 'WinHUBLinuxAgent')
                original_binary = binary.read_bytes()
                binary.write_bytes(b'tampered file')
                self.verify(command, folder, state, False)
                binary.write_bytes(original_binary)
                extra = folder / 'unsigned.txt'
                extra.write_text('extra')
                self.verify(command, folder, state, False)
                extra.unlink()
                self.verify(command, folder, state, False, installed='2.0.0')
                floor = {'Serial': 10, 'Version': '2.0.0-rc.3', 'ManifestHash': hashlib.sha256(base64.b64decode(json.loads(original)['payload'])).hexdigest(),
                         'Platform': platform, 'Architecture': 'x64'}
                state.write_text(json.dumps(floor))
                self.verify(command, folder, state)
                for replacement in ({'Serial': 11}, {'ManifestHash': 'a' * 64}, {'Version': '2.1.0'}, {'ManifestHash': None}):
                    state.write_text(json.dumps(dict(floor, **replacement)))
                    self.verify(command, folder, state, False)
                state.unlink()
                manifest_path.unlink()
                self.verify(command, folder, state, False)
                package.unlink()


if __name__ == '__main__':
    unittest.main()
