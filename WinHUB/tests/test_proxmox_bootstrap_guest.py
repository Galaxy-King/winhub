import importlib.util
import io
import json
from pathlib import Path
import subprocess
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/import_templates/proxmox_vm_create/bootstrap_guest.py'
SPEC = importlib.util.spec_from_file_location('bootstrap_guest_test', SOURCE)
GUEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUEST)


class GuestBootstrapTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Requires Windows PowerShell/.NET Framework')
    def test_real_powershell_pinned_tls_delegate_and_parser(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta, timezone
        import base64
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'bootstrap.test')])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).sign(key, hashes.SHA256())
        source = (SOURCE.parent / 'install_bootstrap.ps1').read_text()
        compiled = source[source.index('    Add-Type -TypeDefinition'):source.index('    $pinnedTls =')]
        script = compiled + """
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String('__CERT__'))
$tls=New-Object WinHubPinnedTls -ArgumentList (,[string[]]@('__PIN__'))
if (-not $tls.Callback.Invoke($null,$cert,$null,[Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors)) { throw 'Valid explicit pin rejected' }
$wrong=New-Object WinHubPinnedTls -ArgumentList (,[string[]]@(('B'*64)))
if ($wrong.Callback.Invoke($null,$cert,$null,[Net.Security.SslPolicyErrors]::None)) { throw 'Wrong pin accepted' }
""".replace('__CERT__', base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()).replace('__PIN__', cert.fingerprint(hashes.SHA256()).hex())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pin.ps1'
            path.write_text(script, encoding='utf-8-sig')
            encoded = base64.b64encode(script.encode('utf-16-le')).decode()
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_secret_descriptor_goes_to_stdin_not_guest_argv(self):
        with patch.object(GUEST.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"exited":true,"exitcode":0}', '')) as run:
            GUEST.guest_exec(115, "'fixed script'", stdin='{"token":"SYNTHETIC_CAPABILITY"}')
            self.assertNotIn('SYNTHETIC_CAPABILITY', ' '.join(run.call_args.args[0]))
            self.assertEqual(run.call_args.kwargs['input'], '{"token":"SYNTHETIC_CAPABILITY"}')
            self.assertIn('--pass-stdin', run.call_args.args[0])

    def test_cloudbase_failure_prevents_installation(self):
        descriptor = {'grant_id': '621061af-42d4-443f-b220-e251c8fab924'}
        with patch.object(GUEST, 'guest_exec', return_value={'exited': True, 'exitcode': 0, 'out-data': '{"failed":true,"ready":false}'}) as execute:
            with self.assertRaisesRegex(ValueError, 'Cloudbase-Init failed'):
                GUEST.install_agent(115, 'WIN-TEST', '192.0.2.15', descriptor)
            self.assertEqual(execute.call_count, 1)

    def test_success_requires_server_confirmed_enrollment_and_no_capability_output(self):
        descriptor = {'grant_id': '621061af-42d4-443f-b220-e251c8fab924', 'token': 'SYNTHETIC_CAPABILITY'}
        status = {'exited': True, 'exitcode': 0, 'out-data': '{"registered":true,"endpoint_id":"NEW-VM","approval_status":"Pending"}'}
        results = [{'exited': True, 'exitcode': 0, 'out-data': '{"ready":true,"failed":false}'},
                   {'exited': True, 'exitcode': 0}, {'pid': 123}]
        output = io.StringIO()
        with patch.object(GUEST, 'guest_exec', side_effect=results) as execute, patch.object(GUEST.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(status), '')), redirect_stdout(output):
            GUEST.install_agent(115, 'WIN-TEST', '192.0.2.15', descriptor)
            self.assertIn('SYNTHETIC_CAPABILITY', execute.call_args_list[1].kwargs['stdin'])
            self.assertNotIn('SYNTHETIC_CAPABILITY', output.getvalue())
            self.assertIn('"approval_status": "Pending"', output.getvalue())

    def test_timeout_preserves_vm_and_does_not_start_installation(self):
        with patch.object(GUEST, 'guest_exec') as execute:
            with self.assertRaisesRegex(ValueError, 'readiness timeout'):
                GUEST.install_agent(115, 'WIN-TEST', '192.0.2.15',
                    {'grant_id': '621061af-42d4-443f-b220-e251c8fab924'}, deadline_seconds=0)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
