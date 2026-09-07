"""Exercise new CLI against an ephemeral loopback TLS server, never a real WinHUB."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None

REPO = Path(__file__).resolve().parents[2]
BINARIES = [path for path in (
    REPO / 'WinHUBAgentWindows/bin/Release/net8.0-windows/WinHUBAgent.dll',
    REPO / 'WinHUBLinuxAgent/bin/Release/net8.0/WinHUBLinuxAgent.dll',
) if path.is_file() and (os.name == 'nt' or 'net8.0-windows' not in str(path))]


@unittest.skipUnless(x509 and shutil.which('dotnet') and BINARIES, 'Requires cryptography and built agent DLLs')
class UpdateTlsPreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='winhub-preflight-tls-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'WinHUB ephemeral test')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(minutes=5)).sign(key, hashes.SHA256()))
        self.pin = cert.fingerprint(hashes.SHA256()).hex()
        cert_path, key_path = self.root / 'test-cert.pem', self.root / 'test-key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        self.paths, self.body, self.code = [], b'{"status":"ok"}', 200
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.paths.append(self.path)
                self.send_response(test.code)
                if test.code == 302:
                    self.send_header('Location', '/must-not-follow')
                self.send_header('Content-Length', str(len(test.body)))
                self.end_headers()
                try:
                    self.wfile.write(test.body)
                except (BrokenPipeError, ssl.SSLError, ConnectionResetError):
                    pass

            def log_message(self, *_):
                pass

        class Server(HTTPServer):
            def handle_error(self, *_):
                # A rejected certificate is expected in the negative pin test.
                import sys
                if not isinstance(sys.exception(), ssl.SSLError):
                    super().handle_error(*_)

        self.server = Server(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def probe(self, binary, pin=None):
        config = {'ServerUrl': f'https://127.0.0.1:{self.server.server_port}',
                  'ServerCertificateSha256': self.pin if pin is None else pin,
                  'RequireTaskSignature': True, 'IgnoreTlsCertificateErrors': False}
        path = self.root / 'synthetic.conf'
        content = json.dumps(config).encode()
        path.write_bytes(content)
        result = subprocess.run(['dotnet', str(binary), '--check-update-server', str(path)],
                                capture_output=True, timeout=45, cwd=self.root)
        self.assertEqual(path.read_bytes(), content, 'Preflight must not rewrite config/state')
        return result

    def test_matching_explicit_pin_succeeds_without_enrollment_or_poll(self):
        for binary in BINARIES:
            result = self.probe(binary)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(self.paths, ['/api/health'] * len(BINARIES))

    def test_wrong_pin_never_sends_http_request(self):
        for binary in BINARIES:
            self.assertNotEqual(self.probe(binary, 'ab' * 32).returncode, 0)
        self.assertEqual(self.paths, [])

    def test_redirect_is_not_followed(self):
        self.code = 302
        for binary in BINARIES:
            self.assertNotEqual(self.probe(binary).returncode, 0)
        self.assertEqual(self.paths, ['/api/health'] * len(BINARIES))

    def test_error_and_oversized_response_fail(self):
        for body in (b'{"status":"error"}', b'x' * 65537):
            self.body = body
            for binary in BINARIES:
                self.assertNotEqual(self.probe(binary).returncode, 0)
