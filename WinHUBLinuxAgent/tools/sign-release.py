#!/usr/bin/env python3
"""Offline release publisher. Requires cryptography on the BUILD machine, not endpoints."""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile
import io

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


MANIFEST = 'release-manifest.json'
REPO = Path(__file__).resolve().parents[2]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def signing_key(path, password):
    path = Path(path).resolve()
    if path.is_relative_to(REPO) or any(part.lower() in {'opencloud', 'onedrive', 'dropbox'} for part in path.parts):
        raise ValueError('Private signing key must remain outside Git and synchronized folders')
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, rsa.RSAPrivateKey) or not 3072 <= key.key_size <= 8192:
        raise ValueError('RSA 3072-8192 release key required')
    return key


def key_id(key):
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    return hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def signed_envelope(key, payload):
    data = canonical(payload)
    signature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return canonical({'algorithm': 'rsa-pss-sha256', 'payload': base64.b64encode(data).decode(),
                      'signature': base64.b64encode(signature).decode()})


def create_package(source, output, key, platform, architecture, version, serial):
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.is_relative_to(source) or output.exists():
        raise ValueError('Output must be a NEW file outside the publish directory')
    if platform not in {'windows', 'linux'} or architecture not in {'x64', 'arm64'}:
        raise ValueError('Unsupported platform/architecture')
    if (len(version) > 128 or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?', version)
            or ('-' in version and any(p.isascii() and p.isdigit() and len(p) > 1 and p[0] == '0' for p in version.split('-', 1)[1].split('.')))
            or not 0 < serial < 2**63):
        raise ValueError('A semantic version and positive globally increasing release serial are required')
    descriptor = json.loads((source / 'update-protocol.json').read_text(encoding='utf-8'))
    if descriptor != {'protocol': 2, 'platform': platform}:
        raise ValueError('Publish folder lacks the expected update protocol descriptor')
    snapshot, entries, folded, total = [], [], set(), 0
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinks are forbidden in published files')
        if path.is_dir():
            continue
        name = path.relative_to(source).as_posix()
        if path.suffix.lower() in {'.pdb', '.dbg'}:
            continue
        if (name == MANIFEST or any(part.startswith('.') for part in path.relative_to(source).parts)
                or path.name.lower() in {'winhub_agent.conf', 'winhub_agent.bootstrap.conf', 'agent.secrets', 'release-state.json'}
                or path.suffix.lower() in {'.pem', '.key', '.pfx', '.p12', '.zip', '.gz', '.db', '.log'}):
            raise ValueError('Runtime, secret or pre-signed artifact in publish folder: ' + name)
        if (name.lower() in folded or len(name) > 512 or '\\' in name or ':' in name
                or any(part in {'', '.', '..'} or part.endswith((' ', '.')) for part in name.split('/'))):
            raise ValueError('Unsafe or duplicate publish path: ' + name)
        folded.add(name.lower())
        # Build artifacts are snapshotted once, so the signed hash describes archived bytes.
        size = path.stat().st_size
        total += size
        if size > 512 * 1024**2 or total > 2 * 1024**3 or len(entries) >= 4096:
            raise ValueError('Release exceeds supported limits')
        content = path.read_bytes()
        if len(content) != size:
            raise ValueError('Publish file changed while signing')
        entries.append({'path': name, 'size': size, 'sha256': hashlib.sha256(content).hexdigest()})
        snapshot.append((name, content))
    binary = 'WinHUBAgent.exe' if platform == 'windows' else 'WinHUBLinuxAgent'
    if binary not in folded and binary.lower() not in folded:
        raise ValueError('Agent executable missing')
    payload = {'schema': 1, 'key_id': key_id(key), 'platform': platform, 'architecture': architecture,
               'version': version, 'serial': serial, 'files': entries}
    envelope = signed_envelope(key, payload)
    snapshot.append((MANIFEST, envelope))
    output.parent.mkdir(parents=True, exist_ok=True)
    if platform == 'windows':
        if output.suffix != '.zip':
            raise ValueError('Windows output must end in .zip')
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in snapshot:
                archive.writestr(name, content)
    else:
        if not output.name.endswith('.tar.gz'):
            raise ValueError('Linux output must end in .tar.gz')
        with tarfile.open(output, 'x:gz') as archive:
            for name, content in snapshot:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o755 if name == binary or name.endswith('.sh') else 0o644
                member.uid = member.gid = 0
                archive.addfile(member, io.BytesIO(content))
    return hashlib.sha256(output.read_bytes()).hexdigest()


def create_key(directory, password):
    directory = Path(directory).resolve()
    if directory.is_relative_to(REPO) or any(part.lower() in {'opencloud', 'onedrive', 'dropbox'} for part in directory.parts):
        raise ValueError('Private signing material must remain outside Git and synchronized folders')
    if directory.exists():
        raise ValueError('Use a NEW dedicated signing-key directory; never overwrite or rotate implicitly')
    directory.mkdir(mode=0o700, parents=False)
    if os.name == 'nt':
        subprocess.run(['icacls', str(directory), '/inheritance:r', '/grant:r',
                        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], check=True)
    else:
        directory.chmod(0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(password))
    for name, content in (
        ('release-signing-private.pem', private),
        ('release-signing-public.pem', key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)),
    ):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return key_id(key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init-key')
    init.add_argument('--directory', required=True, type=Path)
    sign = sub.add_parser('sign')
    sign.add_argument('--source', required=True, type=Path)
    sign.add_argument('--output', required=True, type=Path)
    sign.add_argument('--key', required=True, type=Path)
    sign.add_argument('--platform', choices=['windows', 'linux'], required=True)
    sign.add_argument('--architecture', choices=['x64', 'arm64'], default='x64')
    sign.add_argument('--version', required=True)
    sign.add_argument('--serial', type=int, required=True)
    args = parser.parse_args()
    # Passwords never appear in arguments, manifests, stdout or environment variables.
    if not sys.stdin.isatty():
        raise ValueError('Use an interactive local terminal for the signing key passphrase; never pipe it or put it in arguments')
    password = getpass.getpass('Signing key passphrase: ').encode()
    if args.command == 'init-key':
        if len(password) < 20 or password != getpass.getpass('Repeat passphrase: ').encode():
            raise ValueError('Use a matching passphrase of at least 20 bytes')
        print('Public key ID:', create_key(args.directory, password))
        print('Keep an encrypted off-host backup of the private key and its passphrase separately.')
    else:
        key = signing_key(args.key, password)
        print('Signed package SHA256:', create_package(args.source, args.output, key, args.platform,
                                                       args.architecture, args.version, args.serial))


if __name__ == '__main__':
    main()
