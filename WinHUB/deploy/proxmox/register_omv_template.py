#!/usr/bin/env python3
"""Run from WSL: configure OMV CIFS via Proxmox and register existing template disks."""
import argparse
import getpass
import inspect
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

DEFAULT_SERVER = '10.97.197.100'
DEFAULT_SHARE = 'Proxmox'
DEFAULT_USERNAME = 'proxmox'
STORAGE = 'OMV'
TEMPLATE_ID = 9006

TEMPLATE = '''agent: 1
balloon: 0
bios: ovmf
boot: order=scsi0
citype: configdrive2
cores: 8
cpu: x86-64-v2-AES
efidisk0: OMV:9006/base-9006-disk-0.qcow2,efitype=4m,pre-enrolled-keys=1,size=528K
ide2: OMV:9006/vm-9006-cloudinit.qcow2,media=cdrom,size=4M
machine: pc-q35-11.0+pve2
memory: 16384
name: TPL-WS2025-CLOUDINIT
net0: virtio=BC:24:11:B1:FE:74,bridge=vmbr1,firewall=1
numa: 0
ostype: win11
scsi0: OMV:9006/base-9006-disk-1.qcow2,discard=on,iothread=1,size=110G,ssd=1
scsihw: virtio-scsi-single
smbios1: uuid=00a229ee-8ace-4c33-bac9-3e51eac2fb3d
sockets: 1
template: 1
vmgenid: 958cf739-a3f0-41a5-805b-6af3720147b8
'''


def remote_main(p):
    import fcntl
    import json
    import os
    from pathlib import Path
    import subprocess
    import time

    def run(*args):
        result = subprocess.run(args, text=True, capture_output=True, timeout=120)
        if result.returncode:
            # pvesm argv can contain the SMB password. Never echo it or stderr.
            raise ValueError(f'{args[0]} {args[1]} failed (exit {result.returncode}); inspect Proxmox locally')
        return result.stdout

    def api(path, *args):
        return json.loads(run('pvesh', 'get', path, *args, '--output-format', 'json'))

    def parse_config(text):
        return dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line and not line.startswith('#'))

    def verify_template(actual):
        expected = parse_config(p['template'])
        for key, value in expected.items():
            current = actual.get(key)
            # qm config canonicalizes property-string ordering (e.g. efidisk0).
            # Compare the volume/model and options rather than their text order.
            if key in ('efidisk0', 'ide2', 'scsi0', 'net0', 'smbios1') and current is not None:
                def properties(text):
                    return sorted(part.strip() for part in text.split(',') if not (key == 'efidisk0' and part.strip() == 'ms-cert=2023k'))
                equal = properties(current) == properties(value)
            else:
                equal = current == value
            if not equal:
                raise ValueError(f'VMID {p["vmid"]} exists with different {key}; left unchanged. Expected: {value!r}; actual: {current!r}')

    if os.geteuid() != 0:
        raise ValueError('SSH user must be root')
    os.umask(0o077)
    with open('/run/lock/winhub-omv-template.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        node = api('/nodes')
        local_name = Path('/etc/pve/local').resolve().name
        if local_name not in {x['node'] for x in node}:
            raise ValueError('Cannot identify local Proxmox node')
        vmid, storage = str(p['vmid']), p['storage']
        guests = api('/cluster/resources', '--type', 'vm')
        matches = [x for x in guests if str(x.get('vmid')) == vmid]
        existing = bool(matches)
        if existing:
            if len(matches) != 1 or matches[0].get('type') != 'qemu' or matches[0].get('node') != local_name:
                raise ValueError(f'VMID {vmid} occupied elsewhere in cluster; no duplicate registration')
            current = parse_config(run('qm', 'config', vmid))
            if 'efidisk0' not in current:
                # Older qemu-server drops the whole property from parsed output.
                target = Path('/etc/pve/qemu-server') / (vmid + '.conf')
                raw = target.read_text(encoding='utf-8')
                parsed = parse_config(raw)
                verify_template(parsed)
                if ',ms-cert=2023k' not in parsed.get('efidisk0', ''):
                    raise ValueError('EFI parsing failure is not the known ms-cert compatibility issue')
                if 'lock' in parsed or '[' in raw:
                    raise ValueError('Locked/snapshot configuration requires manual inspection')
                backup_dir = Path('/var/lib/winhub-proxmox-admin/config-backups')
                backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                import secrets
                backup = backup_dir / (vmid + '-' + secrets.token_hex(8) + '.conf')
                with backup.open('x', encoding='utf-8') as output:
                    output.write(raw)
                if target.read_text(encoding='utf-8') != raw:
                    raise ValueError('Configuration changed during inspection; no repair applied')
                repaired = '\n'.join(line.replace(',ms-cert=2023k', '') if line.startswith('efidisk0: ') else line for line in raw.splitlines()) + '\n'
                target.write_text(repaired, encoding='utf-8')
                print(f'Unsupported ms-cert removed from template config; backup: {backup}', flush=True)
                current = parse_config(run('qm', 'config', vmid))
            verify_template(current)
        stores = api('/storage')
        found = next((x for x in stores if x.get('storage') == storage), None)
        if found:
            for field, expected in [('type', 'cifs'), ('server', p['server']), ('share', p['share']), ('username', p['username']), ('domain', p['domain']), ('subdir', '')]:
                if str(found.get(field) or '') != expected:
                    raise ValueError(f'{storage}: different {field}; existing storage left unchanged')
            if found.get('disable'):
                raise ValueError(f'{storage} is disabled; enable it explicitly after inspection')
            content = set(found.get('content', '').split(',')) - {''}
            changes = []
            if 'images' not in content:
                changes += ['--content', ','.join(sorted(content | {'images'}))]
            nodes = found.get('nodes', '')
            if nodes and local_name not in nodes.split(','):
                changes += ['--nodes', ','.join(sorted(set(nodes.split(',')) | {local_name}))]
            if changes:
                run('pvesm', 'set', storage, *changes)
            print(f'{storage}: matching CIFS configuration found; existing credentials preserved', flush=True)
        else:
            args = ['pvesm', 'add', 'cifs', storage, '--server', p['server'], '--share', p['share'],
                    '--username', p['username'], '--password', p['password'], '--content', p['content'], '--nodes', local_name]
            if p['domain']:
                args += ['--domain', p['domain']]
            run(*args)
            print(f'{storage}: added through pvesm; visible in Proxmox GUI', flush=True)
        # pvesm status activates configured storage using the Proxmox plugin.
        active = False
        for attempt in range(3):
            status = run('pvesm', 'status', '--storage', storage).splitlines()
            active = any(len(line.split()) >= 3 and line.split()[:3] == [storage, 'cifs', 'active'] for line in status)
            if active:
                break
            time.sleep(2)
        if not active:
            raise ValueError(f'{storage} is not active; template not registered')
        settings = api('/storage/' + storage)
        mount = Path(settings.get('path') or '/mnt/pve/' + storage)
        info = json.loads(run('findmnt', '-J', '-M', str(mount)))['filesystems'][0]
        if info.get('fstype') != 'cifs' or info.get('source', '').rstrip('/') != f'//{p["server"]}/{p["share"]}':
            raise ValueError('Mounted source does not match the requested OMV IP/share')
        if not Path('/sys/class/net/vmbr1').exists():
            raise ValueError('vmbr1 missing; template not registered')
        cfg = parse_config(p['template'])
        for drive in ('scsi0', 'efidisk0', 'ide2'):
            volume = cfg[drive].split(',', 1)[0]
            path = Path(run('pvesm', 'path', volume).strip())
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(mount.resolve()) or not resolved.is_file() or resolved.stat().st_size == 0:
                raise ValueError(f'Missing/invalid shared template disk: {drive}')
        if existing:
            print(f'Template {vmid}: already registered correctly; no config changes')
            return
        # Recheck immediately before exclusive creation. Never overwrite any config.
        if any(str(x.get('vmid')) == vmid for x in api('/cluster/resources', '--type', 'vm')):
            raise ValueError(f'VMID {vmid} became occupied; template not registered')
        if list(Path('/etc/pve/nodes').glob('*/lxc/' + vmid + '.conf')) or list(Path('/etc/pve/nodes').glob('*/qemu-server/' + vmid + '.conf')):
            raise ValueError(f'VMID {vmid} has an existing configuration; left unchanged')
        target = Path('/etc/pve/qemu-server') / (vmid + '.conf')
        with target.open('x', encoding='utf-8') as output:
            output.write(p['template'])
        verify_template(parse_config(run('qm', 'config', vmid)))
        print(f'Template {vmid}: registered. No disk changes, cloning, qm template or VM start performed.')


def read_hosts(path):
    hosts = []
    for raw in Path(path).read_text(encoding='utf-8-sig').splitlines():
        value = raw.split('#', 1)[0].strip()
        if not value:
            continue
        user, sep, host = value.rpartition('@')
        if sep and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', user):
            raise ValueError('Invalid SSH user in hosts file')
        if not sep:
            host = value
        ipaddress.IPv4Address(host)
        destination = (user if sep else 'root') + '@' + host
        if destination not in hosts:
            hosts.append(destination)
    if not hosts:
        raise ValueError('Hosts file is empty')
    return hosts


def prompt(label, default=''):
    return input(f'{label}' + (f' [{default}]' if default else '') + ': ').strip() or default


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hosts', help='Text file: IPv4 or user@IPv4, one per line')
    parser.add_argument('--identity', help='SSH private key in WSL filesystem')
    parser.add_argument('--port', type=int, default=22)
    args = parser.parse_args()
    hosts = read_hosts(args.hosts or prompt('Hosts file', '../1C_Project.txt'))
    server = str(ipaddress.IPv4Address(prompt('OMV server IPv4', DEFAULT_SERVER)))
    share = prompt('SMB share name (not a URL)', DEFAULT_SHARE)
    if not share or any(c in share for c in '/\\\r\n\x00'):
        raise ValueError('Enter only the SMB share name, e.g. Proxmox')
    username = prompt('SMB username', DEFAULT_USERNAME)
    domain = prompt('SMB domain (Enter: none)')
    password = getpass.getpass('SMB password (hidden): ')
    if not password or any(c in password + username + domain for c in '\r\n\x00'):
        raise ValueError('Credentials must be nonempty single-line values')
    if not 1 <= args.port <= 65535:
        raise ValueError('Invalid SSH port')
    p = dict(server=server, share=share, username=username, domain=domain, password=password,
             storage=STORAGE, vmid=TEMPLATE_ID, template=TEMPLATE,
             content='images,iso,vztmpl,backup,rootdir,snippets,import')
    print(f'Hosts: {len(hosts)}; {STORAGE}: //{server}/{share}; template: {TEMPLATE_ID}')
    if prompt('Proceed? y/N', 'N').lower() not in ('y', 'yes'):
        return
    # Data is sent over encrypted SSH stdin, never interpolated into remote code.
    source = inspect.getsource(remote_main) + '\nimport json,sys\ntry:\n remote_main(json.load(sys.stdin))\nexcept Exception as e:\n print("ERROR: " + str(e) if isinstance(e, ValueError) else "ERROR: " + type(e).__name__, file=sys.stderr)\n sys.exit(1)\n'
    command = 'python3 -c ' + shlex.quote(source)
    failures = []
    for host in hosts:
        print(f'==> {host}', flush=True)
        argv = ['ssh', '-p', str(args.port), '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2']
        if args.identity:
            argv += ['-i', str(Path(args.identity).expanduser())]
        # SSH authentication prompts remain on the terminal; payload uses stdin.
        try:
            result = subprocess.run(argv + [host, command], input=json.dumps(p), text=True, timeout=600)
            if result.returncode:
                failures.append(host)
        except subprocess.TimeoutExpired:
            print('Timeout: inspect storage/config on this node before retry', flush=True)
            failures.append(host)
    password = ''
    p['password'] = ''
    print(f'Completed: success={len(hosts)-len(failures)}, failed={len(failures)}')
    if failures:
        print('Failed hosts: ' + ', '.join(failures))
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nInterrupted; inspect current node before retry', file=sys.stderr)
        sys.exit(130)
