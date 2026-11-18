"""Executed by the import-pack Bash wrapper; inputs are data, never Python code."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import string
import subprocess
import sys
import fcntl


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=1500)
    if result.returncode:
        # Commands may contain credentials. Do not print argv/stdout/stderr.
        raise ValueError(f"{args[0]} {args[1]} failed; inspect Proxmox task log locally")
    return result.stdout


def number(value, minimum, maximum):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("Expected an unsigned integer")
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError("Integer outside allowed range")
    return value


def generate_password():
    alphabet = string.ascii_letters + string.digits + '!@#%+-_'
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(24))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in '!@#%+-_' for c in password)):
            return password


def main(p):
    mode = p['Mode']
    if mode not in ('Validate', 'Create'):
        raise ValueError('Mode must be Validate or Create')
    template = number(p['TemplateID'], 100, 999999999)
    vmid = number(p['VMID'], 100, 999999999) if p['VMID'].strip() else None
    if template == vmid:
        raise ValueError('VMID must differ from template')
    name = p['Name']
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9.-]{0,252}', name) or any(not label or label.endswith('-') or len(label) > 63 for label in name.split('.')):
        raise ValueError('Invalid Proxmox VM name: use DNS-style letters, digits, dots and hyphens')
    hostname = p['WindowsHostname'].strip() or ('WIN-' + secrets.token_hex(5).upper())
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,14}', hostname) or hostname.endswith('-'):
        raise ValueError('Windows hostname: 1..15 ASCII letters/digits/hyphens, starting with a letter')
    storage = p['Storage']
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', storage):
        raise ValueError('Invalid storage name')
    address = ipaddress.IPv4Interface(p['IP'] + '/' + p['Mask'])
    gateway = ipaddress.IPv4Address(p['Gateway'])
    if address.ip in (address.network.network_address, address.network.broadcast_address):
        raise ValueError('IP is a network or broadcast address')
    if gateway not in address.network or gateway == address.ip:
        raise ValueError('Gateway must be a different address within subnet')
    dns = ' '.join(str(ipaddress.IPv4Address(x)) for x in p['DNS'].replace(',', ' ').split())
    if not dns:
        raise ValueError('DNS is required')
    overrides = []
    for key, flag, minimum, maximum in [('Cores', '--cores', 1, 256), ('MemoryMB', '--memory', 512, 1048576)]:
        if p[key]:
            overrides += [flag, str(number(p[key], minimum, maximum))]
    disk = number(p['DiskGB'], 1, 65536) if p['DiskGB'] else None
    bridge = p['Bridge']
    if bridge and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', bridge):
        raise ValueError('Invalid bridge')
    vlan = str(number(p['VLAN'], 1, 4094)) if p['VLAN'] else None
    if os.geteuid() != 0:
        raise ValueError('Run on Proxmox as root')
    os.umask(0o077)
    # Serialize this pack across VMIDs on this node; Proxmox also arbitrates VMID allocation.
    with open('/run/lock/winhub-vm-create.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guests = json.loads(run('pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'))
        occupied = {int(x['vmid']) for x in guests}
        occupied.add(template)
        if vmid is None:
            vmid = 100
            while vmid in occupied:
                vmid += 1
            if vmid > 999999999:
                raise ValueError('No free VMID available')
        if vmid in occupied:
            raise ValueError('VMID already exists; no changes made. Choose a new VMID or inspect partial VM')
        cfg = dict(line.split(': ', 1) for line in run('qm', 'config', str(template)).splitlines() if ': ' in line)
        if cfg.get('template') != '1' or cfg.get('citype') != 'configdrive2' or 'cloudinit' not in cfg.get('ide2', ''):
            raise ValueError(f'Invalid source template {template}: expected template=1, citype=configdrive2, Cloud-Init at ide2; actual template={cfg.get("template")!r}, citype={cfg.get("citype")!r}, ide2={cfg.get("ide2")!r}')
        if not cfg.get('ostype', '').startswith('win'):
            raise ValueError('Template is not Windows')
        match = re.search(r'(?:^|,)size=([0-9.]+)([GMT])(?:,|$)', cfg.get('scsi0', ''))
        if disk:
            if not match:
                raise ValueError('Cannot determine scsi0 size')
            current = float(match[1]) * {'M': 1/1024, 'G': 1, 'T': 1024}[match[2]]
            if disk < current:
                raise ValueError('Disk shrinking is forbidden')
        stores = json.loads(run('pvesh', 'get', '/storage', '--output-format', 'json'))
        if not any(x.get('storage') == storage and 'images' in x.get('content', '').split(',') and not x.get('disable') for x in stores):
            raise ValueError('Storage must support VM images and be enabled')
        snippet_store = next((x for x in stores if x.get('storage') == storage and x.get('type') == 'dir' and 'snippets' in x.get('content', '').split(',') and not x.get('disable')), None)
        if snippet_store is None:
            raise ValueError('Target storage must be Directory storage with Images and Snippets enabled')
        if bridge and not Path('/sys/class/net', bridge).exists():
            raise ValueError('Bridge does not exist on node')
        print(json.dumps({'mode': mode, 'vmid': vmid, 'name': name, 'windows_hostname': hostname, 'ip': str(address), 'storage': storage}))
        if mode == 'Validate':
            print('Validation passed. VMID is a preview, not a reservation; Create selects again. No VM created. IP availability and guest readiness are not verified.')
            return
        password = generate_password()
        try:
            run('qm', 'clone', str(template), str(vmid), '--name', name, '--full', '1', '--storage', storage)
            run('qm', 'set', str(vmid), '--citype', 'configdrive2', '--ciuser', 'Administrator', '--cipassword', password,
                '--ipconfig0', f'ip={address},gw={gateway}', '--nameserver', dns, '--ciupgrade', '0', *overrides)
            print(json.dumps({'vmid': vmid, 'username': 'Administrator', 'temporary_password': password, 'guest_password_applied': 'not verified'}), flush=True)
            if bridge or vlan:
                net = dict(line.split(': ', 1) for line in run('qm', 'config', str(vmid)).splitlines() if ': ' in line)['net0']
                parts = [x for x in net.split(',') if not (bridge and x.startswith('bridge=')) and not (vlan and x.startswith('tag='))]
                if bridge:
                    parts.append('bridge=' + bridge)
                if vlan:
                    parts.append('tag=' + vlan)
                run('qm', 'set', str(vmid), '--net0', ','.join(parts))
            if disk:
                run('qm', 'resize', str(vmid), 'scsi0', str(disk) + 'G')
            # Preserve generated instance identity; override only Windows naming metadata.
            metadata = json.loads(run('qm', 'cloudinit', 'dump', str(vmid), 'meta'))
            metadata['hostname'] = hostname
            metadata['name'] = hostname
            metadata['admin_username'] = 'Administrator'
            metadata['admin_pass'] = password
            volume = f'{storage}:snippets/winhub-vm-{vmid}-{secrets.token_hex(12)}-meta.json'
            snippet = Path(run('pvesm', 'path', volume).strip())
            if not snippet.is_absolute() or snippet.parent.is_symlink():
                raise ValueError('Unsafe snippets directory')
            snippet.parent.mkdir(parents=True, exist_ok=True)
            with snippet.open('x', encoding='utf-8') as output:
                json.dump(metadata, output)
            run('qm', 'set', str(vmid), '--cicustom', 'meta=' + volume)
            run('qm', 'cloudinit', 'update', str(vmid))
            run('qm', 'start', str(vmid))
            print('VM started. Temporary credentials are listed above. Guest preparation/password application/RDP readiness must be checked separately.')
        except Exception:
            print(f'Inspect VMID {vmid} before retry; partial clone may exist. No automatic deletion or resume.', file=sys.stderr)
            raise


if __name__ == '__main__':
    try:
        raw = Path(sys.argv[1]).read_text(encoding='utf-8').split('\n# WINHUB_INPUT\n', 1)[1]
        pairs = [line.split('=', 1) for line in raw.splitlines()]
        expected = {'Mode', 'TemplateID', 'VMID', 'Name', 'WindowsHostname', 'Storage', 'IP', 'Mask', 'Gateway', 'DNS', 'Cores', 'MemoryMB', 'DiskGB', 'Bridge', 'VLAN'}
        if any(len(x) != 2 for x in pairs) or len(pairs) != len(expected) or {x[0] for x in pairs} != expected:
            raise ValueError('Invalid input fields; multiline values are forbidden')
        main(dict(pairs))
    except Exception as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
