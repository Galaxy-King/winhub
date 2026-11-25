import json
import base64
from pathlib import Path

BASE = Path(__file__).resolve().parent
FIELDS = {
    'TemplateID': ('Source template VMID', '9006'),
    'Name': ('Proxmox VM name (e.g. term-192.168.38.234)', ''),
    'WindowsHostname': ('Windows hostname (blank: random; max 15 characters)', ''),
    'VMID': ('New VM ID (blank: first free from 100)', ''),
    'Mode': ('Operation', 'Validate'),
    'Storage': ('Target storage', 'local'),
    'IP': ('IPv4 address', ''),
    'Mask': ('Subnet mask or prefix (255.255.255.0 or 24)', ''),
    'Gateway': ('Default gateway', ''),
    'DNS': ('DNS servers (space-separated)', ''),
    'Bridge': ('Network bridge (blank: inherit)', ''),
    'VLAN': ('VLAN ID (blank: inherit)', ''),
    'Cores': ('CPU cores (blank: inherit)', ''),
    'MemoryMB': ('Memory in MiB (blank: inherit)', ''),
    'DiskGB': ('System disk size in GiB (blank: inherit)', ''),
    'BootstrapPackageID': ('Agent Bootstrap package ID (blank: skip installation)', ''),
}



def build():
    helper = (BASE / 'bootstrap_guest.py').read_text(encoding='utf-8')
    encoded = base64.b64encode((BASE / 'install_bootstrap.ps1').read_bytes()).decode()
    helper = helper.replace('BOOTSTRAP_INSTALLER_B64 = ""', 'BOOTSTRAP_INSTALLER_B64 = ' + repr(encoded))
    source = helper + '\n' + (BASE / 'create_vm.py').read_text(encoding='utf-8')
    # exec replaces Bash before it parses the untrusted input tail. Python reads
    # that tail as data and passes validated values using subprocess argv.
    script = "#!/bin/bash\nexec /usr/bin/python3 - \"$0\" \"${1:-}\" <<'WINHUB_PYTHON'\n" + source + '\nWINHUB_PYTHON\n# WINHUB_INPUT\n'
    names = {key: f'A{index:02d}_{key}' for index, key in enumerate(FIELDS, 1)}
    script += ''.join(key + '={{' + names[key] + '}}\n' for key in FIELDS)
    script += 'BootstrapDescriptor=WINHUB_BOOTSTRAP_DESCRIPTOR_V1\n'
    schema = {names[key]: {'type': 'text', 'label': label, 'default': default, 'order': index} for index, (key, (label, default)) in enumerate(FIELDS.items(), 1)}
    schema[names['Mode']].update(type='select', options=['Validate', 'Create'])
    return {'format': 'winhub-template-library', 'version': 1, 'exported_at': '2026-11-12T00:00:00Z',
            'templates': [{'id': '621061af-42d4-443f-b220-e251c8fab924', 'name': 'Proxmox — Create Windows VM',
                           'category': 'Proxmox', 'type': 'action', 'action_type': 'run_script', 'is_approved': False,
                           'payload': {'script': script, 'bootstrap_package_id': '{{' + names['BootstrapPackageID'] + '}}', 'bootstrap_mode': '{{' + names['Mode'] + '}}', '__variable_schema': schema,
                                       '__template_policy': {'hide_code': False, 'lock_edit': False, 'lock_delete': False}}}]}


if __name__ == '__main__':
    (BASE / 'proxmox_vm_create_pack.json').write_text(json.dumps(build(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
