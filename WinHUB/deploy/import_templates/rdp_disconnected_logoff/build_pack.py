import json
from pathlib import Path

base = Path(__file__).resolve().parent
source = (base / 'rdp_disconnected_logoff.ps1').read_text(encoding='utf-8')
source = source.replace("[string]$Mode = 'Audit'", "[string]$Mode = '{{Mode}}'")
report_id = 'cd987d64-82d8-459e-84d6-931e1d00cb3d'
pack = {
    'format': 'winhub-template-library', 'version': 1, 'exported_at': '2026-10-06T00:00:00Z',
    'templates': [{
        'id': 'f21ea5a3-fb06-48ce-9b03-f8869a3b567b',
        'name': 'RDP — Log off disconnected users', 'category': 'Windows Administration',
        'type': 'action', 'action_type': 'run_script', 'is_approved': False,
        'payload': {'script': source, '__report_template_id': report_id, '__variable_schema': {
            'Mode': {'type': 'select', 'label': 'Execution mode', 'default': 'Audit',
                     'options': ['Audit', 'LogoffDisconnected']}
        }, '__template_policy': {'hide_code': False, 'lock_edit': False, 'lock_delete': False}}
    }, {
        'id': report_id, 'name': 'RDP Session Report',
        'category': 'Windows Administration', 'type': 'report',
        'action_type': 'run_script', 'is_approved': False,
        'payload': {'script': (base / 'rdp_disconnected_logoff_report.jinja').read_text(encoding='utf-8')}
    }]
}
(base / 'rdp_disconnected_logoff_pack.json').write_text(json.dumps(pack, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
