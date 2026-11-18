import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
source = (BASE / 'telegram_rds.ps1').read_text(encoding='utf-8')
header, body = source.split("$ErrorActionPreference = 'Stop'", 1)
# The agent prepends executable encoding setup. A script-level param() block
# cannot follow it; imported actions receive validated variable assignments.
source = """#requires -Version 5.1
#requires -RunAsAdministrator
[ValidateSet('Audit','Install','Repair','Uninstall')][string]$Action = '{{Action}}'
[ValidateSet('Blocked','Allowed')][string]$AutoUpdate = '{{AutoUpdate}}'
$ErrorActionPreference = 'Stop'""" + body
pack = {
    'format': 'winhub-template-library', 'version': 1,
    'exported_at': '2026-10-06T00:00:00Z',
    'templates': [{
        'id': 'a642ccbb-255d-4d69-9016-4d3081fe221a',
        'name': 'Telegram Desktop — Windows / RDS',
        'category': 'Windows Administration', 'action_type': 'run_script',
        'type': 'action', 'is_approved': False,
        'payload': {
            'script': source,
            '__variable_schema': {
                'Action': {'type': 'select', 'label': 'Режим роботи', 'default': 'Audit',
                           'options': ['Audit', 'Install', 'Repair', 'Uninstall']},
                'AutoUpdate': {'type': 'select', 'label': 'Автооновлення Telegram',
                               'default': 'Blocked', 'options': ['Blocked', 'Allowed']},
            },
            '__template_policy': {'hide_code': False, 'lock_edit': False, 'lock_delete': False},
        },
    }],
}
(BASE / 'telegram_rds_pack.json').write_text(json.dumps(pack, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
