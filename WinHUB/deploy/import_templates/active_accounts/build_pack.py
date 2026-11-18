import json
from pathlib import Path

base = Path(__file__).resolve().parent
report_id = '1bcf7078-83f7-4782-9c1a-e94f616e25ef'
pack = {
    'format': 'winhub-template-library', 'version': 1,
    'exported_at': '2026-10-20T00:00:00Z',
    'templates': [
        {'id': '9565635a-381b-43a6-b117-c21e59e5f673',
         'name': 'Аудит активних локальних облікових записів',
         'category': 'Inventory', 'type': 'action', 'action_type': 'run_script',
         'is_approved': False,
         'payload': {'script': (base / 'active_accounts.ps1').read_text(encoding='utf-8'),
                     '__report_template_id': report_id, '__agent_timeout_seconds': 120,
                     '__variable_schema': {}}},
        {'id': report_id, 'name': 'Активні облікові записи — зведений аудит',
         'category': 'Inventory', 'type': 'report', 'action_type': 'run_script',
         'is_approved': False,
         'payload': {'script': (base / 'active_accounts_report.jinja').read_text(encoding='utf-8')}}
    ]
}
(base / 'active_accounts_pack.json').write_text(
    json.dumps(pack, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
