import json
from pathlib import Path

base = Path(__file__).resolve().parent
template = json.loads((base / 'template_definition.json').read_text(encoding='utf-8'))['template']
template['payload'] = {'script': (base / 'configure_psk.ps1').read_text(encoding='utf-8'), **template['payload']}
pack = {'format': 'winhub-template-library', 'version': 1, 'templates': [template]}
(base / 'zabbix_agent2_winhub_pack.json').write_text(json.dumps(pack, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
