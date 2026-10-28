"""Optional isolated browser validation of the real Scheduler form and guide."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WINHUB_PLAYWRIGHT_MODULE') and shutil.which('node'), 'Requires optional Playwright and browser')
class SchedulerBrowserTests(unittest.TestCase):
    def test_recurrence_history_statuses_and_bilingual_guide(self):
        app = Flask(__name__, template_folder=str(ROOT / 'modules/Infrastructure/templates'))
        schedule = dict(id='s1', name='Fortnightly backup', category='Backups', cron='CALENDAR', is_active=True,
            launch_reason='Maintenance', template_name='Backup', target_name='Pilot hosts', last_run='—', next_run='—',
            last_status='ScriptFailed', timeout_minutes=30, target_type='group', target_id='g1', template_id='t1',variables={},
            recurrence=dict(kind='weekly', timezone='UTC', start='2030-01-01T03:00', every=2, weekdays=[6]), execution_policy=None)
        with app.app_context():
            context = dict(permissions={'manage_scheduler': True, 'run_tasks': True, 'view_queue': True}, is_admin=True,
                scheduled_tasks=[schedule], templates=[dict(id='t1',name='Backup',category='Backups',type='action',can_run=True,variables=[],variable_schema={})],
                groups=[dict(id='g1',name='Pilot hosts')],agents=[])
            body = render_template('tabs/_scheduler.html', **context) + render_template('modals/_modals.html', **context)
            body += render_template('modals/_launch_reason.html', **context)
        theme = '\n'.join(re.findall(r'<style[^>]*>([\s\S]*?)</style>', (ROOT / 'templates/base.html').read_text(encoding='utf-8')))
        html = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/tailwind.local.css"><style>''' + theme + '''</style>
<link rel="stylesheet" href="/static/css/software.css"><link rel="stylesheet" href="/static/css/scheduler.css">
</head><body><main style="padding:20px">''' + body + '''</main>
<script>window.WinhubPermissions={manage_scheduler:true,run_tasks:true,view_queue:true};window.WinhubHosts=[];</script>
<script src="/static/js/task_launch_reason.js"></script><script src="/static/js/infrastructure.js"></script>
<script src="/static/js/scheduler.js"></script><script>document.getElementById('view-scheduler').classList.remove('hidden');</script>
</body></html>'''
        with tempfile.TemporaryDirectory(prefix='winhub-scheduler-browser-') as temp:
            fixture = Path(temp) / 'scheduler.html'
            fixture.write_text(html, encoding='utf-8')
            result = subprocess.run(['node', str(ROOT/'tests/browser/scheduler_ui.cjs'), str(fixture), str(ROOT)],
                                    capture_output=True, text=True, timeout=120, env=os.environ.copy())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
