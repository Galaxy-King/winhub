"""Optional real-browser checks of queue history controls and export workflow."""
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
class QueueHistoryBrowserTests(unittest.TestCase):
    def test_history_export_cleanup_and_responsive_toolbar(self):
        app = Flask(__name__, template_folder=str(ROOT / 'modules/Infrastructure/templates'))
        with app.app_context():
            body = render_template('tabs/_queue.html', permissions={'view_queue':True,'view_sensitive_reports':True,'run_tasks':True}, is_admin=True)
        theme = '\n'.join(re.findall(r'<style[^>]*>([\s\S]*?)</style>', (ROOT/'templates/base.html').read_text(encoding='utf-8')))
        html = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/tailwind.local.css"><style>''' + theme + '''</style>
<link rel="stylesheet" href="/static/css/software.css"><link rel="stylesheet" href="/static/css/queue_history.css"></head>
<body><main style="padding:20px">''' + body + '''</main><script>window.WinhubPermissions={view_queue:true,run_tasks:true};</script>
<script src="/static/js/infrastructure.js"></script><script src="/static/js/queue_history.js"></script>
<script>document.getElementById('view-queue').classList.remove('hidden');</script></body></html>'''
        with tempfile.TemporaryDirectory(prefix='winhub-queue-ui-') as temporary:
            file=Path(temporary)/'queue.html'
            file.write_text(html, encoding='utf-8')
            result=subprocess.run(['node', str(ROOT/'tests/browser/queue_history_ui.cjs'), str(file), str(ROOT)],
                capture_output=True, text=True, timeout=120, env=os.environ.copy())
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
