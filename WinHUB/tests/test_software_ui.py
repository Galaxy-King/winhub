"""Optional browser regression against Software templates and the real base theme.

Set WINHUB_PLAYWRIGHT_MODULE to an installed Playwright module directory.
No WinHUB instance or endpoint is contacted; the browser intercepts fixture APIs.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WINHUB_PLAYWRIGHT_MODULE') and shutil.which('node'),
                     'Optional: requires Node.js, Playwright and a browser')
class SoftwareBrowserTests(unittest.TestCase):
    def test_theme_and_confirmed_target_selection(self):
        app = Flask(__name__, template_folder=str(ROOT / 'modules/Infrastructure/templates'))
        with app.app_context():
            body = render_template('tabs/_software.html', permissions={'run_tasks': True, 'manage_software': True}, is_admin=True)
            body += render_template('tabs/_queue.html', permissions={'run_tasks': True, 'view_sensitive_reports': True}, is_admin=True)
            body += render_template('modals/_modals.html', permissions={'run_tasks': True, 'manage_hosts': True}, is_admin=True)
        base = (ROOT / 'templates/base.html').read_text(encoding='utf-8')
        theme = '\n'.join(re.findall(r'<style[^>]*>([\s\S]*?)</style>', base))
        html = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/tailwind.local.css"><style>''' + theme + '''</style>
<link rel="stylesheet" href="/static/css/software.css"></head><body>
<main style="padding:20px">''' + body + '''</main>
<script>window.WinhubCanManageSoftware=true;
function askTaskLaunchReason(){return Promise.resolve('Browser fixture deployment');}
function switchView(){}
</script><script src="/static/js/software.js"></script><script>
document.getElementById('view-software').classList.remove('hidden');loadSoftwareRegistry();
</script></body></html>'''
        with tempfile.TemporaryDirectory(prefix='winhub-software-browser-') as temporary:
            fixture = Path(temporary) / 'software.html'
            fixture.write_text(html, encoding='utf-8')
            result = subprocess.run(['node', str(ROOT / 'tests/browser/software_ui.cjs'), str(fixture), str(ROOT)],
                                    capture_output=True, text=True, timeout=180, env=os.environ.copy())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
