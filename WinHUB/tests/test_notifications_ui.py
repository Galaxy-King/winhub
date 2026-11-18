"""Optional real-browser inbox checks at desktop and phone widths."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WINHUB_PLAYWRIGHT_MODULE') and shutil.which('node'), 'Requires optional Playwright and browser')
class NotificationBrowserTests(unittest.TestCase):
    def test_inbox_desktop_mobile_filters_and_personal_actions(self):
        app = Flask(__name__, template_folder=str(ROOT/'templates'))
        with app.test_request_context('/'):
            html = '<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body>' + render_template('_notifications.html') + '</body></html>'
        with tempfile.TemporaryDirectory(prefix='winhub-notifications-ui-') as temporary:
            file = Path(temporary)/'fixture.html';file.write_text(html, encoding='utf-8')
            result = subprocess.run(['node',str(ROOT/'tests/browser/notifications_ui.cjs'),str(file),str(ROOT)], capture_output=True,text=True,timeout=120,env=os.environ.copy())
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
