"""Optional browser verification of parameter editing, fixed targets and secret reuse."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from flask import Flask, render_template

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WINHUB_PLAYWRIGHT_MODULE') and shutil.which('node'),'Requires optional Playwright and browser')
class TaskRerunBrowserTests(unittest.TestCase):
    def test_edit_parameters_and_repeat_without_target_changes(self):
        app=Flask(__name__,template_folder=str(ROOT/'modules/Infrastructure/templates'))
        with app.app_context():
            body=render_template('modals/_task_rerun.html')
        theme='\n'.join(re.findall(r'<style[^>]*>([\s\S]*?)</style>',(ROOT/'templates/base.html').read_text(encoding='utf-8')))
        html='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/tailwind.local.css"><style>'''+theme+'''</style><link rel="stylesheet" href="/static/css/software.css"><link rel="stylesheet" href="/static/css/task_rerun.css"></head><body>
<button onclick="taskRerunOpen('job','original-job')">Re-run original job</button>'''+body+'''
<script>window.WinhubPermissions={view_queue:true,run_tasks:true};</script><script src="/static/js/infrastructure.js"></script><script src="/static/js/task_rerun.js"></script></body></html>'''
        with tempfile.TemporaryDirectory(prefix='winhub-rerun-ui-') as temporary:
            file=Path(temporary)/'rerun.html';file.write_text(html,encoding='utf-8')
            result=subprocess.run(['node',str(ROOT/'tests/browser/task_rerun_ui.cjs'),str(file),str(ROOT)],capture_output=True,text=True,timeout=120,env=os.environ.copy())
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
