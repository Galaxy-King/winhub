"""Optional browser checks of the third template editor and read-only guides."""
import json
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
class TemplateDescriptionBrowserTests(unittest.TestCase):
    def test_third_editor_loads_saves_and_honors_readonly(self):
        app=Flask(__name__,template_folder=str(ROOT/'modules/Infrastructure/templates'))
        template=dict(id='t1',name='Documented template',category='General',action_type='run_script',type='action',
            payload=json.dumps({'script':'echo fixture'}),is_approved=True,policy={},can_edit=True,can_view_code=True,
            can_run=True,can_delete=True,variables=[],variable_schema={})
        with app.app_context():
            context=dict(permissions={'manage_templates':True,'run_tasks':True,'view_queue':True},is_admin=True,
                templates=[template],groups=[],agents=[])
            body=render_template('tabs/_deploy.html',**context)+render_template('modals/_modals.html',**context)
        theme='\n'.join(re.findall(r'<style[^>]*>([\s\S]*?)</style>',(ROOT/'templates/base.html').read_text(encoding='utf-8')))
        html='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/static/css/tailwind.local.css"><link rel="stylesheet" href="/static/vendor/codemirror/5.65.16/codemirror.min.css"><link rel="stylesheet" href="/static/vendor/codemirror/5.65.16/theme/material-darker.min.css"><style>'''+theme+'''</style><link rel="stylesheet" href="/static/css/software.css"></head><body>'''+body+'''
<script>window.WinhubPermissions={manage_templates:true,run_tasks:true,view_queue:true};window.WinhubIsAdmin=true;</script>
<script src="/static/vendor/codemirror/5.65.16/codemirror.min.js"></script><script src="/static/vendor/codemirror/5.65.16/mode/powershell/powershell.min.js"></script>
<script src="/static/js/infrastructure.js"></script><script>document.getElementById('view-deploy').classList.remove('hidden');</script></body></html>'''
        with tempfile.TemporaryDirectory(prefix='winhub-description-ui-') as temporary:
            file=Path(temporary)/'description.html';file.write_text(html,encoding='utf-8')
            result=subprocess.run(['node',str(ROOT/'tests/browser/template_description_ui.cjs'),str(file),str(ROOT)],capture_output=True,text=True,timeout=120,env=os.environ.copy())
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
