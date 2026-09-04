import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from flask import Blueprint, Flask, session

from core.ai_template_contract import parse_bundle, bundle_hash, report_fixture
from core.ai_templates import process_ai_template_queue
from core.database import db, AiTemplateDraft, User, TaskTemplate, AgentTask
from modules.Infrastructure.ai_editor import register_ai_editor

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = {'name': 'Endpoint inventory', 'language': 'powershell',
          'code': '[pscustomobject]@{ endpoint = "vpn.example.test:51820" } | ConvertTo-Json -Compress',
          'report_template': '<h1>{{ job_title }}</h1>{% for r in results %}<p>{{ r.host }} {{ r.data.endpoint | default("unknown") }}</p>{% endfor %}',
          'sample_result': {'endpoint': 'vpn.example.test:51820'}, 'explanation': 'Synthetic report', 'warnings': []}
SETTINGS = {'enabled': True, 'base_url': 'https://ai.example.test', 'model': 'test-coder', 'has_api_key': True}


def checked(bundle):
    return {'ok': True, 'status': 'checked', 'executed': False, 'code_hash': bundle_hash(bundle), 'diagnostics': []}


class TemplateContractTests(unittest.TestCase):
    def test_valid_bundle_and_report_context_match_winhub(self):
        self.assertEqual(parse_bundle(json.dumps(BUNDLE), 'powershell', True), BUNDLE)
        context = report_fixture(BUNDLE['sample_result'])
        self.assertEqual(set(context), {'results', 'all_results', 'ignored_results', 'failed_results', 'summary', 'job_title'})
        self.assertEqual(context['results'][0]['host'], 'TEST-01')
        self.assertEqual(len(context['results']), 1)
        self.assertEqual(len(context['all_results']), 2)

    def test_unknown_fields_wrong_language_duplicates_and_legacy_binding_rejected(self):
        for update in ({'tools': []}, {'language': 'python'}, {'code': 'echo {{user_input}}'},
                       {'code': 'x' * 65537}, {'report_template': ''}, {'sample_result': []}):
            with self.subTest(update=list(update)):
                bundle = {**BUNDLE, **update}
                with self.assertRaises(ValueError):
                    parse_bundle(json.dumps(bundle), 'powershell', True)
        with self.assertRaises(ValueError):
            parse_bundle('{"name":"a","name":"b"}', 'powershell', True)

    def test_validator_deployment_has_no_secret_or_network_access(self):
        unit = (ROOT / 'deploy/debian/winhub-code-validator@.service').read_text(encoding='utf-8')
        for control in ('User=winhub-validator', 'PrivateNetwork=true', 'ProtectSystem=strict',
                        'SystemCallFilter=~@network-io', 'MemoryMax=768M', 'TasksMax=64', 'KillMode=control-group'):
            self.assertIn(control, unit)
        self.assertNotIn('EnvironmentFile=', unit)
        client = (ROOT / 'core/code_validator_client.py').read_text(encoding='utf-8')
        self.assertNotIn('subprocess', client)
        self.assertIn('AF_UNIX', client)
        wrapper = (ROOT / 'core/validate_powershell.ps1').read_text(encoding='utf-8')
        self.assertIn('Parser]::ParseFile', wrapper)
        self.assertNotIn('Invoke-Expression', wrapper)

    def test_ui_uses_inert_content_not_model_html(self):
        script = (ROOT / 'static/js/ai_template_editor.js').read_text(encoding='utf-8')
        self.assertNotIn('innerHTML', script)
        self.assertNotIn('/tasks/create', script)
        self.assertIn('textContent', script)
        self.assertIn('aiEditorEpoch', script)

    def test_ai_actions_never_enter_legacy_parameter_or_secret_binding(self):
        from modules.Infrastructure.routes import apply_template_variables
        marker = {'draft_id': 'synthetic-test', 'language': 'powershell'}
        with mock.patch('modules.Infrastructure.routes.load_template_secrets') as secrets:
            payload = {'script': 'Write-Output "test"', '__ai_generated': marker}
            self.assertEqual(apply_template_variables(payload, {'value': 'ignored'}), (payload, []))
            for code in ('echo {{value}}', 'echo {{secret:api_key}}', '{% include "x" %}'):
                with self.assertRaises(ValueError):
                    apply_template_variables({**payload, 'script': code}, {})
            secrets.assert_not_called()

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell parser not installed')
    def test_native_powershell_parser_never_executes_submitted_code(self):
        from core.code_validator import validate
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / 'not-executed.txt'
            bundle = {**BUNDLE, 'code': f"Set-Content -LiteralPath '{marker}' -Value 'must-not-run'"}
            result = validate(bundle)
            self.assertTrue(result['ok'], result)
            self.assertFalse(marker.exists())
            self.assertFalse(validate({**bundle, 'code': 'if ('})['ok'])

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Native POSIX Bash required')
    def test_native_bash_parser_never_executes_submitted_code(self):
        from core.code_validator import validate
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / 'not-executed.txt'
            result = validate({**BUNDLE, 'language': 'bash', 'code': f"printf forbidden > '{marker}'"})
            self.assertTrue(result['ok'], result)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX worker requires resource limits')
    def test_standalone_worker_protocol_with_synthetic_report(self):
        bundle = {**BUNDLE, 'language': 'jinja', 'code': '{{ summary.total }}', 'report_template': ''}
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'core/code_validator.py')],
                                input=json.dumps(bundle), text=True, capture_output=True, timeout=35, check=True)
        response = json.loads(result.stdout)
        self.assertTrue(response['ok'], response)
        self.assertEqual(response['code_hash'], bundle_hash(bundle))
        self.assertIs(response['executed'], False)

    def test_new_runtime_files_are_in_release_allowlist_and_install_paths(self):
        prefixes = (ROOT / 'deploy/server-files.txt').read_text(encoding='utf-8').splitlines()
        for path in ('core/code_validator.py', 'core/validate_powershell.ps1', 'core/ai_template_contract.py',
                     'modules/Infrastructure/ai_editor.py', 'static/js/ai_template_editor.js',
                     'static/css/ai_template_editor.css', 'deploy/debian/install_code_validator.sh',
                     'deploy/debian/winhub-code-validator.socket', 'deploy/debian/winhub-code-validator@.service',
                     'migrations/versions/20260904_01_ai_template_drafts.py'):
            self.assertTrue((ROOT / path).is_file(), path)
            self.assertTrue(any(path.startswith(prefix) for prefix in prefixes), path)
        for name in ('install_debian.sh', 'update_winhub.sh', 'restore_winhub.sh'):
            self.assertIn('install_code_validator.sh', (ROOT / 'deploy/debian' / name).read_text(encoding='utf-8'))
        self.assertIn('validator_healthcheck', (ROOT / 'deploy/debian/healthcheck_winhub.sh').read_text(encoding='utf-8'))


class AiEditorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.secret_key = 'isolated-test-only'
        cls.app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///:memory:', SQLALCHEMY_TRACK_MODIFICATIONS=False)
        db.init_app(cls.app)
        bp = Blueprint('ai_editor_test', __name__)
        register_ai_editor(bp)
        cls.app.register_blueprint(bp)
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        db.session.remove()
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        self.user = User(username='author', is_active=True, allowed_modules=json.dumps([
            'Infrastructure:use_ai_templates', 'Infrastructure:manage_templates']))
        self.other = User(username='other', is_active=True, is_admin=True)
        db.session.add_all([self.user, self.other])
        db.session.commit()
        self.client = self.app.test_client()
        self.login(self.user.id)
        self.audit = mock.patch('modules.Infrastructure.routes.write_infra_audit')
        self.audit.start()
        self.provider = mock.patch('modules.Infrastructure.ai_editor.load_ai_provider', return_value=SETTINGS)
        self.provider.start()

    def tearDown(self):
        self.provider.stop()
        self.audit.stop()
        db.session.remove()
        self.context.pop()

    def login(self, user_id, api=False):
        with self.client.session_transaction() as state:
            state.clear()
            state.update(user_id=user_id, username='author', api_key_auth=api)

    def create(self, **kwargs):
        payload = {'prompt': 'Collect endpoints', 'language': 'powershell', 'include_report': True, **kwargs}
        return self.client.post('/api/infrastructure/ai-editor/drafts', json=payload)

    def generate(self, **kwargs):
        response = self.create(**kwargs)
        self.assertEqual(response.status_code, 202, response.json)
        row_id = response.json['draft']['id']
        with mock.patch('core.ai_templates.load_ai_provider', return_value=SETTINGS), \
             mock.patch('core.ai_templates.OpenWebUIClient') as client, \
             mock.patch('core.ai_templates.validate_code_bundle', side_effect=checked):
            client.return_value.chat_completion.return_value = json.dumps(BUNDLE)
            process_ai_template_queue()
        return row_id

    def test_generation_is_private_and_creates_no_task_or_template(self):
        row_id = self.generate()
        self.assertEqual(TaskTemplate.query.count(), 0)
        self.assertEqual(AgentTask.query.count(), 0)
        response = self.client.get('/api/infrastructure/ai-editor/drafts/' + row_id)
        self.assertEqual(response.json['draft']['status'], 'Ready')
        self.login(self.other.id)
        self.assertEqual(self.client.get('/api/infrastructure/ai-editor/drafts/' + row_id).status_code, 404)
        self.assertEqual(self.client.get('/api/infrastructure/ai-editor/drafts').json['drafts'], [])

    def test_explicit_permission_and_interactive_session_required(self):
        self.user.allowed_modules = '["Infrastructure"]'
        db.session.commit()
        self.assertEqual(self.create().status_code, 403)
        self.login(self.other.id, api=True)
        self.assertEqual(self.create().status_code, 403)

    def test_source_masking_and_request_limits(self):
        response = self.create(source_code='password=super-secret\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----')
        row = db.session.get(AiTemplateDraft, response.json['draft']['id'])
        self.assertNotIn('super-secret', row.source_code)
        self.assertNotIn('private-material', row.source_code)
        self.assertEqual(self.create(source_code='x' * 65537).status_code, 400)
        self.assertEqual(self.create(tools=[]).status_code, 400)
        self.assertEqual(self.create().status_code, 202)
        self.assertEqual(self.create().status_code, 429)

    def test_save_pair_is_idempotent_unapproved_and_not_runnable_by_owner(self):
        row_id = self.generate()
        path = f'/api/infrastructure/ai-editor/drafts/{row_id}/save'
        first = self.client.post(path)
        self.assertEqual(first.status_code, 201, first.json)
        self.assertEqual(self.client.post(path).json['template_ids'], first.json['template_ids'])
        self.assertEqual(TaskTemplate.query.count(), 2)
        self.assertEqual(AgentTask.query.count(), 0)
        self.assertTrue(all(not t.is_approved for t in TaskTemplate.query.all()))
        action = TaskTemplate.query.filter_by(type='action').first()
        from modules.Infrastructure import routes
        with self.app.test_request_context('/api/infrastructure/tasks/create', method='POST', json={'template_id': action.id}):
            session.update(user_id=self.user.id, username=self.user.username, is_admin=False)
            with mock.patch.object(routes, 'require_permission', return_value=None), mock.patch.object(routes, 'can', return_value=True):
                self.assertEqual(routes.create_task()[1], 403)

    def test_unavailable_validator_prevents_saving(self):
        row_id = self.generate()
        row = db.session.get(AiTemplateDraft, row_id)
        row.validation_json = json.dumps({'ok': False, 'status': 'unavailable'})
        db.session.commit()
        self.assertEqual(self.client.post(f'/api/infrastructure/ai-editor/drafts/{row_id}/save').status_code, 400)
        self.assertEqual(TaskTemplate.query.count(), 0)

    def test_stale_hash_cannot_save(self):
        row_id = self.generate()
        row = db.session.get(AiTemplateDraft, row_id)
        row.result_json = json.dumps({**BUNDLE, 'code': 'different'})
        db.session.commit()
        self.assertEqual(self.client.post(f'/api/infrastructure/ai-editor/drafts/{row_id}/save').status_code, 400)

    def test_cancel_wins_over_model_response(self):
        row_id = self.create().json['draft']['id']
        def cancel(*args, **kwargs):
            row = db.session.get(AiTemplateDraft, row_id)
            row.status = 'Cancelled'
            db.session.commit()
            return json.dumps(BUNDLE)
        with mock.patch('core.ai_templates.load_ai_provider', return_value=SETTINGS), \
             mock.patch('core.ai_templates.OpenWebUIClient') as client, \
             mock.patch('core.ai_templates.validate_code_bundle', side_effect=checked):
            client.return_value.chat_completion.side_effect = cancel
            process_ai_template_queue()
        self.assertEqual(db.session.get(AiTemplateDraft, row_id).status, 'Cancelled')
        self.assertIsNone(db.session.get(AiTemplateDraft, row_id).result_json)

    def test_invalid_provider_json_keeps_error_not_executable_output(self):
        row_id = self.create().json['draft']['id']
        with mock.patch('core.ai_templates.load_ai_provider', return_value=SETTINGS), mock.patch('core.ai_templates.OpenWebUIClient') as client:
            client.return_value.chat_completion.return_value = 'not json'
            process_ai_template_queue()
        self.assertEqual(db.session.get(AiTemplateDraft, row_id).status, 'Error')
        self.assertEqual(TaskTemplate.query.count(), 0)

    def test_revoked_permission_prevents_queued_model_request(self):
        row_id = self.create().json['draft']['id']
        self.user.allowed_modules = '[]'
        db.session.commit()
        with mock.patch('core.ai_templates.OpenWebUIClient') as client:
            process_ai_template_queue()
        client.assert_not_called()
        self.assertEqual(db.session.get(AiTemplateDraft, row_id).status, 'Error')

    def test_check_edited_code_never_calls_model(self):
        with mock.patch('modules.Infrastructure.ai_editor.check_draft', side_effect=checked), \
             mock.patch('core.ai_templates.OpenWebUIClient') as model:
            response = self.client.post('/api/infrastructure/ai-editor/check', json=BUNDLE)
        self.assertEqual(response.status_code, 201, response.json)
        model.assert_not_called()
        self.assertEqual(response.json['draft']['model'], 'static-validator')
        self.assertEqual(AgentTask.query.count(), 0)


class BoundedAiClientTests(unittest.TestCase):
    def test_completions_disable_tools_and_reject_tool_calls(self):
        from core.ai_client import OpenWebUIClient
        client = OpenWebUIClient({**SETTINGS, 'api_key': 'synthetic-test-key'})
        response = {'choices': [{'message': {'content': 'text only'}}]}
        with mock.patch.object(client, '_request', return_value=response) as request:
            self.assertEqual(client.chat_completion([]), 'text only')
            self.assertEqual(request.call_args.kwargs['json']['tools'], [])
            self.assertFalse(any(request.call_args.kwargs['json']['features'].values()))
            response['choices'][0]['message']['tool_calls'] = [{'id': 'must-not-execute'}]
            with self.assertRaises(ValueError):
                client.chat_completion([])

    def test_oversized_http_body_is_rejected_and_closed_before_json_parsing(self):
        from core.ai_client import OpenWebUIClient
        client = OpenWebUIClient({**SETTINGS, 'api_key': 'synthetic-test-key'})
        response = mock.Mock(status_code=200, is_redirect=False)
        response.iter_content.return_value = iter([b'x' * 11])
        client.session.request = mock.Mock(return_value=response)
        with mock.patch('core.ai_client.pinned_outbound_url'), mock.patch('core.ai_client.Config.AI_MAX_HTTP_RESPONSE_BYTES', 10):
            with self.assertRaises(ValueError):
                client.models()
        response.close.assert_called_once()
        response.json.assert_not_called()
