"""Interactive AI editor API. All results remain private inert drafts."""
import json
import re
from datetime import datetime, timedelta

from flask import jsonify, request, session

from core.ai_client import load_ai_provider
from core.ai_template_contract import LANGUAGES, MAX_CODE_BYTES, MAX_BUNDLE_BYTES, bundle_hash, validate_bundle
from core.ai_templates import check_draft, serialize_draft
from core.database import AiTemplateDraft, TaskTemplate, User, db
from core.permissions import has_permission
from core.sensitive_data import mask_sensitive_text


def editor_user():
    user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
    if session.get('api_key_auth') or not user or not user.is_active or not all(
        has_permission(user, 'Infrastructure', p) for p in ('manage_templates', 'use_ai_templates')
    ):
        return None
    return user


def body():
    raw = request.stream.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError('Request is too large')
    value = json.loads(raw or b'{}')
    if not isinstance(value, dict):
        raise ValueError('Request must be a JSON object')
    return value


def redact_source(value):
    value = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
                   '[PRIVATE KEY REDACTED]', value)
    return mask_sensitive_text(value)


def owned_draft(draft_id, user):
    return AiTemplateDraft.query.filter_by(id=draft_id, actor_user_id=user.id).first()


def validated_result(row):
    if not row or row.status != 'Ready':
        raise ValueError('Draft is not ready')
    bundle = validate_bundle(json.loads(row.result_json or '{}'))
    validation = json.loads(row.validation_json or '{}')
    if validation.get('ok') is not True or validation.get('code_hash') != bundle_hash(bundle):
        raise ValueError('The isolated validator must successfully check this draft first')
    return bundle


def stamp_ai_origin(payload, draft_id):
    user = editor_user()
    row = owned_draft(draft_id, user) if user else None
    validated_result(row)
    payload['__ai_generated'] = {'draft_id': row.id, 'language': row.language}
    return payload


def register_ai_editor(bp):
    def guard():
        user = editor_user()
        return user, (jsonify(success=False, message='AI editor requires explicit use_ai_templates and manage_templates permissions'), 403)

    @bp.route('/api/infrastructure/ai-editor/drafts', methods=['GET', 'POST'])
    def ai_editor_drafts():
        user, denied = guard()
        if not user:
            return denied
        if request.method == 'GET':
            rows = AiTemplateDraft.query.filter_by(actor_user_id=user.id).order_by(AiTemplateDraft.created_at.desc()).limit(30).all()
            return jsonify(success=True, drafts=[serialize_draft(row, False) for row in rows])
        try:
            data = body()
            if set(data) - {'prompt', 'source_code', 'language', 'include_report'}:
                raise ValueError('Unknown request fields')
            prompt, source = data.get('prompt', ''), data.get('source_code', '')
            language, include_report = data.get('language'), data.get('include_report', False)
            if not isinstance(prompt, str) or not 1 <= len(prompt.strip()) <= 4000:
                raise ValueError('Prompt must contain 1–4000 characters')
            if not isinstance(source, str) or len(source.encode()) > MAX_CODE_BYTES:
                raise ValueError('Reference code exceeds 64 KiB')
            if not isinstance(language, str) or language not in LANGUAGES or type(include_report) is not bool:
                raise ValueError('Invalid language or report option')
            if language == 'jinja' and include_report:
                raise ValueError('Jinja drafts already are report templates')
            settings = load_ai_provider()
            if not all(settings.get(k) for k in ('enabled', 'base_url', 'model', 'has_api_key')):
                raise ValueError('Enable and configure AI / Open WebUI first')
            # Serialize submissions per owner to keep limits reliable across web workers.
            db.session.query(User).filter_by(id=user.id).with_for_update().first()
            active = AiTemplateDraft.query.filter_by(actor_user_id=user.id).filter(AiTemplateDraft.status.in_(['Queued', 'Running'])).count()
            recent = AiTemplateDraft.query.filter_by(actor_user_id=user.id).filter(AiTemplateDraft.created_at > datetime.utcnow() - timedelta(minutes=1)).count()
            if active >= 2 or recent >= 3 or AiTemplateDraft.query.filter(AiTemplateDraft.status.in_(['Queued', 'Running'])).count() >= 50:
                db.session.rollback()
                return jsonify(success=False, message='AI queue limit reached. Wait for the current request.'), 429
            row = AiTemplateDraft(actor_user_id=user.id, prompt=redact_source(prompt.strip()),
                                  source_code=redact_source(source), language=language,
                                  include_report=include_report, model=settings['model'])
            db.session.add(row)
            db.session.commit()
            from modules.Infrastructure.routes import write_infra_audit
            write_infra_audit('ai_template_requested', 'ai_template_draft', row.id, {'language': language})
            return jsonify(success=True, draft=serialize_draft(row)), 202
        except (ValueError, TypeError, RecursionError) as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)[:300]), 400

    @bp.route('/api/infrastructure/ai-editor/drafts/<draft_id>', methods=['GET', 'DELETE'])
    def ai_editor_draft(draft_id):
        user, denied = guard()
        if not user:
            return denied
        row = owned_draft(draft_id, user)
        if not row:
            return jsonify(success=False, message='Draft not found'), 404
        if request.method == 'DELETE':
            # Cancellation keeps history but late worker output cannot overwrite it.
            row = AiTemplateDraft.query.filter_by(id=row.id).with_for_update().first()
            row.status = 'Cancelled'
            row.completed_at = datetime.utcnow()
            db.session.commit()
        return jsonify(success=True, draft=serialize_draft(row))

    @bp.route('/api/infrastructure/ai-editor/drafts/<draft_id>/validate', methods=['POST'])
    def ai_editor_validate(draft_id):
        user, denied = guard()
        if not user:
            return denied
        row = AiTemplateDraft.query.filter_by(id=draft_id, actor_user_id=user.id).with_for_update().first()
        if not row:
            return jsonify(success=False, message='Draft not found'), 404
        if row.status != 'Ready':
            return jsonify(success=False, message='Draft is not ready'), 409
        if row.started_at and row.started_at > datetime.utcnow() - timedelta(seconds=10):
            return jsonify(success=False, message='Wait 10 seconds before validating again'), 429
        # Validate the exact server-side artifact, never command arguments from the browser.
        bundle = json.loads(row.result_json)
        row.status = 'Validating'
        row.started_at = datetime.utcnow()
        db.session.commit()
        validation = check_draft(bundle)
        db.session.expire_all()
        row = AiTemplateDraft.query.filter_by(id=draft_id, actor_user_id=user.id).with_for_update().first()
        if not row or row.status != 'Validating':
            return jsonify(success=False, message='Draft changed or was cancelled'), 409
        row.validation_json = json.dumps(validation, ensure_ascii=False)
        row.status = 'Ready'
        db.session.commit()
        return jsonify(success=True, draft=serialize_draft(row))

    @bp.route('/api/infrastructure/ai-editor/check', methods=['POST'])
    def ai_editor_check_current():
        user, denied = guard()
        if not user:
            return denied
        try:
            bundle = validate_bundle(body())
            db.session.query(User).filter_by(id=user.id).with_for_update().first()
            if AiTemplateDraft.query.filter_by(actor_user_id=user.id).filter(
                AiTemplateDraft.created_at > datetime.utcnow() - timedelta(minutes=1)).count() >= 3:
                db.session.rollback()
                return jsonify(success=False, message='Validation limit reached; wait one minute'), 429
            row = AiTemplateDraft(actor_user_id=user.id, prompt='Static check of edited code; no model request',
                language=bundle['language'], include_report=bool(bundle['report_template']), model='static-validator',
                status='Validating', started_at=datetime.utcnow(), result_json=json.dumps(bundle, ensure_ascii=False))
            db.session.add(row)
            db.session.commit()
            row_id = row.id
            validation = check_draft(bundle)
            db.session.expire_all()
            row = AiTemplateDraft.query.filter_by(id=row_id).with_for_update().first()
            if not row:
                return jsonify(success=False, message='Draft no longer available'), 409
            if row.status == 'Validating':
                row.validation_json = json.dumps(validation, ensure_ascii=False)
                row.status = 'Ready'
                row.completed_at = datetime.utcnow()
                db.session.commit()
            return jsonify(success=True, draft=serialize_draft(row)), 201
        except (ValueError, TypeError, RecursionError) as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)[:300]), 400

    @bp.route('/api/infrastructure/ai-editor/drafts/<draft_id>/save', methods=['POST'])
    def ai_editor_save(draft_id):
        user, denied = guard()
        if not user:
            return denied
        row = AiTemplateDraft.query.filter_by(id=draft_id, actor_user_id=user.id).with_for_update().first()
        if not row:
            return jsonify(success=False, message='Draft not found'), 404
        try:
            bundle = validated_result(row)
            if row.saved_template_ids:
                return jsonify(success=True, template_ids=json.loads(row.saved_template_ids))
            ids = []
            marker = {'draft_id': row.id, 'language': row.language}
            companion = None
            if bundle['report_template']:
                companion = TaskTemplate(name=(bundle['name'] + ' — report')[:150], category='AI drafts',
                    type='report', action_type='aggregation_report', created_by=user.username, is_approved=False,
                    payload=json.dumps({'script': bundle['report_template'], '__ai_generated': marker}, ensure_ascii=False))
                db.session.add(companion)
                db.session.flush()
                ids.append(companion.id)
            payload = {'script': bundle['code'], '__ai_generated': marker}
            if companion:
                payload['__report_template_id'] = companion.id
            template = TaskTemplate(name=bundle['name'], category='AI drafts',
                type='report' if row.language == 'jinja' else 'action',
                action_type='aggregation_report' if row.language == 'jinja' else 'run_script',
                payload=json.dumps(payload, ensure_ascii=False), created_by=user.username, is_approved=False)
            db.session.add(template)
            db.session.flush()
            ids.append(template.id)
            row.saved_template_ids = json.dumps(ids)
            db.session.commit()
            from modules.Infrastructure.routes import write_infra_audit
            write_infra_audit('ai_templates_saved_unapproved', 'ai_template_draft', row.id, {'template_ids': ids})
            return jsonify(success=True, template_ids=ids), 201
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)), 400
