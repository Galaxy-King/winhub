"""Private, bounded generation queue. This module never dispatches endpoint tasks."""
import json
import logging
from datetime import datetime, timedelta

from core.ai_client import OpenWebUIClient, load_ai_provider
from core.ai_template_contract import CONTRACT_VERSION, SYSTEM_PROMPT, MAX_BUNDLE_BYTES, parse_bundle, bundle_hash
from core.code_validator_client import validate_code_bundle
from core.database import AiTemplateDraft, User, db
from core.permissions import has_permission

log = logging.getLogger('winhub.ai_templates')


def serialize_draft(row, detail=True):
    result = {"id": row.id, "status": row.status, "language": row.language,
              "include_report": row.include_report, "model": row.model,
              "created_at": row.created_at.isoformat() + 'Z', "error": row.error,
              "contract_version": CONTRACT_VERSION,
              "saved_template_ids": json.loads(row.saved_template_ids or '[]')}
    if detail:
        result.update(prompt=row.prompt, result=json.loads(row.result_json or 'null'),
                      validation=json.loads(row.validation_json or 'null'))
    return result


def check_draft(bundle):
    try:
        return validate_code_bundle(bundle)
    except Exception:
        return {"ok": False, "status": "unavailable", "code_hash": bundle_hash(bundle), "executed": False,
                "diagnostics": [{"severity": "unavailable", "message": "Isolated validator unavailable. Check winhub-code-validator.socket and its service logs."}]}


def process_ai_template_queue():
    now = datetime.utcnow()
    # Expired work fails closed: do not automatically duplicate model requests.
    AiTemplateDraft.query.filter(AiTemplateDraft.status.in_(['Running', 'Validating']), AiTemplateDraft.started_at < now - timedelta(minutes=15)).update(
        {"status": "Error", "error": "Generation deadline expired; create a new draft", "completed_at": now}, synchronize_session=False)
    # Bounded private history. Saved templates do not depend on draft retention.
    AiTemplateDraft.query.filter(AiTemplateDraft.created_at < now - timedelta(days=30),
                                 AiTemplateDraft.status.in_(['Ready', 'Error', 'Cancelled'])).delete(synchronize_session=False)
    row = AiTemplateDraft.query.filter_by(status='Queued').order_by(AiTemplateDraft.created_at).with_for_update(skip_locked=True).first()
    if not row:
        db.session.commit()
        return
    row.status = 'Running'
    row.started_at = now
    row_id = row.id
    owner_id, language, include_report, model = row.actor_user_id, row.language, row.include_report, row.model
    content = json.dumps({"request": row.prompt, "language": language, "include_report": include_report,
                          "reference_code": row.source_code or ""}, ensure_ascii=False)
    db.session.commit()
    try:
        user = db.session.get(User, owner_id)
        if not user or not user.is_active or not all(has_permission(user, 'Infrastructure', p) for p in ('manage_templates', 'use_ai_templates')):
            raise PermissionError('Owner access revoked')
        settings = load_ai_provider(include_secret=True)
        if not settings.get('enabled') or settings.get('model') != model:
            raise ValueError('Provider disabled or model changed')
        client = OpenWebUIClient(settings)
        output = client.chat_completion([{"role": "system", "content": SYSTEM_PROMPT},
                                         {"role": "user", "content": content}], model=model, max_output_bytes=MAX_BUNDLE_BYTES)
        bundle = parse_bundle(output, language, include_report)
        validation = check_draft(bundle)
        # Refresh after network I/O; cancellation/expiry wins over late completion.
        db.session.expire_all()
        row = AiTemplateDraft.query.filter_by(id=row_id).with_for_update().first()
        if row and row.status == 'Running':
            row.result_json = json.dumps(bundle, ensure_ascii=False)
            row.validation_json = json.dumps(validation, ensure_ascii=False)
            row.status = 'Ready'
            row.completed_at = datetime.utcnow()
            db.session.commit()
    except Exception as exc:
        db.session.rollback()
        row = AiTemplateDraft.query.filter_by(id=row_id).with_for_update().first()
        if row and row.status == 'Running':
            row.status = 'Error'
            # Model output, source, credentials and exception response bodies never enter logs.
            row.error = 'AI draft failed: provider, JSON contract or access check. Review configuration and retry.'
            row.completed_at = datetime.utcnow()
            db.session.commit()
        log.warning('AI template draft failed id=%s category=%s', row_id, type(exc).__name__)
