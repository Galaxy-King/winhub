"""Blind indexing helpers for encrypted audit, task, and report content."""

import hashlib
import hmac
import json
import re
import unicodedata
from datetime import datetime

from sqlalchemy import func

from core.config import Config
from core.database import (
    AgentTask,
    AggregatedJob,
    AuditLog,
    HistorySearchToken,
    ReportDelivery,
    ReportRevision,
    Task,
    db,
)


TOKEN_PATTERN = re.compile(r"[^\W_]+(?:[-._][^\W_]+)*", re.UNICODE)
MAX_INDEX_TOKENS_PER_FIELD = 12000
MAX_QUERY_TERMS = 20


def normalize_search_text(value):
    return unicodedata.normalize("NFKC", str(value or "")).casefold()


def search_words(value, *, limit=MAX_INDEX_TOKENS_PER_FIELD):
    words = []
    seen = set()
    for match in TOKEN_PATTERN.finditer(normalize_search_text(value)):
        word = match.group(0).strip("-._")
        if len(word) < 2 or word in seen:
            continue
        seen.add(word)
        words.append(word)
        if len(words) >= limit:
            break
    return words


def blind_token(word):
    key = str(Config.HISTORY_SEARCH_KEY or Config.AGENT_TASK_HMAC_SECRET).encode("utf-8")
    return hmac.new(key, normalize_search_text(word).encode("utf-8"), hashlib.sha256).hexdigest()


def query_token_hashes(value):
    return [blind_token(word) for word in search_words(value, limit=MAX_QUERY_TERMS)]


def replace_search_field(entity_type, entity_id, field, content):
    entity_type = str(entity_type or "")[:30]
    entity_id = str(entity_id or "")[:64]
    field = str(field or "")[:30]
    if not entity_type or not entity_id or not field:
        return 0
    HistorySearchToken.query.filter_by(
        entity_type=entity_type,
        entity_id=entity_id,
        field=field,
    ).delete(synchronize_session=False)
    # The marker distinguishes an indexed empty document from a document that
    # still needs backfilling. It is HMACed and cannot collide with user terms.
    hashes = {blind_token(word) for word in search_words(content)}
    hashes.add(blind_token(f"__winhub_indexed_field__{field}"))
    db.session.add_all([
        HistorySearchToken(
            entity_type=entity_type,
            entity_id=entity_id,
            field=field,
            token_hash=token_hash,
        )
        for token_hash in hashes
    ])
    return len(hashes)


def remove_search_document(entity_type, entity_id):
    return HistorySearchToken.query.filter_by(
        entity_type=str(entity_type),
        entity_id=str(entity_id),
    ).delete(synchronize_session=False)


def matching_entity_ids(entity_type, content, *, fields=None, mode="all"):
    hashes = query_token_hashes(content)
    if not hashes:
        return None
    query = db.session.query(HistorySearchToken.entity_id).filter(
        HistorySearchToken.entity_type == str(entity_type),
        HistorySearchToken.token_hash.in_(hashes),
    )
    if fields:
        query = query.filter(HistorySearchToken.field.in_([str(item) for item in fields]))
    query = query.group_by(HistorySearchToken.entity_id)
    if str(mode).lower() != "any":
        query = query.having(func.count(func.distinct(HistorySearchToken.token_hash)) == len(set(hashes)))
    return query


def index_agent_task(task):
    if not task or not getattr(task, "id", None):
        return 0
    total = replace_search_field("task", task.id, "input", task.payload or "")
    total += replace_search_field("task", task.id, "output", task.result_log or "")
    return total


def index_report(report):
    if not report or not getattr(report, "id", None):
        return 0
    total = replace_search_field("report", report.id, "current", report.report_data or "")
    original = ReportRevision.query.filter_by(report_id=report.id, revision_number=1).first()
    if original:
        total += replace_search_field("report", report.id, "original", original.content or "")
    revisions = ReportRevision.query.filter_by(report_id=report.id).order_by(
        ReportRevision.revision_number
    ).all()
    deliveries = ReportDelivery.query.filter_by(report_id=report.id).order_by(
        ReportDelivery.created_at
    ).all()
    total += replace_search_field(
        "report", report.id, "revisions", "\n".join(item.content or "" for item in revisions)
    )
    total += replace_search_field(
        "report", report.id, "deliveries", "\n".join(item.content_snapshot or "" for item in deliveries)
    )
    return total


def index_audit_log(entry):
    if not entry or getattr(entry, "id", None) is None:
        return 0
    content = "\n".join([
        str(entry.details or ""),
        str(entry.ip_address or ""),
        str(entry.user_agent or ""),
    ])
    return replace_search_field("audit", str(entry.id), "details", content)


def index_legacy_task(task):
    if not task or not getattr(task, "id", None):
        return 0
    return replace_search_field("legacy_task", task.id, "details", task.targets or "")


def _missing_index_query(model, entity_type, id_column):
    return model.query.filter(~db.session.query(HistorySearchToken.id).filter(
        HistorySearchToken.entity_type == entity_type,
        HistorySearchToken.entity_id == db.cast(id_column, db.String),
    ).exists())


def backfill_history_search_index(limit=250):
    """Index a bounded batch so deployment never blocks on five years of data."""
    limit = max(1, min(int(limit or 250), 2000))
    indexed = {"tasks": 0, "reports": 0, "audit": 0, "legacy_tasks": 0}
    remaining = limit

    if remaining:
        rows = _missing_index_query(AgentTask, "task", AgentTask.id).order_by(
            AgentTask.created_at.desc()
        ).limit(remaining).all()
        for row in rows:
            index_agent_task(row)
        indexed["tasks"] = len(rows)
        remaining -= len(rows)

    if remaining:
        rows = _missing_index_query(AggregatedJob, "report", AggregatedJob.id).order_by(
            AggregatedJob.created_at.desc()
        ).limit(remaining).all()
        from core.report_versions import ensure_report_revision
        for row in rows:
            ensure_report_revision(
                row,
                actor_user_id=getattr(row, "actor_user_id", None),
                actor_name=getattr(row, "created_by", None) or "System",
            )
            index_report(row)
        indexed["reports"] = len(rows)
        remaining -= len(rows)

    if remaining:
        rows = _missing_index_query(AuditLog, "audit", AuditLog.id).order_by(
            AuditLog.timestamp.desc()
        ).limit(remaining).all()
        for row in rows:
            index_audit_log(row)
        indexed["audit"] = len(rows)
        remaining -= len(rows)

    if remaining:
        rows = _missing_index_query(Task, "legacy_task", Task.id).order_by(
            Task.created_at.desc()
        ).limit(remaining).all()
        for row in rows:
            index_legacy_task(row)
        indexed["legacy_tasks"] = len(rows)

    indexed["total"] = sum(indexed.values())
    indexed["indexed_at"] = datetime.utcnow().isoformat() + "Z"
    return indexed


def search_index_stats():
    rows = db.session.query(
        HistorySearchToken.entity_type,
        func.count(func.distinct(HistorySearchToken.entity_id)),
        func.count(HistorySearchToken.id),
    ).group_by(HistorySearchToken.entity_type).all()
    return {
        entity_type: {"documents": int(documents), "tokens": int(tokens)}
        for entity_type, documents, tokens in rows
    }
