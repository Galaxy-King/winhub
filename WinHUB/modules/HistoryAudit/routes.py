"""Unified, server-side audit and execution-history search."""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import Blueprint, current_app, g, jsonify, render_template, request, session
from sqlalchemy import String, cast, or_

from core.database import (
    AgentTask, AggregatedJob, AuditLog, HistorySearchToken, RegistrationHistory,
    ReportDelivery, ReportRevision, Task, User, db,
)
from core.group_access import allowed_host_ids_for_action
from core.history_search import backfill_history_search_index, matching_entity_ids, search_index_stats
from core.permissions import has_module_access, has_permission
from core.sensitive_data import mask_sensitive_text

history_bp = Blueprint("history_audit", __name__, template_folder="templates")
log = logging.getLogger("winhub.history")
try:
    KYIV_TZ = ZoneInfo("Europe/Kyiv")
except Exception:
    KYIV_TZ = ZoneInfo("Europe/Kiev")

TYPE_PREFIXES = {
    "audit": "aud_", "task": "agent_", "report": "report_",
    "registration": "reg_", "legacy_task": "task_",
}


def _display_dt(value):
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(KYIV_TZ)


def _date(value):
    local = _display_dt(value)
    return local.strftime("%Y-%m-%d %H:%M:%S %Z") if local else ""


def _parse_date(value, *, end=False):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if len(raw) == 10 and end:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=KYIV_TZ)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _csv_arg(name):
    values = []
    for part in request.args.getlist(name):
        values.extend(item.strip() for item in str(part).split(","))
    return [item for item in values if item and item.lower() != "all"]


def _cursor_encode(item):
    payload = json.dumps({"ts": item["timestamp"].isoformat(), "id": item["id"]}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _cursor_decode(value):
    try:
        raw = str(value or "")
        payload = json.loads(base64.urlsafe_b64decode((raw + "=" * (-len(raw) % 4)).encode()).decode())
        return datetime.fromisoformat(payload["ts"]), str(payload["id"])
    except Exception:
        return None


def _format_details(value):
    if value is None or value == "":
        return "No details available."
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    try:
        return json.dumps(json.loads(value), ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


@history_bp.before_request
def check_access():
    user = User.query.get(session.get("user_id"))
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    g.history_current_user = user
    if not has_module_access(user, "HistoryAudit"):
        return jsonify({"success": False, "message": "Access Denied"}), 403


def _current_user():
    return getattr(g, "history_current_user", None)


def _is_superadmin(user=None):
    user = user or _current_user()
    return bool(user and user.is_admin and not session.get("api_key_auth"))


def _require_permission(permission_id):
    if not has_permission(_current_user(), "HistoryAudit", permission_id):
        return jsonify({"success": False, "message": "Access Denied"}), 403
    return None


def _require_superadmin():
    if not _is_superadmin():
        return jsonify({"success": False, "message": "Only an interactive superadmin can permanently delete history"}), 403
    return None


def _allowed_host_ids(user, action_id="view_queue"):
    if not user or not has_permission(user, "Infrastructure", action_id):
        return set()
    return allowed_host_ids_for_action(user, action_id, approved_only=not _is_superadmin(user))


def _can_view_sensitive(user, endpoint_id=None):
    if _is_superadmin(user):
        return True
    if not endpoint_id or not has_permission(user, "Infrastructure", "view_sensitive_reports"):
        return False
    return str(endpoint_id) in _allowed_host_ids(user, "view_sensitive_reports")


def _token_subquery(entity_type, text, fields):
    if not text:
        return None
    return matching_entity_ids(entity_type, text, fields=fields, mode=request.args.get("content_mode", "all"))


def _apply_time(query, column, filters):
    if filters["start"]:
        query = query.filter(column >= filters["start"])
    if filters["end"]:
        query = query.filter(column <= filters["end"])
    if filters["cursor"]:
        query = query.filter(column <= filters["cursor"][0])
    return query


def _item(record_id, event_type, timestamp, user, action, details, status, **extra):
    result = {
        "id": TYPE_PREFIXES[event_type] + str(record_id), "type": event_type,
        "timestamp": timestamp or datetime.min, "date": _date(timestamp),
        "user": user or "System", "action": action or "", "details": details or "",
        "status": status or "Success",
    }
    result.update(extra)
    return result


def _query_audit(f, limit):
    q = _apply_time(AuditLog.query, AuditLog.timestamp, f)
    if f["actor"]:
        q = q.filter(or_(AuditLog.actor_name.ilike(f"%{f['actor']}%"), AuditLog.user.ilike(f"%{f['actor']}%")))
    if f["actor_id"]:
        q = q.filter(AuditLog.actor_user_id == f["actor_id"])
    if f["roles"]:
        q = q.filter(AuditLog.actor_role.in_(f["roles"]))
    if f["actor_types"]:
        q = q.filter(AuditLog.actor_type.in_(f["actor_types"]))
    if f["sources"]:
        q = q.filter(AuditLog.source_type.in_(f["sources"]))
    if f["modules"]:
        q = q.filter(AuditLog.module.in_(f["modules"]))
    if f["statuses"]:
        q = q.filter(AuditLog.status.in_(f["statuses"]))
    if f["action"]:
        q = q.filter(AuditLog.action.ilike(f"%{f['action']}%"))
    if f["target"]:
        q = q.filter(or_(AuditLog.target_id.ilike(f"%{f['target']}%"), AuditLog.target_type.ilike(f"%{f['target']}%")))
    if f["session_hash"]:
        q = q.filter(AuditLog.session_id_hash == f["session_hash"])
    if f["request_id"]:
        q = q.filter(AuditLog.request_id == f["request_id"])
    token_ids = _token_subquery("audit", f["content"], ["details"])
    if f["content"]:
        q = q.filter(cast(AuditLog.id, String).in_(token_ids)) if token_ids is not None else q.filter(False)
    if f["q"]:
        tokens = _token_subquery("audit", f["q"], ["details"])
        metadata = or_(AuditLog.actor_name.ilike(f"%{f['q']}%"), AuditLog.user.ilike(f"%{f['q']}%"), AuditLog.module.ilike(f"%{f['q']}%"), AuditLog.action.ilike(f"%{f['q']}%"), AuditLog.target_id.ilike(f"%{f['q']}%"))
        q = q.filter(or_(metadata, cast(AuditLog.id, String).in_(tokens))) if tokens is not None else q.filter(metadata)
    rows = q.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(limit).all()
    return [_item(row.id, "audit", row.timestamp, row.actor_name or row.user, row.action,
                  f"{row.module or 'System'} / {row.target_type or 'event'}: {row.target_id or '-'}",
                  row.status, source=row.source_type, module=row.module, actor_role=row.actor_role) for row in rows]


def _query_agent_tasks(f, user, limit):
    q = _apply_time(AgentTask.query, AgentTask.created_at, f)
    if not _is_superadmin(user):
        allowed = _allowed_host_ids(user)
        if not allowed:
            return []
        q = q.filter(or_(AgentTask.endpoint_id.in_(allowed), AgentTask.endpoint_id_snapshot.in_(allowed)))
    if f["actor"]:
        q = q.filter(AgentTask.created_by.ilike(f"%{f['actor']}%"))
    if f["actor_id"]:
        q = q.filter(AgentTask.actor_user_id == f["actor_id"])
    if f["sources"]:
        q = q.filter(AgentTask.source_type.in_(f["sources"]))
    if f["modules"]:
        q = q.filter(AgentTask.module_source.in_(f["modules"]))
    if f["statuses"]:
        q = q.filter(AgentTask.status.in_(f["statuses"]))
    if f["action"]:
        q = q.filter(or_(AgentTask.action_type.ilike(f"%{f['action']}%"), AgentTask.title.ilike(f"%{f['action']}%")))
    if f["target"]:
        term = f"%{f['target']}%"
        q = q.filter(or_(AgentTask.endpoint_id.ilike(term), AgentTask.endpoint_id_snapshot.ilike(term), AgentTask.endpoint_hostname_snapshot.ilike(term), AgentTask.endpoint_name_snapshot.ilike(term)))
    if f["job_id"]:
        q = q.filter(AgentTask.job_id == f["job_id"])
    if f["template_id"]:
        q = q.filter(AgentTask.template_id == f["template_id"])
    fields = f["content_fields"] or ["input", "output"]
    token_ids = _token_subquery("task", f["content"], fields)
    if f["content"]:
        q = q.filter(AgentTask.id.in_(token_ids)) if token_ids is not None else q.filter(False)
    if f["q"]:
        tokens = _token_subquery("task", f["q"], ["input", "output"]) if f["allow_content_search"] else None
        term = f"%{f['q']}%"
        metadata = or_(AgentTask.title.ilike(term), AgentTask.created_by.ilike(term), AgentTask.action_type.ilike(term), AgentTask.module_source.ilike(term), AgentTask.endpoint_hostname_snapshot.ilike(term), AgentTask.endpoint_name_snapshot.ilike(term), AgentTask.job_id.ilike(term))
        q = q.filter(or_(metadata, AgentTask.id.in_(tokens))) if tokens is not None else q.filter(metadata)
    rows = q.order_by(AgentTask.created_at.desc(), AgentTask.id.desc()).limit(limit).all()
    return [_item(
        row.id, "task", row.created_at, row.created_by, row.title,
        f"{row.module_source or 'Agent'} / {row.action_type or 'Task'} / Target: {row.endpoint_name_snapshot or row.endpoint_hostname_snapshot or row.endpoint_id_snapshot or row.endpoint_id or 'deleted host'}",
        row.status, source=row.source_type, module=row.module_source, job_id=row.job_id,
        target_id=row.endpoint_id_snapshot or row.endpoint_id,
    ) for row in rows]


def _query_reports(f, user, limit):
    q = _apply_time(AggregatedJob.query, AggregatedJob.created_at, f)
    if f["actor"]:
        q = q.filter(AggregatedJob.created_by.ilike(f"%{f['actor']}%"))
    if f["actor_id"]:
        q = q.filter(AggregatedJob.actor_user_id == f["actor_id"])
    if f["sources"]:
        q = q.filter(AggregatedJob.source_type.in_(f["sources"]))
    if f["statuses"]:
        q = q.filter(or_(*[
            AggregatedJob.status.ilike(f"{item}%") if item in {"Sent", "Published"}
            else AggregatedJob.status == item
            for item in f["statuses"]
        ]))
    if f["action"]:
        q = q.filter(AggregatedJob.title.ilike(f"%{f['action']}%"))
    if f["job_id"]:
        q = q.filter(AggregatedJob.id == f["job_id"])
    if f["template_id"]:
        q = q.filter(AggregatedJob.template_id == f["template_id"])
    fields = f["content_fields"] or ["current", "original", "revisions", "deliveries"]
    token_ids = _token_subquery("report", f["content"], fields)
    if f["content"]:
        q = q.filter(AggregatedJob.id.in_(token_ids)) if token_ids is not None else q.filter(False)
    if f["q"]:
        tokens = _token_subquery("report", f["q"], ["current", "original", "revisions", "deliveries"]) if f["allow_content_search"] else None
        metadata = or_(AggregatedJob.title.ilike(f"%{f['q']}%"), AggregatedJob.created_by.ilike(f"%{f['q']}%"), AggregatedJob.id.ilike(f"%{f['q']}%"))
        q = q.filter(or_(metadata, AggregatedJob.id.in_(tokens))) if tokens is not None else q.filter(metadata)
    if not _is_superadmin(user):
        candidate_ids = [row[0] for row in q.with_entities(AggregatedJob.id).all()]
        from modules.Infrastructure.routes import accessible_report_id_set
        accessible = accessible_report_id_set(candidate_ids, user.id, "view_reports")
        if not accessible:
            return []
        q = q.filter(AggregatedJob.id.in_(accessible))
    rows = q.order_by(AggregatedJob.created_at.desc(), AggregatedJob.id.desc()).limit(limit).all()
    return [_item(row.id, "report", row.created_at, row.created_by, row.title,
                  f"Revision {row.current_revision_number or 1} / {row.success_count} success / {row.error_count} errors",
                  row.status, source=row.source_type, job_id=row.id) for row in rows]


def _query_registrations(f, limit):
    q = _apply_time(RegistrationHistory.query, RegistrationHistory.timestamp, f)
    if f["statuses"] and "Success" not in f["statuses"]:
        return []
    if f["action"]:
        q = q.filter(RegistrationHistory.event_type.ilike(f"%{f['action']}%"))
    if f["target"]:
        term = f"%{f['target']}%"
        q = q.filter(or_(RegistrationHistory.hw_id.ilike(term), RegistrationHistory.hostname.ilike(term)))
    if f["q"]:
        term = f"%{f['q']}%"
        q = q.filter(or_(RegistrationHistory.hw_id.ilike(term), RegistrationHistory.hostname.ilike(term), RegistrationHistory.event_type.ilike(term)))
    rows = q.order_by(RegistrationHistory.timestamp.desc(), RegistrationHistory.id.desc()).limit(limit).all()
    return [_item(row.id, "registration", row.timestamp, "System", f"Agent {row.event_type}: {row.hostname}", f"HWID: {row.hw_id}", "Success", target_id=row.hw_id) for row in rows]


def _query_legacy(f, user, limit):
    q = _apply_time(Task.query, Task.created_at, f)
    if not _is_superadmin(user):
        q = q.filter(Task.user_id == user.id)
    if f["actor_id"]:
        q = q.filter(Task.user_id == f["actor_id"])
    if f["actor"]:
        q = q.join(User, User.id == Task.user_id).filter(User.username.ilike(f"%{f['actor']}%"))
    if f["modules"]:
        q = q.filter(Task.module_name.in_(f["modules"]))
    if f["statuses"]:
        q = q.filter(Task.status.in_(f["statuses"]))
    if f["action"]:
        q = q.filter(Task.action.ilike(f"%{f['action']}%"))
    token_ids = _token_subquery("legacy_task", f["content"], ["details"])
    if f["content"]:
        q = q.filter(Task.id.in_(token_ids)) if token_ids is not None else q.filter(False)
    if f["q"]:
        tokens = _token_subquery("legacy_task", f["q"], ["details"]) if f["allow_content_search"] else None
        metadata = or_(Task.module_name.ilike(f"%{f['q']}%"), Task.action.ilike(f"%{f['q']}%"), Task.targets.ilike(f"%{f['q']}%"))
        q = q.filter(or_(metadata, Task.id.in_(tokens))) if tokens is not None else q.filter(metadata)
    rows = q.order_by(Task.created_at.desc(), Task.id.desc()).limit(limit).all()
    return [_item(row.id, "legacy_task", row.created_at, row.user.username if row.user else "System", f"{row.module_name or 'Module'}: {row.action or 'Task'}", row.targets, row.status, module=row.module_name) for row in rows]


@history_bp.route("/module/history")
def index():
    user = _current_user()
    retention = int(current_app.config.get("HISTORY_RETENTION_DAYS", 1825) or 0)
    return render_template(
        "history_index.html", retention=retention,
        retention_years=round(retention / 365, 1) if retention else None,
        permissions={"view_history": has_permission(user, "HistoryAudit", "view_history")},
        username=user.username, is_admin=_is_superadmin(user),
        can_search_content=bool(_is_superadmin(user) or has_permission(user, "Infrastructure", "view_sensitive_reports")),
    )


@history_bp.route("/api/history/search", methods=["GET"])
@history_bp.route("/api/history/tasks", methods=["GET"])
def search_history():
    denied = _require_permission("view_history")
    if denied:
        return denied
    user = _current_user()
    requested = set(_csv_arg("type") or _csv_arg("types"))
    allowed_types = {"task", "report", "legacy_task"}
    if _is_superadmin(user):
        allowed_types.update({"audit", "registration"})
    types = requested & allowed_types if requested else allowed_types
    content = request.args.get("content", "").strip()
    if content and not (_is_superadmin(user) or has_permission(user, "Infrastructure", "view_sensitive_reports")):
        return jsonify({"success": False, "message": "Sensitive-content search permission required"}), 403
    try:
        actor_id = int(request.args.get("actor_id")) if request.args.get("actor_id") else None
        limit = max(10, min(int(request.args.get("limit", 100)), 250))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid numeric filter"}), 400
    cursor = _cursor_decode(request.args.get("cursor"))
    f = {
        "q": request.args.get("q", "").strip(), "content": content,
        "content_fields": _csv_arg("content_field"), "actor": request.args.get("actor", "").strip(),
        "actor_id": actor_id, "roles": _csv_arg("role"), "actor_types": _csv_arg("actor_type"), "sources": _csv_arg("source"),
        "modules": _csv_arg("module"), "statuses": _csv_arg("status"),
        "action": request.args.get("action", "").strip(), "target": request.args.get("target", "").strip(),
        "job_id": request.args.get("job_id", "").strip(), "template_id": request.args.get("template_id", "").strip(),
        "session_hash": request.args.get("session_id_hash", "").strip(), "request_id": request.args.get("request_id", "").strip(),
        "start": _parse_date(request.args.get("date_from")), "end": _parse_date(request.args.get("date_to"), end=True),
        "cursor": cursor,
        "allow_content_search": bool(_is_superadmin(user) or has_permission(user, "Infrastructure", "view_sensitive_reports")),
    }
    per_source = min(limit + 1, 251)
    items = []
    if "audit" in types:
        items.extend(_query_audit(f, per_source))
    if "task" in types:
        items.extend(_query_agent_tasks(f, user, per_source))
    if "report" in types:
        items.extend(_query_reports(f, user, per_source))
    if "registration" in types:
        items.extend(_query_registrations(f, per_source))
    if "legacy_task" in types:
        items.extend(_query_legacy(f, user, per_source))
    items.sort(key=lambda item: (item["timestamp"], item["id"]), reverse=True)
    if cursor:
        items = [item for item in items if (item["timestamp"], item["id"]) < cursor]
    has_more = len(items) > limit
    items = items[:limit]
    next_cursor = _cursor_encode(items[-1]) if has_more and items else None
    for item in items:
        item["timestamp_utc"] = item["timestamp"].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") if item["timestamp"] != datetime.min else None
        del item["timestamp"]
    if current_app.config.get("AUDIT_SENSITIVE_READS", True):
        from core.history_search import search_words
        from core.sdk import WinHubCore
        WinHubCore.audit(
            user_id=session.get("user_id"), module="HistoryAudit", action="Search History",
            details={
                "types": sorted(types), "actor_filter": f["actor"] or f["actor_id"],
                "source_filters": f["sources"], "module_filters": f["modules"],
                "status_filters": f["statuses"], "target_filter": bool(f["target"]),
                "metadata_query": bool(f["q"]), "content_term_count": len(search_words(f["content"], limit=20)),
                "date_from": request.args.get("date_from"), "date_to": request.args.get("date_to"),
                "result_count": len(items), "page_has_more": has_more,
            },
            target_type="history", target_id="search", status="Success", source_type="interactive",
        )
    return jsonify({"success": True, "history": items, "next_cursor": next_cursor, "has_more": has_more, "limit": limit, "retention_days": int(current_app.config.get("HISTORY_RETENTION_DAYS", 1825) or 0)})


@history_bp.route("/api/history/facets", methods=["GET"])
def history_facets():
    denied = _require_permission("view_history")
    if denied:
        return denied
    user = _current_user()
    if _is_superadmin(user):
        task_scope = True
        actor_rows = User.query.order_by(User.username).all()
    else:
        allowed = _allowed_host_ids(user)
        task_scope = or_(AgentTask.endpoint_id.in_(allowed), AgentTask.endpoint_id_snapshot.in_(allowed)) if allowed else False
        actor_ids = db.session.query(AgentTask.actor_user_id).filter(
            task_scope, AgentTask.actor_user_id.isnot(None)
        )
        actor_rows = User.query.filter(or_(User.id.in_(actor_ids), User.id == user.id)).order_by(User.username).all()
    sources = {row[0] for row in db.session.query(AgentTask.source_type).filter(task_scope).distinct().all() if row[0]}
    modules = {row[0] for row in db.session.query(AgentTask.module_source).filter(task_scope).distinct().all() if row[0]}
    if _is_superadmin():
        sources.update(row[0] for row in db.session.query(AggregatedJob.source_type).distinct().all() if row[0])
        sources.update(row[0] for row in db.session.query(AuditLog.source_type).distinct().all() if row[0])
        modules.update(row[0] for row in db.session.query(AuditLog.module).distinct().all() if row[0])
    return jsonify({
        "success": True,
        "actors": [{"id": row.id, "name": row.username, "role": "superadmin" if row.is_admin else "user"} for row in actor_rows],
        "sources": sorted(sources), "modules": sorted(modules),
        "statuses": ["Success", "Error", "Warning", "Pending", "Running", "PickedUp", "Cancelled", "Waiting Review", "Sent", "Dismissed"],
        "index": search_index_stats() if _is_superadmin() else None,
    })


def _audit_sensitive_read(kind, record_id):
    if not current_app.config.get("AUDIT_SENSITIVE_READS", True):
        return
    from core.sdk import WinHubCore
    WinHubCore.audit(user_id=session.get("user_id"), module="HistoryAudit", action="View History Detail", details={"record_type": kind, "record_id": record_id}, status="Success", source_type="interactive")


@history_bp.route("/api/history/log/<record_id>")
def get_log_details(record_id):
    denied = _require_permission("view_history")
    if denied:
        return denied
    user = _current_user()
    if record_id.startswith("aud_"):
        if not _is_superadmin(user):
            return jsonify({"success": False, "message": "Access Denied"}), 403
        entry = AuditLog.query.get(record_id[4:])
        if not entry:
            return jsonify({"success": False, "message": "Record not found"}), 404
        _audit_sensitive_read("audit", entry.id)
        return jsonify({"success": True, "log": _format_details({
            "date": _date(entry.timestamp), "actor": entry.actor_name or entry.user,
            "actor_role": entry.actor_role, "actor_type": entry.actor_type, "source": entry.source_type,
            "session_id_hash": entry.session_id_hash, "module": entry.module, "action": entry.action,
            "target_type": entry.target_type, "target_id": entry.target_id, "ip_address": entry.ip_address,
            "request_id": entry.request_id, "user_agent": entry.user_agent, "status": entry.status,
            "details": entry.details,
        })})
    if record_id.startswith("agent_"):
        entry = AgentTask.query.get(record_id[6:])
        if not entry:
            return jsonify({"success": False, "message": "Record not found"}), 404
        endpoint_id = entry.endpoint_id_snapshot or entry.endpoint_id
        if not _is_superadmin(user) and endpoint_id not in _allowed_host_ids(user):
            return jsonify({"success": False, "message": "Access Denied"}), 403
        sensitive = _can_view_sensitive(user, endpoint_id)
        _audit_sensitive_read("task", entry.id)
        return jsonify({"success": True, "log": _format_details({
            "task_id": entry.id, "job_id": entry.job_id, "actor": entry.created_by,
            "source": entry.source_type, "module": entry.module_source, "action": entry.action_type,
            "target_id": endpoint_id, "target_hostname": entry.endpoint_hostname_snapshot,
            "target_name": entry.endpoint_name_snapshot, "target_groups": entry.endpoint_groups_snapshot,
            "created_at": _date(entry.created_at), "finished_at": _date(entry.finished_at),
            "status": entry.status, "input": entry.payload if sensitive else mask_sensitive_text(entry.payload),
            "output": entry.result_log if sensitive else mask_sensitive_text(entry.result_log),
        })})
    if record_id.startswith("report_"):
        entry = AggregatedJob.query.get(record_id[7:])
        if not entry:
            return jsonify({"success": False, "message": "Record not found"}), 404
        if not _is_superadmin(user):
            allowed = _allowed_host_ids(user, "view_reports")
            accessible = AgentTask.query.filter(AgentTask.job_id == entry.id, or_(AgentTask.endpoint_id.in_(allowed), AgentTask.endpoint_id_snapshot.in_(allowed))).first()
            if not accessible:
                return jsonify({"success": False, "message": "Access Denied"}), 403
        _audit_sensitive_read("report", entry.id)
        can_view = _is_superadmin(user) or has_permission(user, "Infrastructure", "view_sensitive_reports")
        revisions = ReportRevision.query.filter_by(report_id=entry.id).order_by(ReportRevision.revision_number.desc()).all()
        deliveries = ReportDelivery.query.filter_by(report_id=entry.id).order_by(ReportDelivery.created_at.desc()).all()
        return jsonify({"success": True, "log": _format_details({
            "report_id": entry.id, "title": entry.title, "actor": entry.created_by, "source": entry.source_type,
            "status": entry.status, "created_at": _date(entry.created_at), "current_revision": entry.current_revision_number,
            "original_hash": entry.original_content_hash,
            "revisions": [{"number": row.revision_number, "kind": row.kind, "actor": row.actor_name, "date": _date(row.created_at), "hash": row.content_hash, "reason": row.reason} for row in revisions],
            "deliveries": [{"channel": row.channel, "destination": row.destination, "status": row.status, "date": _date(row.created_at), "hash": row.content_hash} for row in deliveries],
            "current_content": entry.report_data if can_view else mask_sensitive_text(entry.report_data),
        })})
    if record_id.startswith("task_"):
        entry = Task.query.get(record_id[5:])
        if not entry:
            return jsonify({"success": False, "message": "Record not found"}), 404
        if not _is_superadmin(user) and entry.user_id != user.id:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        log_file = entry.log_file
        if not _is_superadmin(user) and log_file:
            public_file = log_file.replace(".log", "_public.log")
            if os.path.exists(public_file):
                log_file = public_file
        body = ""
        if log_file and os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
                body = handle.read()
        if not body:
            body = f"{entry.module_name}: {entry.action}\nTargets: {entry.targets}\nStatus: {entry.status}"
        _audit_sensitive_read("legacy_task", entry.id)
        return jsonify({"success": True, "log": body if _is_superadmin(user) else mask_sensitive_text(body)})
    if record_id.startswith("reg_"):
        if not _is_superadmin(user):
            return jsonify({"success": False, "message": "Access Denied"}), 403
        entry = RegistrationHistory.query.get(record_id[4:])
        if not entry:
            return jsonify({"success": False, "message": "Record not found"}), 404
        _audit_sensitive_read("registration", entry.id)
        return jsonify({"success": True, "log": _format_details({"date": _date(entry.timestamp), "hw_id": entry.hw_id, "hostname": entry.hostname, "ip_address": entry.ip_address, "event": entry.event_type})})
    return jsonify({"success": False, "message": "Unknown record type"}), 400


@history_bp.route("/api/history/reindex", methods=["POST"])
def reindex_history():
    denied = _require_superadmin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    requested = payload.get("limit", current_app.config.get("HISTORY_SEARCH_BACKFILL_BATCH_SIZE", 250))
    reset = payload.get("reset") is True
    if reset:
        HistorySearchToken.query.delete(synchronize_session=False)
        db.session.commit()
    result = backfill_history_search_index(requested)
    db.session.commit()
    from core.sdk import WinHubCore
    WinHubCore.audit(
        user_id=session.get("user_id"), module="HistoryAudit", action="Rebuild History Search Index",
        details={"reset": reset, "indexed": result}, target_type="history_index",
        target_id="all", status="Success", source_type="interactive",
    )
    return jsonify({"success": True, "result": result, "index": search_index_stats(), "reset": reset})


@history_bp.route("/api/history/cleanup", methods=["POST"])
def run_cleanup():
    denied = _require_superadmin()
    if denied:
        return denied
    try:
        from core import _run_history_retention
        result = _run_history_retention(datetime.utcnow())
        from core.sdk import WinHubCore
        WinHubCore.audit(user_id=session.get("user_id"), module="HistoryAudit", action="Manual History Retention", details=result, status="Success", source_type="interactive")
        return jsonify({"success": True, "message": "Retention cleanup completed", "result": result})
    except Exception as exc:
        db.session.rollback()
        log.exception("Manual history cleanup failed")
        return jsonify({"success": False, "message": str(exc)}), 500


@history_bp.route("/api/history/delete_selected", methods=["POST"])
def delete_selected_logs():
    denied = _require_superadmin()
    if denied:
        return denied
    ids = [str(item) for item in (request.get_json(silent=True) or {}).get("task_ids", [])]
    if not ids:
        return jsonify({"success": False, "message": "No records selected"}), 400
    deleted = {key: 0 for key in TYPE_PREFIXES}
    try:
        for record_id in ids[:500]:
            if record_id.startswith("aud_"):
                raw_id = record_id[4:]
                HistorySearchToken.query.filter_by(entity_type="audit", entity_id=raw_id).delete(synchronize_session=False)
                deleted["audit"] += AuditLog.query.filter_by(id=raw_id).delete(synchronize_session=False)
            elif record_id.startswith("agent_"):
                raw_id = record_id[6:]
                HistorySearchToken.query.filter_by(entity_type="task", entity_id=raw_id).delete(synchronize_session=False)
                deleted["task"] += AgentTask.query.filter_by(id=raw_id).delete(synchronize_session=False)
            elif record_id.startswith("report_"):
                raw_id = record_id[7:]
                ReportDelivery.query.filter_by(report_id=raw_id).delete(synchronize_session=False)
                ReportRevision.query.filter_by(report_id=raw_id).delete(synchronize_session=False)
                HistorySearchToken.query.filter_by(entity_type="report", entity_id=raw_id).delete(synchronize_session=False)
                deleted["report"] += AggregatedJob.query.filter_by(id=raw_id).delete(synchronize_session=False)
            elif record_id.startswith("task_"):
                raw_id = record_id[5:]
                HistorySearchToken.query.filter_by(entity_type="legacy_task", entity_id=raw_id).delete(synchronize_session=False)
                deleted["legacy_task"] += Task.query.filter_by(id=raw_id).delete(synchronize_session=False)
            elif record_id.startswith("reg_"):
                deleted["registration"] += RegistrationHistory.query.filter_by(id=record_id[4:]).delete(synchronize_session=False)
        db.session.commit()
        from core.sdk import WinHubCore
        WinHubCore.audit(user_id=session.get("user_id"), module="HistoryAudit", action="Permanently Delete History", details={"requested_ids": ids[:500], "deleted": deleted}, status="Success", source_type="interactive")
        return jsonify({"success": True, "message": "Selected history permanently deleted", "deleted": deleted})
    except Exception as exc:
        db.session.rollback()
        return jsonify({"success": False, "message": str(exc)}), 500
