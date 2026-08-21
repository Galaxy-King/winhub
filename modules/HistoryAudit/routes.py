# ==============================================================================
# ШЛЯХ: modules/history_audit/routes.py
# ПРИЗНАЧЕННЯ: Уніфікований API історії з підтримкою аудиту логінів та реєстрацій
# ==============================================================================
import logging
import os
import json
from flask import Blueprint, jsonify, session, current_app, render_template, request, g
from core.database import db, User, AgentTask, AuditLog, Task, RegistrationHistory
from core.security import sec_manager
from core.permissions import has_module_access, has_permission
from core.sensitive_data import mask_sensitive_text
from core.group_access import allowed_host_ids_for_action
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

history_bp = Blueprint('history_audit', __name__, template_folder='templates')
log = logging.getLogger("winhub.history")

try:
    KYIV_TZ = ZoneInfo("Europe/Kyiv")
except Exception:
    KYIV_TZ = ZoneInfo("Europe/Kiev")


def _display_dt(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KYIV_TZ)


def _date(dt):
    local_dt = _display_dt(dt)
    return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z') if local_dt else ""


def _history_item(record_id, event_type, dt, user, action, details, status):
    return {
        "id": record_id,
        "type": event_type,
        "date": _date(dt),
        "user": user or "System",
        "action": action or "",
        "details": details or "",
        "status": status or "Success",
        "timestamp": dt or datetime.min,
    }


def _format_details(details):
    if not details:
        return "No details available."
    if isinstance(details, (dict, list)):
        return json.dumps(details, ensure_ascii=False, indent=2)
    try:
        parsed = json.loads(details)
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    except Exception:
        return str(details)


def _task_log_problem_summary(task, is_full_admin):
    if not is_full_admin or not task or not getattr(task, "log_file", None):
        return ""
    if not os.path.exists(task.log_file):
        return ""
    try:
        with open(task.log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        log.warning("Failed to read task log summary for %s: %s", getattr(task, "id", ""), e)
        return ""

    markers = (
        "Failed:",
        "CRITICAL ERROR",
        "Encryption Error",
        "Missing GPG Key",
        "GPG Encryption Error",
        "SMTP Connection/Send Error",
        "Failure Breakdown",
    )
    matches = []
    for line in lines:
        clean = line.strip()
        if clean and any(marker in clean for marker in markers):
            matches.append(clean)
    if not matches:
        return ""
    return "Problems: " + " | ".join(matches[-4:])


def _is_newsletter_campaign_audit(entry):
    if not entry or getattr(entry, "module", None) != "Newsletter":
        return False
    return getattr(entry, "action", "") in {
        "Newsletter: Send Campaign",
        "Newsletter: Campaign Finished",
        "Newsletter: Campaign Failed",
        "Newsletter: Send Mailing",
        "Newsletter: Mailing Finished",
        "Newsletter: Mailing Failed",
    }

@history_bp.before_request
def check_access():
    user = User.query.get(session.get('user_id'))
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    g.history_current_user = user
    if not has_module_access(user, "HistoryAudit"):
        return jsonify({"success": False, "message": "Access Denied"}), 403


def _current_user():
    cached = getattr(g, "history_current_user", None)
    if cached is not None:
        return cached
    user = User.query.get(session.get('user_id'))
    g.history_current_user = user
    return user


def _is_interactive_admin(user):
    return bool(user and user.is_admin and not session.get("api_key_auth"))


def _can_view_sensitive_output(user, endpoint_id=None):
    if _is_interactive_admin(user):
        return True
    if not endpoint_id or not has_permission(user, "Infrastructure", "view_sensitive_reports"):
        return False
    return str(endpoint_id) in _allowed_host_ids(user, "view_sensitive_reports")


def _allowed_host_ids(user, action_id="view_queue"):
    if not user or not has_permission(user, "Infrastructure", action_id):
        return set()
    return allowed_host_ids_for_action(
        user,
        action_id,
        approved_only=not _is_interactive_admin(user),
    )


def _require_history_permission(permission_id):
    if not has_permission(_current_user(), "HistoryAudit", permission_id):
        return jsonify({"success": False, "message": "Access Denied"}), 403
    return None

@history_bp.route("/module/history")
def index():
    retention = current_app.config.get('LOG_RETENTION_DAYS', 30)
    user = _current_user()
    permissions = {
        "view_history": has_permission(user, "HistoryAudit", "view_history"),
        "manage_history": has_permission(user, "HistoryAudit", "manage_history"),
        "delete_tasks": has_permission(user, "Infrastructure", "delete_tasks"),
    }
    return render_template(
        'history_index.html',
        retention=retention,
        permissions=permissions,
        username=getattr(user, "username", ""),
        is_admin=_is_interactive_admin(user),
    )

@history_bp.route("/api/history/tasks", methods=["GET"])
def get_unified_history():
    """Повертає об'єднану історію: Аудит (Логіни/Модулі) + Задачі + Реєстрації"""
    denied = _require_history_permission("view_history")
    if denied:
        return denied
    user = _current_user()
    is_full_admin = _is_interactive_admin(user)
    history = []

    # 1. Системний Аудит (Логіни, Спроби, Доступ до модулів)
    if is_full_admin:
        audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
        for a in audits:
            if _is_newsletter_campaign_audit(a):
                continue
            event_type = "module" if a.action and ":" in a.action else "audit"
            history.append(_history_item(
                f"aud_{a.id}",
                event_type,
                a.timestamp,
                a.user,
                a.action,
                a.details,
                a.status,
            ))

    # 2. Історія реєстрації агентів (Enrollment)
    if is_full_admin:
        reg_history = RegistrationHistory.query.order_by(RegistrationHistory.timestamp.desc()).limit(100).all()
        for r in reg_history:
            history.append(_history_item(
                f"reg_{r.id}",
                "registration",
                r.timestamp,
                "System",
                f"Agent {r.event_type}: {r.hostname}",
                f"HWID: {r.hw_id}; IP: {r.ip_address}",
                "Success",
            ))

    # 3. Завдання нових агентів (Infrastructure Tasks)
    q = AgentTask.query
    if not is_full_admin:
        q = q.filter(AgentTask.endpoint_id.in_(_allowed_host_ids(user)))

    agent_tasks = q.order_by(AgentTask.created_at.desc()).limit(200).all()
    for t in agent_tasks:
        history.append(_history_item(
            f"agent_{t.id}",
            "task",
            t.created_at,
            t.created_by,
            t.title,
            f"{t.module_source or 'Agent'} / {t.action_type or 'Task'} / Target: {t.endpoint_id}",
            t.status,
        ))

    # 4. Legacy Task table used by optional modules such as Newsletter.
    legacy_q = Task.query
    if not is_full_admin:
        legacy_q = legacy_q.filter_by(user_id=user.id)

    legacy_tasks = legacy_q.order_by(Task.created_at.desc()).limit(200).all()
    for t in legacy_tasks:
        task_user = t.user.username if getattr(t, "user", None) else "System"
        details = t.targets
        problem_summary = _task_log_problem_summary(t, is_full_admin)
        if problem_summary:
            details = f"{t.targets or 'Targets unavailable'} / {problem_summary}"
        history.append(_history_item(
            f"task_{t.id}",
            "task",
            t.created_at,
            task_user,
            f"{t.module_name or 'Module'}: {t.action or 'Task'}",
            details,
            t.status,
        ))

    # Сортування за об'єктом datetime для точності
    history.sort(key=lambda x: x["timestamp"], reverse=True)

    # Очищуємо об'єкт timestamp перед відправкою JSON
    for h in history:
        del h["timestamp"]

    return jsonify({"success": True, "history": history[:400]})

@history_bp.route("/api/history/log/<task_id>")
def get_log_details(task_id):
    denied = _require_history_permission("view_history")
    if denied:
        return denied
    user = _current_user()
    is_full_admin = _is_interactive_admin(user)
    """Отримує детальний лог або опис події аудиту"""
    if task_id.startswith("aud_"):
        if not is_full_admin:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        entry = AuditLog.query.get(task_id.replace("aud_", ""))
        return jsonify({"success": True, "log": _format_details(entry.details) if entry else "No details available."})

    if task_id.startswith("agent_"):
        entry = AgentTask.query.get(task_id.replace("agent_", ""))
        if entry and not is_full_admin and entry.endpoint_id not in _allowed_host_ids(user):
            return jsonify({"success": False, "message": "Access Denied"}), 403
        log_body = entry.result_log if entry else "No execution log returned."
        if not _can_view_sensitive_output(user, entry.endpoint_id if entry else None):
            log_body = mask_sensitive_text(log_body)
        return jsonify({"success": True, "log": log_body})

    if task_id.startswith("task_"):
        entry = Task.query.get(task_id.replace("task_", ""))
        if not entry:
            return jsonify({"success": True, "log": "No details available."})
        if not is_full_admin and entry.user_id != user.id:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        log_file = entry.log_file
        if not is_full_admin and log_file:
            public_log_file = log_file.replace(".log", "_public.log")
            if os.path.exists(public_log_file):
                log_file = public_log_file
        if log_file and os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                log_body = f.read()
                if not _can_view_sensitive_output(user):
                    log_body = mask_sensitive_text(log_body)
                return jsonify({"success": True, "log": log_body})
        return jsonify({"success": True, "log": f"{entry.module_name}: {entry.action}\nTargets: {entry.targets}\nStatus: {entry.status}"})

    if task_id.startswith("reg_"):
        if not is_full_admin:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        entry = RegistrationHistory.query.get(task_id.replace("reg_", ""))
        return jsonify({"success": True, "log": f"HWID: {entry.hw_id}\nHostname: {entry.hostname}\nIP: {entry.ip_address}\nEvent: {entry.event_type}"})

    return jsonify({"success": False, "message": "Unknown record type."}), 400

@history_bp.route("/api/history/cleanup", methods=["POST"])
def run_cleanup():
    denied = _require_history_permission("manage_history")
    if denied:
        return denied
    if not _is_interactive_admin(_current_user()):
        return jsonify({"success": False, "message": "Global history cleanup requires superadmin"}), 403
    """Видаляє старі записи згідно з налаштуваннями ретенції"""
    retention_days = current_app.config.get('LOG_RETENTION_DAYS', 30)
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    try:
        # Видаляємо застарілий аудит та завдання
        AuditLog.query.filter(AuditLog.timestamp < cutoff_date).delete()
        AgentTask.query.filter(AgentTask.created_at < cutoff_date).delete()
        Task.query.filter(Task.created_at < cutoff_date).delete()
        RegistrationHistory.query.filter(RegistrationHistory.timestamp < cutoff_date).delete()

        db.session.commit()
        return jsonify({"success": True, "message": f"Cleanup finished. Records older than {retention_days} days removed."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@history_bp.route("/api/history/delete_selected", methods=["POST"])
def delete_selected_logs():
    denied = _require_history_permission("manage_history")
    if denied:
        return denied
    """Масове видалення вибраних записів адміністратором"""
    data = request.json or {}
    ids = data.get("task_ids", [])
    if not ids: return jsonify({"success": False, "message": "No records selected."}), 400

    user = _current_user()
    is_full_admin = _is_interactive_admin(user)
    if not is_full_admin:
        if not has_permission(user, "Infrastructure", "delete_tasks"):
            return jsonify({"success": False, "message": "Task deletion permission required"}), 403
        if any(not str(item_id).startswith("agent_") for item_id in ids):
            return jsonify({"success": False, "message": "Only scoped agent tasks may be deleted"}), 403
        agent_ids = {str(item_id).replace("agent_", "", 1) for item_id in ids}
        rows = db.session.query(
            AgentTask.id,
            AgentTask.endpoint_id,
        ).filter(AgentTask.id.in_(agent_ids)).all()
        allowed_hosts = _allowed_host_ids(user, "delete_tasks")
        if len(rows) != len(agent_ids) or any(
            endpoint_id not in allowed_hosts
            for _, endpoint_id in rows
        ):
            return jsonify({"success": False, "message": "One or more tasks are outside your scope"}), 403
        AgentTask.query.filter(AgentTask.id.in_(agent_ids)).delete(synchronize_session=False)
        db.session.add(AuditLog(
            user=user.username,
            actor_type="api_key" if session.get("api_key_auth") else "user",
            actor_name=user.username,
            module="HistoryAudit",
            action="Delete Scoped Task History",
            target_type="agent_task",
            target_id="bulk",
            details=json.dumps({"deleted_count": len(agent_ids)}, ensure_ascii=False),
            status="Success",
        ))
        db.session.commit()
        return jsonify({"success": True, "message": f"Deleted {len(agent_ids)} scoped task record(s)."})

    for item_id in ids:
        if item_id.startswith("aud_"):
            AuditLog.query.filter_by(id=item_id.replace("aud_", "")).delete()
        elif item_id.startswith("agent_"):
            AgentTask.query.filter_by(id=item_id.replace("agent_", "")).delete()
        elif item_id.startswith("task_"):
            Task.query.filter_by(id=item_id.replace("task_", "")).delete()
        elif item_id.startswith("reg_"):
            RegistrationHistory.query.filter_by(id=item_id.replace("reg_", "")).delete()

    db.session.commit()
    return jsonify({"success": True, "message": "Selected records deleted."})
