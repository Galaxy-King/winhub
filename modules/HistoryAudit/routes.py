# ==============================================================================
# ШЛЯХ: modules/history_audit/routes.py
# ПРИЗНАЧЕННЯ: Уніфікований API історії з підтримкою аудиту логінів та реєстрацій
# ==============================================================================
import logging
import os
from flask import Blueprint, jsonify, session, current_app, render_template, request
from core.database import db, User, AgentTask, AuditLog, Task, RegistrationHistory
from core.security import sec_manager
from core.permissions import has_module_access, has_permission
from datetime import datetime, timedelta

history_bp = Blueprint('history_audit', __name__, template_folder='templates')
log = logging.getLogger("winhub.history")


def _date(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else ""


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

@history_bp.before_request
def check_access():
    user = User.query.get(session.get('user_id'))
    if not user: 
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if not has_module_access(user, "HistoryAudit"):
        return jsonify({"success": False, "message": "Access Denied"}), 403


def _current_user():
    return User.query.get(session.get('user_id'))


def _is_interactive_admin(user):
    return bool(user and user.is_admin and not session.get("api_key_auth"))


def _require_history_permission(permission_id):
    if not has_permission(_current_user(), "HistoryAudit", permission_id):
        return jsonify({"success": False, "message": "Access Denied"}), 403
    return None

@history_bp.route("/module/history")
def index():
    retention = current_app.config.get('LOG_RETENTION_DAYS', 30)
    permissions = {
        "view_history": has_permission(_current_user(), "HistoryAudit", "view_history"),
        "manage_history": has_permission(_current_user(), "HistoryAudit", "manage_history"),
    }
    return render_template('history_index.html', retention=retention, permissions=permissions)

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
        q = q.filter_by(created_by=user.username)
    
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
        history.append(_history_item(
            f"task_{t.id}",
            "task",
            t.created_at,
            task_user,
            f"{t.module_name or 'Module'}: {t.action or 'Task'}",
            t.targets,
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
        return jsonify({"success": True, "log": entry.details if entry else "No details available."})
    
    if task_id.startswith("agent_"):
        entry = AgentTask.query.get(task_id.replace("agent_", ""))
        if entry and not is_full_admin and entry.created_by != user.username:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        return jsonify({"success": True, "log": entry.result_log if entry else "No execution log returned."})

    if task_id.startswith("task_"):
        entry = Task.query.get(task_id.replace("task_", ""))
        if not entry:
            return jsonify({"success": True, "log": "No details available."})
        if not is_full_admin and entry.user_id != user.id:
            return jsonify({"success": False, "message": "Access Denied"}), 403
        if entry.log_file and os.path.exists(entry.log_file):
            with open(entry.log_file, "r", encoding="utf-8", errors="replace") as f:
                return jsonify({"success": True, "log": f.read()})
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
