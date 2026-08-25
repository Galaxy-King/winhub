import os
import logging
import importlib
import json
import secrets
import time
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import Flask, g, request, redirect, url_for, session, render_template, Blueprint, jsonify
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, or_, text
from werkzeug.exceptions import RequestEntityTooLarge

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from core.config import Config
from core.csp import build_csp_headers, new_csp_nonce
from core.database import (
    db, User, Endpoint, AgentTask, AuditLog, TelemetryHistory, ScheduledTask,
    EndpointGroup, ApiKey, TaskTemplate, AggregatedJob, Task,
    RegistrationHistory, ConnectionIpHistory, ReportRevision, ReportDelivery,
    HistorySearchToken,
)
from core.security import sec_manager
from core.host_security import apply_endpoint_encryption_status
from core.auth import auth_bp
from core.admin import admin_bp
from core.agent_gateway import agent_gateway_bp
from core.version import get_version
from core.module_registry import REQUIRED_MODULES, get_loaded_modules, get_module_registry, reset_module_registry, set_module_status
from core.permissions import full_module_grants, has_module_access, has_permission

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("winhub")

socketio = SocketIO(cors_allowed_origins="*", async_mode='gevent')
core_routes = Blueprint('core_routes', __name__)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT] if Config.RATELIMIT_DEFAULT else [],
    storage_uri=Config.RATELIMIT_STORAGE_URI,
)

# Київський часовий пояс
kyiv_tz = ZoneInfo("Europe/Kyiv")
scheduler = BackgroundScheduler(timezone=kyiv_tz)

# ГЛОБАЛЬНА ЗМІННА ДЛЯ ФОНОВИХ ПОТОКІВ (Захист від RuntimeError Context)
global_app = None
_last_retention_cleanup_day = None


def _bounded_ids(query, id_column, limit):
    return [row[0] for row in query.with_entities(id_column).limit(limit).all()]


def _remove_legacy_task_logs(tasks, data_dir):
    """Remove only task logs that resolve inside DATA_DIR/logs."""
    log_root = (Path(data_dir) / "logs").resolve()
    removed = 0
    for task in tasks:
        if not task.log_file:
            continue
        for candidate in (Path(task.log_file), Path(str(task.log_file).replace(".log", "_public.log"))):
            try:
                resolved = candidate.resolve()
                if resolved.parent != log_root or not resolved.name.startswith("task_"):
                    continue
                if resolved.is_file():
                    resolved.unlink()
                    removed += 1
            except OSError:
                log.warning("Retention could not remove legacy task log %s", candidate)
    return removed


def _expired_report_query(cutoff):
    """Keep an old report while it has a revision or delivery inside retention."""
    recent_revision = db.session.query(ReportRevision.id).filter(
        ReportRevision.report_id == AggregatedJob.id,
        ReportRevision.created_at >= cutoff,
    ).exists()
    recent_delivery = db.session.query(ReportDelivery.id).filter(
        ReportDelivery.report_id == AggregatedJob.id,
        ReportDelivery.created_at >= cutoff,
    ).exists()
    return AggregatedJob.query.filter(
        AggregatedJob.created_at < cutoff,
        ~recent_revision,
        ~recent_delivery,
    )


def _run_history_retention(now):
    """Delete one bounded batch of expired history in dependency-safe order."""
    retention_days = int(global_app.config.get("HISTORY_RETENTION_DAYS", 1825) or 0)
    if retention_days <= 0:
        return {"disabled": True, "retention_days": retention_days}

    cutoff = now - timedelta(days=retention_days)
    batch_size = max(100, min(int(global_app.config.get("HISTORY_CLEANUP_BATCH_SIZE", 5000)), 50000))
    counts = {
        "reports": 0,
        "tasks": 0,
        "legacy_tasks": 0,
        "registrations": 0,
        "connection_ips": 0,
        "audit": 0,
        "log_files": 0,
    }

    report_ids = _bounded_ids(
        _expired_report_query(cutoff).order_by(AggregatedJob.created_at),
        AggregatedJob.id,
        batch_size,
    )
    if report_ids:
        revision_ids = [row[0] for row in db.session.query(ReportRevision.id).filter(
            ReportRevision.report_id.in_(report_ids)
        ).all()]
        ReportDelivery.query.filter(ReportDelivery.report_id.in_(report_ids)).delete(synchronize_session=False)
        if revision_ids:
            ReportDelivery.query.filter(ReportDelivery.revision_id.in_(revision_ids)).delete(synchronize_session=False)
        ReportRevision.query.filter(ReportRevision.report_id.in_(report_ids)).delete(synchronize_session=False)
        HistorySearchToken.query.filter(
            HistorySearchToken.entity_type == "report",
            HistorySearchToken.entity_id.in_(report_ids),
        ).delete(synchronize_session=False)
        counts["reports"] = AggregatedJob.query.filter(AggregatedJob.id.in_(report_ids)).delete(synchronize_session=False)

    task_ids = _bounded_ids(
        AgentTask.query.filter(
            AgentTask.created_at < cutoff,
            or_(AgentTask.finished_at.is_(None), AgentTask.finished_at < cutoff),
        ).order_by(AgentTask.created_at),
        AgentTask.id,
        batch_size,
    )
    if task_ids:
        HistorySearchToken.query.filter(
            HistorySearchToken.entity_type == "task",
            HistorySearchToken.entity_id.in_(task_ids),
        ).delete(synchronize_session=False)
        counts["tasks"] = AgentTask.query.filter(AgentTask.id.in_(task_ids)).delete(synchronize_session=False)

    legacy_ids = _bounded_ids(
        Task.query.filter(
            Task.created_at < cutoff,
            or_(Task.ended_at.is_(None), Task.ended_at < cutoff),
        ).order_by(Task.created_at),
        Task.id,
        batch_size,
    )
    if legacy_ids:
        legacy_rows = Task.query.filter(Task.id.in_(legacy_ids)).all()
        counts["log_files"] = _remove_legacy_task_logs(legacy_rows, global_app.config["DATA_DIR"])
        HistorySearchToken.query.filter(
            HistorySearchToken.entity_type == "legacy_task",
            HistorySearchToken.entity_id.in_(legacy_ids),
        ).delete(synchronize_session=False)
        counts["legacy_tasks"] = Task.query.filter(Task.id.in_(legacy_ids)).delete(synchronize_session=False)

    registration_ids = _bounded_ids(
        RegistrationHistory.query.filter(RegistrationHistory.timestamp < cutoff).order_by(RegistrationHistory.timestamp),
        RegistrationHistory.id,
        batch_size,
    )
    if registration_ids:
        counts["registrations"] = RegistrationHistory.query.filter(
            RegistrationHistory.id.in_(registration_ids)
        ).delete(synchronize_session=False)

    connection_ids = _bounded_ids(
        ConnectionIpHistory.query.filter(ConnectionIpHistory.timestamp < cutoff).order_by(ConnectionIpHistory.timestamp),
        ConnectionIpHistory.id,
        batch_size,
    )
    if connection_ids:
        counts["connection_ips"] = ConnectionIpHistory.query.filter(
            ConnectionIpHistory.id.in_(connection_ids)
        ).delete(synchronize_session=False)

    audit_ids = _bounded_ids(
        AuditLog.query.filter(AuditLog.timestamp < cutoff).order_by(AuditLog.timestamp),
        AuditLog.id,
        batch_size,
    )
    if audit_ids:
        audit_entity_ids = [str(item) for item in audit_ids]
        HistorySearchToken.query.filter(
            HistorySearchToken.entity_type == "audit",
            HistorySearchToken.entity_id.in_(audit_entity_ids),
        ).delete(synchronize_session=False)
        counts["audit"] = AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)

    db.session.commit()
    counts["retention_days"] = retention_days
    counts["cutoff_utc"] = cutoff.isoformat() + "Z"
    counts["has_more"] = any((
        _expired_report_query(cutoff).first() is not None,
        AgentTask.query.filter(
            AgentTask.created_at < cutoff,
            or_(AgentTask.finished_at.is_(None), AgentTask.finished_at < cutoff),
        ).first() is not None,
        Task.query.filter(
            Task.created_at < cutoff,
            or_(Task.ended_at.is_(None), Task.ended_at < cutoff),
        ).first() is not None,
        RegistrationHistory.query.filter(RegistrationHistory.timestamp < cutoff).first() is not None,
        ConnectionIpHistory.query.filter(ConnectionIpHistory.timestamp < cutoff).first() is not None,
        AuditLog.query.filter(AuditLog.timestamp < cutoff).first() is not None,
    ))
    return counts

# --- ФОНОВІ ЗАДАЧІ ---
def scheduled_cleanup(*args):
    global global_app, _last_retention_cleanup_day
    if not global_app: return
    with global_app.app_context():
        now = datetime.utcnow()
        completed_job_ids = set()
        timed_out_schedule_ids = set()
        changed_history_tasks = []
        # Очищення завислих задач
        zombie_threshold = now - timedelta(seconds=global_app.config.get('AGENT_TASK_TIMEOUT_SECONDS', 1800))
        zombies = AgentTask.query.filter(AgentTask.status == "PickedUp", AgentTask.created_at < zombie_threshold).all()
        for z in zombies:
            z.status = "Error"
            z.result_log = "TIMEOUT: Agent picked up the task but never returned a result."
            z.finished_at = now
            completed_job_ids.add(z.job_id)
            changed_history_tasks.append(z)

        deadline_candidates = AgentTask.query.filter(
            AgentTask.status.in_(["Pending", "PickedUp", "Running"]),
            AgentTask.payload.isnot(None)
        ).limit(5000).all()
        for task in deadline_candidates:
            try:
                payload = json.loads(task.payload or "{}")
            except Exception:
                continue
            deadline_raw = payload.get("__deadline_utc")
            if not deadline_raw:
                continue
            try:
                deadline = datetime.fromisoformat(str(deadline_raw).replace("Z", "+00:00"))
                if deadline.tzinfo:
                    deadline = deadline.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                continue
            if deadline > now:
                continue
            task.status = "Error"
            task.result_log = "TIMEOUT: Scheduled task deadline reached before this host returned a final result."
            task.finished_at = now
            completed_job_ids.add(task.job_id)
            changed_history_tasks.append(task)
            schedule_id = payload.get("__schedule_id")
            if schedule_id:
                timed_out_schedule_ids.add(str(schedule_id))

        if changed_history_tasks:
            from core.history_search import index_agent_task
            for changed_task in changed_history_tasks:
                index_agent_task(changed_task)

        # Telemetry has an independent, typically much shorter retention window.
        telemetry_days = int(global_app.config.get('TELEMETRY_RETENTION_DAYS', 30) or 0)
        if telemetry_days > 0:
            telemetry_threshold = now - timedelta(days=telemetry_days)
            TelemetryHistory.query.filter(TelemetryHistory.timestamp < telemetry_threshold).delete()
        db.session.commit()

        # Long-term history cleanup runs once per UTC day and is deliberately
        # bounded so a five-year deployment never locks the database for long.
        today = now.date()
        if _last_retention_cleanup_day != today:
            try:
                retention_result = _run_history_retention(now)
                if not retention_result.get("has_more"):
                    _last_retention_cleanup_day = today
                from core.sdk import WinHubCore
                WinHubCore.audit(
                    user_id=None,
                    module="HistoryAudit",
                    action="Scheduled History Retention",
                    details=retention_result,
                    status="Success",
                    source_type="retention",
                )
            except Exception as exc:
                db.session.rollback()
                log.exception("Scheduled history retention failed")
                from core.sdk import WinHubCore
                WinHubCore.audit(
                    user_id=None,
                    module="HistoryAudit",
                    action="Scheduled History Retention",
                    details={"error": str(exc)},
                    status="Error",
                    source_type="retention",
                )

        try:
            from core.history_search import backfill_history_search_index
            backfill_result = backfill_history_search_index(
                global_app.config.get("HISTORY_SEARCH_BACKFILL_BATCH_SIZE", 250)
            )
            if backfill_result.get("total"):
                db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("History search index backfill failed")

        if completed_job_ids:
            from core.sdk import WinHubCore
            for job_id in completed_job_ids:
                pending_tasks = AgentTask.query.filter(
                    AgentTask.job_id == job_id,
                    AgentTask.status.in_(["Pending", "PickedUp", "Running"])
                ).count()
                if pending_tasks == 0:
                    WinHubCore.process_job_completion(job_id, include_statuses=["Success", "Error", "Cancelled"], force=True)
            for schedule_id in timed_out_schedule_ids:
                st = ScheduledTask.query.get(schedule_id)
                if st:
                    st.last_status = "Timed out; report generated"
            db.session.commit()

def process_agent_update_rollouts_job(*args):
    global global_app
    if not global_app:
        return

    with global_app.app_context():
        try:
            from modules.Infrastructure.routes import process_due_agent_update_rollouts
            process_due_agent_update_rollouts()
        except Exception:
            db.session.rollback()
            log.exception("[Scheduler] Agent update rollout checker failed")
        finally:
            db.session.remove()

def scheduled_task_next_run_utc(task, from_time=None):
    if not task or not task.cron_expr or not task.is_active:
        return None
    now_kyiv = from_time or datetime.now(kyiv_tz)
    try:
        if task.cron_expr.startswith("DATE:"):
            time_str = task.cron_expr.replace("DATE:", "").strip()
            run_date = datetime.strptime(time_str, "%Y-%m-%d %H:%M").replace(tzinfo=kyiv_tz)
            return run_date.astimezone(timezone.utc).replace(tzinfo=None) if run_date > now_kyiv else None
        trigger = CronTrigger.from_crontab(task.cron_expr, timezone=kyiv_tz)
        next_run = trigger.get_next_fire_time(None, now_kyiv)
        return next_run.astimezone(timezone.utc).replace(tzinfo=None) if next_run else None
    except Exception:
        return None

def run_scheduled_job(
    scheduled_task_id, *args, manual_run=False, actor_user_id=None, actor_name=None
):
    """Функція, яку викликає APScheduler коли настав точний час або адмін запускає вручну."""
    global global_app
    if not global_app:
        return {"success": False, "message": "Application context is not ready"}

    with global_app.app_context():
        st = ScheduledTask.query.get(scheduled_task_id)
        if not st or not st.template:
            return {"success": False, "message": "Scheduled task or template was not found"}
        if not manual_run and not st.is_active:
            return {"success": False, "message": "Scheduled task is disabled"}

        run_label = "MANUAL RUN" if manual_run else "TRIGGER"
        log.info(f"[Scheduler] ⚡ {run_label}: Запуск задачі '{st.name}'...")

        from core.sdk import WinHubCore
        agent_ids = []
        if st.target_type == "host":
            agent_ids = [st.target_id]
        elif st.target_type == "group":
            group = EndpointGroup.query.get(st.target_id)
            if group: agent_ids = [a.id for a in group.endpoints]

        if not agent_ids:
            log.warning(f"[Scheduler] ⚠️ Задача '{st.name}' скасована: Цільових хостів не знайдено.")
            st.last_run = datetime.utcnow()
            st.last_status = "No target hosts"
            db.session.commit()
            return {"success": False, "message": "No target hosts"}

        try:
            # Шукаємо системного адміна
            admin_user = User.query.filter_by(is_admin=True).first()
            admin_id = admin_user.id if admin_user else 1

            from modules.Infrastructure.routes import apply_template_variables, load_template_payload

            payload_dict = load_template_payload(st.template)
            try:
                scheduled_variables = json.loads(st.variables) if st.variables else {}
            except Exception:
                scheduled_variables = {}
            if not isinstance(scheduled_variables, dict):
                scheduled_variables = {}

            payload_dict, unresolved = apply_template_variables(payload_dict, scheduled_variables)
            if unresolved:
                log.error(
                    "[Scheduler] Missing variables for scheduled task '%s': %s",
                    st.name,
                    ", ".join(unresolved)
                )
                st.last_run = datetime.utcnow()
                st.last_status = f"Missing variables: {', '.join(unresolved)[:80]}"
                db.session.commit()
                return {"success": False, "message": f"Missing variables: {', '.join(unresolved)}"}

            payload_dict["__template_id"] = st.template_id
            payload_dict["__schedule_id"] = st.id

            timeout_minutes = int(st.timeout_minutes or 0)
            if timeout_minutes > 0:
                deadline = datetime.utcnow() + timedelta(minutes=timeout_minutes)
                payload_dict["__deadline_utc"] = deadline.replace(microsecond=0).isoformat() + "Z"
                payload_dict["__agent_timeout_seconds"] = max(60, timeout_minutes * 60)

            # ДОДАНО: Перевіряємо, чи це шаблон метрики, і додаємо необхідні прапорці
            if getattr(st.template, 'type', 'action') == 'metric':
                payload_dict['__is_metric'] = True
                payload_dict['__metric_name'] = st.template.name

            # Відправляємо задачу
            job_id = WinHubCore.dispatch_task(
                user_id=admin_id,
                module_name="Scheduler",
                action=st.template.action_type,
                target_ids=agent_ids,
                payload=payload_dict,
                title=f"[Manual] {st.name}" if manual_run else f"[Auto] {st.name}",
                source_type="manual" if manual_run else "scheduler",
                actor_name=actor_name or (st.created_by if manual_run else "Scheduler"),
                actor_user_id=actor_user_id,
                system_actor=not manual_run,
            )
            st.last_job_id = job_id
            st.last_status = f"Manual run dispatched to {len(agent_ids)} hosts" if manual_run else f"Dispatched to {len(agent_ids)} hosts"
            log.info(f"[Scheduler] ✅ УСПІХ: Задача '{st.name}' відправлена на {len(agent_ids)} агентів.")
        except Exception as e:
            log.error(f"[Scheduler] ❌ ПОМИЛКА: Не вдалося виконати '{st.name}': {e}")
            st.last_status = f"Error: {str(e)[:90]}"
            st.last_run = datetime.utcnow()
            db.session.commit()
            return {"success": False, "message": str(e)}

        # Оновлюємо статус виконання
        st.last_run = datetime.utcnow()
        # Якщо задача була "Одноразова" (DATE:), вимикаємо її після виконання
        if not manual_run:
            if st.cron_expr.startswith("DATE:"):
                st.is_active = False
                st.next_run_at = None
            else:
                st.next_run_at = scheduled_task_next_run_utc(st)

        db.session.commit()
        return {"success": True, "job_id": job_id, "targets": len(agent_ids)}

def reload_scheduler_jobs(ignored_app=None):
    """Оновлює задачі в APScheduler з підтримкою Київського часу"""
    global global_app
    if not global_app: return

    scheduler.remove_all_jobs()
    scheduler.add_job(func=scheduled_cleanup, trigger="interval", minutes=10, id="sys_cleanup")
    scheduler.add_job(
        func=process_agent_update_rollouts_job,
        trigger="interval",
        seconds=Config.AGENT_UPDATE_ROLLOUT_CHECK_SECONDS,
        id="agent_update_rollouts",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )

    with global_app.app_context():
        tasks = ScheduledTask.query.filter_by(is_active=True).all()
        now_kyiv = datetime.now(kyiv_tz)
        log.info(f"[Scheduler] 🔄 Оновлення. Серверний час: {now_kyiv.strftime('%H:%M:%S')}. Активних задач у БД: {len(tasks)}")

        for t in tasks:
            try:
                if t.cron_expr.startswith("DATE:"):
                    # Одноразова задача у конкретну дату та час
                    time_str = t.cron_expr.replace("DATE:", "").strip()
                    naive_run_date = datetime.strptime(time_str, "%Y-%m-%d %H:%M")
                    run_date = naive_run_date.replace(tzinfo=kyiv_tz)

                    # Запускаємо тільки якщо цей час ще не настав
                    if run_date > now_kyiv:
                        trigger = DateTrigger(run_date=run_date, timezone=kyiv_tz)
                        # Передаємо лише ID задачі
                        scheduler.add_job(func=run_scheduled_job, args=[t.id], trigger=trigger, id=f"sch_{t.id}", max_instances=1, coalesce=True, replace_existing=True)
                        t.next_run_at = scheduled_task_next_run_utc(t, now_kyiv)
                        log.info(f"[Scheduler] ➕ ОДНОРАЗОВО ДОДАНО: '{t.name}' виконається о {time_str}")
                    else:
                        # Час вийшов, вимикаємо
                        t.is_active = False
                        t.next_run_at = None
                        t.last_status = t.last_status or "Expired before run"
                        log.warning(f"[Scheduler] ⚠️ ПРОПУЩЕНО: Задача '{t.name}' вимкнена (час {time_str} вже у минулому)")
                else:
                    # Повторювана задача (Cron)
                    trigger = CronTrigger.from_crontab(t.cron_expr, timezone=kyiv_tz)
                    scheduler.add_job(func=run_scheduled_job, args=[t.id], trigger=trigger, id=f"sch_{t.id}", max_instances=1, coalesce=True, replace_existing=True)
                    t.next_run_at = scheduled_task_next_run_utc(t, now_kyiv)
                    log.info(f"[Scheduler] ➕ ПОВТОРЮВАНО ДОДАНО: '{t.name}' (Cron: {t.cron_expr})")
            except Exception as e:
                t.next_run_at = None
                t.last_status = f"Schedule error: {str(e)[:80]}"
                log.error(f"[Scheduler] ❌ ПОМИЛКА розкладу для '{t.name}': {e}")
        db.session.commit()

def seed_default_os_groups():
    """Створює базові групи для різних ОС"""
    default_groups = {
        "Windows Hosts": "System generated group for Windows endpoints",
        "macOS Hosts": "System generated group for Apple endpoints",
        "Linux Hosts": "System generated group for Linux endpoints"
    }
    added = False
    for name, desc in default_groups.items():
        if not EndpointGroup.query.filter_by(name=name).first():
            db.session.add(EndpointGroup(name=name, description=desc))
            added = True
    if added: db.session.commit()

def remove_default_agent_update_template():
    name = "Agent Self Update"
    existing = TaskTemplate.query.filter_by(name=name, action_type="agent_update").first()
    if existing and getattr(existing, "created_by", None) == "System":
        db.session.delete(existing)
        db.session.commit()

def ensure_endpoint_schema():
    inspector = inspect(db.engine)
    columns = {column["name"] for column in inspector.get_columns("endpoints")}
    statements = []
    dialect = db.engine.dialect.name

    if "approval_status" not in columns:
        if dialect == "postgresql":
            statements.append("ALTER TABLE endpoints ADD COLUMN approval_status VARCHAR(20)")
        else:
            statements.append("ALTER TABLE endpoints ADD COLUMN approval_status VARCHAR(20)")
    if "display_name" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN display_name VARCHAR(120)")
    if "agent_version" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN agent_version VARCHAR(50)")
    if "connection_ip" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN connection_ip VARCHAR(64)")
    if "public_key_pem_plain" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN public_key_pem_plain TEXT")
    if "task_signing_private_key" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN task_signing_private_key TEXT")
    if "task_signing_public_key" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN task_signing_public_key TEXT")
    if "task_signing_key_id" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN task_signing_key_id VARCHAR(64)")
    if "task_signing_sequence" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN task_signing_sequence BIGINT DEFAULT 0")
    if "task_signature_v2_seen_at" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN task_signature_v2_seen_at TIMESTAMP")
    if "network_info" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN network_info TEXT")
    if "host_info" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN host_info TEXT")
    if "encryption_status" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN encryption_status VARCHAR(40) DEFAULT 'Unknown'")
    if "encryption_level" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN encryption_level VARCHAR(20) DEFAULT 'unknown'")
    if "encryption_methods" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN encryption_methods VARCHAR(120) DEFAULT ''")
    if "first_seen" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN first_seen TIMESTAMP")
    if "last_enrollment_at" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_enrollment_at TIMESTAMP")
    if "last_enrollment_ip" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_enrollment_ip VARCHAR(255)")
    if "enrollment_attempts" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN enrollment_attempts INTEGER DEFAULT 0")
    if "identity_fingerprint" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN identity_fingerprint VARCHAR(64)")
    if "identity_warning" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN identity_warning VARCHAR(255)")
    if "identity_duplicate_allowed" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN identity_duplicate_allowed BOOLEAN DEFAULT FALSE")
    if "reenroll_allowed_until" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN reenroll_allowed_until TIMESTAMP")

    for statement in statements:
        db.session.execute(text(statement))
    if statements or "approval_status" in columns:
        db.session.execute(text("UPDATE endpoints SET approval_status = 'Approved' WHERE approval_status IS NULL OR approval_status = ''"))
        db.session.execute(text("UPDATE endpoints SET first_seen = last_seen WHERE first_seen IS NULL"))
        db.session.execute(text("UPDATE endpoints SET enrollment_attempts = 0 WHERE enrollment_attempts IS NULL"))
        db.session.execute(text("UPDATE endpoints SET encryption_status = 'Unknown' WHERE encryption_status IS NULL OR encryption_status = ''"))
        db.session.execute(text("UPDATE endpoints SET encryption_level = 'unknown' WHERE encryption_level IS NULL OR encryption_level = ''"))
        db.session.execute(text("UPDATE endpoints SET encryption_methods = '' WHERE encryption_methods IS NULL"))
        db.session.execute(text("UPDATE endpoints SET identity_duplicate_allowed = FALSE WHERE identity_duplicate_allowed IS NULL"))
        db.session.execute(text("UPDATE endpoints SET task_signing_sequence = 0 WHERE task_signing_sequence IS NULL"))
    db.session.commit()


def ensure_template_approval_schema():
    inspector = inspect(db.engine)
    if "task_templates" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("task_templates")}
    statements = []
    if "approved_content_hash" not in columns:
        statements.append("ALTER TABLE task_templates ADD COLUMN approved_content_hash VARCHAR(64)")
    if "approved_at" not in columns:
        statements.append("ALTER TABLE task_templates ADD COLUMN approved_at TIMESTAMP")
    if "approved_by" not in columns:
        statements.append("ALTER TABLE task_templates ADD COLUMN approved_by VARCHAR(100)")
    for statement in statements:
        db.session.execute(text(statement))
    if statements:
        db.session.commit()

    # Existing approved templates are sealed exactly once during this additive
    # migration. Any later content change invalidates the seal at runtime.
    from core.template_security import current_template_hash

    changed = False
    for template in TaskTemplate.query.filter_by(is_approved=True).all():
        if not getattr(template, "approved_content_hash", None):
            template.approved_content_hash = current_template_hash(template)
            template.approved_at = template.approved_at or datetime.utcnow()
            template.approved_by = template.approved_by or "migration"
            changed = True
    if changed:
        db.session.commit()

def ensure_scheduler_schema():
    inspector = inspect(db.engine)
    if "scheduled_tasks" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("scheduled_tasks")}
    statements = []
    if "variables" not in columns:
        statements.append("ALTER TABLE scheduled_tasks ADD COLUMN variables TEXT")
    if "timeout_minutes" not in columns:
        statements.append("ALTER TABLE scheduled_tasks ADD COLUMN timeout_minutes INTEGER")
    if "next_run_at" not in columns:
        statements.append("ALTER TABLE scheduled_tasks ADD COLUMN next_run_at TIMESTAMP")
    if "last_status" not in columns:
        statements.append("ALTER TABLE scheduled_tasks ADD COLUMN last_status VARCHAR(120)")
    if "last_job_id" not in columns:
        statements.append("ALTER TABLE scheduled_tasks ADD COLUMN last_job_id VARCHAR(36)")
    for statement in statements:
        db.session.execute(text(statement))
    if statements:
        db.session.commit()

def ensure_group_access_schema():
    inspector = inspect(db.engine)
    if "user_group_access" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("user_group_access")}
    if "permissions" not in columns:
        db.session.execute(text(
            "ALTER TABLE user_group_access "
            "ADD COLUMN permissions TEXT NOT NULL DEFAULT '[\"*\"]'"
        ))
        db.session.commit()

def backfill_endpoint_encryption_status(limit=5000):
    endpoints = Endpoint.query.filter(
        Endpoint.host_info.isnot(None),
        db.or_(
            Endpoint.encryption_status.is_(None),
            Endpoint.encryption_status == "",
            Endpoint.encryption_status == "Unknown",
            Endpoint.encryption_level.is_(None),
            Endpoint.encryption_level == "",
            Endpoint.encryption_level == "unknown",
        )
    ).limit(limit).all()
    if not endpoints:
        return
    for endpoint in endpoints:
        try:
            apply_endpoint_encryption_status(endpoint, endpoint.host_info or "{}")
        except Exception:
            log.exception("Failed to backfill encryption status for endpoint %s", endpoint.id)
            endpoint.encryption_status = endpoint.encryption_status or "Unknown"
            endpoint.encryption_level = endpoint.encryption_level or "unknown"
            endpoint.encryption_methods = endpoint.encryption_methods or ""
    db.session.commit()

def ensure_performance_indexes():
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    if "agent_tasks" not in tables:
        return

    statements = [
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_endpoint_status_created ON agent_tasks (endpoint_id, status, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_job_status ON agent_tasks (job_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_job_endpoint ON agent_tasks (job_id, endpoint_id)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_actor_created ON agent_tasks (actor_user_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_source_created ON agent_tasks (source_type, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_status_created ON agent_tasks (status, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_endpoint_id_snapshot ON agent_tasks (endpoint_id_snapshot)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_endpoint_hostname_snapshot ON agent_tasks (endpoint_hostname_snapshot)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_endpoint_name_snapshot ON agent_tasks (endpoint_name_snapshot)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_template_id ON agent_tasks (template_id)",
        "CREATE INDEX IF NOT EXISTS ix_agent_tasks_schedule_id ON agent_tasks (schedule_id)",
    ]
    if "endpoint_group_membership" in tables:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_endpoint_group_membership_group_endpoint "
            "ON endpoint_group_membership (group_id, endpoint_id)"
        )
    if "user_group_access" in tables:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_user_group_access_group_user "
            "ON user_group_access (group_id, user_id)"
        )
    if "scheduled_tasks" in tables:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_scheduled_tasks_target "
            "ON scheduled_tasks (target_type, target_id)"
        )
    if "telemetry_history" in tables:
        statements.append("CREATE INDEX IF NOT EXISTS ix_telemetry_endpoint_timestamp ON telemetry_history (endpoint_id, timestamp)")
    if "connection_ip_history" in tables:
        statements.append("CREATE INDEX IF NOT EXISTS ix_connection_ip_endpoint_timestamp ON connection_ip_history (endpoint_id, timestamp)")
    if "aggregated_jobs" in tables:
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_created_at ON aggregated_jobs (created_at)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_actor_created ON aggregated_jobs (actor_user_id, created_at)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_status_created ON aggregated_jobs (status, created_at)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_creator_created ON aggregated_jobs (created_by, created_at)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_source_created ON aggregated_jobs (source_type, created_at)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_aggregated_jobs_template_created ON aggregated_jobs (template_id, created_at)")
    if "audit_logs" in tables:
        statements.append("CREATE INDEX IF NOT EXISTS ix_audit_actor_timestamp ON audit_logs (actor_user_id, timestamp)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_audit_module_status_timestamp ON audit_logs (module, status, timestamp)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_audit_role_timestamp ON audit_logs (actor_role, timestamp)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_audit_source_timestamp ON audit_logs (source_type, timestamp)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_audit_session_timestamp ON audit_logs (session_id_hash, timestamp)")
    if "endpoints" in tables:
        statements.append("CREATE INDEX IF NOT EXISTS ix_endpoints_encryption_level ON endpoints (encryption_level)")
        statements.append("CREATE INDEX IF NOT EXISTS ix_endpoints_agent_version ON endpoints (agent_version)")

    for statement in statements:
        db.session.execute(text(statement))
    db.session.commit()

def ensure_audit_schema():
    inspector = inspect(db.engine)
    if "audit_logs" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    statements = []
    if "actor_type" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN actor_type VARCHAR(20)")
    if "actor_name" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN actor_name VARCHAR(150)")
    if "module" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN module VARCHAR(80)")
    if "target_type" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN target_type VARCHAR(60)")
    if "target_id" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN target_id VARCHAR(150)")
    if "ip_address" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT")
    if "request_id" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN request_id VARCHAR(36)")
    if "actor_user_id" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN actor_user_id INTEGER")
    if "actor_role" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN actor_role VARCHAR(30)")
    if "source_type" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN source_type VARCHAR(30)")
    if "session_id_hash" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN session_id_hash VARCHAR(64)")
    if "user_agent" not in columns:
        statements.append("ALTER TABLE audit_logs ADD COLUMN user_agent TEXT")

    for statement in statements:
        db.session.execute(text(statement))
    if statements:
        db.session.execute(text("UPDATE audit_logs SET actor_type = 'user' WHERE actor_type IS NULL OR actor_type = ''"))
        db.session.execute(text("UPDATE audit_logs SET actor_name = 'user' WHERE actor_name IS NULL OR actor_name = ''"))
        db.session.execute(text(
            "UPDATE audit_logs SET actor_user_id = "
            "(SELECT id FROM users WHERE users.username = COALESCE(audit_logs.actor_name, audit_logs.user)) "
            "WHERE actor_user_id IS NULL"
        ))
        db.session.execute(text(
            "UPDATE audit_logs SET actor_role = CASE "
            "WHEN actor_type = 'api_key' THEN 'api_key' "
            "WHEN actor_user_id IN (SELECT id FROM users WHERE is_admin IS TRUE) THEN 'superadmin' "
            "ELSE 'operator' END WHERE actor_role IS NULL"
        ))
        db.session.execute(text(
            "UPDATE audit_logs SET source_type = CASE "
            "WHEN actor_type = 'api_key' THEN 'api' ELSE 'web' END "
            "WHERE source_type IS NULL"
        ))
        db.session.commit()


def ensure_history_schema():
    """Compatibility DDL for installations that have not run Alembic yet."""
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    additions = {
        "agent_tasks": {
            "endpoint_id_snapshot": "VARCHAR(100)",
            "endpoint_hostname_snapshot": "VARCHAR(100)",
            "endpoint_name_snapshot": "VARCHAR(120)",
            "endpoint_groups_snapshot": "TEXT",
            "source_type": "VARCHAR(30) DEFAULT 'manual'",
            "actor_user_id": "INTEGER",
            "template_id": "VARCHAR(36)",
            "schedule_id": "VARCHAR(36)",
        },
        "aggregated_jobs": {
            "actor_user_id": "INTEGER",
            "created_by": "VARCHAR(150)",
            "source_type": "VARCHAR(30)",
            "template_id": "VARCHAR(36)",
            "original_content_hash": "VARCHAR(64)",
            "current_revision_number": "INTEGER NOT NULL DEFAULT 0",
        },
        "report_deliveries": {
            "content_snapshot": "TEXT",
        },
    }
    changed = False
    for table_name, table_additions in additions.items():
        if table_name not in tables:
            continue
        columns = {column["name"] for column in inspector.get_columns(table_name)}
        for column_name, ddl in table_additions.items():
            if column_name not in columns:
                db.session.execute(text(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"
                ))
                changed = True
    if "agent_tasks" in tables:
        db.session.execute(text(
            "UPDATE agent_tasks SET endpoint_id_snapshot = endpoint_id "
            "WHERE endpoint_id_snapshot IS NULL"
        ))
        db.session.execute(text(
            "UPDATE agent_tasks SET endpoint_hostname_snapshot = "
            "(SELECT hostname FROM endpoints WHERE endpoints.id = agent_tasks.endpoint_id) "
            "WHERE endpoint_hostname_snapshot IS NULL AND endpoint_id IS NOT NULL"
        ))
        db.session.execute(text(
            "UPDATE agent_tasks SET endpoint_name_snapshot = "
            "(SELECT display_name FROM endpoints WHERE endpoints.id = agent_tasks.endpoint_id) "
            "WHERE endpoint_name_snapshot IS NULL AND endpoint_id IS NOT NULL"
        ))
        db.session.execute(text(
            "UPDATE agent_tasks SET source_type = CASE "
            "WHEN title LIKE '[Auto-Fix]%' THEN 'trigger' "
            "WHEN title LIKE '[Auto]%' THEN 'scheduler' "
            "ELSE COALESCE(source_type, 'manual') END"
        ))
        db.session.execute(text(
            "UPDATE agent_tasks SET actor_user_id = "
            "(SELECT id FROM users WHERE users.username = agent_tasks.created_by) "
            "WHERE actor_user_id IS NULL AND created_by IS NOT NULL"
        ))
        changed = True
    if "aggregated_jobs" in tables and "agent_tasks" in tables:
        for column_name in ("actor_user_id", "created_by", "source_type", "template_id"):
            db.session.execute(text(
                f"UPDATE aggregated_jobs SET {column_name} = "
                f"(SELECT {column_name} FROM agent_tasks "
                "WHERE agent_tasks.job_id = aggregated_jobs.id "
                "ORDER BY agent_tasks.created_at LIMIT 1) "
                f"WHERE {column_name} IS NULL"
            ))
        changed = True
    if "report_deliveries" in tables:
        db.session.execute(text(
            "UPDATE report_deliveries SET content_snapshot = '' "
            "WHERE content_snapshot IS NULL"
        ))
        changed = True
    if changed:
        db.session.commit()

# ====================================================================
# ГЛОБАЛЬНИЙ КОНТЕКСТ ДЛЯ ШАБЛОНІВ
# ====================================================================
def inject_global_template_vars(app):
    @app.context_processor
    def inject_csp_vars():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.context_processor
    def inject_vars():
        try:
            if not session.get('logged_in'):
                return dict(
                    system_modules=[],
                    username=None,
                    is_admin=False,
                    can_manage_gpg_keys=False,
                    csrf_token=None,
                    session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS,
                    app_version=get_version(),
                )

            user = User.query.get(session.get('user_id'))
            if not user:
                return dict(
                    system_modules=[],
                    username=None,
                    is_admin=False,
                    can_manage_gpg_keys=False,
                    csrf_token=None,
                    session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS,
                    app_version=get_version(),
                )

            modules_info = []
            for module in get_loaded_modules():
                mod_id = module.get("id")
                if mod_id and has_module_access(user, mod_id):
                    modules_info.append({
                        "id": mod_id,
                        "name": module.get("name", mod_id),
                        "url": module.get("url", f"/module/{mod_id}"),
                        "icon": module.get("icon", "")
                    })

            return dict(
                system_modules=modules_info,
                username=user.username,
                is_admin=user.is_admin,
                can_manage_gpg_keys=bool(user.is_admin or has_permission(user, "Administration", "manage_gpg_keys")),
                csrf_token=session.get("csrf_token"),
                session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS,
                app_version=get_version(),
            )
        except Exception as e:
            return dict(
                system_modules=[],
                username="Error",
                is_admin=False,
                can_manage_gpg_keys=False,
                csrf_token=session.get("csrf_token"),
                session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS,
                app_version=get_version(),
            )

@core_routes.route('/dashboard')
def dashboard():
    if not session.get('logged_in'): return redirect(url_for('auth.login_page'))
    return render_template('dashboard.html')

@core_routes.route('/')
def index():
    return redirect(url_for('auth.login_page'))

@core_routes.route('/api/health')
def health():
    database_ok = False
    database_error = None
    try:
        db.session.execute(text("SELECT 1"))
        database_ok = True
    except Exception as e:
        database_error = str(e)

    registry = get_module_registry()
    required_modules = {
        module_id: {
            "status": registry.get(module_id, {}).get("status", "missing"),
            "error_message": registry.get(module_id, {}).get("error_message"),
        }
        for module_id in REQUIRED_MODULES
    }
    required_ok = all(item["status"] == "loaded" for item in required_modules.values())

    data_dir_ok = os.path.isdir(Config.DATA_DIR) and os.access(Config.DATA_DIR, os.W_OK)
    healthy = database_ok and required_ok and data_dir_ok
    status_code = 200 if healthy else 503
    rate_limit_storage = Config.RATELIMIT_STORAGE_URI or "memory://"
    return jsonify({
        "success": healthy,
        "status": "ok" if healthy else "degraded",
        "version": get_version(),
        "database": {"ok": database_ok, "error": database_error},
        "data_dir": {"ok": data_dir_ok, "path": Config.DATA_DIR},
        "scheduler": {"running": bool(getattr(scheduler, "running", False))},
        "required_modules": required_modules,
        "rate_limit": {
            "storage": rate_limit_storage,
            "mode": "redis" if rate_limit_storage.startswith("redis") else "memory",
            "redis_required": rate_limit_storage.startswith("redis"),
        },
    }), status_code

@core_routes.route('/api/session/ping', methods=['POST'])
def session_ping():
    return jsonify({
        "success": True,
        "idle_timeout_seconds": Config.SESSION_IDLE_TIMEOUT_SECONDS,
        "absolute_timeout_seconds": Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
    })

def handle_security_and_auth():
    g.request_id = str(uuid.uuid4())
    g.request_started_at = time.perf_counter()
    g.csp_nonce = new_csp_nonce()
    open_endpoints = ['auth.login_page', 'auth.api_login', 'auth.forgot_password', 'auth.reset_password', 'core_routes.health', 'static']
    if request.path.startswith('/api/agent/'): return None
    if request.path.startswith('/api/public/agent-packages/') or request.path.startswith('/api/public/software-packages/'):
        return None
    if request.path.startswith('/api/'):
        auth_header = request.headers.get('Authorization', '')
        api_key_value = None
        if auth_header.lower().startswith('bearer '):
            api_key_value = auth_header.split(' ', 1)[1].strip()
        api_key_value = api_key_value or request.headers.get('X-API-Key')
        if api_key_value:
            prefix = api_key_value[:8]
            key = ApiKey.query.filter_by(prefix=prefix, is_active=True).first()
            if key and (not key.expires_at or key.expires_at >= datetime.utcnow()) and sec_manager.verify_password(key.key_hash, api_key_value):
                session['logged_in'] = True
                session['user_id'] = key.user_id
                session['username'] = key.user.username if key.user else 'API Key'
                session['is_admin'] = False
                session['api_key_auth'] = True
                session['api_key_id'] = key.id
                session['api_permissions'] = json.loads(key.permissions or '[]')
                return None
            try:
                from core.sdk import WinHubCore
                WinHubCore.audit(
                    username="Unknown API Key",
                    actor_type="api_key",
                    module="Security",
                    action="Invalid API Key",
                    details={"path": request.path, "method": request.method, "prefix": prefix},
                    status="Denied"
                )
            except Exception:
                log.exception("Failed to audit invalid API key")
            return {"success": False, "message": "Invalid API key"}, 401
        if session.get('api_key_auth'):
            session.clear()
    if request.endpoint not in open_endpoints and not session.get('logged_in'):
        if request.path.startswith('/api/'): return {"success": False, "message": "Unauthorized"}, 401
        return redirect(url_for('auth.login_page'))

    if session.get('logged_in') and not session.get('api_key_auth') and request.endpoint not in open_endpoints:
        now_ts = time.time()
        login_at = float(session.get('login_at') or now_ts)
        last_activity = float(session.get('last_activity') or now_ts)
        absolute_expired = (
            Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS > 0
            and now_ts - login_at > Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS
        )
        idle_expired = (
            Config.SESSION_IDLE_TIMEOUT_SECONDS > 0
            and now_ts - last_activity > Config.SESSION_IDLE_TIMEOUT_SECONDS
        )
        if absolute_expired or idle_expired:
            username = session.get("username", "Unknown")
            try:
                from core.sdk import WinHubCore
                WinHubCore.audit(
                    user_id=session.get("user_id"),
                    username=username,
                    module="Auth",
                    action="Session Expired",
                    details={"reason": "absolute_timeout" if absolute_expired else "idle_timeout"},
                    status="Success",
                    source_type="web",
                )
            except Exception:
                log.exception("Failed to audit expired session for %s", username)
            session.clear()
            if request.path.startswith('/api/'):
                return {"success": False, "message": "Session expired"}, 440
            return redirect(url_for('auth.login_page'))

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected = session.get("csrf_token")
            provided = request.headers.get("X-CSRF-Token")
            if not expected or not provided or not secrets.compare_digest(str(expected), str(provided)):
                try:
                    from core.sdk import WinHubCore
                    WinHubCore.audit(
                        module="Security",
                        action="CSRF Denied",
                        details={"path": request.path, "method": request.method},
                        status="Denied"
                    )
                except Exception:
                    log.exception("Failed to audit CSRF denial")
                if request.path.startswith('/api/'):
                    return {"success": False, "message": "Invalid CSRF token"}, 403
                return redirect(url_for('auth.login_page'))

        session['last_activity'] = now_ts
        session.modified = True


def apply_security_headers(response):
    started_at = getattr(g, "request_started_at", None)
    if started_at is not None and Config.SLOW_REQUEST_LOG_SECONDS:
        elapsed = time.perf_counter() - started_at
        if elapsed >= Config.SLOW_REQUEST_LOG_SECONDS:
            log.warning(
                "Slow request role=%s method=%s path=%s status=%s duration=%.3fs remote=%s request_id=%s",
                Config.WINHUB_ROLE,
                request.method,
                request.full_path.rstrip("?"),
                response.status_code,
                elapsed,
                request.headers.get("X-Forwarded-For", request.remote_addr),
                getattr(g, "request_id", "-"),
            )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    csp_headers = build_csp_headers(
        Config.CSP_MODE,
        Config.CSP_POLICY,
        Config.CSP_NONCE_MODE,
        Config.CSP_NONCE_POLICY,
        g.csp_nonce,
    )
    for header_name, header_value in csp_headers.items():
        response.headers.setdefault(header_name, header_value)
    if session.get("logged_in") and not request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        response.headers.setdefault("Pragma", "no-cache")
    if Config.HSTS_ENABLED and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
    return response

def load_modules(app):
    if not os.path.exists(Config.MODULES_DIR): os.makedirs(Config.MODULES_DIR)
    reset_module_registry()
    seen_modules = set()

    for folder in os.listdir(Config.MODULES_DIR):
        module_path = os.path.join(Config.MODULES_DIR, folder)
        if os.path.isdir(module_path) and not folder.startswith('__'):
            manifest_path = os.path.join(module_path, 'manifest.json')
            if os.path.exists(manifest_path):
                module_id = folder
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        manifest = json.load(f)

                    module_id = manifest.get('id') or folder
                    seen_modules.add(module_id)
                    set_module_status(
                        module_id,
                        name=manifest.get('name', folder),
                        url=manifest.get('url', f"/module/{module_id}"),
                        icon=manifest.get('icon', ''),
                        folder=folder,
                        status="disabled",
                        error_message=None,
                    )

                    routes_module = importlib.import_module(f"modules.{folder}.routes")
                    for item_name in dir(routes_module):
                        item = getattr(routes_module, item_name)
                        if isinstance(item, Blueprint):
                            app.register_blueprint(item)
                            set_module_status(module_id, status="loaded", error_message=None)
                            starter = getattr(routes_module, "start_module", None)
                            if callable(starter):
                                starter(app)
                            break
                    else:
                        raise RuntimeError("Blueprint not found")
                except Exception as e:
                    set_module_status(module_id, folder=folder, status="error", error_message=str(e))
                    if module_id in REQUIRED_MODULES:
                        log.critical(f"Required module {module_id} failed to load: {e}")
                    else:
                        log.error(f"Optional module {module_id} failed to load: {e}")

    for module_id in REQUIRED_MODULES:
        if module_id not in seen_modules:
            message = "Required module folder or manifest.json not found"
            set_module_status(module_id, status="error", error_message=message)
            log.critical(f"Required module {module_id} failed to load: {message}")

def validate_rate_limit_storage():
    storage_uri = Config.RATELIMIT_STORAGE_URI
    if not storage_uri:
        raise RuntimeError("RATELIMIT_STORAGE_URI must be set. Use memory:// or redis://...")
    if storage_uri == "memory://":
        if getattr(Config, "PRODUCTION_MODE", False):
            log.warning(
                "WinHUB is running in production mode with memory:// rate limits. "
                "This is acceptable for a single internal server, but Redis is recommended "
                "for multi-worker or internet-facing deployments."
            )
        return
    if storage_uri.startswith("redis"):
        try:
            import redis
            client = redis.Redis.from_url(storage_uri, socket_connect_timeout=3, socket_timeout=3)
            client.ping()
        except Exception as e:
            raise RuntimeError(
                f"Redis rate-limit storage is not reachable: {storage_uri}. "
                "Start Redis or fix RATELIMIT_STORAGE_URI before starting WinHUB."
            ) from e
        return
    raise RuntimeError(f"Unsupported RATELIMIT_STORAGE_URI: {storage_uri}. Use memory:// or redis://...")

def create_app():
    global global_app
    template_dir = os.path.join(Config.BASE_DIR, 'templates')
    static_dir = os.path.join(Config.BASE_DIR, 'static')
    global_app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    global_app.config.from_object(Config)
    session_lifetime = Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS or max(Config.SESSION_IDLE_TIMEOUT_SECONDS, 86400)
    global_app.permanent_session_lifetime = timedelta(seconds=session_lifetime)

    validate_rate_limit_storage()

    @global_app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(error):
        return jsonify({
            "success": False,
            "message": f"Upload is too large. Current server limit is {Config.AGENT_PACKAGE_MAX_UPLOAD_MB} MB."
        }), 413

    db.init_app(global_app)
    socketio.init_app(global_app)
    limiter.init_app(global_app)

    if auth_bp.view_functions.get('api_login'):
        auth_bp.view_functions['api_login'] = limiter.limit(Config.LOGIN_RATE_LIMIT)(auth_bp.view_functions['api_login'])
    if agent_gateway_bp.view_functions.get('enroll_agent'):
        agent_gateway_bp.view_functions['enroll_agent'] = limiter.limit(Config.AGENT_ENROLLMENT_RATE_LIMIT)(agent_gateway_bp.view_functions['enroll_agent'])

    inject_global_template_vars(global_app)
    global_app.before_request(handle_security_and_auth)
    global_app.after_request(apply_security_headers)

    global_app.register_blueprint(auth_bp)
    global_app.register_blueprint(admin_bp)
    global_app.register_blueprint(core_routes)
    global_app.register_blueprint(agent_gateway_bp)

    with global_app.app_context():
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        os.makedirs(os.path.join(Config.DATA_DIR, 'logs'), exist_ok=True)
        try:
            db.create_all()
        except UnicodeDecodeError as e:
            log.critical(
                "Database connection failed while decoding the driver response. "
                "Check DATABASE_URI encoding and percent-encode special characters "
                "in username/password. Active database URI: %s",
                getattr(Config, 'SAFE_DATABASE_URI', '<unknown>')
            )
            raise RuntimeError(
                "Database connection failed. Check DATABASE_URI in .env. "
                "For a clean local SQLite start, remove/comment DATABASE_URI. "
                "For PostgreSQL, use a UTF-8/ASCII URL and percent-encode special characters in the password."
            ) from e
        except Exception:
            log.exception(
                "Database initialization failed. Active database URI: %s",
                getattr(Config, 'SAFE_DATABASE_URI', '<unknown>')
            )
            raise
        ensure_endpoint_schema()
        ensure_template_approval_schema()
        ensure_scheduler_schema()
        ensure_group_access_schema()
        backfill_endpoint_encryption_status()
        ensure_audit_schema()
        ensure_history_schema()
        ensure_performance_indexes()
        seed_default_os_groups()
        remove_default_agent_update_template()

        if not User.query.first():
            raw_password = secrets.token_urlsafe(24)
            totp = sec_manager.generate_totp_secret()

            admin = User(
                username='admin',
                email='admin@localhost',
                password_hash=sec_manager.hash_password(raw_password),
                totp_secret=totp,
                is_admin=True,
                allowed_modules=json.dumps(full_module_grants())
            )
            db.session.add(admin)
            db.session.commit()

            backup_path = os.path.join(Config.DATA_DIR, 'admin_recovery.txt')
            recovery_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, 'O_NOFOLLOW'):
                recovery_flags |= os.O_NOFOLLOW
            recovery_fd = os.open(backup_path, recovery_flags, 0o600)
            if os.name != 'nt':
                os.fchmod(recovery_fd, 0o600)
            with os.fdopen(recovery_fd, 'w', encoding='utf-8') as f:
                f.write("=== WINHUB ADMIN RECOVERY ===\n")
                f.write(f"Username: admin\n")
                f.write(f"Password: {raw_password}\n")
                f.write(f"2FA Secret: {totp}\n")
                f.write("\nЗбережіть цей файл у безпечному місці!\n")

            # Keep bootstrap output ASCII-safe for Windows service consoles that
            # still use a legacy code page.
            print("\n[!!!] NEW ADMINISTRATOR CREATED [!!!]")
            print(f"Recovery credentials were saved to: {backup_path}\n")

        load_modules(global_app)

        if Config.WINHUB_DISABLE_SCHEDULER:
            log.info("WinHUB scheduler disabled for role=%s.", Config.WINHUB_ROLE)
        else:
            scheduler.start()
            reload_scheduler_jobs(global_app)

    return global_app
