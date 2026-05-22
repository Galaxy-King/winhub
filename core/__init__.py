import os
import logging
import importlib
import json
import secrets
import string
import time
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from flask import Flask, g, request, redirect, url_for, session, render_template, Blueprint, jsonify
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, text

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from core.config import Config
from core.database import db, User, AgentTask, AuditLog, TelemetryHistory, ScheduledTask, EndpointGroup, ApiKey
from core.security import sec_manager
from core.auth import auth_bp
from core.admin import admin_bp
from core.agent_gateway import agent_gateway_bp
from core.version import get_version
from core.module_registry import REQUIRED_MODULES, get_loaded_modules, get_module_registry, reset_module_registry, set_module_status
from core.permissions import full_module_grants, has_module_access

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

# --- ФОНОВІ ЗАДАЧІ ---
def scheduled_cleanup(*args):
    global global_app
    if not global_app: return
    with global_app.app_context():
        now = datetime.utcnow()
        # Очищення завислих задач
        zombie_threshold = now - timedelta(seconds=global_app.config.get('AGENT_TASK_TIMEOUT_SECONDS', 1800))
        zombies = AgentTask.query.filter(AgentTask.status == "PickedUp", AgentTask.created_at < zombie_threshold).all()
        for z in zombies:
            z.status = "Error"
            z.result_log = "TIMEOUT: Agent picked up the task but never returned a result."
            z.finished_at = now
            
        # Очищення телеметрії
        retention_days = global_app.config.get('LOG_RETENTION_DAYS', 30)
        telemetry_threshold = now - timedelta(days=retention_days)
        TelemetryHistory.query.filter(TelemetryHistory.timestamp < telemetry_threshold).delete()
        audit_retention_days = global_app.config.get('AUDIT_RETENTION_DAYS', 365)
        if audit_retention_days > 0:
            audit_threshold = now - timedelta(days=audit_retention_days)
            AuditLog.query.filter(AuditLog.timestamp < audit_threshold).delete()
        db.session.commit()

def run_scheduled_job(scheduled_task_id, *args):
    """Функція, яку викликає APScheduler коли настав точний час"""
    global global_app
    if not global_app: return
    
    with global_app.app_context():
        st = ScheduledTask.query.get(scheduled_task_id)
        if not st or not st.is_active or not st.template: 
            return
        
        log.info(f"[Scheduler] ⚡ ТРИГЕР СПРАЦЮВАВ: Запуск задачі '{st.name}'...")
        
        from core.sdk import WinHubCore
        agent_ids = []
        if st.target_type == "host": 
            agent_ids = [st.target_id]
        elif st.target_type == "group":
            group = EndpointGroup.query.get(st.target_id)
            if group: agent_ids = [a.id for a in group.endpoints]

        if not agent_ids:
            log.warning(f"[Scheduler] ⚠️ Задача '{st.name}' скасована: Цільових хостів не знайдено.")
            return

        try:
            # Шукаємо системного адміна
            admin_user = User.query.filter_by(is_admin=True).first()
            admin_id = admin_user.id if admin_user else 1

            payload_dict = json.loads(st.template.payload) if st.template.payload else {}
            
            # ДОДАНО: Перевіряємо, чи це шаблон метрики, і додаємо необхідні прапорці
            if getattr(st.template, 'type', 'action') == 'metric':
                payload_dict['__is_metric'] = True
                payload_dict['__metric_name'] = st.template.name
            
            # Відправляємо задачу
            WinHubCore.dispatch_task(
                user_id=admin_id,
                module_name="Scheduler", 
                action=st.template.action_type, 
                target_ids=agent_ids, 
                payload=payload_dict, 
                title=f"[Auto] {st.name}"
            )
            log.info(f"[Scheduler] ✅ УСПІХ: Задача '{st.name}' відправлена на {len(agent_ids)} агентів.")
        except Exception as e:
            log.error(f"[Scheduler] ❌ ПОМИЛКА: Не вдалося виконати '{st.name}': {e}")

        # Оновлюємо статус виконання
        st.last_run = datetime.utcnow()
        # Якщо задача була "Одноразова" (DATE:), вимикаємо її після виконання
        if st.cron_expr.startswith("DATE:"):
            st.is_active = False
            
        db.session.commit()

def reload_scheduler_jobs(ignored_app=None):
    """Оновлює задачі в APScheduler з підтримкою Київського часу"""
    global global_app
    if not global_app: return
    
    scheduler.remove_all_jobs()
    scheduler.add_job(func=scheduled_cleanup, trigger="interval", minutes=10, id="sys_cleanup")
    
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
                        scheduler.add_job(func=run_scheduled_job, args=[t.id], trigger=trigger, id=f"sch_{t.id}")
                        log.info(f"[Scheduler] ➕ ОДНОРАЗОВО ДОДАНО: '{t.name}' виконається о {time_str}")
                    else:
                        # Час вийшов, вимикаємо
                        t.is_active = False
                        db.session.commit()
                        log.warning(f"[Scheduler] ⚠️ ПРОПУЩЕНО: Задача '{t.name}' вимкнена (час {time_str} вже у минулому)")
                else:
                    # Повторювана задача (Cron)
                    trigger = CronTrigger.from_crontab(t.cron_expr, timezone=kyiv_tz)
                    scheduler.add_job(func=run_scheduled_job, args=[t.id], trigger=trigger, id=f"sch_{t.id}")
                    log.info(f"[Scheduler] ➕ ПОВТОРЮВАНО ДОДАНО: '{t.name}' (Cron: {t.cron_expr})")
            except Exception as e:
                log.error(f"[Scheduler] ❌ ПОМИЛКА розкладу для '{t.name}': {e}")

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
    if "agent_version" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN agent_version VARCHAR(50)")
    if "network_info" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN network_info TEXT")
    if "host_info" not in columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN host_info TEXT")
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

    for statement in statements:
        db.session.execute(text(statement))
    if statements or "approval_status" in columns:
        db.session.execute(text("UPDATE endpoints SET approval_status = 'Approved' WHERE approval_status IS NULL OR approval_status = ''"))
        db.session.execute(text("UPDATE endpoints SET first_seen = last_seen WHERE first_seen IS NULL"))
        db.session.execute(text("UPDATE endpoints SET enrollment_attempts = 0 WHERE enrollment_attempts IS NULL"))
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

    for statement in statements:
        db.session.execute(text(statement))
    if statements:
        db.session.execute(text("UPDATE audit_logs SET actor_type = 'user' WHERE actor_type IS NULL OR actor_type = ''"))
        db.session.execute(text("UPDATE audit_logs SET actor_name = \"user\" WHERE actor_name IS NULL OR actor_name = ''"))
        db.session.commit()

# ====================================================================
# ГЛОБАЛЬНИЙ КОНТЕКСТ ДЛЯ ШАБЛОНІВ
# ====================================================================
def inject_global_template_vars(app):
    @app.context_processor
    def inject_vars():
        try:
            if not session.get('logged_in'):
                return dict(system_modules=[], username=None, is_admin=False, csrf_token=None, session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS)
                
            user = User.query.get(session.get('user_id'))
            if not user:
                return dict(system_modules=[], username=None, is_admin=False, csrf_token=None, session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS)
                
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
                                
            return dict(system_modules=modules_info, username=user.username, is_admin=user.is_admin, csrf_token=session.get("csrf_token"), session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS)
        except Exception as e:
            return dict(system_modules=[], username="Error", is_admin=False, csrf_token=session.get("csrf_token"), session_idle_timeout_seconds=Config.SESSION_IDLE_TIMEOUT_SECONDS)

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
    open_endpoints = ['auth.login_page', 'auth.api_login', 'auth.forgot_password', 'auth.reset_password', 'core_routes.health', 'static']
    if request.path.startswith('/api/agent/'): return None
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
        if now_ts - login_at > Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS or now_ts - last_activity > Config.SESSION_IDLE_TIMEOUT_SECONDS:
            username = session.get("username", "Unknown")
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
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
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
    global_app.permanent_session_lifetime = timedelta(seconds=Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS)

    validate_rate_limit_storage()

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
        ensure_audit_schema()
        seed_default_os_groups()
        
        if not User.query.first():
            raw_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
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
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write("=== WINHUB ADMIN RECOVERY ===\n")
                f.write(f"Username: admin\n")
                f.write(f"Password: {raw_password}\n")
                f.write(f"2FA Secret: {totp}\n")
                f.write("\nЗбережіть цей файл у безпечному місці!\n")
            
            print(f"\n[!!!] СТВОРЕНО НОВОГО АДМІНІСТРАТОРА [!!!]")
            print(f"Дані для входу збережено у файл: {backup_path}\n")
                
        load_modules(global_app)

        # Старт планувальника
        scheduler.start()
        reload_scheduler_jobs(global_app)

    return global_app
