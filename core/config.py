# ==============================================================================
# ШЛЯХ ДО ФАЙЛУ: core/config.py
# ПРИЗНАЧЕННЯ: Головний файл конфігурації системи. Читає змінні з .env
# ==============================================================================

import os
import shutil
from urllib.parse import quote_plus, urlsplit, urlunsplit
from dotenv import load_dotenv

from core.csp import COMPATIBILITY_CSP_POLICY, DEFAULT_CSP_POLICY

# Завантаження змінних з .env файлу
load_dotenv()

DEFAULT_SECRET_KEY = 'default-dev-secret-key-change-in-production'  # nosec B105
DEFAULT_AGENT_API_KEY = 'WinHUB-Secret-Enroll-2026'  # nosec B105

def clean_env_value(value):
    if value is None:
        return None
    value = value.strip().lstrip('\ufeff').strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1].strip()
    return value or None

def env_int(name, default, minimum=None, maximum=None):
    try:
        value = int(clean_env_value(os.environ.get(name)) or default)
    except (TypeError, ValueError):
        value = int(default)
    if minimum is not None:
        value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value

def mask_database_uri(uri):
    try:
        parsed = urlsplit(uri)
        if not parsed.password:
            return uri
        host = parsed.hostname or ''
        port = f":{parsed.port}" if parsed.port else ''
        username = parsed.username or ''
        auth = f"{username}:***@" if username else ''
        return urlunsplit((parsed.scheme, f"{auth}{host}{port}", parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return "<invalid database uri>"

def build_postgres_uri_from_env():
    host = clean_env_value(os.environ.get('POSTGRES_HOST'))
    database = clean_env_value(os.environ.get('POSTGRES_DB'))
    user = clean_env_value(os.environ.get('POSTGRES_USER'))
    password = clean_env_value(os.environ.get('POSTGRES_PASSWORD'))
    if not all([host, database, user, password]):
        return None

    port = clean_env_value(os.environ.get('POSTGRES_PORT')) or '5432'
    return (
        f"postgresql://{quote_plus(user)}:{quote_plus(password)}"
        f"@{host}:{port}/{quote_plus(database)}"
    )

class Config:
    # Базовий секретний ключ для криптографії Flask (сесії)
    SECRET_KEY = clean_env_value(os.environ.get('SECRET_KEY')) or DEFAULT_SECRET_KEY

    # Визначення головних шляхів системи
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    DATA_DIR = clean_env_value(os.environ.get('DATA_DIR')) or os.path.join(BASE_DIR, 'data')
    MODULES_DIR = clean_env_value(os.environ.get('MODULES_DIR')) or os.path.join(BASE_DIR, 'modules')
    SERVER_LOG_FILE = clean_env_value(os.environ.get('SERVER_LOG_FILE')) or os.path.join(DATA_DIR, 'logs', 'winhub_prod.log')
    SERVER_CERT_PATH = clean_env_value(os.environ.get('SERVER_CERT_PATH')) or os.path.join(BASE_DIR, 'certs', 'cert.pem')
    SERVER_KEY_PATH = clean_env_value(os.environ.get('SERVER_KEY_PATH')) or os.path.join(BASE_DIR, 'certs', 'key.pem')
    WINHUB_ROLE = (clean_env_value(os.environ.get('WINHUB_ROLE')) or 'web').lower()
    WINHUB_DISABLE_SCHEDULER = (clean_env_value(os.environ.get('WINHUB_DISABLE_SCHEDULER')) or 'false').lower() in ('1', 'true', 'yes', 'on')

    # ---------------------------------------------------------
    # НАЛАШТУВАННЯ БАЗИ ДАНИХ (ДЛЯ 5K ХОСТІВ - ТІЛЬКИ POSTGRESQL)
    # Приклад URL: postgresql://user:pass@localhost:5432/winhub
    # ---------------------------------------------------------
    DEFAULT_SQLITE = f"sqlite:///{os.path.join(DATA_DIR, 'winhub.db')}"
    DATABASE_URI = clean_env_value(os.environ.get('DATABASE_URI')) or build_postgres_uri_from_env()
    if DATABASE_URI and DATABASE_URI.startswith('postgres://'):
        DATABASE_URI = DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = DATABASE_URI or DEFAULT_SQLITE
    SAFE_DATABASE_URI = mask_database_uri(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Rate-limit backend.
    # Simple single-server mode: RATELIMIT_STORAGE_URI=memory://
    # Strict/multi-worker production mode: RATELIMIT_STORAGE_URI=redis://localhost:6379/0
    RATELIMIT_STORAGE_URI = clean_env_value(os.environ.get('RATELIMIT_STORAGE_URI')) or 'memory://'
    RATELIMIT_DEFAULT = clean_env_value(os.environ.get('RATELIMIT_DEFAULT')) or ''
    LOGIN_RATE_LIMIT = clean_env_value(os.environ.get('LOGIN_RATE_LIMIT')) or '5 per minute'
    AGENT_ENROLLMENT_RATE_LIMIT = clean_env_value(os.environ.get('AGENT_ENROLLMENT_RATE_LIMIT')) or '10 per minute'

    AGENT_API_KEY = clean_env_value(os.environ.get('AGENT_API_KEY')) or DEFAULT_AGENT_API_KEY
    AGENT_ENROLLMENT_ENABLED = (clean_env_value(os.environ.get('AGENT_ENROLLMENT_ENABLED')) or 'true').lower() in ('1', 'true', 'yes', 'on')
    AGENT_ENROLLMENT_ALLOWLIST = clean_env_value(os.environ.get('AGENT_ENROLLMENT_ALLOWLIST')) or ''
    AGENT_ALLOW_REENROLL_EXISTING = (clean_env_value(os.environ.get('AGENT_ALLOW_REENROLL_EXISTING')) or 'false').lower() in ('1', 'true', 'yes', 'on')
    AGENT_TASK_HMAC_SECRET = clean_env_value(os.environ.get('AGENT_TASK_HMAC_SECRET')) or SECRET_KEY
    # Dedicated key for deterministic blind search tokens. Existing installations
    # fall back to the stable task HMAC secret; production deployments should set
    # a separate value and reindex after rotating it.
    HISTORY_SEARCH_KEY = clean_env_value(os.environ.get('HISTORY_SEARCH_KEY')) or AGENT_TASK_HMAC_SECRET
    AGENT_TASK_SIGNATURE_MODE = (clean_env_value(os.environ.get('AGENT_TASK_SIGNATURE_MODE')) or 'dual').lower()
    AGENT_MAX_RESULT_LOG_BYTES = int(os.environ.get('AGENT_MAX_RESULT_LOG_BYTES', 262144))
    AGENT_TASK_TIMEOUT_SECONDS = int(os.environ.get('AGENT_TASK_TIMEOUT_SECONDS', 1800))
    AGENT_PACKAGE_MAX_UPLOAD_MB = int(os.environ.get('AGENT_PACKAGE_MAX_UPLOAD_MB', 256))
    AGENT_PUBLIC_BASE_URL = (clean_env_value(os.environ.get('AGENT_PUBLIC_BASE_URL')) or '').rstrip('/')
    AGENT_PACKAGE_URL_MODE = (clean_env_value(os.environ.get('AGENT_PACKAGE_URL_MODE')) or 'absolute').lower()
    AGENT_REQUIRE_SIGNED_REQUESTS = (clean_env_value(os.environ.get('AGENT_REQUIRE_SIGNED_REQUESTS')) or 'true').lower() in ('1', 'true', 'yes', 'on')
    AGENT_ALLOW_LEGACY_AGENT_SIGNATURES = (clean_env_value(os.environ.get('AGENT_ALLOW_LEGACY_AGENT_SIGNATURES')) or 'false').lower() in ('1', 'true', 'yes', 'on')
    AGENT_SIGNATURE_MAX_SKEW_SECONDS = env_int('AGENT_SIGNATURE_MAX_SKEW_SECONDS', 900, 1, 86400)
    AGENT_IDLE_POLL_SECONDS = env_int('AGENT_IDLE_POLL_SECONDS', 30, 10, 3600)
    AGENT_TASK_POLL_SECONDS = env_int('AGENT_TASK_POLL_SECONDS', 30, 10, 3600)
    AGENT_PENDING_POLL_SECONDS = env_int('AGENT_PENDING_POLL_SECONDS', 30, 10, 3600)
    AGENT_POLL_JITTER_SECONDS = env_int('AGENT_POLL_JITTER_SECONDS', 30, 0, 3600)
    AGENT_TELEMETRY_SECONDS = env_int('AGENT_TELEMETRY_SECONDS', 300, 60, 86400)
    AGENT_PENDING_TASK_MISS_CACHE_SECONDS = env_int('AGENT_PENDING_TASK_MISS_CACHE_SECONDS', 10, 0, 300)
    AGENT_UPDATE_ROLLOUT_CHECK_SECONDS = env_int('AGENT_UPDATE_ROLLOUT_CHECK_SECONDS', 5, 1, 300)
    AGENT_UPDATE_ROLLOUT_MAX_WAVES_PER_TICK = env_int('AGENT_UPDATE_ROLLOUT_MAX_WAVES_PER_TICK', 25, 1, 500)
    MAX_CONTENT_LENGTH = AGENT_PACKAGE_MAX_UPLOAD_MB * 1024 * 1024
    LATEST_AGENT_VERSION = clean_env_value(os.environ.get('LATEST_AGENT_VERSION')) or ''
    PRODUCTION_MODE = (clean_env_value(os.environ.get('WINHUB_ENV')) or '').lower() in ('prod', 'production')
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get('SESSION_IDLE_TIMEOUT_SECONDS', 21600))
    SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.environ.get('SESSION_ABSOLUTE_TIMEOUT_SECONDS', 0))
    SESSION_COOKIE_SECURE = (clean_env_value(os.environ.get('SESSION_COOKIE_SECURE')) or ('true' if PRODUCTION_MODE else 'false')).lower() in ('1', 'true', 'yes', 'on')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = clean_env_value(os.environ.get('SESSION_COOKIE_SAMESITE')) or 'Strict'
    HSTS_ENABLED = (clean_env_value(os.environ.get('HSTS_ENABLED')) or ('true' if PRODUCTION_MODE else 'false')).lower() in ('1', 'true', 'yes', 'on')
    SLOW_REQUEST_LOG_SECONDS = env_int('SLOW_REQUEST_LOG_SECONDS', 2, 0, 3600)
    REPORT_RENDERER_MODE = (clean_env_value(os.environ.get('REPORT_RENDERER_MODE')) or 'subprocess').lower()
    REPORT_RENDERER_SOCKET = clean_env_value(os.environ.get('REPORT_RENDERER_SOCKET')) or '/run/winhub-renderer.sock'
    REPORT_RENDERER_TIMEOUT_SECONDS = env_int('REPORT_RENDERER_TIMEOUT_SECONDS', 10, 1, 120)
    OUTBOUND_POLICY_MODE = (clean_env_value(os.environ.get('OUTBOUND_POLICY_MODE')) or 'audit').lower()
    OUTBOUND_ALLOWED_HOSTS = clean_env_value(os.environ.get('OUTBOUND_ALLOWED_HOSTS')) or ''
    CSP_MODE = (clean_env_value(os.environ.get('CSP_MODE')) or 'report-only').lower()
    CSP_POLICY = clean_env_value(os.environ.get('CSP_POLICY')) or COMPATIBILITY_CSP_POLICY
    CSP_NONCE_MODE = (clean_env_value(os.environ.get('CSP_NONCE_MODE')) or 'report-only').lower()
    CSP_NONCE_POLICY = clean_env_value(os.environ.get('CSP_NONCE_POLICY')) or DEFAULT_CSP_POLICY

    # 🚀 ОПТИМІЗАЦІЯ ДЛЯ ВИСОКОГО НАВАНТАЖЕННЯ (Connection Pooling)
    # Додаємо пул з'єднань тільки якщо використовуємо PostgreSQL, бо SQLite цього не підтримує
    if "postgres" in SQLALCHEMY_DATABASE_URI or "postgresql" in SQLALCHEMY_DATABASE_URI:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_size": 100,          # Кількість постійних підключень до БД
            "max_overflow": 200,       # Додаткові підключення в пікові моменти
            "pool_timeout": 30,        # Скільки чекати на вільне підключення (сек)
            "pool_recycle": 1800,      # Перезапуск підключень кожні 30 хв
        }

    # Назва сервісу для збереження Master Password у Windows Credential Manager
    SERVICE_NAME = os.environ.get('SERVICE_NAME', 'WinHUB_v2')

    # Searchable security/task/report history is retained for five years by
    # default. Telemetry remains a separate high-volume operational dataset.
    HISTORY_RETENTION_DAYS = env_int('HISTORY_RETENTION_DAYS', 1825, 0, 36500)
    TELEMETRY_RETENTION_DAYS = env_int(
        'TELEMETRY_RETENTION_DAYS',
        clean_env_value(os.environ.get('LOG_RETENTION_DAYS')) or 30,
        0,
        36500,
    )
    HISTORY_CLEANUP_BATCH_SIZE = env_int('HISTORY_CLEANUP_BATCH_SIZE', 5000, 100, 50000)
    HISTORY_SEARCH_BACKFILL_BATCH_SIZE = env_int('HISTORY_SEARCH_BACKFILL_BATCH_SIZE', 250, 10, 2000)
    AUDIT_SENSITIVE_READS = (
        clean_env_value(os.environ.get('AUDIT_SENSITIVE_READS')) or 'true'
    ).lower() in ('1', 'true', 'yes', 'on')

    # Deprecated compatibility names. They no longer control task/report/audit
    # history deletion and therefore cannot accidentally retain only 30 days.
    LOG_RETENTION_DAYS = TELEMETRY_RETENTION_DAYS
    AUDIT_RETENTION_DAYS = HISTORY_RETENTION_DAYS

    # ---------------------------------------------------------
    # НАЛАШТУВАННЯ ПОШТИ (ДЛЯ СПОВІЩЕНЬ)
    # ---------------------------------------------------------
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'admin@winhub.local')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_PASSWORD = clean_env_value(os.environ.get('SMTP_PASSWORD'))
    GPG_PATH = clean_env_value(os.environ.get('GPG_PATH')) or shutil.which('gpg') or (
        r"C:\Program Files (x86)\GnuPG\bin\gpg.exe" if os.name == 'nt' else '/usr/bin/gpg'
    )
    GPG_HOME = clean_env_value(os.environ.get('GNUPGHOME')) or clean_env_value(os.environ.get('GPG_HOME')) or os.path.join(DATA_DIR, 'gnupg')


def _looks_like_strong_secret(value, minimum_length):
    value = str(value or "")
    if len(value) < minimum_length:
        return False
    return len(set(value)) >= 16


def production_secret_errors():
    errors = []
    if not _looks_like_strong_secret(Config.SECRET_KEY, 48) or Config.SECRET_KEY == DEFAULT_SECRET_KEY:
        errors.append("SECRET_KEY must be a unique 48+ character secret in production.")
    if not _looks_like_strong_secret(Config.AGENT_API_KEY, 32) or Config.AGENT_API_KEY == DEFAULT_AGENT_API_KEY:
        errors.append("AGENT_API_KEY must be a unique 32+ character enrollment secret in production.")
    if not _looks_like_strong_secret(Config.AGENT_TASK_HMAC_SECRET, 32):
        errors.append("AGENT_TASK_HMAC_SECRET must be a unique 32+ character task-signing secret in production.")
    if Config.AGENT_TASK_HMAC_SECRET == Config.SECRET_KEY:
        errors.append("AGENT_TASK_HMAC_SECRET must be different from SECRET_KEY in production.")
    if Config.REPORT_RENDERER_MODE == "inprocess":
        errors.append("REPORT_RENDERER_MODE=inprocess is not allowed in production.")
    return errors
