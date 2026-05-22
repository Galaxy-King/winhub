# ==============================================================================
# ШЛЯХ ДО ФАЙЛУ: core/config.py
# ПРИЗНАЧЕННЯ: Головний файл конфігурації системи. Читає змінні з .env
# ==============================================================================

import os
import shutil
from urllib.parse import quote_plus, urlsplit, urlunsplit
from dotenv import load_dotenv

# Завантаження змінних з .env файлу
load_dotenv()

def clean_env_value(value):
    if value is None:
        return None
    value = value.strip().lstrip('\ufeff').strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1].strip()
    return value or None

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
    SECRET_KEY = clean_env_value(os.environ.get('SECRET_KEY')) or 'default-dev-secret-key-change-in-production'
    
    # Визначення головних шляхів системи
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    DATA_DIR = clean_env_value(os.environ.get('DATA_DIR')) or os.path.join(BASE_DIR, 'data')
    MODULES_DIR = clean_env_value(os.environ.get('MODULES_DIR')) or os.path.join(BASE_DIR, 'modules')
    SERVER_LOG_FILE = clean_env_value(os.environ.get('SERVER_LOG_FILE')) or os.path.join(DATA_DIR, 'logs', 'winhub_prod.log')
    SERVER_CERT_PATH = clean_env_value(os.environ.get('SERVER_CERT_PATH')) or os.path.join(BASE_DIR, 'certs', 'cert.pem')
    SERVER_KEY_PATH = clean_env_value(os.environ.get('SERVER_KEY_PATH')) or os.path.join(BASE_DIR, 'certs', 'key.pem')
    
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

    AGENT_API_KEY = clean_env_value(os.environ.get('AGENT_API_KEY')) or 'WinHUB-Secret-Enroll-2026'
    AGENT_ENROLLMENT_ENABLED = (clean_env_value(os.environ.get('AGENT_ENROLLMENT_ENABLED')) or 'true').lower() in ('1', 'true', 'yes', 'on')
    AGENT_ENROLLMENT_ALLOWLIST = clean_env_value(os.environ.get('AGENT_ENROLLMENT_ALLOWLIST')) or ''
    AGENT_ALLOW_REENROLL_EXISTING = (clean_env_value(os.environ.get('AGENT_ALLOW_REENROLL_EXISTING')) or 'false').lower() in ('1', 'true', 'yes', 'on')
    AGENT_TASK_HMAC_SECRET = clean_env_value(os.environ.get('AGENT_TASK_HMAC_SECRET')) or SECRET_KEY
    AGENT_MAX_RESULT_LOG_BYTES = int(os.environ.get('AGENT_MAX_RESULT_LOG_BYTES', 262144))
    AGENT_TASK_TIMEOUT_SECONDS = int(os.environ.get('AGENT_TASK_TIMEOUT_SECONDS', 1800))
    LATEST_AGENT_VERSION = clean_env_value(os.environ.get('LATEST_AGENT_VERSION')) or ''
    PRODUCTION_MODE = (clean_env_value(os.environ.get('WINHUB_ENV')) or '').lower() in ('prod', 'production')
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get('SESSION_IDLE_TIMEOUT_SECONDS', 900))
    SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.environ.get('SESSION_ABSOLUTE_TIMEOUT_SECONDS', 0))
    SESSION_COOKIE_SECURE = (clean_env_value(os.environ.get('SESSION_COOKIE_SECURE')) or ('true' if PRODUCTION_MODE else 'false')).lower() in ('1', 'true', 'yes', 'on')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = clean_env_value(os.environ.get('SESSION_COOKIE_SAMESITE')) or 'Strict'
    HSTS_ENABLED = (clean_env_value(os.environ.get('HSTS_ENABLED')) or ('true' if PRODUCTION_MODE else 'false')).lower() in ('1', 'true', 'yes', 'on')
    
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
    
    # Термін зберігання історії виконання скриптів та їх логів (у днях)
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 30))
    AUDIT_RETENTION_DAYS = int(os.environ.get('AUDIT_RETENTION_DAYS', 365))

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
