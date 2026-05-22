import os
import sys
import logging
import ssl
import socket
from logging.handlers import RotatingFileHandler

# Gevent monkey patching має бути на самому початку!
from gevent import monkey
monkey.patch_all()

# --- ПРИДУШУЄМО КРАШ-ЛОГИ SSL ВІД GEVENT ---
from gevent import hub
original_handle_error = hub.Hub.handle_error

def custom_handle_error(self, context, type, value, tb):
    # Якщо це помилка SSL або обрив з'єднання агента - повністю ігноруємо
    err_str = str(value)
    if issubclass(type, ssl.SSLError) and ("CERTIFICATE_UNKNOWN" in err_str or "UNEXPECTED_EOF" in err_str):
        return 
    if issubclass(type, ConnectionAbortedError) and "10053" in err_str:
        return
    original_handle_error(self, context, type, value, tb)

hub.Hub.handle_error = custom_handle_error
# ----------------------------------------------------

from core import create_app, socketio
from core.config import Config

os.makedirs(os.path.dirname(Config.SERVER_LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        RotatingFileHandler(Config.SERVER_LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("winhub.server")

# Також придушуємо логи WSGI
class QuietWSGILogger:
    def write(self, message):
        if "SSLV3_ALERT_CERTIFICATE_UNKNOWN" in message or "SSLError" in message or "10053" in message: return
        sys.stderr.write(message)
    def flush(self):
        pass


def validate_port_available(host, port):
    bind_host = "0.0.0.0" if host in ("", "0.0.0.0", "::") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, port))


def run_gevent_https(app, host, port, cert_path, key_path):
    from gevent import pywsgi

    try:
        from geventwebsocket.handler import WebSocketHandler
        handler_class = WebSocketHandler
        log.info("WebSocket handler enabled.")
    except Exception as e:
        handler_class = None
        log.warning(f"gevent-websocket is not available. Socket.IO will fall back where possible. Details: {e}")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server_kwargs = {
        "log": QuietWSGILogger(),
        "error_log": QuietWSGILogger(),
        "ssl_context": ssl_context,
    }
    if handler_class:
        server_kwargs["handler_class"] = handler_class

    server = pywsgi.WSGIServer((host, port), app, **server_kwargs)
    server.start()
    log.info(f"HTTPS server is accepting connections on https://{host}:{port}")
    server.serve_forever()

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', getattr(Config, 'SERVER_PORT', 8443)))
    host = os.environ.get('HOST', '0.0.0.0')
    
    cert_path = Config.SERVER_CERT_PATH
    key_path = Config.SERVER_KEY_PATH

    log.info("=================================================")
    log.info("🚀 ЗАПУСК WINHUB PRODUCTION СЕРВЕРА (Gevent + SocketIO)")
    log.info(f"📡 Слухаємо на {host}:{port}")
    log.info("=================================================")

    app.debug = False
    if getattr(Config, 'PRODUCTION_MODE', False):
        if not getattr(Config, 'RATELIMIT_STORAGE_URI', None):
            log.warning("Production mode is enabled but RATELIMIT_STORAGE_URI is not set. Configure Redis for durable rate limits.")
        if getattr(Config, 'SECRET_KEY', '').startswith('default-dev-secret-key'):
            log.warning("Production mode is enabled but SECRET_KEY still uses the development default.")
        if getattr(Config, 'AGENT_TASK_HMAC_SECRET', None) == getattr(Config, 'SECRET_KEY', None):
            log.warning("AGENT_TASK_HMAC_SECRET is not set separately. Set it before updating agents to enforce task signatures.")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        log.info(f"🔒 SSL Сертифікати знайдено у {os.path.dirname(cert_path)}. Запуск захищеного HTTPS.")
        try:
            validate_port_available(host, port)
            run_gevent_https(app, host, port, cert_path, key_path)
        except OSError as e:
            log.critical(f"Cannot bind {host}:{port}. Port is busy or blocked: {e}", exc_info=True)
            sys.exit(1)
        except ssl.SSLError as e:
            log.critical(f"SSL certificate/key load failed: {e}", exc_info=True)
            sys.exit(1)
        except Exception as e:
            log.critical(f"HTTPS server failed to start: {e}", exc_info=True)
            sys.exit(1)
    else:
        log.error("❌ КРИТИЧНА ПОМИЛКА: SSL сертифікати не знайдено!")
        log.error(f"Переконайтеся, що файли {cert_path} та {key_path} існують.")
        sys.exit(1)
