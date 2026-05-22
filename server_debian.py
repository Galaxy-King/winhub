import os
import sys
import logging
import socket
from logging.handlers import RotatingFileHandler

from gevent import monkey
monkey.patch_all()

from gevent import hub
from werkzeug.middleware.proxy_fix import ProxyFix

from core import create_app
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
log = logging.getLogger("winhub.debian")

original_handle_error = hub.Hub.handle_error


def custom_handle_error(self, context, type, value, tb):
    err_str = str(value)
    if issubclass(type, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
        return
    if "UNEXPECTED_EOF" in err_str or "Connection reset" in err_str:
        return
    original_handle_error(self, context, type, value, tb)


hub.Hub.handle_error = custom_handle_error


class QuietWSGILogger:
    def write(self, message):
        if "Connection reset" in message or "Broken pipe" in message:
            return
        sys.stderr.write(message)

    def flush(self):
        pass


def validate_port_available(host, port):
    bind_host = "0.0.0.0" if host in ("", "0.0.0.0", "::") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, port))


def run_gevent_http(app, host, port):
    from gevent import pywsgi

    try:
        from geventwebsocket.handler import WebSocketHandler
        handler_class = WebSocketHandler
        log.info("WebSocket handler enabled.")
    except Exception as e:
        handler_class = None
        log.warning("gevent-websocket is not available. Socket.IO will fall back where possible. Details: %s", e)

    server_kwargs = {
        "log": QuietWSGILogger(),
        "error_log": QuietWSGILogger(),
    }
    if handler_class:
        server_kwargs["handler_class"] = handler_class

    server = pywsgi.WSGIServer((host, port), app, **server_kwargs)
    server.start()
    log.info("Debian backend is accepting local HTTP connections on http://%s:%s", host, port)
    server.serve_forever()


app = create_app()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', getattr(Config, 'SERVER_PORT', 8443)))
    host = os.environ.get('HOST', '127.0.0.1')

    log.info("=================================================")
    log.info("Starting WinHUB Debian backend (Gevent + SocketIO)")
    log.info("Listening on %s:%s behind Nginx TLS reverse proxy", host, port)
    log.info("=================================================")

    app.debug = False
    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Debian backend is not bound to localhost. Put Nginx in front and firewall this port.")
    if getattr(Config, 'PRODUCTION_MODE', False):
        if getattr(Config, 'SECRET_KEY', '').startswith('default-dev-secret-key'):
            log.warning("Production mode is enabled but SECRET_KEY still uses the development default.")
        if getattr(Config, 'AGENT_TASK_HMAC_SECRET', None) == getattr(Config, 'SECRET_KEY', None):
            log.warning("AGENT_TASK_HMAC_SECRET is not set separately.")

    try:
        validate_port_available(host, port)
        run_gevent_http(app, host, port)
    except OSError as e:
        log.critical("Cannot bind %s:%s. Port is busy or blocked: %s", host, port, e, exc_info=True)
        sys.exit(1)
    except Exception as e:
        log.critical("Debian backend failed to start: %s", e, exc_info=True)
        sys.exit(1)
