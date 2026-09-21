"""Dedicated durable Newsletter queue and inbound mailbox worker."""
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler

from core import create_app
from core.config import Config, production_secret_errors
from modules.Newsletter.routes import run_newsletter_worker


def configure_logging():
    os.makedirs(os.path.dirname(Config.SERVER_LOG_FILE), exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(os.path.dirname(Config.SERVER_LOG_FILE), "newsletter_worker.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[handler, logging.StreamHandler(sys.stdout)],
        force=True,
    )


def main():
    configure_logging()
    log = logging.getLogger("winhub.newsletter.worker")
    if getattr(Config, "PRODUCTION_MODE", False):
        errors = production_secret_errors()
        if errors:
            for error in errors:
                log.critical(error)
            return 1
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    app = create_app()
    log.info("Newsletter worker started.")
    run_newsletter_worker(app)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
