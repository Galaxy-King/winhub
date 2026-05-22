# WinHUB database migrations

WinHUB now has an Alembic migration baseline for controlled production updates.

Create a migration after changing models:

```bash
source /etc/winhub/winhub.env
/opt/winhub/venv/bin/alembic revision --autogenerate -m "describe change"
```

Apply migrations:

```bash
source /etc/winhub/winhub.env
/opt/winhub/venv/bin/alembic upgrade head
```

The Debian update script runs `alembic upgrade head` automatically when migrations are present.
