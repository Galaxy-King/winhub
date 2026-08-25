# База даних і migrations

Production використовує PostgreSQL і Alembic.

## Upgrade

```bash
sudo /opt/winhub/deploy/debian/migrate_winhub.sh upgrade
```

## Нова revision у development

```bash
deploy/debian/migrate_winhub.sh revision -m "describe change"
```

Перевірте generated migration вручну. Schema change повинен мати upgrade path для наявних даних, indexes, rollback/backup strategy та tests.

Не редагуйте production database вручну без incident/change procedure. `db.create_all()` не замінює контрольований Alembic rollout.
