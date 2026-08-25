# Backup і test restore

## Регулярний backup

```bash
sudo /opt/winhub/deploy/debian/backup_winhub.sh
```

Автоматизація повинна переносити результат до encrypted off-host storage і перевіряти checksums.

## Test restore

1. Підготуйте ізольований Debian host/network.
2. Скопіюйте конкретний backup.
3. Виконайте restore script.
4. Перевірте login/MFA, reports, encryption keys, endpoint records і Audit Log.
5. Не дозволяйте test server приймати production agents.
6. Зафіксуйте RTO/RPO та помилки процедури.

Успішне створення archive без test restore не доводить відновлюваність.
