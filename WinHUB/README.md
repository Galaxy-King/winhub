# Сервер WinHUB

Цей каталог містить лише серверну частину. Агенти й [Wiki](../WinHUB-WiKi/README.md) лежать поруч із ним у корені репозиторію.

| Каталог | Вміст |
| --- | --- |
| `core/` | Конфігурація, БД, авторизація, безпека, Agent Gateway, AI і renderer |
| `modules/` | Infrastructure, HistoryAudit, Newsletter |
| `templates/`, `static/` | Вебінтерфейс та його ресурси |
| `migrations/` | Міграції Alembic |
| `deploy/debian/` | Встановлення, оновлення, backup/restore, systemd і Nginx |
| `deploy/import_templates/` | Готові пакети завдань і звітів |
| `tests/` | Серверні регресійні тести |

## Debian

З цього каталогу: `sudo bash deploy/debian/install_debian.sh`.

[Встановлення з нуля](../WinHUB-WiKi/02-Сервер/01-Встановлення-з-нуля.md) · [Оновлення](../WinHUB-WiKi/02-Сервер/05-Оновлення-сервера.md) · [Технічна документація Debian](deploy/debian/README_DEBIAN.md).

[AI-редактор PowerShell/Bash/Jinja](../WinHUB-WiKi/guides/features/AI_TEMPLATE_EDITOR_UA.md) використовує Open WebUI та окремий `winhub-code-validator.socket`. Для перевірки PowerShell потрібний `pwsh` на Debian; згенерований код не запускається під час генерації/перевірки.

## Локальні перевірки

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m compileall -q core modules migrations server_debian.py server_prod.py
```

Тести пакування запускають Bash, GNU tar і rsync на Linux/WSL; за їх відсутності відповідні тести пропускаються. CI виконує їх на Ubuntu.

## Серверний release

```bash
bash deploy/create_release.sh
```

Результат: `dist/winhub-v<version>.tar.gz` та JSON manifest із SHA-256. Версія береться з `VERSION`. Архів містить лише серверні компоненти; Git, агенти, Wiki, тести, кеші й runtime-секрети до нього не входять. Той самий перелік компонентів використовують install/update.
