# WinHUB: правила роботи з проєктом

Цей файл задає спільний контекст для всього репозиторію: сервера, агентів і Wiki. Шляхи нижче відраховуються від кореня Git, незалежно від того, у якому каталозі відкрито задачу. Спілкуйся з користувачем українською. Виконуй поточний запит з урахуванням уже погоджених рішень.

## Початок нової задачі

1. Визнач корінь через `git rev-parse --show-toplevel`; перевір `git status --short --branch`, поточну гілку, staged та unstaged зміни. Не припускай, що checkout чистий або вже синхронізований з GitHub.
2. Прочитай кореневий [README.md](README.md), README потрібного компонента та локальний `AGENTS.md`, якщо він є. Перед переходом в інший компонент перевір його інструкції.
3. Знайди відповідну реалізацію, тести й сторінку Wiki. Орієнтуйся на поточні файли та Git, а не на припущення про зміст попередніх чатів.
4. Перед редагуванням визнач, які компоненти зачіпає задача. Зміни shared Worker, API/protocol або розгортання перевіряй з обох боків відповідної залежності.
5. Збережи наявні правки користувача. Не скидай index, не перезаписуй локальні файли й не прибирай чужі зміни для отримання чистого diff.

## Карта проєкту

| Шлях | Призначення |
| --- | --- |
| `WinHUB/` | Python-сервер: Flask, SQLAlchemy/Alembic, Socket.IO; production — Debian, PostgreSQL, Nginx, systemd |
| `WinHUB/core/` | Конфігурація, БД, auth/permissions, security, Agent Gateway, AI та report renderer |
| `WinHUB/modules/Infrastructure/` | Хости, групи, шаблони, задачі, telemetry, звіти, software, scheduler і rollout агентів |
| `WinHUB/modules/HistoryAudit/` | Історія й аудит |
| `WinHUB/modules/Newsletter/` | Розсилки та поштові інтеграції |
| `WinHUB/templates/`, `WinHUB/static/` | Спільні templates, CSS, JS та vendor assets; модульні templates залишаються у модулях |
| `WinHUB/migrations/` | Версійні міграції БД |
| `WinHUB/deploy/debian/` | Install/update, backup/restore, healthcheck, systemd і Nginx |
| `WinHUB/deploy/import_templates/` | Готові task/report packs, кожен у власному тематичному каталозі |
| `WinHUB/tests/` | Серверні regression tests і перевірки distribution |
| `WinHUBAgentWindows/` | Windows-агент, .NET 8, `WinHUBAgentWindows.csproj` |
| `WinHUBLinuxAgent/` | Linux-агент, .NET 8, спільний Unix `Worker.cs` |
| `WinHUBMacAgent/` | macOS-агент, .NET 10, власні `docs/`, `tests/` і `global.json` |
| `WinHUB-WiKi/` | Документація всіх компонентів; [зміст](WinHUB-WiKi/SUMMARY.md) |
| `.github/workflows/ci.yml` | Команди й середовища CI для сервера та агентів |

Сервер ставить задачі через Agent Gateway, агенти повертають результати й telemetry. Доступ контролюють permissions, групи, політики API keys та підписи запитів/задач. Звіти мають revisions і delivery snapshots; production renderer працює окремою службою. Деталі перевіряй у коді потрібного потоку.

## Розміщення файлів і порядок

- Сервер, три агенти та Wiki залишаються сусідніми компонентами. Не повертай агентів або Wiki всередину `WinHUB/`.
- У корені зберігай лише спільні правила, README і конфігурацію репозиторію/збірки. Новий каталог верхнього рівня має випливати із задачі; разом із ним онови цю карту та root allowlist у `.gitignore`.
- Докладні посібники розміщуй у `WinHUB-WiKi/guides/features/`, `guides/security/` або `guides/agents/`. Короткі сценарії — у відповідному розділі Wiki. Технічні інструкції складання окремого агента можуть бути в його `docs/`.
- Не створюй у корені файли на кшталт `NOTES.md`, `REPORT.md`, `TODO.md`, `*_GUIDE_*.md`, копії `final2` або `backup_old`. Доповнюй наявний документ за темою.
- Разові helper scripts, дампи для аналізу, screenshots і проміжні звіти задачі зберігай у виділеній папці системного TEMP поза репозиторієм. Повторно потрібний інструмент розміщуй у відповідному компоненті та документуй.
- Згенеровані серверні пакети — `WinHUB/dist/`; агентські — `dist-agent/` відповідного агента. Build outputs — штатні `bin/`, `obj/` або ігнорований `artifacts/`. Вони не належать до Git.
- Після перевірок прибери створені тобою непотрібні проміжні файли. Не видаляй робочий venv, runtime data, старі release-пакети чи резервні копії лише через те, що вони ігноруються Git.
- Сусідні локальні backups, архіви, security-review каталоги та інші worktree не є вихідним кодом цієї задачі. Не змінюй їх без відповідного запиту.

## Сумісність і розгортання

- Назва Windows-проєкту — `WinHUBAgentWindows`. `AssemblyName`, executable, установлена служба та update-пакети зберігають сумісне ім'я `WinHUBAgent`. Перейменування каталогу не є підставою міняти встановлений агент.
- macOS підключає `../WinHUBLinuxAgent/Worker.cs`. Зміна цього файла потребує перевірки Linux і macOS. Для macOS запускай `dotnet` із `WinHUBMacAgent/`, щоб обирався його SDK через `global.json`.
- `WinHUBLinuxAgent/Security/*.cs` підключається також Windows/macOS як shared source. Зміни цих перевірок потребують збірки та self-tests відповідних агентів; Windows-компонент більше не можна збирати з ізольованої копії лише його каталогу.
- Версії SDK і залежностей перевіряй у `global.json`, `.csproj`, `requirements.txt`; версію серверного release — у `WinHUB/VERSION`. Не підвищуй версії без потреби задачі.
- Production server source встановлюється безпосередньо в `/opt/winhub`; конфігурація — `/etc/winhub`, дані — `/var/lib/winhub`, логи — `/var/log/winhub`. Git checkout готується окремо від установленої програми.
- Install, update і release використовують `WinHUB/deploy/server-files.txt` та `server-excludes.txt`. Новий runtime-компонент додавай узгоджено. Не замінюй це пакуванням усього checkout.
- Оновлення має створювати backup старої версії до заміни коду, зберігати runtime data і secrets, застосовувати міграції та виконувати healthcheck. Чисте встановлення повинно залишатися простим сценарієм із README.
- Зміни схеми БД оформлюй новою міграцією; не переписуй вже застосовані міграції для маскування проблеми оновлення.
- Не вимикай TLS verification, підписи агентів, access checks, masking чи ізоляцію renderer заради проходження тесту. Не ротуй робочі секрети під час звичайного update. Зміна `HISTORY_SEARCH_KEY` потребує плану переіндексації.
- Перед змінами AI, шаблонів, виконання задач, delivery або service boundaries прочитай [правила безпеки та ізоляції](WinHUB-WiKi/guides/security/SECURITY_RULES_AND_ISOLATION_UA.md). Відрізняй обов'язкові вимоги від ще не реалізованих controls; нова функція не повинна перетворювати недовірені дані на виконуваний код без окремого дозволу та відповідної ізоляції.

## Git і конфіденційні дані

- Кореневий `.gitignore` містить allowlist компонентів. Не обходь його через `git add -f` для випадкових локальних файлів.
- Не коміть `.env`, runtime-конфігурації агентів, ключі, токени, recovery-файли, БД, логи, archives, venv, caches або build outputs. У прикладах використовуй placeholders.
- Перед staging перевір конкретний перелік файлів; збережи вже підготовлені користувачем зміни. Перед завершенням переглянь `git diff --check`, за наявності staging — `git diff --cached --check`, а також status/diff.
- Якщо потрібна нова гілка, використовуй префікс `codex/`, якщо користувач не задав інший. Не змінюй remote, історію чи Git root як побічний ефект звичайної задачі.
- Commit, push, публікацію release та deployment виконуй, коли вони входять до запиту або вже погоджені. Для рутинних локальних правок у межах задачі не запитуй повторного дозволу.

## Перевірки за типом зміни

Використовуй наявні тести; додавай regression test для зміни поведінки, якщо він перевіряє реальний ризик. Для документації достатньо перевірити посилання, шляхи й diff. Повний набір команд і поточні SDK звіряй із `.github/workflows/ci.yml`.

- Сервер, із `WinHUB/` у Python environment із `requirements.txt`: `python -m unittest discover -s tests -v`.
- Install/update/release, на Linux або WSL із Bash, GNU tar і rsync: `python -m unittest discover -s tests -p test_server_distribution.py -v`, shell syntax, `bash deploy/create_release.sh`; перевір склад архіву й checksum manifest.
- Windows-агент, на Windows із кореня Git: `dotnet build WinHUBAgentWindows/WinHUBAgentWindows.csproj -c Release`; для змін `.ps1` перевір PowerShell parser.
- Linux-агент, із кореня Git: `dotnet build WinHUBLinuxAgent/WinHUBLinuxAgent.csproj -c Release -p:PublishAot=false`, потім `dotnet WinHUBLinuxAgent/bin/Release/net8.0/WinHUBLinuxAgent.dll --self-test`.
- macOS managed validation на Windows, із `WinHUBMacAgent/`: `dotnet build WinHUBMacAgent.csproj -c Release -p:PublishAot=false -p:RuntimeIdentifier=win-x64 -p:SelfContained=false`, потім `dotnet bin/Release/net10.0/win-x64/WinHUBMacAgent.dll --self-test`; контрактні тести — `python -m unittest discover -s tests -v`.
- Native macOS release/signing/notarization перевіряються на Mac за `WinHUBMacAgent/docs/BUILD_MAC_M4_UA.md`. Managed build не підтверджує проходження цих кроків.
- Тести distribution не запускають повний production installer. Не повідомляй про перевірену чисту Debian-інсталяцію, upgrade або restore, якщо відповідний сценарій не був реально виконаний.

## Документація і завершення задачі

- Якщо змінюються UI, API, конфігурація, права, встановлення або оновлення, онови відповідну Wiki в тій самій задачі. Якщо змінюється структура, онови також цей файл і кореневий README.
- Довготривалі архітектурні рішення та їх причини записуй у відповідну сторінку `WinHUB-WiKi/09-Розробка/`. Не роби з `AGENTS.md` журнал кожної сесії; не закріплюй тут поточну гілку, незавершений diff чи кількість тестів.
- Завершуючи задачу, коротко вкажи результат, виконані перевірки, суттєві обмеження та стан commit/push. Невиконані перевірки називай явно.
