# Software: доставка через WinHUB та черга розгортання

## Рішення

OMV є джерелом пакетів для сервера, а не публічним API агентів. Підготовка у scheduler завантажує один файл за раз, з обмеженням розміру/часу, чинним TLS, точним origin без redirects і central outbound policy у режимі enforce. Після підготовки immutable blob адресується SHA-256. Source URLs не потрапляють у задачі.

Каталог перенесено з JSON у `SoftwarePackage` із encrypted record, налаштування — у singleton `SoftwareControl`. Старий JSON імпортується без видалення. Шифрування спільне з рештою payload БД; це не окремий secret store із власними grants.

`SoftwareDeployment` зберігає актора, причину, паралельність і строк очікування. `SoftwareStep` зберігає encrypted snapshot програми/точного коду, позицію на хості, task ID та download lease. Зміна каталогу не змінює чергу.

Короткі транзакції з `SELECT FOR UPDATE` singleton-row серіалізують admission, queue controls і download leases між PostgreSQL-процесами. Локальний RLock підтримує потоковий доступ у тестовому SQLite; глобальний admission перевірено окремим PostgreSQL integration test із чотирма незалежними процесами. Мережеве завантаження OMV відбувається поза queue lock, із lease claim та перевіркою preparation ID перед записом результату.

## Виконання та безпека

Використовується наявний `run_script`, чинний task-signing і agent timeout; C# protocol не змінюється. Windows PowerShell downloader використовує системний TLS trust store, а не agent strict pin. Потрібен довірений сертифікат WinHUB на хості. Linux/macOS явно відхиляються цим каталогом Windows-рецептів.

Рецепт погоджується superadmin за hash. Посилання на Workspace приймає лише чинний approved `action/run_script`, без runtime variables/Jinja/AI marker. Inline code і detection command — виконуваний адміністративний код, не sandbox. Зафіксовані рецепти працюють із правами служби агента.

GET `/api/public/software-delivery/<step_id>` не є анонімним публічним каталогом: потрібен випадковий bearer token у Authorization, hash якого зберігається на активному step. Він видається при admission, передається всередині signed/encrypted-at-rest payload і діє не довше agent timeout + 300 секунд; сервер також перевіряє task status і блокування хоста. Capability не прив’язана криптографічно до пристрою під час GET; її витік дає тимчасовий доступ до одного snapshot blob. Token не додається в URL/логи. Range/resume не підтримується; повторний повний GET допускається до завершення строку, паралельний GET того самого step відхиляється.

Download lease поновлюється під час стримінгу; при аварійному обриві звільняється після 2 хвилин. Сервер обмежує число потоків та консервативну сумарну швидкість. Nginx buffering/cache вимкнено для маршруту.

## Межі та експлуатація

Черга гарантує послідовність саме Software, не виключає задачі інших підсистем, створені пізніше. Початок чекає відсутності інших активних задач на хості. Офлайн-хости не займають слот; непідтверджений результат виконання утримує слот, бо повторний інсталятор може конфліктувати з попереднім. Ручне завершення — лише superadmin після перевірки припинення процесів, з причиною та аудитом. Generic retry/cancel/finalize не повинні обходити ці правила.

Reboot-required зупиняє наступні програми, без автоматичного restart або resume. Немає автоматичного rollback, dependency solver, content publisher signature, cache GC чи загальної дискової квоти. Порядок задається числом на програмі та назвою; окремий порядок однієї програми для різних наборів не підтримується.

Тестування використовує isolated Flask/SQLite і синтетичні байти: жодних реальних інсталяторів на endpoints. Nginx-конфігурацію перевірено на тимчасових сертифікатах і непривілейованих портах; synthetic PowerShell перевіряє коди завершення без реального встановлення. Потрібні окремі приймальні перевірки OMV, production Nginx, Windows trust store, реального MSI exit/reboot та встановлення на canary перед production rollout.

[Інструкція оператора](../04-Endpoint-Management/07-Software.md).


### Бібліотека інсталяторів та явне погодження

Записи `kind=installer` використовують наявне зашифроване JSON-поле `software_catalog`, спільну чергу підготовки й immutable blobs. Вони вилучені зі списку deployable applications і розгортання наборів. Міграції SQL не потрібні: схема не змінена. Додаток копіює готові blob metadata вибраного installer; посилання не є живим зв'язком, автоматичного оновлення рецептів/погодження немає. POST installers потребує інтерактивного `manage_software`; POST approve додатково superadmin та точну revision. Approval аудіюється. Тест посилання не надає approval і не виконує скрипти.


### Lean protocol, contacts and clone lifecycle (2026-10-23)

Windows Software now uses a relative path and signed download descriptor, consumed by the existing pinned agent HttpClient. The server capability still requires the active picked-up task and expires/revokes as before. SHA-256 and declared size are checked before PowerShell. No credentials or OMV source URLs enter the agent downloader. Old clients are capability-gated, not silently downgraded to unsigned or system-trust downloads.

Lean agents no longer schedule telemetry. Basic host data accompanies authenticated polls; explicit inventory remains an ordinary authorized, journalled task with lower dispatch priority, one collector and a bounded response deadline. The host passport omits stale CPU/disk/security snapshots. Legacy telemetry endpoint/history remain for rolling upgrades.

Migration `20261023_01` adds expected contact windows to endpoints and per-UTC-hour contact aggregates. Authenticated poll receipt is measured by the server; jitter and task timeout produce an estimated range, not a promise of liveness. The chart shows contacts and late observations, not invented uptime percentages. Missing buckets are unknown, including possible server outages. Aggregates retain 30 days.

Clone completion locks the original endpoint and conflict before finalization; 3+ sessions keep quarantine until all additional active sessions/pending commands are resolved. Completed splits create pairwise distinct-host exceptions. A staged clone has no invented last contact. Agent split recovery resets per-endpoint task trust in runtime config as well as state and reloads in-process. Targeting remains session-specific; after a pre-delivery process restart an administrator must review the new session rather than rebinding by IP/MAC. Old timed-out requests are visible and require explicit retry; no unverified automatic adoption is introduced.


### Узгодження Software delivery із poll cadence (2026-10-24)

Фіксовані 120 секунд для host freshness та повернення незабраної Pending-задачі створювали цикл SoftwareQueued при interval 120 + jitter 120: задача могла бути прибрана перед наступним poll. Бюджет доставки тепер `max(120, min(7200, max(configured interval+jitter, observed next_contact_max-last_poll_at)) + 60)` секунд. Він застосовується до freshness й очікування pickup; строк download capability також включає цей бюджет до timeout виконання. Підписи, ліміти навантаження, заборона повторного запуску забраного installer та task ID зберігаються. Regression test відтворює 150 секунд між контактами й перевіряє доступність задачі наступному poll та звільнення слота після справжньої відсутності контакту.
