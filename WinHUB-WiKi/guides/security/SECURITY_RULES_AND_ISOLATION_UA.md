# Правила безпеки та ізоляції WinHUB

Це спільний контракт безпеки для сервера, агентів, AI, шаблонів і доставки звітів. Правила нижче — вимоги до розробки та експлуатації, а не твердження, що кожна з них уже реалізована. Сам Markdown-файл нічого не блокує: обмеження мають забезпечувати API, ОС, права доступу та тести.

## Межі перевірки

Статична звірка: **2026-09-04**, поточні робочі файли після перенесення компонентів у спільний Git-корінь. Переглянуто основні потоки генерації/доставки звітів, AI, виконання задач, systemd, backup/restore та відповідні тести. Це цільовий огляд меж довіри, не повний pentest або аудит усіх залежностей.

Живі Debian-служби, firewall, PostgreSQL grants, Windows service token, macOS TCC та конфігурація зовнішнього Open WebUI **не перевірені**. Наявність правильної unit-конфігурації у Git не доводить її застосування на сервері. Особливо важливо перевірити старі інсталяції: update зберігає частину попередніх режимів сумісності.

### Доповнення після реалізації AI-редактора (2026-09-04)

Початкові F01–F11 нижче зберігають опис стану до реалізації. Додано [AI-редактор приватних чернеток](../features/AI_TEMPLATE_EDITOR_UA.md) та [архітектурне рішення](../../09-Розробка/07-AI-редактор-архітектура.md). Це не повне усунення всіх знайдених прогалин і не дозвіл на autonomous execution.

- **F05 — новий AI-шлях захищений:** draft окремо від task/template; перевірка й генерація не створюють задач; save створює непогоджені шаблони, explicit approval обов'язковий, `own_runnable` не діє на AI marker. Перевірено regression; provenance не переживає ручне копіювання коду адміністратором у зовсім новий немаркований template.
- **F02 — обхідний захист для AI v1:** генератор не використовує raw parameter/secret substitution. Позначені AI action payloads відхиляють `{{`/`{%` перед підстановкою навіть після ручного редагування; template secrets не читаються. Старий механізм у звичайних templates лишається окремою невирішеною задачею.
- **F07 — AI completions:** bounded HTTP reading до JSON parsing, ліміти bundle/source/code/fixture, квоти черги та HTTP timeout. AI scheduler ще не окремий killable worker; slow-drip deadline і Windows `ReadToEndAsync` не закриті повністю. `health()` provider не перебудовувався як частина цього cap.
- **F08 — новий code validator:** Unix socket без fallback, інший UID, no-network/secrets units, fixed parsers, resource limits; submitted скрипти не виконуються. Інші Jinja-save/GPG/web/gateway межі не змінені. Фактичне застосування systemd restrictions на Debian ще треба перевірити.
- **F10 — новий AI UI:** code/explanation/warnings показуються text-only; контраст/overflow перевірено в ізольованому browser fixture. Completion вимикає tools і відхиляє tool calls. Основний report preview та зовнішня конфігурація Open WebUI залишаються окремими перевірками.
- **F01, F03, F04, F06, F09, F11** не виправлено цією реалізацією. До широкого rollout перевірте й закрийте потрібні межі за пріоритетами нижче; перший запуск — лише окремим підтвердженням на canary.

Додаткові перевірки реалізації: server suite — 121 тест, успішно на Windows (6 platform skips) і WSL (1 skip: немає pwsh); native PowerShell parser перевірений на Windows, Bash і standalone worker — у WSL. Builds Windows/Linux/macOS-managed та Unix self-tests пройшли; native macOS signing і Debian deployment не виконувалися. Остаточний перелік перевірок — у результаті задачі/CI, а не доказ відсутності ризиків.

Після цих agent builds у робочому дереві з'явилися паралельні зміни `ProductionSecurity.cs`, Windows/Unix `Worker.cs` і пов'язаних `.csproj`. Вони не входять до підтвердження цих збірок або оцінки F01–F11. Перед спільним commit/release потрібно завершити їхній окремий огляд і повторити відповідні перевірки; цей документ не позначає незавершений паралельний hardening як прийнятий.

Навігація: [поточні межі](#isolation-map) · [правила за технологіями](#technology-rules) · [знайдені прогалини](#findings) · [перевірка production](#production-checks) · [порядок реалізації](#implementation-order).

## Основний принцип: дані не стають командами

- Звіт, prompt, відповідь AI, лист, ім'я хоста, результат агента та імпортований файл — недовірені дані.
- Текст PowerShell/Bash можна зберігати, показувати та передавати як **чернетку**. Це не дає права його виконувати.
- Перетворення чернетки на задачу — окрема авторизована операція з перевіркою користувача, цільових хостів, версії коду та параметрів. Після редагування коду попередні результати перевірки не застосовуються.
- AI не визначає права, не затверджує власний код і не вирішує, куди надсилати секрети. Інструкція в prompt — не механізм ізоляції.
- Підпис задачі підтверджує її походження та цілісність, а не нешкідливість. Синтаксично правильний та підписаний скрипт може видалити дані.
- Безпека не зводиться до blacklist «небезпечних команд»: адміністративні команди часто і є функцією WinHUB. Потрібні мінімальні права, явне підтвердження та обмеження наслідків помилки.
- Недоступна sandbox-служба або помилка перевірки не повинні спричиняти автоматичний запуск у вебпроцесі чи з більшими правами.

<a id="isolation-map"></a>
## Поточні межі ізоляції

| Середовище | Що підтверджено кодом | Межа та залишковий ризик |
| --- | --- | --- |
| Flask / web backend | `User=winhub`, `NoNewPrivileges`, `PrivateTmp`; install/update роблять код root-owned | Доступ до runtime data, БД і ключів потрібен застосунку. Це довірений керівний компонент, не sandbox для скриптів |
| Agent API backend на Debian | Окрема служба `winhub-agent`, scheduler вимкнений | Ті самі `User=winhub`, env і каталоги. Окремий порт/процес не відокремлює секрети від web backend |
| Jinja renderer, `service` | Інший UID `winhub-renderer`, Unix socket, заборона мережі, приховані secrets/data/home, read-only filesystem, CPU/RAM/time/process limits | Наявна сильніша межа ОС; її активність на production ще потрібно підтвердити. Це не VM |
| Jinja renderer, `subprocess` | Окремий Python `-I`, чистіше env, temporary cwd, timeout; POSIX resource limits | Той самий UID і доступні йому файли/мережа. Не еквівалентний `service`; `inprocess` у production заборонено |
| Перевірка Jinja при save/import | Викликає `validate_report_template` у маршруті Flask | AST parsing/compilation ще відбувається у вебпроцесі, хоча фінальний render може бути ізольований |
| AI-звіти | Masking, outbound checks, API key encrypted, відповідь проходить restricted Markdown renderer | AI worker працює в application scheduler. Це не окрема OS sandbox, але отриманий текст зараз не запускається як PowerShell/Python/Bash |
| HTML preview | Allowlist тегів, видалення всіх атрибутів, plain text fallback | Очищений fragment вставляється в DOM WinHUB; окремого sandboxed iframe немає |
| Windows PowerShell tasks | Підпис/доступи, timeout, запуск без профілю, ACL файлів | Штатна служба встановлюється без окремого Credential; очікуваний LocalSystem. Дочірній PowerShell успадковує права; sandbox відсутня |
| Linux Bash tasks | Root service, `PrivateTmp`, `NoNewPrivileges`, локальна execution policy, timeout/output cap | `full` — віддалене root-виконання. `allowlist` фільтрує тип дії, а не кожну команду всередині дозволеного `run_script` |
| macOS Bash tasks | Root LaunchDaemon, локальна execution policy, спільний Unix Worker | Не App Sandbox. Code signing/Hardened Runtime/TCC — додаткові механізми, не ізоляція довільного Bash від системи |
| GPG / вхідні листи | GPG запускається через список аргументів і timeout | GPG дочірній процес має UID вебсервісу, його keyring і успадковане env; окремого parser worker немає |
| PostgreSQL / backups | Окрема БД; runtime files мають обмежені Unix permissions | Runtime DB role є власником БД. Локальні backups належать `winhub`, тобто доступні компрометованому web backend |
| Open WebUI / inference backend | WinHUB використовує звичайні `/api/models` і `/api/chat/completions` | Фактичні користувачі, mounts, tools, functions, GPU/container permissions і egress зовнішнього сервера невідомі |
| AI-редактор/validator | Private drafts, strict contract, Unix socket до `winhub-validator`, no-network/no-secrets units, code hash, approval gate | Статична перевірка не доводить поведінку коду. OS isolation перевірити на deployed Debian; генерація ще в application scheduler |

Джерела: [web unit](../../../WinHUB/deploy/debian/winhub.service), [Agent API unit](../../../WinHUB/deploy/debian/winhub-agent.service), [renderer unit](../../../WinHUB/deploy/debian/winhub-renderer@.service), [renderer client](../../../WinHUB/core/report_renderer_client.py), [Windows Worker](../../../WinHUBAgentWindows/Worker.cs), [Unix Worker](../../../WinHUBLinuxAgent/Worker.cs), [macOS README](../../../WinHUBMacAgent/README.md).

<a id="technology-rules"></a>
## Правила за технологіями

### AI / Open WebUI / модель

- **AI-01.** Для звітів і генерації коду використовувати text-only integration без інструментів виконання. API-ключ окремого неадміністративного service account: тільки потрібна модель та необхідні endpoints. Не передавати цей ключ у браузер.
- **AI-02.** Для integration account/model вимкнути непотрібні Tools, Functions, Pipelines, Terminal, Code Interpreter, MCP та мережевий пошук. Перевіряти також глобальні filters/pipes: відсутність поля `tools` у запиті WinHUB не доводить, що профіль Open WebUI не виконає серверне розширення. Офіційна документація прямо попереджає про виконання Python із правами процесу Open WebUI. [Open WebUI hardening](https://docs.openwebui.com/getting-started/advanced-topics/hardening/).
- **AI-03.** Відокремити Open WebUI/inference від WinHUB: окрема VM або обмежений non-root container; тільки потрібні model/data volumes, без host root/home, Docker socket, SSH keys і WinHUB secrets. Не використовувати privileged container. Для недовіреного реального виконання коду потрібна окрема disposable VM; звичайний container поділяє ядро хоста. [Docker security](https://docs.docker.com/engine/security/).
- **AI-04.** Передавати мінімальний дозволений набір полів після access checks і masking. Не збирати private keys, паролі й tokens «про запас». Masking типових патернів не гарантує знаходження всіх секретів. Для генерації коду використовувати placeholders, а не значення template secrets.
- **AI-05.** Вкладені інструкції в результатах агентів/документах ігноруються як дані. Відповідь AI перевіряється незалежним кодом: schema, типи, довжини, заборона невідомих полів, output format. Не робити `eval`, `exec`, shell dispatch чи імпорт модулів із відповіді.
- **AI-06.** Ліміти потрібні на HTTP body до JSON parsing, час усієї операції, кількість спроб, queue/concurrency, input/output і зберігання revisions. Обмеження числа символів після повного завантаження не захищає RAM від великої відповіді. Великі масиви обробляти порціями з явною позначкою неповноти, а не мовчки обрізати.
- **AI-07.** HTTPS з перевіркою сертифіката. HTTP допускається лише як задокументований виняток із перевіреним захищеним транспортом і мережевими ACL; приватна IP-адреса сама по собі не шифрує API key. Allowlist — точні integration destinations, не вся приватна мережа.
- **AI-08.** Prompt logs, revisions і дані в Open WebUI мають власні retention та ACL. Локальний сервер моделі не означає автоматично «нічого не зберігається» або «немає зовнішніх звернень».

Поточна реалізація: [AI client](../../../WinHUB/core/ai_client.py), [AI reports](../../../WinHUB/core/ai_reports.py), [налаштування інтеграції](../../08-Експлуатація/01-AI-звіти-Open-WebUI.md).

### Python / Jinja / звіти

- **RPT-01.** Вебсервер не виконує користувацький Python. У renderer передається тільки JSON-compatible snapshot потрібних даних — без Flask request/session/config, ORM objects, file handles чи callable objects.
- **RPT-02.** Production render — через `REPORT_RENDERER_MODE=service`, без автоматичного fallback у `subprocess`/`inprocess`. Renderer не входить у групу `winhub` і не має доступу до DB credentials, data, backup, GPG, agent signing keys або мережі.
- **RPT-03.** Зберігати Jinja allowlist: `StrictUndefined`, autoescape, заборона private attributes та `include/import/extends/macro`, тільки явно дозволені filters/calls. Не додавати `safe`, довільні object methods або доступ до Python globals для сумісності шаблона.
- **RPT-04.** `range()` обмежений 4096 елементами; це лише один контроль. Вкладені цикли можуть перемножувати навантаження, тому зберігати CPU/RAM/wall-time/process/output limits. `loop.index0` — дозволене read-only значення, не дозвіл усіх методів LoopContext.
- **RPT-05.** Поточні жорсткі розміри: template 512 KiB, context 8 MiB, rendered output 16 MiB; клієнт додатково обмежує socket request/response. Не підвищувати їх без тесту пікового споживання. Output перевіряється після render, тому зовнішні resource limits залишаються необхідними.
- **RPT-06.** Parsing/validation при save/import також має бути обмежений процесом і часом. Template validation не повинна ставати альтернативним важким обчисленням усередині Flask.

Jinja sandbox не замінює обмеження ресурсів та ОС — це також зазначає [документація Jinja](https://jinja.palletsprojects.com/en/stable/sandbox/). Код: [report_renderer.py](../../../WinHUB/core/report_renderer.py).

### HTML / JavaScript / email / Confluence

- **WEB-01.** Значення хостів, задач, метрик, користувачів та AI показувати через `textContent` або контекстно правильне escaping. Не вставляти їх напряму в `innerHTML`, inline handlers, CSS чи URL.
- **WEB-02.** Форматований звіт — тільки allowlist інертних тегів. Прибирати всі джерельні атрибути, scripts, styles, iframe, forms, objects, SVG/MathML, зовнішні зображення/посилання. Застосовувати server-side sanitizer для доставки; client-side очищення не захищає email чи Confluence.
- **WEB-03.** Додаткова межа для preview — sandboxed iframe без `allow-scripts` і `allow-same-origin`, із забороною зовнішніх ресурсів у його CSP. Це план посилення, не опис поточного preview. Sanitizer при цьому залишається обов'язковим.
- **WEB-04.** Email: formatted HTML після sanitizer + plain-text alternative; GPG шифрує MIME, але не робить HTML безпечним. Confluence: `safe_html` за замовчуванням; `escaped_pre` для текстового показу. Raw `storage_html` — окремий небезпечніший режим, не для автоматичного результату AI.
- **WEB-05.** Ручний, API, scheduled і automatic delivery мають однаково перевіряти доступи, masking, raw-format permission, отримувача і snapshot revision. Право бачити sensitive data не слід автоматично прирівнювати до права публікувати активні Confluence macros.
- **WEB-06.** CSP nonce у `enforce` — додатковий захист, не заміна escaping. Перевіряти malformed/nested HTML у реальному браузері; regex/static source tests не покривають усіх DOM parsing випадків.

Код: [buildSafeReportPreviewFragment](../../../WinHUB/static/js/infrastructure.js), [safe_report_html та delivery routes](../../../WinHUB/modules/Infrastructure/routes.py), [CSP](../../../WinHUB/core/csp.py).

### PowerShell / Bash / агенти

- **EXEC-01.** Розділити «створити», «перевірити», «зберегти», «затвердити» та «запустити». Дозвіл AI-генерації не надає `run_tasks`, admin або доступу до нових host groups.
- **EXEC-02.** Перед dispatch повторно перевіряти роль, групи, allowed action, конкретну revision/approval hash і параметри. Зміна коду скидає approval. Підписувати остаточний payload для конкретного endpoint; перевіряти expiry/replay/sequence згідно з протоколом.
- **EXEC-03.** Не підставляти недовірені значення в текст скрипту без language-aware binding. Новий режим має використовувати типізовані параметри, allowlist значень і передавання даних окремо від коду. У Bash — коректні positional arguments/quoting; у PowerShell — параметри/структуровані дані. JSON сам по собі не захистить, якщо потім вставити його в shell command.
- **EXEC-04.** У `disabled`/`allowlist` Unix-агенти залишаються максимально обмеженими. Дозвіл `run_script` в allowlist фактично відкриває довільний Bash; він не означає allowlist команд. `full` дозволяти тільки адміністраторам відповідних хостів.
- **EXEC-05.** `-NoProfile`, `-NonInteractive`, `UseShellExecute=false`, timeout, `PrivateTmp`, `NoNewPrivileges` і TLS не перетворюють SYSTEM/root-скрипт на sandbox. PowerShell Execution Policy також не є security boundary. [Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6).
- **EXEC-06.** Не запускати пробний AI-код на WinHUB-сервері, контролері домену, production hypervisor чи інших критичних хостах. Функціональні тести — в окремій VM зі snapshot, синтетичними даними, без production credentials та без маршруту до production за замовчуванням.
- **EXEC-07.** Для inventory розвивати окремий малопривілейований runner з read-only доступом. Для адміністрування — вузькі привілейовані операції/broker з перевіркою аргументів. Повна заборона доступу до основної ОС несумісна з задачею її адмініструвати; це мають бути різні режими.
- **EXEC-08.** Обмежувати stdout/stderr під час читання, CPU/RAM, диск, час і дочірні процеси; завершувати все дерево та прибирати temporary artifacts. Обрізання готового великого рядка не обмежує витрати пам'яті до цього моменту.
- **EXEC-09.** Ніколи не вкладати agent identity/signing/bootstrap secrets у скрипт або AI-контекст. Скрипт із root/SYSTEM правами потенційно може прочитати локальний стан агента: ACL не відокремлює його від власного UID агента. Для сильнішої межі потрібне розділення privileged broker / runner.

### Майбутній AI-редактор та validator

Це вимоги до нового функціоналу, який ще не реалізований.

1. AI повертає структуровану чернетку: мова, код, параметри, очікувана output schema, пояснення ризиків і за потреби report template. Зберігати її окремо від runnable `TaskTemplate`.
2. Перевірку виконує нова короткоживуча служба/контейнер без root, мережі, БД, provider key, agent keys, runtime data, Docker socket або writable source checkout. Root filesystem read-only; тільки обмежений scratch-каталог; CPU/RAM/PID/time/input/output quotas.
3. PowerShell: parser + перевірені PSScriptAnalyzer rules. Не виконувати згенерований `.ps1`, не dot-source його, не завантажувати запропоновані AI modules/custom rules/configuration.
4. Bash: syntax check + ShellCheck з фіксованими аргументами; мінімальне env без `BASH_ENV`, `ENV`, профілів і користувацьких startup/config files. Parser/linter також обробляє недовірені дані, отже потребує sandbox.
5. Jinja: наявний обмежений renderer на synthetic JSON fixture. Не послаблювати його `NPROC`/network restrictions заради PowerShell: validator має інший профіль і окрему службу.
6. Результати розділяти: «синтаксис перевірено», «статичні зауваження», «не перевірено функціонально». Не показувати зелений напис «код безпечний» лише за висновком моделі або linter.
7. Кнопка «Застосувати в редакторі» показує diff і не запускає задачу. Збереження та запуск лишаються окремими діями; тестовий запуск дозволяється лише на явно вибраній тестовій групі.
8. Перевірки прив'язувати до hash коду, параметричної схеми, версії validator і ruleset. Будь-яка зміна скидає попередній статус. Retry не запускає скрипт і не створює дубль задачі.

### Flask / systemd / мережа / інтеграції

- **SYS-01.** Production source і venv належать root, вебкористувачу дозволене тільки читання/виконання. Runtime data, logs і secrets відокремлені від release; вебсервіс не має sudo, Docker group/socket або права змінювати units.
- **SYS-02.** `ProtectSystem=full` не дорівнює повністю read-only ОС. Після перевірки сумісності перейти на `strict` із точними writable paths, `ProtectHome`, обмеженнями capabilities/devices/kernel/process visibility та resource quotas. Не копіювати no-network профіль renderer на web backend: йому потрібні БД та дозволені інтеграції. Значення директив звіряти з [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).
- **SYS-03.** Окремі OS identities та мінімальні credentials для gateway, AI worker і GPG/inbound worker — цільова модель. Просте винесення в process під тим самим UID з усім env не відокремлює доступи.
- **NET-01.** Nginx — зовнішній вхід; backend, PostgreSQL і Redis не виставляти в загальну мережу. Розділяти browser/admin plane та endpoint plane; CSRF, server-side permissions і rate limits залишаються обов'язковими.
- **NET-02.** `OUTBOUND_POLICY_MODE=enforce` плюс точний непорожній `OUTBOUND_ALLOWED_HOSTS`. У поточному коді порожній список у enforce блокує не всі destinations: публічні адреси загалом дозволяються. `audit` лише журналює і не вмикає DNS pinning.
- **NET-03.** Додати мережевий egress control за адресами **і портами**. Application host allowlist не є firewall і не обмежує довільну мережу скомпрометованого процесу. Credentials не пересилати через redirects; env proxy не повинен обходити policy.
- **INT-01.** SMTP/IMAP/LDAP/Confluence/GPG fetch — перевірений TLS, вузькі service accounts, allowlisted destinations, caps до parsing, timeout і контроль одержувача. Отриманий email/PGP/JSON не стає програмою.
- **INT-02.** GPG import/decrypt перенести в worker із мінімальним env, окремим keyring і обмеженими файлами/ресурсами. Не успадковувати весь server env. Decryption саме по собі не підтверджує відправника; authorization/signature checks — окремий рівень для mail-triggered дій.

### PostgreSQL / secrets / backups / update

- **DATA-01.** Runtime DB role: тільки потрібні DML/sequence permissions, без superuser/role creation/schema ownership. Окрема migration role доступна лише deploy workflow. Перед застосуванням перевірити startup/create-all та міграції; це не безпечний one-line change на живій БД.
- **DATA-02.** Зашифровані secrets і ключі розшифрування не доступні validator/renderer/model server. Шифрування at rest не захищає від процесу, який має право розшифровувати ці значення.
- **DATA-03.** Backups — поза writable областю вебсервісу, власник root/окремий backup account. Усі батьківські каталоги також захищені від rename/delete вебкористувачем. Потрібна encrypted off-host/immutable копія та окремі credentials. Backup у тій самій VM не захищає від root-компрометації чи втрати VM.
- **DATA-04.** Restore приймає лише довірені artifacts. SHA-256 поруч із writable архівом виявляє випадкове пошкодження, але не підміну обох файлів. Перевіряти provenance/manifest, archive paths/links, права і контрольоване відновлення на тестовій системі.
- **DEP-01.** Не встановлювати залежності або plugins, запропоновані AI, на production автоматично. Перевірені версії/артефакти, контроль supply chain, окреме build environment без production secrets.
- **DEP-02.** Нові runtime workers включати через server packaging allowlist; units створюють потрібних користувачів і права. Update робить backup до заміни коду, не ротує робочі secrets і виконує healthcheck. Hardening не вмикати «наосліп» без перевірки сумісності та плану rollback.

<a id="findings"></a>
## Знайдені прогалини та пріоритети

P1 — виправити в першу чергу / до розширення доступу або AI-виконання; P2 — заплановане посилення. Це оцінка коду, не підтвердження експлуатації на production. Немає підстав стверджувати, що систему вже скомпрометовано.

### F01 · P1 · Backup довіряє тому самому користувачу, що й web

[backup_winhub.sh](../../../WinHUB/deploy/debian/backup_winhub.sh) робить `chown ... winhub:winhub` для backup root і створеної копії. [update](../../../WinHUB/deploy/debian/update_winhub.sh) та [restore](../../../WinHUB/deploy/debian/restore_winhub.sh) також рекурсивно віддають `/var/lib/winhub` цьому користувачу. Компрометація web дозволяє пошкодити локальні backups. Restore від root довіряє їхнім коду, requirements і service files; перевірки `SHA256SUMS` перед відновленням у цьому скрипті немає.

Дія: окреме backup сховище поза app-writable деревом; узгодити install/update/backup/restore, довіру до manifest і off-host копію. Одного `chmod` усередині `/var/lib/winhub/backups` недостатньо, якщо батьківський каталог можна змінювати.

### F02 · P1 · Параметри змішуються з виконавчим кодом

`apply_template_variables` у [routes.py](../../../WinHUB/modules/Infrastructure/routes.py) вставляє scalar values без PowerShell/Bash binding. Ліміти довжини та перевірка NUL/CR не прибирають метасимволи мови. При запуску під високими правами недовірене значення може змінити сенс затвердженого скрипту.

Дія: новий typed/bound parameter mode, regression tests для лапок, newline, shell metacharacters і Windows/UNC paths; міграція legacy templates з перевіркою сумісності. Схвалення template hash не є перевіркою довільних значень параметрів.

### F03 · P1 · Не всі UI-поля проходять escaping

У [infrastructure.js](../../../WinHUB/static/js/infrastructure.js), побудова `mHistory`, `h.title` та `h.by` вставляються в `innerHTML` без `escapeHtml`. Host details API у [routes.py](../../../WinHUB/modules/Infrastructure/routes.py) повертає ці поля з БД. Це небезпечний шлях для stored HTML/XSS у браузері користувача, який відкриє історію; вплив залежить також від активної CSP. Виконання payload у production не перевірялося.

Дія: text nodes/contextual escaping на цьому та аналогічних шляхах; browser regression для збережених task titles. Поточний safe report preview не захищає сусідні UI-компоненти.

### F04 · P1 · Automatic Confluence обходить окрему raw-format перевірку

Ручний `publish_report_confluence` в [routes.py](../../../WinHUB/modules/Infrastructure/routes.py) вимагає sensitive access для `storage_html`. Натомість create/API-run зберігають `__auto_confluence_body_format` після перевірки `send_reports`, а `perform_auto_confluence_publish` приймає raw mode без еквівалентної перевірки та використовує `report.report_data` напряму.

Дія: спільна delivery policy для всіх шляхів; raw mode заборонити для AI й auto-delivery або вимагати окремого явного дозволу, перевіреного при виконанні. Окремо узгодити masking та збереження actor permissions для background jobs. Це не твердження, що будь-який Confluence гарантовано виконає JavaScript; проблема — обхід WinHUB sanitization/access boundary.

### F05 · P1 для AI-функціоналу · Генерацію не можна одразу робити runnable

У `create_task` є дозволений сценарій `own_runnable`: інтерактивний автор із `manage_templates` може запускати власний незатверджений template. Тому автоматичне збереження AI-відповіді як `TaskTemplate` не дає гарантованого approval gate. Windows та Unix full-mode execution не ізольовані від керованої ОС.

Дія: окремі AI drafts, незалежні validate/apply/save/run permissions, тестова група хостів і явна політика approval для AI-коду. Переглянути всі dispatch paths, не лише нову кнопку редактора.

### F06 · P1, якщо лишився legacy mode · Підтвердити renderer service

[config.py](../../../WinHUB/core/config.py) за відсутності налаштування обирає `subprocess`; [update_winhub.sh](../../../WinHUB/deploy/debian/update_winhub.sh) не примушує старе значення перейти на service. Socket може бути active, але запити продовжуватимуть використовувати subprocess.

Дія: перевірити effective config і реальний render через socket. Якщо service уже активний, це не невиправлена вада інсталяції — лише необхідна перевірка. [Контрольований cutover](SECURITY_HARDENING_V3_UA.md).

### F07 · P2 · Ліміти застосовуються запізно

[ai_client.py](../../../WinHUB/core/ai_client.py) завантажує HTTP-відповідь і робить `.json()` до `AI_MAX_OUTPUT_BYTES`; [Windows Worker](../../../WinHUBAgentWindows/Worker.cs) використовує `ReadToEndAsync`, а обрізає лог після читання. Великий результат може вичерпати RAM раніше. Timeout не обмежує обсяг отриманих даних.

Дія: bounded streaming до parsing, hard deadline, bounded output capture, окремі resource quotas; тести великого/повільного output. Для AI generation — обов'язково до відкриття функції широкому колу користувачів.

### F08 · P2 · Додаткові parser/worker межі

`validate_report_template_payload` у [routes.py](../../../WinHUB/modules/Infrastructure/routes.py) парсить Jinja у Flask; [AI scheduler](../../../WinHUB/core/__init__.py) працює в app context; [gpg_env](../../../WinHUB/core/gpg.py) копіює весь `os.environ` для GPG. [web](../../../WinHUB/deploy/debian/winhub.service) і [gateway](../../../WinHUB/deploy/debian/winhub-agent.service) мають однаковий UID/credentials і обмежений systemd hardening.

Дія: ізолювати Jinja validation та майбутній code validator; винести GPG/inbound parsing; окремо спроєктувати AI/gateway identities з мінімальними credentials. Не кожній фоновій задачі потрібна VM, але процес, який парсить недовірене, не повинен без потреби бачити всі ключі сервера.

### F09 · P2 · DB role та egress ще не є вузькими межами

[install_debian.sh](../../../WinHUB/deploy/debian/install_debian.sh) створює БД з owner `winhub`; ті самі налаштування БД використовують runtime і [міграції](../../../WinHUB/deploy/debian/migrate_winhub.sh). [outbound_security.py](../../../WinHUB/core/outbound_security.py) має host allowlist, але не окремий OS/network egress policy за портами.

Дія: migration/runtime DB roles, точний integration allowlist, firewall/segmentation для сервісних ролей; перевірити фактичні grants/режими на сервері. Fresh installer встановлює strict modes, але приклад env і старий config можуть мати `audit`/`report-only`.

### F10 · P2 · Preview та Open WebUI потребують окремої перевірки

Preview очищується, але живе в основному DOM; sandboxed iframe — додатковий захист. Конфігурація зовнішнього Open WebUI не міститься в перевіреному checkout, тому його tools/mounts/egress не можна вважати ізольованими без перевірки.

Дія: browser tests і sandboxed preview; read-only аудит Open WebUI deployment та прав service account до AI-редактора. Не встановлювати сторонні Tools/Functions як спосіб «просто перевірити код».

### F11 · P2 · Security smoke test не узгоджений із clean release

[security_smoke_test.sh](../../../WinHUB/deploy/debian/security_smoke_test.sh) запускає `tests.test_security_foundation` з installed app, але [server-files.txt](../../../WinHUB/deploy/server-files.txt) не включає `tests/`. На чистому пакеті ця частина перевірки не має потрібного модуля. Також HTTPS probe у скрипті використовує `curl -k`, отже не підтверджує довіру до TLS certificate.

Дія: розділити CI regression suite і самодостатній production smoke probe, включений у runtime allowlist; окремий TLS probe з trusted CA. Не вимикати TLS verification у production clients і не копіювати весь checkout в `/opt/winhub` заради тестів.

<a id="production-checks"></a>
## Як підтвердити стан на production

Нижче read-only checks для адміністратора Debian; вони не перемикають режими й не перезапускають служби. Не публікуйте повний `env`, `systemctl show Environment`, Docker inspect або файли конфігурації з ключами.

```bash
sudo systemctl is-active winhub winhub-renderer.socket
sudo systemctl show winhub.service \
  -p User -p Group -p ProtectSystem -p ProtectHome -p NoNewPrivileges \
  -p ReadWritePaths -p PrivateNetwork -p MemoryMax -p TasksMax
sudo systemctl cat winhub-renderer.socket winhub-renderer@.service
id winhub-renderer
sudo stat -c '%U:%G %a %n' /opt/winhub /opt/winhub/core/report_renderer.py \
  /etc/winhub /var/lib/winhub /var/lib/winhub/backups /run/winhub-renderer.sock
sudo runuser -u winhub-renderer -- test -r /etc/winhub/winhub.env
echo "renderer env read exit code: $? (очікується 1)"
sudo runuser -u winhub-renderer -- test -x /var/lib/winhub
echo "renderer data traverse exit code: $? (очікується 1)"
sudo awk -F= '$1 ~ /^(REPORT_RENDERER_MODE|OUTBOUND_POLICY_MODE|CSP_MODE|CSP_NONCE_MODE|AI_ALLOW_INSECURE_HTTP)$/ {print $1 "=" $2}' /etc/winhub/winhub.env
```

Команди `test` з очікуваним exit code 1 виконувати в інтерактивному shell без `set -e`. Помилка запуску `sudo/runuser` або відсутній файл не означає успішної ізоляції. `systemctl cat` перевіряти локально: custom overrides можуть містити секрети. Не надсилати їх без редагування.

Файл env показує конфіг на диску, не доводить, що процес перечитав його. Після звірки потрібно виконати звичайний нешкідливий render через WinHUB і перевірити фактичне використання renderer socket/instance. `systemd-analyze security` корисний для огляду unit restrictions, але його оцінка не є penetration test.

Додатково перевірити локально:

- власника і writable permissions **усього шляху** backup, а також наявність off-host копії;
- runtime PostgreSQL role attributes/grants без показу паролів;
- `OUTBOUND_ALLOWED_HOSTS`, firewall destinations/ports і фактичні CSP response headers;
- Windows `Win32_Service.StartName` для WinHUBAgent; Linux/macOS execution policy і права служби;
- Open WebUI: користувача контейнера/служби, privileged/capabilities, volumes/socket mounts, tools/functions/pipelines, права integration account, TLS і доступ до model backend;
- чи не має test runner маршруту, облікових даних або host mounts до production.

Наявний security smoke script запускати з урахуванням F11. Не використовувати його успіх або відсутність тестів як заміну перевірці живих меж.

## Перевірки початкового аудиту (до AI-редактора)

Із `WinHUB/` виконано `python -m unittest discover -s tests -v` у локальному Python environment: **100 тестів, 96 успішних, 4 пропущені** (distribution потребує Linux/WSL, Bash, GNU tar, rsync). Успішні security/AI tests включають Jinja restrictions, HTML escaping, safe delivery, masking, approval hash і outbound DNS pinning. Частина перевіряє код/fixtures, а не живий браузер чи systemd.

Не виконувалися Debian install/update/restore, реальні запити до Open WebUI, виконання нових скриптів на endpoint-ах, agent builds та перевірка container isolation. Проходження наявних тестів не закриває F01–F11: для виправлень потрібні окремі regressions.

<a id="implementation-order"></a>
## Порядок реалізації та критерії приймання

1. **Закрити наявні шляхи обходу:** F02–F04, перевірити F06. Приймання: malicious-looking параметри лишаються даними; task titles не створюють активний DOM; auto/API/manual delivery однаково відхиляють недозволений raw mode; реальні renders використовують service.
2. **Відокремити recovery:** F01. Приймання: `winhub` не може змінити, видалити чи підмінити backup/manifest/батьківський каталог; restore з довіреної off-host копії перевірений на тестовій VM.
3. **Побудувати AI draft + validator:** F05, F07, потрібні частини F08/F10. Приймання: generate/validate не створюють `AgentTask`, не мають production secrets/мережі; invalid/oversized/timeout результат не застосовується; права перевірені для всіх ролей та API.
4. **Посилити service boundaries:** решта F07–F11. Приймання: runtime role не робить DDL; workers бачать тільки потрібні secrets; egress блокує невідомі адреси/порти; clean release має самодостатній smoke test.
5. **Лише потім функціональні AI-тести на хостах:** explicit canary run у disposable VM, перевірка змін і журналу; production rollout окремим підтвердженням. Масовий запуск або natural-language administration — інший рівень ризику, не прихована можливість генератора шаблонів.

Для кожного винятку з правил записувати причину, область доступу, відповідального, компенсувальні обмеження, строк перегляду та спосіб повернення до strict mode. Статус знахідки оновлювати лише після code review і відповідної перевірки, а не після додавання опису в Wiki.
