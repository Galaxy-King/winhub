# Endpoint Management: інструкція користувача

Модуль `Endpoint Management` у WinHUB призначений для централізованого керування endpoint-вузлами, агентами, групами, виконанням задач, шаблонами, звітами, програмним забезпеченням та автоматизацією.

У коді модуль має технічний ідентифікатор `Infrastructure`, але в інтерфейсі відображається як `Endpoint Management`.

## 1. Вхід до модуля

Відкрийте WinHUB і перейдіть до модуля `Endpoint Management` через бокове меню або напряму за адресою:

```text
/module/infrastructure
```

У верхній частині модуля є групи меню:

| Меню | Основні вкладки |
| --- | --- |
| `Infrastructure` | `Nodes`, `Groups` |
| `Operations` | `Deploy`, `Queue`, `Reports`, `Software` |
| `Automation` | `Scheduler`, `Triggers` |
| `Administration` | Налаштування, доступні користувачам із розширеними правами |

Якщо певної вкладки або кнопки немає, ваш обліковий запис не має відповідного дозволу.

## 2. Права доступу

### Базові права

| Дозвіл | Що дозволяє |
| --- | --- |
| `View` | Переглядати вузли, групи, чергу задач і звіти |
| `Change` | Запускати задачі, редагувати звіти, керувати шаблонами, SMTP, scheduler, triggers, групами та software |
| `Delete` | Видаляти звіти, чистити історію задач, блокувати або видаляти вузли |

### Детальні права

| Дозвіл | Призначення |
| --- | --- |
| `view_hosts` | Перегляд вузлів |
| `view_groups` | Перегляд груп |
| `view_queue` | Перегляд черги задач |
| `view_reports` | Перегляд звітів |
| `view_sensitive_reports` | Перегляд незамаскованих sensitive-значень у звітах |
| `edit_reports` | Редагування тексту звітів |
| `dismiss_reports` | Приховування або закриття звітів |
| `delete_reports` | Видалення звітів |
| `run_tasks` | Запуск затверджених шаблонів |
| `manage_software` | Керування пакетами ПЗ |
| `send_reports` | Відправка звітів email-повідомленням |
| `manage_templates` | Створення, редагування, імпорт та експорт шаблонів |
| `manage_smtp` | Керування SMTP-профілями для email-звітів |
| `manage_scheduler` | Керування розкладом автоматичних задач |
| `manage_triggers` | Керування trigger-правилами |
| `manage_hosts` | Approve, reject, block, unblock або delete вузлів |
| `manage_groups` | Створення, редагування та видалення груп |
| `cleanup_tasks` | Очищення історії задач |

## 3. Nodes

Вкладка `Nodes` показує endpoint-вузли, які підключилися до WinHUB через агент.

### Що видно у `Nodes`

| Поле | Значення |
| --- | --- |
| `Total` | Загальна кількість вузлів |
| `Online` | Вузли, які нещодавно надсилали heartbeat |
| `Signed` | Вузли з enrolled identity key |
| `Pending` | Вузли, що очікують підтвердження |
| `Outdated` | Вузли зі старою версією агента |

### Стани вузлів

| Стан | Пояснення |
| --- | --- |
| `Approved` | Вузол дозволений для роботи |
| `Pending` | Вузол зареєстрований, але очікує перевірки |
| `Rejected` | Вузол відхилений |
| `Blocked` | Вузол заблокований адміністратором |
| `Live` | Агент нещодавно виходив на зв'язок |
| `Passive` | Агент давно не надсилав heartbeat |

## 4. Review Center

`Review Center` доступний користувачам із правом `manage_hosts`. Він використовується для контролю нових, відхилених і потенційно дубльованих агентів.

### Pending Approval

Тут відображаються нові агенти, які очікують рішення.

Щоб підтвердити один вузол:

1. Відкрийте `Nodes`.
2. Перейдіть у `Review Center`.
3. Відкрийте вкладку `Pending Approval`.
4. Натисніть `Review`, щоб перевірити деталі.
5. Натисніть `Approve` або `Reject`.

Щоб підтвердити кілька вузлів:

1. Позначте потрібні checkbox-и.
2. Натисніть `Approve Selected`.

Щоб підтвердити всі pending-вузли:

1. Натисніть `Approve All Pending`.
2. Підтвердьте дію.

### Identity Duplicates

Вкладка `Identity Duplicates` показує approved-вузли, які можуть бути записами одного й того самого endpoint-а.

Щоб об'єднати дублікати:

1. Перевірте обидва записи.
2. Виберіть запис, який потрібно залишити.
3. Натисніть `Keep First` або `Keep Second`.
4. Підтвердьте merge.

Після merge групи, історія, telemetry і задачі з видаленого запису переносяться до запису, який залишився.

### Rejected Hosts

У `Rejected Hosts` можна:

- повернути вузол у `Pending`;
- затвердити вузол через `Approve`;
- видалити rejected-запис через `Delete`;
- виконати bulk-дії через `Approve Selected` або `Delete Selected`.

## 5. Host Details

Натисніть на вузол у `Nodes`, щоб відкрити `Host Details`.

### Information & Actions

У вкладці `Information & Actions` відображається:

- hostname;
- display name;
- endpoint ID;
- connection IP;
- OS;
- agent version;
- agent key status;
- last pulse;
- approval status;
- access status;
- network interfaces;
- host inventory;
- security state;
- group membership.

Якщо у вас є `manage_hosts`, доступні дії:

| Кнопка | Дія |
| --- | --- |
| `Edit Name` | Змінити display name вузла |
| `Approve Host` | Підтвердити вузол |
| `Reject Host` | Відхилити вузол |
| `Block Host` / `Unblock Host` | Заблокувати або розблокувати вузол |
| `Delete Record` | Видалити запис endpoint-а |

### Custom Items

`Custom Items` показує останні значення, зібрані `Metric Item` шаблонами.

Приклади:

- статус служби;
- кількість вільного місця;
- версія локального компонента;
- будь-який інший результат, який повертає metric-script.

### Task History

`Task History` показує задачі, які виконувалися на цьому вузлі. Натисніть на запис, щоб відкрити terminal log.

### Telemetry (RMM)

`Telemetry (RMM)` показує:

- resource usage trends;
- disk free space;
- agent activity timeline;
- online/offline періоди;
- connection IP history.

Доступні фільтри:

- `1 Day`;
- `7 Days`;
- `30 Days`.

## 6. Groups

Вкладка `Groups` використовується для логічного об'єднання endpoint-вузлів.

Групи потрібні для:

- обмеження доступу користувачів;
- запуску задач на набір вузлів;
- software rollout;
- scheduler jobs;
- trigger rules;
- bulk block/unblock.

### Як створити групу

1. Відкрийте `Groups`.
2. Натисніть `Create Group`.
3. Заповніть `Group Name`.
4. За потреби додайте `Description`.
5. Натисніть `Create`.

### Як додати вузли до групи

1. Відкрийте потрібну групу.
2. Натисніть `Add Hosts`.
3. Знайдіть потрібні вузли через search.
4. Позначте вузли checkbox-ами.
5. Натисніть `Add Selected`.

### Дії з групою

| Кнопка | Дія |
| --- | --- |
| `Block` | Заблокувати всі вузли групи |
| `Unblock` | Розблокувати всі вузли групи |
| `Add Hosts` | Додати вузли до групи |
| `Delete Group` | Видалити групу |
| `Remove` | Видалити вузол із групи |

## 7. Deploy

Вкладка `Deploy` використовується для створення шаблонів і запуску задач на endpoint-вузлах.

### Template Library

Ліва панель `Template Library` містить шаблони, згруповані за категоріями.

Типи шаблонів:

| Тип | Призначення |
| --- | --- |
| `Action Script` | Виконує команду або скрипт на endpoint-ах |
| `Metric Item` | Виконує скрипт і зберігає результат як metric/custom item |
| `Report Template` | Формує агрегований report після виконання задач |

### Як запустити готовий шаблон

1. Відкрийте `Deploy`.
2. У `Template Library` виберіть потрібний шаблон.
3. У блоці `Target Selection` виберіть `Specific Endpoints` або `Endpoint Group`.
4. Якщо вибрано `Specific Endpoints`, натисніть `Click to select hosts`.
5. Виберіть вузли вручну або вставте hostname/IP у `Bulk Add`.
6. Заповніть variables, якщо шаблон їх вимагає.
7. За потреби виберіть `Post-Execution` report template.
8. Натисніть `Execute Task`.
9. Перевірте виконання у `Queue`.

### Як створити шаблон

Потрібне право `manage_templates`.

1. Відкрийте `Deploy`.
2. Натисніть `New Template`.
3. Заповніть `Display Name`.
4. Вкажіть `Category Group`.
5. Виберіть тип: `Action Script`, `Metric Item` або `Report Template`.
6. Додайте код у редактор.
7. За потреби додайте variables або secrets.
8. Увімкніть `Share with Team`, якщо шаблон має бути доступний іншим користувачам.
9. Натисніть `Save Template`.

### Variables і secrets

У шаблонах можна використовувати variables:

```text
{{variable_name}}
```

Також можна використовувати secrets із `Template Secrets`:

```text
{{secret:name}}
```

Secrets зберігаються зашифрованими і підставляються тільки під час dispatch задачі.

### Import / Export

Користувач із `manage_templates` може:

- експортувати один шаблон;
- експортувати набір шаблонів;
- імпортувати шаблони з JSON-файлу;
- керувати категоріями через `Manage Categories`;
- керувати secrets через `Manage Template Secrets`.

## 8. Queue

Вкладка `Queue` показує live-чергу задач і batch-job-и.

### Що можна робити в Queue

| Дія | Опис |
| --- | --- |
| Search | Шукати за job title, target або status |
| `All Tasks` | Показати всі задачі |
| `Manual` | Показати задачі, запущені вручну |
| `Auto (Scheduler)` | Показати задачі з scheduler |
| `Auto-Fix (Trigger)` | Показати задачі, запущені trigger-ом |
| `View Log` | Відкрити terminal log конкретної задачі |
| `Retry failed hosts` | Повторити запуск для failed-вузлів |
| `Cancel pending/running hosts` | Скасувати pending/running задачі |
| `Finalize Report` | Завершити report без очікування active hosts |
| `Delete job` | Видалити job з історії |

### Clean History

Якщо є право `cleanup_tasks`, можна очистити історію:

- older than `7 days`;
- older than `1 month`;
- older than `2 months`.

## 9. Reports

Вкладка `Reports` містить агреговані результати, сформовані після виконання задач.

### Доступні дії

| Кнопка | Право | Дія |
| --- | --- | --- |
| `Save Changes` | `edit_reports` | Зберегти змінений текст report-а |
| `Dismiss` | `dismiss_reports` | Приховати або закрити report |
| `Delete Report` | `delete_reports` | Видалити report |
| `Send to Email` | `send_reports` | Відправити report поштою |

### Sensitive values

Якщо report містить passwords, tokens або secrets, WinHUB може маскувати їх у UI.

Повні значення бачать тільки користувачі з правом:

```text
view_sensitive_reports
```

### Send Secure Report

Для email-відправки report-а:

1. Відкрийте report.
2. Натисніть `Send to Email`.
3. Виберіть `Sender Profile`.
4. Заповніть `Email Subject`.
5. Вкажіть `Recipients`.
6. За потреби додайте `Custom Note`.
7. Залиште `Encrypt Email (PGP/GPG)` увімкненим, якщо потрібне шифрування.
8. Натисніть `Send Securely`.

Для керування sender-профілями потрібне право `manage_smtp`.

## 10. Software

Вкладка `Software` використовується для бібліотеки пакетів, install/uninstall рецептів і запуску software actions на endpoint-вузлах.

### Package Library

У `Package Library` можна:

- шукати пакет за name, vendor або version;
- відкривати категорії пакетів;
- вибирати пакет для встановлення або видалення;
- запускати дію на checked nodes або на group.

### Як встановити пакет

1. Відкрийте `Software`.
2. Перейдіть у `Package Library`.
3. Виберіть пакет.
4. У `Run Software Action` виберіть `Install`.
5. Виберіть scope:
   - `Install for all users / machine-wide`;
   - `Install for specific users`.
6. Якщо вибрано specific users, введіть логіни у `User logins`.
7. Виберіть target mode:
   - `Checked nodes`;
   - `Selected group`.
8. Виберіть вузли або групу.
9. Натисніть `Install Selected Package`.
10. Перевірте виконання у `Queue`.

### Як видалити пакет

1. Виберіть пакет у `Package Library`.
2. У `Run Software Action` виберіть `Uninstall`.
3. Виберіть target nodes або group.
4. Натисніть кнопку запуску.
5. Перевірте результат у `Queue`.

### Add Package

Потрібне право `manage_software`.

Під час створення пакета вказуються:

| Поле | Призначення |
| --- | --- |
| Name / Version / Vendor | Ідентифікація пакета |
| Category / Group | Де пакет буде показаний у library |
| Package type | Тип installer-а або архіву |
| Architecture | x64, x86, ARM64 або any |
| File | Installer, який завантажується у WinHUB |
| External URL | Посилання на зовнішній repository |
| SHA256 | Контроль цілісності файлу |
| Install command | Команда встановлення |
| Specific users install command | Команда для user-scoped install |
| Uninstall command | Команда видалення |
| Detection type / value | Як перевіряти, що ПЗ встановлено |
| Expected exit codes | Успішні exit codes, зазвичай `0,3010` |

### Recipe variables

У install/uninstall recipes доступні:

```text
{file}
{extract_dir}
{package_dir}
{users}
{name}
{version}
```

## 11. Scheduler

`Automation Scheduler` запускає задачі автоматично за розкладом. Час у UI вказаний як `Kyiv Time`.

### Як створити schedule

1. Відкрийте `Scheduler`.
2. Натисніть `New Schedule`.
3. Заповніть `Job Name`.
4. Вкажіть `Category`.
5. Виберіть `Script Template`.
6. Виберіть `Target Type`:
   - `Target Group`;
   - `Specific Endpoint`.
7. Виберіть target.
8. У `Execution Timing (Kyiv Time)` виберіть:
   - `Execute Once`;
   - `Recurring Weekly`.
9. Вкажіть дату, час або дні тижня.
10. Залиште `Enable this schedule immediately`, якщо schedule має запрацювати одразу.
11. Натисніть `Save Schedule`.

### Дії зі schedule

| Кнопка | Дія |
| --- | --- |
| `Edit` | Змінити schedule |
| Delete icon | Видалити schedule |
| `Enable this schedule immediately` | Активувати або деактивувати schedule |

## 12. Triggers

`Automation Triggers` запускають auto-remediation на основі metric values.

Trigger працює за логікою:

```text
IF metric condition is true
THEN run action script
```

### Як створити trigger

1. Відкрийте `Triggers`.
2. Натисніть `New Trigger`.
3. Заповніть `Trigger Name`.
4. Виберіть `Target Group`.
5. У блоці `Condition (IF)` виберіть `Metric / Item Name`.
6. Виберіть `Operator`.
7. Вкажіть `Value`.
8. У блоці `Reaction (THEN)` виберіть `Run Action Script`.
9. Залиште `Enable this trigger` увімкненим, якщо правило має працювати одразу.
10. Натисніть `Save Trigger`.

### Operators

| Operator | Значення |
| --- | --- |
| `==` | Дорівнює |
| `!=` | Не дорівнює |
| `>` | Більше |
| `<` | Менше |
| `contains` | Містить текст |

### Приклад

| Поле | Значення |
| --- | --- |
| Metric | `Spooler Status` |
| Operator | `==` |
| Value | `Stopped` |
| Action | `Start Spooler` |

Такий trigger запустить action script, якщо metric item поверне значення `Stopped`.

## 13. Agent Updates

Оновлення агентів зазвичай виконується через template/action або спеціальний agent update workflow, якщо він налаштований у бібліотеці шаблонів.

Перед rollout перевірте:

- чи є актуальний agent package для потрібної платформи;
- чи endpoint-и online;
- чи target group правильна;
- чи є rollback-план;
- чи не запускається оновлення одночасно з критичними задачами.

Після запуску перевіряйте `Queue` і поле `Agent` у `Nodes`.

## 14. Рекомендований робочий процес

1. Агент встановлюється на endpoint і реєструється у WinHUB.
2. Адміністратор перевіряє endpoint у `Review Center`.
3. Endpoint отримує статус `Approved`.
4. Адміністратор додає endpoint до потрібної групи.
5. Оператор запускає готовий template через `Deploy` або software action через `Software`.
6. Виконання контролюється у `Queue`.
7. Результати переглядаються у `Reports`, `Task History` або `Custom Items`.
8. Регулярні задачі переносяться у `Scheduler`.
9. Auto-remediation налаштовується через `Triggers`.

## 15. Типові проблеми

### Вузол не з'являється у `Nodes`

Перевірте:

- чи встановлений і запущений агент;
- чи правильний `ServerUrl` у конфігурації агента;
- чи endpoint має доступ до WinHUB;
- чи немає TLS або certificate pinning помилок;
- чи агент не заблокований firewall-ом.

### Вузол у `Pending`, але задачі не запускаються

Вузол потрібно підтвердити через `Approve`. Pending або Rejected вузли не повинні використовуватися для production-задач.

### Вузол показується як `Passive`

Можливі причини:

- агент не працює;
- endpoint вимкнений;
- endpoint не має мережевого доступу до WinHUB;
- агент не може пройти TLS/API перевірку;
- heartbeat давно не надходив.

### Задача зависла у `Pending`

Перевірте:

- чи endpoint online;
- чи агент polling працює;
- чи target не заблокований;
- чи задача не очікує на agent update або іншу довгу операцію.

### Задача завершилася `Error`

Відкрийте `Queue`, натисніть `View Log` і перевірте:

- exit code;
- stderr/stdout;
- права запуску;
- доступність файлів;
- коректність variables і secrets;
- сумісність скрипта з ОС endpoint-а.

### Report не містить очікуваних даних

Перевірте:

- чи завершилися всі target tasks;
- чи action script повернув коректний output;
- чи report template правильно обробляє `results`;
- чи sensitive data не замасковані через відсутність `view_sensitive_reports`.

### Software install пропущено

Якщо detection rule вже показує, що ПЗ встановлено, задача може пропустити install. Перевірте `Detection type` і `Detection value`.

## 16. Практичні поради

- Створюйте групи за логікою доступу або rollout-у: `Accounting`, `Terminals`, `Servers`, `Pilot`, `Production`.
- Спочатку тестуйте шаблони на 1-2 endpoint-ах.
- Для production-операцій використовуйте `Endpoint Group`, а не ручний список, якщо група вже підтримується в актуальному стані.
- Для небезпечних дій робіть templates private draft, доки вони не перевірені.
- Не використовуйте interactive prompts у скриптах.
- Для Windows scripts орієнтуйтесь на PowerShell 5.1, якщо не впевнені в новіших версіях.
- Для задач із секретами використовуйте `Template Secrets`, а не plain text у коді.
- Після bulk-запуску завжди перевіряйте `Queue` і reports.
- Для регулярних перевірок використовуйте `Metric Item` + `Scheduler`.
- Для автоматичного виправлення використовуйте `Metric Item` + `Trigger` + `Action Script`.
