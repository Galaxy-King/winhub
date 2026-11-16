# Editable task re-runs

Рішення від 2026-11-16: повторний запуск з Queue використовує поточний дозволений template, збережені введені параметри та незмінний набір початкових endpoint ID.

- `AgentTask.launch_context` — nullable EncryptedText із versioned JSON. Snapshot зберігається до dispatch у тій самій транзакції, що й task; містить значення полів, hash шаблону, timeout і посилання на попередній job. Дані не додаються до agent payload, індексу пошуку або відкритого task-details API. Життєвий цикл snapshot збігається із записом AgentTask, окрема retention-таблиця не потрібна.
- Кожен AgentTask має свій snapshot: після часткового retry можна повторити саме хост зі своїми параметрами. Для цілого job перевіряється однорідність template/context; різні snapshots вимагають повтору окремих host tasks.
- GET/POST вимагають інтерактивного view_queue + run_tasks, поточного дозволу на template та всіх початкових targets. POST не приймає від клієнта код чи targets. Він викликає штатне create_task з довіреним server-side descriptor; звичайна endpoint API не може передати Python data_override/rerun_parent. Endpoint row locks захищають від видалення цілі між перевіркою й dispatch.
- Hash попереднього template потрібен для повідомлення про зміну, hash preview — для відхилення застарілої форми. Новий dispatch ніколи не відновлює старий rendered script. Спеціальні current-template/draft/AI approval правила залишаються у can_run_template/create_task. Змінений вручну код первинного запуску відмічається окремим warning.
- Чутливі значення не повертаються в браузер. Reuse saved value — server-side повтор із перевіркою власника/чутливого доступу; інший оператор може ввести свої значення. Template secrets читаються актуальними зі сховища, а не копіюються зі старого payload.
- Active/ResultUnknown не допускаються. Повтор створює нові UUID/job, не змінює status/log первинної задачі. Reports/email/Confluence не повторюються автоматично. API keys та software packages використовують свої штатні шляхи запуску.
- Legacy rows мають NULL context: параметри не відновлюються евристично з тексту команди. Міграція additive; агентський протокол і версія агентів не змінюються.

[Користувацька інструкція](../04-Endpoint-Management/05-Queue-та-History.md#re-run-повторний-запуск-із-редагуванням-параметрів).
