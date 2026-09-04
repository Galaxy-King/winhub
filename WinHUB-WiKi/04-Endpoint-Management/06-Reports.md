# Reports

Reports формуються з task results у відокремленому `winhub-renderer` service.

## Дії

- перегляд і download;
- edit дозволеного тексту;
- dismiss або delete;
- email delivery;
- publish до Confluence;
- scheduled send;
- finalize grouped job.

## Sensitive values

Право `view_sensitive_reports` відокремлено від звичайного `view_reports`. Не вставляйте секрети у report template або необроблений HTML.

## Перед відправленням

1. Перевірте recipients/Confluence target.
2. Перевірте masking.
3. Переконайтеся, що вкладення не перевищує limit.
4. Для sensitive email використовуйте затверджене GPG-шифрування.
5. Перевірте Audit Log після відправлення.


## Перегляд і форматування

Viewer підтримує форматований preview та перегляд тексту/коду. Форматований вигляд зберігає таблиці, заголовки й списки через дозволений набір HTML-тегів. Скрипти, атрибути вихідного HTML та активний вміст не переносяться; sensitive values маскуються за правами користувача. Для великих звітів доступні прокручування та розширений перегляд.

Email містить текстовий варіант і очищений форматований HTML. Для Confluence типовий формат — `safe_html`; `escaped_pre` публікує екранований текст. `storage_html` потребує права на sensitive reports і дозволяє передати raw storage HTML.

## Історія та AI

Зміни звіту створюють незмінні revisions; delivery зберігає знімок фактично надісланого вмісту. Доступні фільтри за датою, автором, джерелом і шаблоном. Пошук за вмістом current/original/revisions/deliveries потребує `view_sensitive_reports`.

[Обробка AI](../08-Експлуатація/01-AI-звіти-Open-WebUI.md) доступна і для вже надісланих, dismissed, superseded та split reports. Вона використовує поточний звіт навіть за відсутності старих task results, зберігаючи попередню revision.

## Можливості Jinja-шаблонів

Ізольований renderer дозволяє `range(start, stop, step)` лише з цілими аргументами й максимум 4096 елементами. У циклах доступні read-only `loop.index`, `index0`, `first`, `last`, `length`, `revindex`, `revindex0`, `depth`, `depth0`. Довільні методи, private attributes, import/include/macro залишаються забороненими. При помилці перевірте шаблон у test environment і логи renderer.
