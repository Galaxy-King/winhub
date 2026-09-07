# Templates і Deploy

Task Template описує action, script/payload, input fields, variables, secrets, timeout і report rendering.

## Запуск

1. Виберіть approved template.
2. Вкажіть endpoint або group.
3. Заповніть non-secret parameters.
4. Заповніть обов’язкове поле **`Launch reason *`**: наприклад, «Перевірка WireGuard за заявкою INC-123».
5. Перевірте preview/summary.
6. Запустіть спочатку на test group.

Причина — окреме поле `launch_reason` (1–2000 символів після видалення крайніх пробілів). Це не назва задачі й не параметр скрипта. Вимога діє для Deploy, Quick Launch, Mobile Operator та API; порожній/невалідний текст сервер відхиляє до створення задач. Наявність причини не замінює права, approval чи перевірку цільових хостів.

Причина зберігається зашифрованою в кожній задачі групового запуску та показується в деталях і History. HTML/Jinja/shell-синтаксис у цьому полі залишається текстом, не виконується та не передається агенту як команда. Не вказуйте паролі, токени чи інші секрети.

Збереження шаблону без запуску не потребує причини. Причина заповнюється для конкретного запуску, а не в коді чи змінних шаблону.

## Створення

- задайте чітку назву й призначення;
- обмежте platform/action;
- валідуйте user input;
- використовуйте Template Secrets замість plaintext credentials;
- задайте реалістичний timeout;
- не повертайте secrets у task log/report;
- перевірте script окремо до approval.

## Import/Export

Пакет шаблону може містити scripts і report templates, але не production secrets. Перед import перевірте код, actions, URLs, hashes і approval metadata.
