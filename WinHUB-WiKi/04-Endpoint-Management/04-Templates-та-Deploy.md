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

Звичайний користувач із `manage_templates` може створювати й редагувати шаблони, але не може позначати їх **Approved for execution**. Для ручної розробки адміністратор може окремо видати `run_own_draft_templates`; разом із `run_tasks` воно дозволяє автору тестувати лише власні private action/metric drafts на доступних йому endpoint-групах. Право явне, не працює через API key і не поширюється на чужі чернетки.

AI-чернетка перед таким запуском має успішно пройти статичну валідацію після останньої зміни коду. Валідація перевіряє синтаксис, але не безпечність поведінки. Scheduler і Triggers виконують тільки approved templates із чинною approval-печаткою. Рекомендований доступ розробника — окрема canary-група; `run_own_draft_templates` еквівалентне можливості виконувати створений ним PowerShell/Bash із service-правами агента в межах цієї групи.

## Import/Export

Пакет шаблону може містити scripts і report templates, але не production secrets. Перед import перевірте код, actions, URLs, hashes і approval metadata.
