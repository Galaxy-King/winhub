# Templates і Deploy

Task Template описує action, script/payload, input fields, variables, secrets, timeout і report rendering.

## Запуск

1. Виберіть approved template.
2. Вкажіть endpoint або group.
3. Заповніть non-secret parameters.
4. Перевірте preview/summary.
5. Запустіть спочатку на test group.

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
