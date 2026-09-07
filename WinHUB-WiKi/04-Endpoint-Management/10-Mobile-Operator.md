# Mobile Operator

Mobile Operator надає permission-filtered мобільний інтерфейс для оперативного перегляду стану та дозволених дій.

Доступ користувача визначається тими самими module/group permissions, що й desktop UI. Mobile interface не повинен обходити Review Center, approval або action permissions.

На останньому кроці запуску заповніть `Launch reason` — обов’язкову причину (до 2000 символів). У деталях групового запуску та окремого task log видно збережену причину. Вона не додається до скрипта.

## Рекомендації

- використовуйте MFA;
- не зберігайте password у незахищеному mobile browser;
- перевіряйте endpoint ID перед дією;
- для масових або destructive operations переходьте до desktop interface;
- після втрати пристрою завершіть sessions і змініть credentials.
