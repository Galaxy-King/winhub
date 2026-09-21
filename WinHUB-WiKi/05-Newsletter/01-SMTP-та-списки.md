# SMTP і списки отримувачів

## SMTP profile

Створіть profile із sender address, server, port, TLS mode та credentials. Password вводиться у protected UI/storage і не документується.

Перед збереженням виконайте `Test Mail Profile`: він перевіряє SMTP login, контрольну доставку на адресу профілю та, якщо налаштовано, IMAP. Якщо outbound policy працює в enforce mode, додайте лише потрібний SMTP/IMAP host.

## Recipient lists

- використовуйте стабільне унікальне ім’я з літер, цифр, `.`, `_`, `-`;
- одна address на рядок або формат, який показує UI;
- перевіряйте ownership і legal basis;
- не публікуйте повні recipient lists у WiKi;
- залежні inbound routes автоматично блокують видалення; перейменування оновлює їхні посилання.
