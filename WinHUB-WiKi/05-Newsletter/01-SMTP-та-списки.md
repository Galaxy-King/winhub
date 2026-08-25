# SMTP і списки отримувачів

## SMTP profile

Створіть profile із sender address, server, port, TLS mode та credentials. Password вводиться у protected UI/storage і не документується.

Після збереження виконайте test mail на контрольовану адресу. Якщо outbound policy працює в enforce mode, додайте лише потрібний SMTP host/діапазон.

## Recipient lists

- використовуйте стабільне унікальне ім’я;
- одна address на рядок або формат, який показує UI;
- перевіряйте ownership і legal basis;
- не публікуйте повні recipient lists у WiKi;
- перед видаленням перевірте inbound routes і scheduled usage.
