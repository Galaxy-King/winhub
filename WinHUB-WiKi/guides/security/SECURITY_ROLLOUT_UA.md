# Плавне ввімкнення security hardening

## 1. Перший деплой без відключення старих агентів

Початкові значення для наявного сервера:

```dotenv
AGENT_TASK_SIGNATURE_MODE=dual
OUTBOUND_POLICY_MODE=audit
OUTBOUND_ALLOWED_HOSTS=
CSP_MODE=report-only
CSP_NONCE_MODE=report-only
REPORT_RENDERER_MODE=subprocess
```

У цьому режимі сервер віддає старий HMAC старим агентам і окремий RSA-PSS
підпис агентам з підтримкою v2. Вихідні з'єднання лише журналюються, тому
внутрішні Confluence, SMTP, IMAP та LDAP не відключаються.

## 2. Оновлення агентів хвилями

Зібрати пакети з новою унікальною версією, завантажити їх у Fleet Center і
запускати rollout невеликими хвилями. Новий агент повідомляє capability
`rsa-pss-sha256-v2`. Після першої успішно перевіреної задачі він пінить свій
public key, зберігає anti-replay sequence та видаляє спільний HMAC локально.

У Fleet Center має з'явитися зелений badge `Task v2`. Для підтвердження міграції
кожному оновленому агенту потрібно виконати хоча б одну безпечну тестову задачу.

## 3. Allowlist вихідних інтеграцій

Переглянути журнал:

```bash
sudo journalctl -u winhub --since "24 hours ago" | grep "Outbound policy audit"
```

Додати фактичні DNS-імена або CIDR, наприклад:

```dotenv
OUTBOUND_ALLOWED_HOSTS=wiki.corp.example,mail.corp.example,ipa.corp.example,10.20.0.0/16
```

Після тестів Confluence, SMTP/IMAP, LDAP/FreeIPA та GPG keyserver увімкнути:

```dotenv
OUTBOUND_POLICY_MODE=enforce
```

У режимі `enforce` credentialed HTTP інтеграції вимагають HTTPS, LDAP — LDAPS,
редіректи не приймаються, приватні адреси працюють лише через allowlist.

## 4. Остаточний cutover підписів

Лише коли всі потрібні endpoint-и мають `Task v2`:

```dotenv
AGENT_TASK_SIGNATURE_MODE=v2
```

Старий агент після цього отримає `upgrade_required` і не забере задачу. Новий
агент з pinned key відхиляє downgrade до HMAC та підпис, призначений іншому
`endpoint_id`.

На наявному сервері сумісну CSP можна залишити в `enforce`, а nonce-політику
спочатку ввімкнути паралельно без блокування:

```dotenv
CSP_MODE=enforce
CSP_NONCE_MODE=report-only
```

У цьому стані `Content-Security-Policy` продовжує блокувати за сумісною
політикою, а `Content-Security-Policy-Report-Only` перевіряє нову політику з
унікальним nonce для кожної відповіді. Після перевірки входу, основних сторінок,
Fleet Center, звітів та відсутності CSP-помилок у консолі браузера:

```dotenv
CSP_NONCE_MODE=enforce
```

Новий режим прибирає загальний `unsafe-inline` для блоків `<script>` і `<style>`.
Наявні HTML event/style attributes тимчасово ізольовані директивами
`script-src-attr` та `style-src-attr`, доки вони поетапно переносяться у статичні файли.

Після кожної зміни `/etc/winhub/winhub.env`:

```bash
sudo systemctl restart winhub
sudo systemctl restart winhub-agent 2>/dev/null || true
sudo systemctl status winhub --no-pager
```

## Швидкий rollback режимів

Rollback не потребує відкату БД:

```dotenv
AGENT_TASK_SIGNATURE_MODE=dual
OUTBOUND_POLICY_MODE=audit
CSP_MODE=report-only
CSP_NONCE_MODE=report-only
```

Агент, який уже пінить v2-ключ, навмисно не повернеться до HMAC. Це захист від
downgrade; для такого агента сервер повинен і надалі віддавати v2 (режим `dual`
це робить).
