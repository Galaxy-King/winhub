# Security hardening v3: перевірка і плавне ввімкнення

Цей етап закриває три залишкові ризики:

1. Значення метрик та інші дані агентів більше не вставляються в Fleet Center як активний HTML.
2. У режимі `OUTBOUND_POLICY_MODE=enforce` перевірена IP-адреса фіксується на час реального з'єднання. Повторна DNS-відповідь не може перевести HTTP, SMTP, IMAP або LDAP на приватну/службову адресу. TLS-перевірку FreeIPA та GPG у цьому режимі вимкнути не можна.
3. Шаблони звітів виконуються окремим користувачем `winhub-renderer` через systemd socket. Він не має мережі, доступу до `/etc/winhub`, `/var/lib/winhub`, логів або домашніх каталогів.

## Оновлення наявного сервера

Команди нижче виконуються від `root`, тому `sudo` не потрібен. Виконувати після merge PR у `main`:

```bash
cd /opt/winhub
bash deploy/debian/update_winhub.sh
```

Оновлення встановить і запустить `winhub-renderer.socket`. Для наявного сервера воно не змінює автоматично старе значення `REPORT_RENDERER_MODE=subprocess`, тому вебсервіс продовжує працювати у попередньому режимі до контрольованого cutover.

Перевірити підготовлену службу:

```bash
systemctl status winhub-renderer.socket --no-pager --full
test -S /run/winhub-renderer.sock && echo "Renderer socket OK"
id winhub-renderer
id -nG winhub-renderer
```

У списку груп `winhub-renderer` не повинно бути групи `winhub`.

## Перемикання renderer

```bash
ENV_FILE=/etc/winhub/winhub.env

if grep -q '^REPORT_RENDERER_MODE=' "$ENV_FILE"; then
  sed -i 's/^REPORT_RENDERER_MODE=.*/REPORT_RENDERER_MODE=service/' "$ENV_FILE"
else
  printf '\nREPORT_RENDERER_MODE=service\n' >> "$ENV_FILE"
fi

if grep -q '^REPORT_RENDERER_SOCKET=' "$ENV_FILE"; then
  sed -i 's|^REPORT_RENDERER_SOCKET=.*|REPORT_RENDERER_SOCKET=/run/winhub-renderer.sock|' "$ENV_FILE"
else
  printf 'REPORT_RENDERER_SOCKET=/run/winhub-renderer.sock\n' >> "$ENV_FILE"
fi

systemctl restart winhub
/opt/winhub/deploy/debian/healthcheck_winhub.sh
```

Після цього створити або відкрити звичайний звіт у WinHUB. Відображення має бути таким самим, як до перемикання.

## Повна автоматична security-перевірка

Коли вже встановлені строгі режими (`Task v2`, signed requests, outbound enforce, CSP nonce enforce і renderer service):

```bash
/opt/winhub/deploy/debian/security_smoke_test.sh
```

Скрипт перевіряє:

- production healthcheck;
- строгі значення конфігурації;
- відсутність у renderer доступу до env і каталогу БД;
- активні systemd-обмеження файлової системи та мережі;
- блокування Jinja sandbox escape і HTML-екранування контексту;
- регресійні тести XSS, DNS rebinding, CSP, підпису задач і approval hash;
- фактичний CSP nonce у HTTPS-відповіді.

## Ручна перевірка Stored XSS

На тестовому агенті створити custom metric, результатом якого є:

```text
<img src=x onerror="document.body.dataset.xss='executed'">
```

Відкрити Fleet Center → потрібний host → custom metrics. Безпечний результат: рядок показаний як текст, значення `document.body.dataset.xss` у консолі браузера порожнє. Не використовуйте зовнішні URL або payload, який передає cookies/дані.

## Швидкий відкат лише renderer

Відкат не змінює БД і не впливає на агентів:

```bash
sed -i 's/^REPORT_RENDERER_MODE=.*/REPORT_RENDERER_MODE=subprocess/' /etc/winhub/winhub.env
systemctl restart winhub
/opt/winhub/deploy/debian/healthcheck_winhub.sh
```

Після усунення причини знову встановити `REPORT_RENDERER_MODE=service`. Режим `inprocess` у production тепер заборонений.
