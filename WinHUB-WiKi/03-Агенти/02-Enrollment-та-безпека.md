# Enrollment і безпека агентів

## Enrollment flow

1. Агент читає runtime і bootstrap config.
2. Генерує локальну RSA identity.
3. Надсилає signed enrollment request.
4. Сервер перевіряє bootstrap secret і rate limit.
5. Endpoint з’являється у `Pending Approval`.
6. Після перевірки адміністратор виконує `Approve` або `Reject`.
7. Агент зберігає per-host token/identity у захищеному локальному сховищі.
8. Plaintext bootstrap config видаляється.

## Перевірка перед Approve

- hostname і display name;
- OS та agent version;
- connection IP;
- hardware/identity information;
- очікуване джерело rollout;
- відсутність підозрілого duplicate identity.

## Task v2

Сучасні агенти повідомляють capability `rsa-pss-sha256-v2`. Сервер підписує задачу для конкретного endpoint з task ID, payload hash, timeout, expiration і sequence. Агент пінить per-agent public key і відхиляє replay/downgrade.

## Клоновані VM

Агенти з capability `identity-session-v1` надсилають випадковий process session ID, boot ID та хеш platform identity. Сервер підтверджує clone conflict лише коли дві session одного endpoint-а продовжують надсилати запити паралельно; звичайний restart служби не створює конфлікт.

Під час підтвердженого конфлікту task dispatch працює fail-closed. Адміністратор може адресувати підписану `identity-split-v1` команду одній session. Після ротації новий endpoint отримує власні token, RSA key і task-signing sequence.

Перед створенням VM template зупиніть службу та виконайте від Administrator/root:

```text
WinHUBAgent --prepare-clone-template PREPARE-CLONE
```

Для Linux/macOS використовується executable відповідного агента з тим самим параметром. Команда прибирає лише WinHUB enrollment identity, secrets і journals, зберігає runtime config та не змінює прикладне ПЗ. Після клонування кожній VM потрібно окремо передати bootstrap config.

## Після rollout

- закрийте `AGENT_ENROLLMENT_ENABLED` або задайте allowlist;
- залиште re-enrollment забороненим за замовчуванням;
- не розповсюджуйте старий bootstrap config повторно;
- перевірте badge `Task v2` у Fleet Center;
- оновлюйте агенти хвилями.
