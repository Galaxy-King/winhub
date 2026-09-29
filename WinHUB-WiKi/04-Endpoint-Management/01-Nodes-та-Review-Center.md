# Nodes і Review Center

`Nodes` показує зареєстровані endpoint-вузли, їхній стан, OS, agent version, останню активність і security status.

## Основні стани

- `Pending` — очікує перевірки;
- `Approved` — дозволений до роботи;
- `Rejected` — відхилений;
- `Blocked` — заблокований;
- `Live` або `Passive` — оцінка останньої активності.

## Pending Approval

1. Відкрийте `Nodes → Review Center`.
2. Перевірте hostname, IP, OS, version та identity.
3. Порівняйте з планом rollout.
4. Натисніть `Approve` або `Reject`.

Bulk approve використовуйте лише для вже перевіреної rollout-хвилі.

## Identity Duplicates

При merge визначте canonical endpoint. Групи, history, telemetry і tasks другого запису переносяться. Перед merge переконайтеся, що це справді один фізичний/віртуальний вузол.

`Keep Both` створює виняток лише для вибраної пари endpoint-ів. Він не вимикає duplicate detection для інших пар.

## Clone Conflicts

Якщо дві запущені VM мають скопійовані `agent.hwid`, token і RSA identity, сервер виявляє дві активні agent session та переводить endpoint у карантин. Telemetry і діагностичні heartbeat зберігаються, але нові задачі не видаються, доки адміністратор не вирішить конфлікт.

У `Review Center → Clone Conflicts`:

1. Порівняйте hostname, connection IP, agent version і час останнього poll.
2. На VM, яка повинна стати окремим хостом, натисніть `Split this VM identity`.
3. Вкажіть display name нового endpoint-а.
4. Дочекайтеся перезапуску агента й появи обох endpoint-ів online.

Команда split підписана, одноразова, обмежена конкретною активною session та строком дії. Вона створює нові endpoint ID, token, RSA identity і task-signing state. Старий execution journal архівується локально й не виконується під новою identity.

Для старого агента без capability `identity-split-v1` спочатку виконайте agent update або вручну перевстановіть агент із purge identity.

## Rejected Hosts

Rejected endpoint можна повернути до Pending, approve або видалити. Видалення не замінює блокування компрометованого агента.
