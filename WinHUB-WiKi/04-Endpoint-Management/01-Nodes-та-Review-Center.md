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

## Rejected Hosts

Rejected endpoint можна повернути до Pending, approve або видалити. Видалення не замінює блокування компрометованого агента.
