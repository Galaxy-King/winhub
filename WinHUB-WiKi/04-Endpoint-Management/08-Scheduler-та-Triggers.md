# Scheduler і Triggers

## Scheduler

Scheduler запускає затверджений template на endpoint/group за розкладом.

Перед збереженням перевірте timezone, target group, overlap, timeout, expected load і report delivery. `Run now` використовуйте як контрольний тест.

## Triggers

Trigger rule порівнює metric із threshold та запускає action template.

Перевірте:

- точну назву metric;
- operator і type значення;
- hysteresis/cooldown логіку шаблону;
- target group;
- ризик повторних запусків;
- права template action.

Не використовуйте trigger для необмеженої remote shell action. Для destructive remediation потрібні додаткові guards і test rollout.
