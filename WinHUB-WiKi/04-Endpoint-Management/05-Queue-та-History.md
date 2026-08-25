# Queue та History

`Queue` показує поточні й завершені задачі, їхній endpoint, status, timestamps та terminal log.

## Основні дії

- відкрити task details;
- переглянути terminal log;
- cancel pending tasks;
- retry failed job;
- finalize aggregated report;
- очистити завершену history відповідно до retention policy.

## Стани

Типовий шлях: `Pending → Running → Completed/Failed`. Cancel діє лише до або під час підтримуваної стадії.

`Audit & History` використовуйте для ретроспективного пошуку. Cleanup є destructive action: перед видаленням перевірте audit/legal retention requirements.

Task logs можуть містити sensitive operational data. Не копіюйте їх до WiKi без redaction.
