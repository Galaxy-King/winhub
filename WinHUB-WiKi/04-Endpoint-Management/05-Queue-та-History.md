# Queue та History

`Queue` показує поточні й завершені задачі, їхній endpoint, status, timestamps та terminal log.

У деталях групового запуску, окремої задачі та в `Audit & History` видно причину запуску. Збережена причина є знімком на момент створення задачі: редагування розкладу/тригера не змінює минулі записи. `Retry failed` запитує нову причину й створює новий запуск, зберігаючи стару історію.

Для історичних задач без цього поля відображається `Not recorded` — система не вигадує причини заднім числом. Скасування, перегляд і формування звіту не запускають новий код на хості та не потребують нової причини.

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
