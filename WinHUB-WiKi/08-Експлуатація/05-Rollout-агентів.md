# Rollout агентів

## Хвилі

1. Lab/test endpoint.
2. Pilot 1–5%.
3. Перша production wave.
4. Поступове розширення.
5. Завершальна перевірка Outdated/Failed.

## Stop criteria

- service не запускається;
- різкий ріст poll/signature errors;
- update rollback на кількох endpoint-вузлах;
- втрата telemetry;
- platform mismatch;
- task execution regression.

Для Windows GPO, Linux SSH і WinHUB Fleet rollout використовуйте одні й ті самі acceptance criteria. Не змішуйте bootstrap rollout із звичайним binary update.
