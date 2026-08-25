# Fleet і Agent Rollout

Fleet Center показує agent versions, update readiness, identity/signature status і rollout progress.

## Безпечне оновлення хвилями

1. Завантажте versioned package.
2. Перевірте platform, architecture, embedded version і SHA-256.
3. Оновіть test group.
4. Перевірте service stability, poll, telemetry і tasks.
5. Запустіть pilot wave.
6. Розгорніть production з обмеженим wave size та delay.
7. Зупиніть rollout при системній помилці.

Не використовуйте один package для різних platform/architecture. Після завершення перевірте `Outdated`, `Task v2` і failed endpoints.
