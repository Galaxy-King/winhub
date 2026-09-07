# Fleet і Agent Rollout

Fleet Center показує agent versions, update readiness, identity/signature status і rollout progress.

Під час старту rollout потрібно ввести причину запуску. Вона зберігається в rollout та копіюється в усі його хвилі, включно з підготовчими задачами updater. Старий незавершений rollout без причини переходить у `Reason required` і не запускає наступні хвилі. Скасуйте залишок такого rollout та створіть новий для потрібних хостів із зазначенням причини; вже створені задачі залишаються в історії.

## Безпечне оновлення хвилями

1. Завантажте versioned package.
2. Перевірте platform, architecture, embedded version і SHA-256.
3. Оновіть test group.
4. Перевірте service stability, poll, telemetry і tasks.
5. Запустіть pilot wave.
6. Розгорніть production з обмеженим wave size та delay.
7. Зупиніть rollout при системній помилці.

Не використовуйте один package для різних platform/architecture. Після завершення перевірте `Outdated`, `Task v2` і failed endpoints.
