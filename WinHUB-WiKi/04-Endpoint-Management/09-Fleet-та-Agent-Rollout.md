# Fleet і Agent Rollout

`Nodes Control Center` має три окремі логічні вкладки:

- `Nodes` — інвентаризація, стан з’єднання, health, encryption, групи та версія агента;
- `Review Center` — pending, rejected та identity duplicates;
- `Package Registry` — пакети агента й керовані rollout waves.

У `Nodes` постійно відображається лише пошук і компактна кнопка `Filters`. Кнопка відкриває діалог зі status/health та групами; зміни починають діяти після `Apply filters`. Активні критерії показуються під пошуком, `Clear` скидає їх, а праворуч відображається фактична кількість знайдених nodes. Пошук груп усередині діалогу не змінює fleet-фільтр — він лише допомагає знайти потрібну групу в довгому списку.

`Package Registry` винесено з модального вікна в окрему вкладку, щоб завантаження package і запуск rollout не перекривали таблицю nodes та мали стабільне посилання `?view=hosts&nodeTab=packages`.

Під час старту rollout потрібно заповнити поле `Launch reason *`. Воно зберігається в rollout та копіюється в усі його хвилі, включно з підготовчими задачами updater. Старий незавершений rollout без причини переходить у `Reason required` і не запускає наступні хвилі. Скасуйте залишок такого rollout та створіть новий для потрібних хостів із зазначенням причини; вже створені задачі залишаються в історії.

## Безпечне оновлення хвилями

1. Завантажте versioned package.
2. Перевірте platform, architecture, embedded version і SHA-256.
3. Оновіть test group.
4. Перевірте service stability, poll, telemetry і tasks.
5. Запустіть pilot wave.
6. Розгорніть production з обмеженим wave size та delay.
7. Зупиніть rollout при системній помилці.

Не використовуйте один package для різних platform/architecture. Після завершення перевірте `Outdated`, `Task v2` і failed endpoints.
