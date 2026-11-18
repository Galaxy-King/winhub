# Архітектура сповіщень

## Транзакції та виконання

`core/notifications.py` реєструє SQLAlchemy listeners у server application factory. Зміни стану відомих domain models записують короткі `notification_signals` у тій самій транзакції. Rollback прибирає і подію, і основну зміну. Окремий hook покриває bulk-оновлення terminal-статусів AgentTask, зокрема cancellation. Невідомі raw SQL producers не покриваються автоматично: при додаванні такого producer необхідно явно записати сигнал у його транзакції та додати regression test.

Web-роль має два незалежні фонові потоки: створення inbox із сигналів та Web Push delivery. Вони не використовують AgentTask queue чи пул виконання APScheduler. Agent Gateway записує сигнали, але не виконує мережеву доставку. Один poll UI відбувається раз на 30 секунд лише у видимій вкладці; звичайний interval обробки сигналів — п'ять секунд.

Inbox дедуплікується унікальним ключем `(user_id, event_key)`. Підсумок job з'являється після terminal-стану всіх цілей. Software і Scheduler мають власні результати й не дублюють внутрішні AgentTask notifications. Результат визначається domain status/outcome, а не пошуком слів у логах.

PostgreSQL `FOR UPDATE SKIP LOCKED` координує обробку сигналів. Push має lease, retries/backoff і обмежений TTL; це best-effort / at-least-once delivery, не гарантія exactly-once. Однаковий notification ID є browser notification tag, що зменшує дублювання після аварії між відправкою та commit.

## Дані та права

Міграція `20261118_01` додає inbox, preferences, transactional signals, push subscriptions/deliveries, VAPID identity та remembered sessions. Titles, endpoint capability URL/key material та приватний VAPID ключ використовують штатне шифрування БД. Реципієнти мають власні read/dismissed стани; очистка не видаляє джерело або аудит. Retention — 90 днів, UI — останні 500 доступних рядків.

Одержувач перевіряється при створенні, читанні, відкритті та доставці. Доступ до всіх target endpoints потрібний для групових результатів. Відсутнє/видалене джерело fail-closed. API keys не мають доступу до інтерактивного inbox або approval API. Поля UI показуються text-only/Jinja autoescape. Запити mutation проходять чинний CSRF middleware.

Відкритий notification detail повторно перевіряє джерело. Host/template approval бере row lock та перевіряє revision. Software approval викликає наявний handler із catalogue lock і recipe hash, не дублює логіку доступу. Шаблон не можна погодити з невалідним AI provenance. Конфлікти ідентичності залишаються у спеціалізованому Review workflow.

## Web Push і PWA

Стандартні manifest + service worker охоплюють desktop/mobile. Service worker не має fetch/cache handler; авторизовані дані не потрапляють в offline cache. Лише allowlisted внутрішній notification URL може відкриватися з push. Payload містить загальне повідомлення, а не domain details.

`notification_push.py` обмежує push endpoint відомими browser providers, HTTPS:443, без userinfo та fragments. Перед відправкою застосовується чинна outbound policy, усі адреси повинні бути public, з'єднання йде до перевіреної numeric IP зі збереженою перевіркою TLS hostname. Redirects, environment proxy та незахищені TLS fallback не використовуються. Timeout і розмір response body обмежені. Provider response/endpoint secrets не пишуться в журнал.

VAPID key створюється один раз через явний authenticated POST з CSRF при ввімкненні push, зберігається зашифрованим у БД та переживає звичайне оновлення/restore. Обмеження підписок — десять активних пристроїв на користувача. Власник capability endpoint може змінитися лише при явній підписці іншого авторизованого користувача цього браузера; queued deliveries попереднього власника відкидаються.

## Сеанси

Remembered session — серверний запис на 30 днів, прив'язаний до підписаної session cookie, user ID і hash поточного password/TOTP state. Не окремий безстроковий bearer token. Налаштований absolute timeout має пріоритет. Пароль і MFA перевіряються звичайним login handler до створення запису. Deactivation, credential change, expiry та explicit revocation перевіряються на кожному authenticated запиті. Manual logout відкликає поточний запис і push subscription.

Звичайні сесії зберігають idle timeout. `/api/notifications` не оновлює `last_activity`. Remembered sessions є явною опцією тільки при HTTPS-вході; вони не створюються фоновим poll або service worker.

## Межі перевірки

Unit/integration tests перевіряють rollback, дедуплікацію групових результатів, bulk cancellation, ACL/revocation, CSRF, revisions, MIME/PWA, remembered credential invalidation, migration та справжнє VAPID шифрування з mock transport. Playwright перевіряє реальні desktop/mobile CSS, filters/actions та text-only rendering. Production acceptance Web Push і native Home Screen UX потрібні окремо на фізичних пристроях.

[Посібник користувача](../guides/features/NOTIFICATIONS_UA.md)
