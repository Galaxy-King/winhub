# API keys

API key використовується для інтеграцій на кшталт Element-бота. Для кожного бота або проєкту створюйте окремий ключ. Не використовуйте один глобальний ключ для всіх груп.

## Модель доступу

WinHUB дозволяє запит лише коли одночасно виконані всі умови:

1. ключ активний, не протермінований, а його owner не заблокований;
2. фактична адреса клієнта входить до `Allowed Source IPs / CIDRs`;
3. ключ має глобальний permission для endpoint, наприклад `Infrastructure:run_tasks`;
4. для потрібної групи хостів ключ має саме цю дію (`run_tasks`, `view_queue` тощо);
5. шаблон входить до allowlist ключа, має тип action/metric і чинну approval-печатку;
6. кількість хостів не перевищує `Max Hosts per Run`;
7. усі передані змінні відповідають серверній схемі шаблону.

Отже, групи Element регулюють, хто може звертатися до бота, а API key WinHUB окремо обмежує, що цей бот може зробити в конкретному проєкті. Дозвіл бота не замінює перевірку WinHUB.

## Створення ключа

У `Admin Control Center -> API Keys -> New API Key`:

- задайте назву з ботом і проєктом, наприклад `element-reset-project-a`;
- виберіть лише потрібні глобальні permissions;
- для кожної host group увімкніть лише потрібні дії;
- виберіть дозволені approved templates;
- внесіть IP бота як `/32` (IPv4) або `/128` (IPv6), або контрольовану підмережу;
- залиште увімкненими `Enforce IP allowlist` і `Enforce template allowlist`;
- задайте найменший практичний `Max Hosts per Run` (для self-service reset — `1`);
- встановіть строк дії.

Secret показується один раз. Збережіть його у secret manager. У URL, Git, Wiki, повідомлення Element та application logs ключ не вставляйте.

## IP-фільтрація та reverse proxy

Нові ключі працюють лише з дозволених IP/CIDR. WinHUB не довіряє `X-Forwarded-For` від довільного клієнта. Заголовок враховується лише тоді, коли безпосереднє з'єднання прийшло від мережі з `TRUSTED_PROXY_CIDRS`.

Для штатного Debian/Nginx достатньо:

```env
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

Якщо перед Nginx є інший load balancer/reverse proxy, додайте лише його керовану CIDR-мережу та переконайтеся, що він перезаписує forwarding headers. Не додавайте `0.0.0.0/0` або `::/0`.

## Безпечні змінні шаблону

API не виконає шаблон з `{{variable}}`, якщо для змінної немає `__variable_schema`. Текстова змінна повинна мати `options`/`choices` або строгий regex `pattern`.

```json
{
  "user_login": {
    "type": "text",
    "pattern": "[A-Za-z0-9_.-]{1,64}",
    "max_length": 64
  }
}
```

Переноси рядків і shell/PowerShell metacharacters у значеннях API блокуються. Для списку логінів краще дозволити контрольований comma-separated формат через regex, а не довільний multiline text.

Після будь-якої зміни коду, payload або schema шаблон треба повторно переглянути й approve: стара approval-печатка стає недійсною.

## Виклик

```bash
curl -X POST 'https://winhub.example/api/infrastructure/templates/TEMPLATE_ID/run' \
  -H 'Authorization: Bearer wh_REDACTED' \
  -H 'Content-Type: application/json' \
  -d '{
    "target_type": "host",
    "target_id": "HOST_ID",
    "variables": {"user_login": "operator.1"}
  }'
```

Успішна відповідь містить лише технічний статус, `job_id`, `task_ids` і кількість створених задач. Пароль або інший secret API боту не повертається: `view_sensitive_reports` для API keys заборонений на сервері, включно зі старими токенами. Надсилання нового пароля на пошту виконує дозволений WinHUB template/внутрішній workflow; бот повідомляє лише, що запит прийнято або доступи відправлено.

Щоб відрізнити «задачу прийнято» від «лист успішно відправлено», бот опитує безпечний status endpoint (потрібні глобальна й групова дія `view_queue`):

```bash
curl -H 'Authorization: Bearer wh_REDACTED' \
  'https://winhub.example/api/infrastructure/jobs/JOB_ID/status'
```

Відповідь містить тільки загальний status/counts та `notification.status` (`Pending`, `Success`, `Error`, `NotRequested`). Адреса одержувача, тіло листа, task log і пароль у цій відповіді відсутні. Бот пише «доступи відправлено на пошту» лише після `notification.status=Success`.

API retry для старого job навмисно заборонений: він міг би повторно використати раніше сформований payload. Бот повинен зробити новий запуск дозволеного шаблону, щоб WinHUB повторив усі актуальні перевірки.

## 2FA та self-service

Перевірка Element user -> корпоративний account/email і одноразовий код реалізується в боті до API-виклику. До WinHUB передається вже підтверджена операція. Для self-service бот сам визначає login користувача зі своєї серверної identity mapping; значення login з довільного тексту користувача не слід приймати як джерело істини.

WinHUB додатково обмежує ключ одним шаблоном, потрібною групою, `run_tasks` і `Max Hosts per Run=1`. Таким чином підстановка іншого hostname або запуск іншої команди буде відхилено незалежно від логіки бота.

## Rotation, revoke та аудит

- `Rotate` негайно робить старий secret недійсним і показує новий один раз;
- `Revoke` вимикає ключ без видалення історії;
- блокування owner автоматично блокує його ключі;
- список показує останній час та IP використання;
- denial через неправильний IP, невалідний ключ і запуски фіксуються в Audit Logs.

Після застосування цієї security migration старі ключі без allowlist блокуються за принципом fail-closed. Відкрийте `Access`, задайте IP, group-action matrix і templates та збережіть. Після перевірки виконайте rotation.
