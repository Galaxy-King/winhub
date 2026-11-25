# Модулі та API

Module містить `manifest.json`, routes, templates і за потреби static assets.

## Вимоги

- унікальний module ID і URL;
- permissions через спільні helpers;
- CSRF/auth/security headers не обходяться;
- user input валідується;
- outbound connections проходять policy;
- secrets зберігаються у protected storage;
- report rendering використовує isolated renderer;
- API повертає послідовні status/error structures;
- destructive endpoints ведуть audit.

Agent protocol змінюйте з backward-compatible rollout plan і tests для canonical JSON/signatures.


## Newsletter: списки із keyserver

Пошук адрес відділено від імпорту GPG-ключів: `POST /api/newsletter/lists/discover` вимагає `manage_lists`, приймає `keyserver` і `domain`, повертає `recipients` для перегляду в редакторі. Використовується HKP `op=index&options=mr` із точним фільтром домену після читання UID; ключі не стають довіреними й не імпортуються. Це дозволяє формувати список без послаблення окремого дозволу на імпорт ключів. Контракт HKP-індексу: [опис формату](https://www.ietf.org/archive/id/draft-gallagher-openpgp-hkp-04.html#section-7.2).

Налаштування `keyserver_auto_sync` і стан `keyserver_sync` зберігаються в наявному JSON списку, без міграції БД і нової служби. `winhub-newsletter.service` перевіряє київську дату між кампаніями й виконує одну додавальну синхронізацію за дату з catch-up після простою. Дата спроби фіксується до HTTP-запиту, тому помилка не спричиняє запити кожну хвилину. Списки та їх перейменування/видалення захищені міжпроцесним файловим блокуванням; мережевий запит виконується поза блокуванням. Перед додаванням worker перечитує список і перевіряє джерело, прапорець та ідентифікатор спроби. Межі: 10 000 записів, 2 MiB індексу, перевірений HTTPS/HKPS, без redirects, зі спільною outbound policy. Деталі експлуатації — у [посібнику Newsletter](../guides/features/NEWSLETTER_GUIDE_UA.md).
