# Newsletter Guide / Посібник Newsletter

Newsletter creates durable email campaigns, validates the audience before launch, and delivers messages through a dedicated worker. Campaign state is stored in PostgreSQL, so closing the browser or restarting the web service does not discard queued work.

Newsletter створює стійкі поштові кампанії, перевіряє аудиторію до запуску та доставляє повідомлення через окремий worker. Стан кампаній зберігається в PostgreSQL, тому закриття браузера або перезапуск web-служби не втрачає роботу в черзі.

---

## English

### Operating modes

| Mode | Purpose | Audience source | Launch source |
| --- | --- | --- | --- |
| Manual campaign | Announcements prepared by an operator | Local mailing lists | Newsletter web page |
| Manual campaign with GPG | Confidential announcements; every recipient must have a verified public key | Local mailing lists | Newsletter web page after preflight |
| Inbound relay | A signed and encrypted email creates a campaign automatically | Fixed local lists, LDAP/FreeIPA groups, or both | Dedicated IMAP mailbox |
| Dedicated worker | Required production execution model for queued campaigns and inbound polling | All configured sources | `winhub-newsletter.service` |
| Embedded worker | Local development only | All configured sources | Web process when explicitly enabled |

The inbound route never takes target lists from the email subject. Targets are fixed in the route, which prevents a sender from expanding the audience.

### Permissions

| Permission | Capability |
| --- | --- |
| `view_newsletter` / legacy `View` | Open Newsletter and view the user's own campaigns |
| `send_campaigns` | Create, cancel, and retry the user's own campaigns |
| `manage_lists` | Create, rename, and delete local mailing lists |
| `manage_smtp` | Manage SMTP/IMAP mail profiles and their secrets |
| `manage_inbound_routes` | Manage inbound routes and LDAP/FreeIPA profiles |
| `check_recipient_keys` | Scan list recipients and view key status/fingerprints |
| `refresh_recipient_keys` | Explicitly import missing or expired recipient keys from a list keyserver |
| `view_all_campaigns` | View all users' campaigns and full processing errors |
| Administrator | All Newsletter capabilities |

`View` does not grant permission to send.

### Production readiness

The top cards show mail profiles, mailing lists, and worker heartbeat. Before the first campaign:

1. Confirm that the worker card says **Running**.
2. Create and test at least one mail profile.
3. Create a local list or configure LDAP/FreeIPA for an inbound route.
4. Import and verify the required GPG keys.
5. Use a small test list before a production audience.

### Configure a mail profile

Open **Settings → Mail Profiles → New**.

| Field | Purpose |
| --- | --- |
| Email Address | Sender identity and profile identifier |
| SMTP Host / Port / Password | Authenticated outgoing delivery |
| IMAP Host / Port / SSL / User / Password | Required only when this profile is read by inbound relay |
| Inbox Folder | Folder polled for unread messages, normally `INBOX` |
| Processed | Destination for accepted inbound messages |
| Failed | Destination for rejected inbound messages |
| GPG Key Passphrase | Unlocks the private key used for inbound decryption; stored encrypted |
| GPG Keyserver URL | Optional key source; it does not enable automatic trust |

Procedure:

1. Enter SMTP settings. Use an app password when the provider requires one.
2. For outbound-only use, IMAP fields may remain empty.
3. For inbound use, enter IMAPS settings and create the `Processed` and `Failed` folders if the mail server does not create them automatically.
4. Select **Test Mail Profile**. WinHUB logs in to SMTP, sends a test message to the profile address, and independently checks IMAP when configured.
5. Save only after the test succeeds.

Renaming a profile updates inbound references. Deleting a profile used by a route is blocked.

### Install the inbound mailbox private key on Debian

This private key lets WinHUB decrypt messages received by an inbound relay mailbox. It is not the sender's signing key and it is not a recipient's public encryption key. The production worker runs as `winhub` and reads `/var/lib/winhub/gnupg`; importing the key into root's default keyring will not work.

WSL and Debian use the same Linux commands, but they are different machines in this procedure:

- **ADMIN COMPUTER** means your WSL terminal on Windows or a trusted Debian workstation where the private key already exists;
- **WINHUB SERVER** means the production Debian server where `/opt/winhub` is installed.

If both machines run Debian, the commands remain the same. Pay attention to the label before every step. Replace `FULL_FINGERPRINT` with the mailbox key's complete fingerprint and `SERVER_ADDRESS` with the server DNS name or IP address. Never commit the exported file, attach it to a ticket, or send it through email or chat.

1. **ADMIN COMPUTER — WSL or Debian.** List the secret keys:

   ```bash
   gpg --list-secret-keys --keyid-format LONG
   ```

   Locate the mailbox identity, independently verify its full fingerprint, and export only that key:

   ```bash
   gpg --armor --export-secret-keys FULL_FINGERPRINT > winhub-mailbox-private.asc
   chmod 600 winhub-mailbox-private.asc
   ```

   The exported file contains the private key. Keep the terminal and directory private until it is removed.

2. **ADMIN COMPUTER — WSL or Debian.** Copy the file directly to root's protected directory on the server:

   ```bash
   scp ./winhub-mailbox-private.asc root@SERVER_ADDRESS:/root/winhub-mailbox-private.asc
   ```

   When SSH asks about a new host, verify the server host-key fingerprint through a trusted channel before accepting it.

3. **WINHUB SERVER — Debian as `root`.** Log in, lock down the file, and create the WinHUB keyring:

   ```bash
   ssh root@SERVER_ADDRESS
   chmod 600 /root/winhub-mailbox-private.asc
   install -d -o winhub -g winhub -m 0700 /var/lib/winhub/gnupg
   ```

4. **WINHUB SERVER.** Import the key as the same `winhub` account that runs the Newsletter worker. Root performs the input redirection, so no second temporary copy is needed:

   ```bash
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --batch --import < /root/winhub-mailbox-private.asc
   ```

5. **WINHUB SERVER.** Verify that a `sec` entry is present and compare the full fingerprint with the trusted source:

   ```bash
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --list-secret-keys --keyid-format LONG
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --with-colons --fingerprint --list-secret-keys | awk -F: '$1 == "sec" {want=1; next} want && $1 == "fpr" {print $10; exit}'
   ```

   If the expected fingerprint is absent, stop and do not enable the inbound route.

6. **WINHUB SERVER.** Remove the transferred copy:

   ```bash
   shred -u /root/winhub-mailbox-private.asc
   ```

7. **ADMIN COMPUTER — WSL or Debian.** Remove the local exported copy:

   ```bash
   shred -u ./winhub-mailbox-private.asc
   ```

   `shred` is only best-effort on SSDs, snapshots, and copy-on-write filesystems. Ensure that the exported file was not synchronized to cloud storage and protect any deliberate encrypted backup separately.

8. In **Newsletter → Settings → Mail Profiles**, edit this mailbox profile. Enter the key's password in **GPG Key Passphrase**, select **Test Mail Profile**, and save. Do not put the passphrase in a shell command or shell history.

9. **WINHUB SERVER.** Check the worker and perform a small end-to-end test:

   ```bash
   systemctl status winhub-newsletter --no-pager
   journalctl -u winhub-newsletter -n 100 --no-pager
   ```

   Send one message encrypted for the mailbox private key and signed by a fingerprint approved on the inbound route. A successful Mail Profile test checks SMTP/IMAP connectivity; the encrypted and signed test message proves the complete GPG relay flow.

### Configure local mailing lists

Open **Recipient lists → Create New**.

1. Use a name containing only Latin letters, digits, `.`, `_`, and `-`; maximum length is 80 characters.
2. Paste recipients separated by commas, spaces, or new lines.
3. Enter full addresses, or set **Default Email Domain** on this particular list. Only then does `alice` resolve to `alice@example.com`.
4. Optionally set the list's **Recipient Keyserver**.
5. Review the resolved-address preview and save.
6. For encrypted delivery, select **Check Keys**. The result identifies every missing, expired, revoked, or disabled key and displays its fingerprint.
7. If permitted, **Fetch Missing / Expired** explicitly downloads keys from the configured list keyserver. Verify resulting fingerprints through a trusted channel.

A list supports up to 10,000 entries. Addresses are validated and deduplicated. There is no global or hidden recipient domain. Legacy lists containing aliases remain readable but cannot be used until a domain is assigned to that list or aliases are replaced with full addresses. Manual and inbound campaigns resolve the same list in exactly the same way. A list used by an inbound route cannot be deleted; renaming updates route references.

### Mode 1: manual campaign

Use this mode for announcements prepared and approved by an operator.

1. Select a tested **Mail profile**.
2. Select one or more **Recipient lists**.
3. Choose the encryption mode:
   - **GPG enabled**: recommended for confidential content. Every unique recipient must have a usable public key.
   - **GPG disabled**: ordinary SMTP message. Use only when policy allows unencrypted delivery.
4. Enter the subject and message body, then add optional attachments.
5. Select **Run preflight**.
6. Review the unique recipient count, encryption mode, missing keys, invalid addresses, and sanitized preview.
7. Select **Queue campaign** and confirm the final summary.

Any edit after preflight invalidates the result and requires another check. A failed API request preserves the draft. Closing the page after queueing is safe because the worker continues independently.

Open **Recent campaigns → View report** to inspect the actual delivery result. The report is paginated and can be filtered by `Sent`, `Failed`, `Skipped`, `Unknown`, `Pending`, or `Sending`. Every row shows the exact recipient, number of attempts, timestamp, message ID, and the delivery or encryption error. Access follows the campaign rules: ordinary operators see their own campaigns; `view_all_campaigns` can inspect every campaign.

### GPG for outgoing campaigns

GPG encrypts the body and attachments separately for each recipient. The subject, sender, recipient, and normal transport headers remain mail metadata.

Production defaults to `NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT=false`. This switch gates the explicit **Fetch Missing / Expired** list action. Key retrieval does not establish identity trust: compare every displayed fingerprint with an independently verified value. During delivery, WinHUB may refresh an unusable local key only by its already-known fingerprint; it never silently discovers a replacement key by email. A missing key must first be explicitly fetched or imported and verified.

Preflight blocks an encrypted campaign when any recipient has no usable public key. To intentionally send without encryption, disable GPG and confirm that organizational policy permits it.

### Mode 2: inbound relay

Use inbound relay when an authorized system or operator should start a predefined campaign by email. The route fixes the audience; the incoming message supplies only the content.

Prerequisites:

- a tested mail profile with IMAP and SMTP;
- the mailbox private key in `/var/lib/winhub/gnupg`;
- the sender's verified public signing key in the same keyring;
- exact allowed sender addresses;
- full approved signer fingerprints;
- at least one local list or an LDAP/FreeIPA group;
- a running Newsletter worker.

Configure **Settings → Inbound Relay → New Route**:

| Field | Purpose |
| --- | --- |
| Enabled | Starts or pauses this route |
| Route Name | Human-readable rule name |
| Read From Mail Profile | IMAP mailbox that receives encrypted source messages |
| Send From Mail Profile | SMTP identity for the resulting campaign; Auto reuses the read profile |
| LDAP Profile | Directory connection used for LDAP Groups |
| Recipient Keyserver | Per-route override for recipient key lookup |
| Campaign Result Report Emails | Optional exact administrator/owner addresses that receive the final result |
| Encrypt result reports | Encrypts each report and its CSV attachment for that report recipient; enabled by default |
| Allowed Senders | Exact From addresses allowed to request a campaign |
| Approved GPG Signer Fingerprints | Full fingerprints allowed to authorize the message |
| LDAP Groups | Fixed directory groups for this route |
| Local Mailing Lists | Fixed local lists for this route |

Save the route draft, then select **Save Inbound Relay** to persist the complete configuration.

After an inbound campaign reaches a final state, WinHUB sends each configured report recipient a summary and a UTF-8 CSV containing every target address, status, attempt count, error, timestamp, and message ID. Report delivery has its own durable status shown in **View report**. A worker restart while a report is being sent marks that delivery `Unknown` and does not resend it automatically, preventing silent duplicates. If report GPG is enabled, each report recipient must have a usable public key; otherwise the web report remains available and records why the email report failed.

An inbound message is accepted only when all checks pass:

1. The From address exactly matches the route allowlist.
2. The message decrypts with the mailbox private key.
3. GPG reports a valid signature.
4. The signing fingerprint matches the route allowlist.
5. The message contains a new `Message-ID`.
6. The route resolves at least one valid recipient.

An accepted message becomes a durable campaign and moves to `Processed`. A rejected message moves to `Failed`. A duplicate `Message-ID` is rejected. A route without approved fingerprints is paused and leaves unread messages untouched.

### Configure LDAP / FreeIPA

Use this mode when recipient membership is already maintained in a corporate directory.

1. Open **Settings → LDAP / FreeIPA → New**.
2. Give the profile a clear name and enter an explicit **Allowed LDAP Groups** allowlist.
3. For FreeIPA group discovery, configure the API URL and a read-only API account.
4. Configure the LDAPS URI, bind DN, bind password, base DN, and group base DN.
5. Confirm the schema attributes:
   - group name, normally `cn`;
   - group member, normally `member`;
   - user email, normally `mail`.
6. Select **Test LDAP / Check Groups** and review the groups returned by the server.
7. Save the profile, then select it in an inbound route and enter only allowed group names.

Use TLS and a dedicated read-only account. Members without the configured email attribute are skipped. Recipients found in multiple lists or groups are deduplicated.

### Worker, recovery, and campaign statuses

Production uses `winhub-newsletter.service`. `NEWSLETTER_EMBEDDED_WORKER=false` must remain the normal production setting.

| Status | Meaning |
| --- | --- |
| `Queued` | Waiting for the worker |
| `Sending` | Delivery is active |
| `Completed` | Every delivery succeeded |
| `Partial` | Some deliveries failed, were skipped, or are unknown |
| `Failed` | Critical failure or no successful delivery |
| `Cancelled` | Remaining deliveries were cancelled |
| Delivery `Unknown` | Worker stopped after delivery began; manual review is required |

**Cancel** affects only work that has not started. **Retry failed** requeues only `Failed` and `Skipped`. `Unknown` is never retried automatically because SMTP may already have accepted the message.

### Diagnostics

```bash
sudo systemctl status winhub-newsletter --no-pager
sudo journalctl -u winhub-newsletter -n 100 --no-pager
sudo systemctl restart winhub-newsletter
sudo /opt/winhub/deploy/debian/healthcheck_winhub.sh
```

Also inspect campaign history, the Audit Log, the IMAP `Failed` folder, Mail Profile test results, the outbound allowlist, and recipient GPG keys. Never paste passwords, private keys, complete recipient lists, or decrypted message content into diagnostics.

---

## Українська

### Режими роботи

| Режим | Для чого потрібний | Джерело аудиторії | Джерело запуску |
| --- | --- | --- | --- |
| Ручна кампанія | Оголошення, які готує оператор | Локальні списки | Сторінка Newsletter |
| Ручна кампанія з GPG | Конфіденційні повідомлення; кожен отримувач повинен мати перевірений публічний ключ | Локальні списки | Сторінка Newsletter після preflight |
| Inbound relay | Підписаний і зашифрований лист автоматично створює кампанію | Закріплені локальні списки, LDAP/FreeIPA-групи або обидва типи | Окрема IMAP-скринька |
| Окремий worker | Обов'язковий production-режим виконання черги та опитування inbound | Усі налаштовані джерела | `winhub-newsletter.service` |
| Embedded worker | Лише локальна розробка | Усі налаштовані джерела | Web-процес після явного ввімкнення |

Inbound route ніколи не бере цільові списки з теми листа. Аудиторія зафіксована в route, тому відправник не може самостійно її розширити.

### Права

| Дозвіл | Можливості |
| --- | --- |
| `view_newsletter` / legacy `View` | Відкрити модуль і переглядати власні кампанії |
| `send_campaigns` | Створювати, скасовувати й повторювати власні кампанії |
| `manage_lists` | Створювати, перейменовувати й видаляти локальні списки |
| `manage_smtp` | Керувати SMTP/IMAP mail profiles та їх секретами |
| `manage_inbound_routes` | Керувати inbound routes та LDAP/FreeIPA profiles |
| `check_recipient_keys` | Перевіряти ключі списку та бачити status/fingerprint |
| `refresh_recipient_keys` | Явно імпортувати або оновлювати ключі з keyserver списку |
| `view_all_campaigns` | Переглядати кампанії всіх користувачів і повні помилки |
| Administrator | Усі можливості Newsletter |

Право `View` не дозволяє надсилати розсилки.

### Готовність production

Верхні картки показують mail profiles, списки та heartbeat worker. Перед першою кампанією:

1. Переконайтеся, що worker має статус **Running**.
2. Створіть і перевірте хоча б один mail profile.
3. Створіть локальний список або налаштуйте LDAP/FreeIPA для inbound route.
4. Імпортуйте й перевірте необхідні GPG-ключі.
5. Спочатку виконайте тест на малому списку.

### Налаштування Mail Profile

Відкрийте **Settings → Mail Profiles → New**.

| Поле | Призначення |
| --- | --- |
| Email Address | Адреса відправника та ідентифікатор профілю |
| SMTP Host / Port / Password | Автентифікована вихідна доставка |
| IMAP Host / Port / SSL / User / Password | Потрібні лише для профілю, який читає inbound relay |
| Inbox Folder | Папка непрочитаних вхідних листів, зазвичай `INBOX` |
| Processed | Папка для прийнятих inbound-листів |
| Failed | Папка для відхилених inbound-листів |
| GPG Key Passphrase | Розблоковує приватний ключ для inbound; зберігається зашифровано |
| GPG Keyserver URL | Необов'язкове джерело ключів; саме по собі не надає довіри |

Порядок:

1. Введіть SMTP-параметри. Якщо провайдер вимагає app password, використовуйте його.
2. Для профілю лише на відправлення IMAP-поля можна залишити порожніми.
3. Для inbound введіть IMAPS-параметри та створіть папки `Processed` і `Failed`, якщо поштовий сервер не створює їх автоматично.
4. Натисніть **Test Mail Profile**. WinHUB входить у SMTP, надсилає тестовий лист на адресу профілю та окремо перевіряє IMAP.
5. Зберігайте профіль лише після успішного тесту.

Перейменування профілю оновлює inbound-посилання. Видалення профілю, який використовує route, блокується.

### Як додати приватний ключ inbound-скриньки на Debian

Цей приватний ключ дає WinHUB змогу розшифровувати листи, які надходять на mailbox для inbound relay. Це не ключ підпису відправника і не публічний ключ отримувача. Production worker працює від користувача `winhub` та читає `/var/lib/winhub/gnupg`, тому імпорт у стандартний keyring користувача `root` не спрацює.

WSL і Debian використовують однакові Linux-команди, але в цій інструкції це різні машини:

- **КОМП'ЮТЕР АДМІНІСТРАТОРА** — термінал WSL у Windows або довірений Debian-комп'ютер, де вже є приватний ключ;
- **СЕРВЕР WINHUB** — production-сервер Debian, де встановлено `/opt/winhub`.

Якщо обидві машини працюють на Debian, команди не змінюються. Перед кожним кроком дивіться на позначку машини. Замініть `FULL_FINGERPRINT` на повний fingerprint ключа mailbox, а `SERVER_ADDRESS` — на DNS-ім'я або IP сервера. Не додавайте експортований файл у Git, не прикріплюйте його до заявок і не передавайте поштою або в чаті.

1. **КОМП'ЮТЕР АДМІНІСТРАТОРА — WSL або Debian.** Покажіть секретні ключі:

   ```bash
   gpg --list-secret-keys --keyid-format LONG
   ```

   Знайдіть адресу потрібної скриньки, окремо звірте повний fingerprint та експортуйте лише цей ключ:

   ```bash
   gpg --armor --export-secret-keys FULL_FINGERPRINT > winhub-mailbox-private.asc
   chmod 600 winhub-mailbox-private.asc
   ```

   У цьому файлі міститься приватний ключ. До видалення файла не залишайте термінал і каталог доступними стороннім.

2. **КОМП'ЮТЕР АДМІНІСТРАТОРА — WSL або Debian.** Скопіюйте файл безпосередньо в захищений каталог `root` на сервері:

   ```bash
   scp ./winhub-mailbox-private.asc root@SERVER_ADDRESS:/root/winhub-mailbox-private.asc
   ```

   Якщо SSH уперше просить підтвердити новий host, спочатку звірте fingerprint SSH-ключа сервера через довірений канал.

3. **СЕРВЕР WINHUB — Debian від `root`.** Увійдіть на сервер, обмежте права файла та створіть keyring WinHUB:

   ```bash
   ssh root@SERVER_ADDRESS
   chmod 600 /root/winhub-mailbox-private.asc
   install -d -o winhub -g winhub -m 0700 /var/lib/winhub/gnupg
   ```

4. **СЕРВЕР WINHUB.** Імпортуйте ключ від того самого користувача `winhub`, від якого працює Newsletter worker. Перенаправлення вводу виконує root-shell, тому друга тимчасова копія не створюється:

   ```bash
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --batch --import < /root/winhub-mailbox-private.asc
   ```

5. **СЕРВЕР WINHUB.** Переконайтеся, що є рядок `sec`, і звірте повний fingerprint із довіреним джерелом:

   ```bash
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --list-secret-keys --keyid-format LONG
   runuser -u winhub -- env GNUPGHOME=/var/lib/winhub/gnupg /usr/bin/gpg --with-colons --fingerprint --list-secret-keys | awk -F: '$1 == "sec" {want=1; next} want && $1 == "fpr" {print $10; exit}'
   ```

   Якщо очікуваного fingerprint немає, зупиніться й не вмикайте inbound route.

6. **СЕРВЕР WINHUB.** Видаліть передану копію:

   ```bash
   shred -u /root/winhub-mailbox-private.asc
   ```

7. **КОМП'ЮТЕР АДМІНІСТРАТОРА — WSL або Debian.** Видаліть локальну експортовану копію:

   ```bash
   shred -u ./winhub-mailbox-private.asc
   ```

   Для SSD, snapshots і copy-on-write файлових систем `shred` дає лише best-effort результат. Переконайтеся, що файл не синхронізувався у хмарне сховище, а навмисну зашифровану резервну копію захищайте окремо.

8. У **Newsletter → Settings → Mail Profiles** відредагуйте профіль цієї скриньки. Введіть пароль ключа в **GPG Key Passphrase**, натисніть **Test Mail Profile** і збережіть профіль. Не передавайте пароль у shell-командах і не залишайте його в історії команд.

9. **СЕРВЕР WINHUB.** Перевірте worker і виконайте малий наскрізний тест:

   ```bash
   systemctl status winhub-newsletter --no-pager
   journalctl -u winhub-newsletter -n 100 --no-pager
   ```

   Надішліть один лист, зашифрований для приватного ключа mailbox і підписаний ключем, fingerprint якого дозволено в inbound route. Успішний Test Mail Profile перевіряє SMTP/IMAP, а тестовий зашифрований і підписаний лист — увесь GPG relay flow.

### Налаштування локальних списків

Відкрийте **Recipient lists → Create New**.

1. Ім'я може містити лише латинські літери, цифри, `.`, `_` і `-`; максимум 80 символів.
2. Вставте адреси через кому, пробіл або новий рядок.
3. Вказуйте повні адреси або задайте **Default Email Domain** саме для цього списку. Лише тоді `alice` перетворюється на `alice@example.com`.
4. За потреби задайте **Recipient Keyserver** списку.
5. Перевірте preview отриманих адрес і збережіть список.
6. Для шифрованої доставки натисніть **Check Keys**. Результат покаже відсутні, прострочені, відкликані чи вимкнені ключі та їх fingerprints.
7. За наявності дозволу **Fetch Missing / Expired** явно завантажує ключі з keyserver списку. Перевірте fingerprints незалежним довіреним каналом.

Один список підтримує до 10 000 записів. Адреси перевіряються й дедуплікуються. Глобального або прихованого домену немає. Старі списки з ніками читаються, але не запускаються, доки їм не задано власний домен або ніки не замінено повними адресами. Ручні й inbound-кампанії однаково обробляють той самий список. Список, який використовує inbound route, не можна видалити; перейменування оновлює посилання route.

### Режим 1: ручна кампанія

Цей режим потрібний для повідомлень, які готує й підтверджує оператор.

1. Виберіть перевірений **Mail profile**.
2. Виберіть один або кілька **Recipient lists**.
3. Виберіть режим шифрування:
   - **GPG enabled** — рекомендовано для конфіденційних даних; кожен унікальний отримувач повинен мати придатний публічний ключ.
   - **GPG disabled** — звичайний SMTP-лист; використовуйте лише коли політика дозволяє незашифровану доставку.
4. Введіть тему й текст, додайте вкладення за потреби.
5. Натисніть **Run preflight**.
6. Перевірте кількість унікальних адрес, режим шифрування, відсутні ключі, некоректні адреси та очищений preview.
7. Натисніть **Queue campaign** і підтвердьте фінальне резюме.

Будь-яке редагування після preflight скасовує перевірку. Помилка API не видаляє чернетку. Після постановки в чергу сторінку можна закрити — worker працює незалежно.

Відкрийте **Recent campaigns → View report**, щоб побачити фактичний результат доставки. Звіт має сторінки та фільтри `Sent`, `Failed`, `Skipped`, `Unknown`, `Pending` і `Sending`. Для кожного рядка показано точного отримувача, кількість спроб, час, message ID та помилку доставки або шифрування. Звичайний оператор бачить власні кампанії, а право `view_all_campaigns` відкриває всі кампанії.

### GPG для вихідних кампаній

GPG окремо шифрує тіло й вкладення для кожного отримувача. Тема, відправник, отримувач і транспортні заголовки залишаються поштовими метаданими.

У production використовується `NEWSLETTER_ALLOW_KEYSERVER_AUTO_IMPORT=false`. Цей параметр дозволяє явну дію **Fetch Missing / Expired**. Завантаження не підтверджує особу власника: кожен показаний fingerprint потрібно звірити незалежним довіреним каналом. Під час доставки WinHUB може оновити непридатний локальний ключ лише за вже відомим fingerprint; він не шукає мовчки заміну за email. Відсутній ключ спочатку потрібно явно завантажити або імпортувати й перевірити.

Preflight блокує зашифровану кампанію, якщо хоча б один отримувач не має придатного ключа. Для навмисної доставки без шифрування вимкніть GPG і переконайтеся, що це дозволяє політика організації.

### Режим 2: Inbound Relay

Inbound relay потрібний, коли авторизована система або оператор повинні запускати заздалегідь визначену кампанію листом. Route фіксує аудиторію, а вхідний лист передає лише вміст.

Передумови:

- перевірений mail profile з IMAP і SMTP;
- приватний ключ mailbox у `/var/lib/winhub/gnupg`;
- перевірений публічний ключ підписувача в тому самому keyring;
- точні адреси Allowed Senders;
- повні дозволені fingerprints підписувачів;
- хоча б один локальний список або LDAP/FreeIPA-група;
- активний Newsletter worker.

Налаштуйте **Settings → Inbound Relay → New Route**:

| Поле | Призначення |
| --- | --- |
| Enabled | Запускає або призупиняє route |
| Route Name | Зрозуміла назва правила |
| Read From Mail Profile | IMAP-скринька для вхідних зашифрованих листів |
| Send From Mail Profile | SMTP-профіль кампанії; Auto використовує Read-профіль |
| LDAP Profile | Каталог для LDAP Groups |
| Recipient Keyserver | Перевизначення джерела ключів для route |
| Campaign Result Report Emails | Необов'язкові точні адреси адміністраторів або власників, які отримають фінальний звіт |
| Encrypt result reports | Окремо шифрує звіт і CSV для кожного отримувача звіту; увімкнено за замовчуванням |
| Allowed Senders | Точні From-адреси, яким дозволено створювати кампанію |
| Approved GPG Signer Fingerprints | Повні fingerprints, яким дозволено авторизувати лист |
| LDAP Groups | Закріплені групи каталогу |
| Local Mailing Lists | Закріплені локальні списки |

Спочатку збережіть draft route, потім натисніть **Save Inbound Relay**, щоб записати повну конфігурацію.

Після фінального статусу inbound-кампанії WinHUB надсилає кожній заданій адресі коротке резюме та UTF-8 CSV з усіма адресатами, статусами, кількістю спроб, помилками, часом і message ID. Доставка звіту має власний durable-статус у **View report**. Якщо worker перезапустився під час відправлення звіту, стан стає `Unknown` і автоматичної повторної відправки немає, щоб уникнути прихованих дублікатів. Коли GPG для звіту ввімкнено, кожен його отримувач повинен мати придатний публічний ключ; інакше веб-звіт залишається доступним і показує причину помилки email-звіту.

Inbound-лист приймається лише коли всі перевірки успішні:

1. From-адреса точно відповідає allowlist route.
2. Лист розшифровується приватним ключем mailbox.
3. GPG підтверджує валідний підпис.
4. Fingerprint підписувача входить до allowlist route.
5. Лист має новий `Message-ID`.
6. Route знаходить хоча б одного валідного отримувача.

Прийнятий лист створює durable campaign і переходить у `Processed`. Відхилений лист переходить у `Failed`. Повторний `Message-ID` відхиляється. Route без дозволеного fingerprint призупинений і залишає непрочитані листи без змін.

### Налаштування LDAP / FreeIPA

Цей режим потрібний, коли членство отримувачів уже ведеться в корпоративному каталозі.

1. Відкрийте **Settings → LDAP / FreeIPA → New**.
2. Дайте профілю зрозумілу назву та введіть явний allowlist **Allowed LDAP Groups**.
3. Для пошуку груп FreeIPA задайте API URL і read-only API account.
4. Налаштуйте LDAPS URI, bind DN, bind password, base DN і group base DN.
5. Перевірте атрибути схеми:
   - назва групи — зазвичай `cn`;
   - член групи — зазвичай `member`;
   - email користувача — зазвичай `mail`.
6. Натисніть **Test LDAP / Check Groups** і перегляньте знайдені групи.
7. Збережіть профіль, виберіть його в inbound route та вкажіть лише дозволені групи.

Використовуйте TLS і окремий read-only account. Учасники без email-атрибута пропускаються. Адреси з кількох списків або груп дедуплікуються.

### Worker, відновлення та статуси

Production використовує `winhub-newsletter.service`. Значення `NEWSLETTER_EMBEDDED_WORKER=false` повинно залишатися стандартним для production.

| Статус | Значення |
| --- | --- |
| `Queued` | Очікує worker |
| `Sending` | Доставка виконується |
| `Completed` | Усі доставки успішні |
| `Partial` | Частина доставок невдала, пропущена або невизначена |
| `Failed` | Критична помилка або немає успішних доставок |
| `Cancelled` | Невиконані доставки скасовано |
| Delivery `Unknown` | Worker зупинився після початку доставки; потрібна ручна перевірка |

**Cancel** впливає лише на ще не розпочаті доставки. **Retry failed** повертає в чергу лише `Failed` і `Skipped`. `Unknown` не повторюється автоматично, тому що SMTP міг уже прийняти лист.

### Діагностика

```bash
sudo systemctl status winhub-newsletter --no-pager
sudo journalctl -u winhub-newsletter -n 100 --no-pager
sudo systemctl restart winhub-newsletter
sudo /opt/winhub/deploy/debian/healthcheck_winhub.sh
```

Також перевіряйте історію кампаній, Audit Log, IMAP-папку `Failed`, результат Test Mail Profile, outbound allowlist і GPG-ключі отримувачів. Не передавайте в діагностиці паролі, приватні ключі, повні списки адрес або розшифрований вміст листів.
