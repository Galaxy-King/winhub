# GPG у Newsletter

GPG encrypts повідомлення для recipient public keys і може decrypt inbound mail за допомогою server-side private key.

## Адміністративні правила

- перевіряйте fingerprint до import; автоматичний keyserver import за замовчуванням вимкнений;
- обмежуйте keyservers;
- private key та passphrase не публікуйте;
- GPG home включайте в encrypted off-host backup;
- видалення key виконуйте лише після перевірки active lists/routes;
- test encryption/decryption робіть на непублічних тестових даних.

Inbound relay додатково вимагає валідний GPG-підпис, fingerprint якого внесений у конкретний mailbox route.

Помилка `Missing/Invalid GPG Key` означає, що хоча б для одного recipient немає придатного verified public key.

## Де шукати приватний ключ

Команди `gpg --list-secret-keys --keyid-format LONG` і `gpg --armor --export-secret-keys FULL_FINGERPRINT` працюють лише з GnuPG keyring поточного користувача, зазвичай `~/.gnupg`. Thunderbird, інший поштовий клієнт або графічний менеджер ключів може використовувати окрему базу. Якщо потрібного ключа немає у виводі `gpg`, експортуйте його вручну через менеджер ключів цієї програми або використайте наявний захищений файл приватного ключа.

На сервері відкрийте **Newsletter → Settings → GPG Key Status**. Ця read-only сторінка показує, які приватні ключі бачить служба WinHUB, їх fingerprints, UID, строк дії та можливості. Вона не показує секретний матеріал, не змінює keyring і не перевіряє парольну фразу. Остаточна перевірка — тестовий лист, зашифрований для mailbox і підписаний дозволеним ключем маршруту.
