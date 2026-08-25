# GPG у Newsletter

GPG encrypts повідомлення для recipient public keys і може decrypt inbound mail за допомогою server-side private key.

## Адміністративні правила

- перевіряйте fingerprint до import/fetch;
- обмежуйте keyservers;
- private key та passphrase не публікуйте;
- GPG home включайте в encrypted off-host backup;
- видалення key виконуйте лише після перевірки active lists/routes;
- test encryption/decryption робіть на непублічних тестових даних.

Помилка `Missing/Invalid GPG Key` означає, що хоча б для одного recipient немає придатного verified public key.
