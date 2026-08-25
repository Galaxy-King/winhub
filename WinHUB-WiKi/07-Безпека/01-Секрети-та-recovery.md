# Секрети та recovery

## Необхідні runtime secrets

- Flask session key;
- PostgreSQL password;
- agent enrollment secret;
- transitional/task-signing secret;
- `master_key.enc` для encrypted payload/report data;
- `sys_secret.enc` для TOTP/system secrets;
- TLS private key;
- integration credentials і GPG private keys.

Ці файли/значення залишаються на сервері лише тому, що потрібні runtime. File permissions і service isolation обмежують доступ.

## Генерація під час fresh install

- session, enrollment і task-signing secrets: по 64 випадкові байти через OS CSPRNG;
- PostgreSQL password: 48 випадкових байтів через OS CSPRNG;
- initial admin password: 24 випадкові байти у URL-safe encoding;
- TOTP seed: криптографічний генератор `pyotp`;
- master/system encryption keys: `Fernet.generate_key()`;
- self-signed TLS private key: RSA 4096 через OpenSSL.

Кожне значення генерується незалежно. Шаблонні або WiKi-значення не використовуються.

## Одноразовий recovery bundle

Під час fresh install bundle формується у `/run`, копіюється адміністратором до encrypted off-host storage і видаляється після підтвердження `SAVED`.

Bundle не є звичайним backup. Після введення системи в експлуатацію використовуйте `backup_winhub.sh`, шифрування off-host storage та test restore.

Не робіть додаткові plaintext-копії секретів у `/root`, home directories або project tree.
