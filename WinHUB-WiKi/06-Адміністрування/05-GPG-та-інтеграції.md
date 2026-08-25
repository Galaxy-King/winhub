# GPG та інтеграції

Admin interface керує GPG keys/keyservers. Infrastructure і Newsletter також використовують SMTP, Confluence, IMAP, LDAP та FreeIPA.

## Загальні правила

- service credentials окремі від user accounts;
- мінімальні зовнішні permissions;
- обов’язкова TLS validation;
- точний outbound allowlist;
- test connection без production data;
- password/key не виводиться у log;
- rotation документується без самого secret value.

## Confluence

Використовуйте окремий technical account/token з доступом лише до цільового space. Перед publish перевіряйте masking report і parent page.

## GPG

Fingerprint перевіряється незалежним каналом. Private keys і passphrases входять лише до encrypted off-host backup.
