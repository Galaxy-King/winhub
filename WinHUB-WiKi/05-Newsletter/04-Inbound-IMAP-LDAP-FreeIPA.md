# Inbound IMAP, LDAP і FreeIPA

Inbound route читає дозволений mailbox, decrypts message, визначає target list/group і передає розсилку через затверджений sender profile.

## Вимоги

- IMAPS/TLS validation;
- allowlist sender addresses;
- окремі folders для processed/failed;
- GPG private key у protected keyring;
- обмежені LDAP/FreeIPA service credentials;
- allowlist LDAP groups;
- outbound policy entry лише для потрібних hosts.

New installations повинні налаштовувати mailbox routes у UI. Legacy env polling використовуйте лише для migration compatibility.

Ніколи не ставте wildcard allowed senders у production без окремого ізольованого security design.
