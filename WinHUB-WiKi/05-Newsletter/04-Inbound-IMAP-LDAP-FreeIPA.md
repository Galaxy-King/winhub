# Inbound IMAP, LDAP і FreeIPA

Inbound route читає дозволений mailbox, decrypts message, визначає target list/group і передає розсилку через затверджений sender profile.

Цілі задаються конфігурацією route. Префікси `[list:...]` і `[ldap:...]` у темі не маршрутизують лист.

## Вимоги

- IMAPS/TLS validation;
- allowlist sender addresses;
- allowlist перевірених GPG signer fingerprints і обов’язковий валідний підпис;
- окремі folders для processed/failed;
- GPG private key у protected keyring;
- обмежені LDAP/FreeIPA service credentials;
- allowlist LDAP groups;
- outbound policy entry лише для потрібних hosts.

New installations повинні налаштовувати mailbox routes у UI. Legacy env polling використовуйте лише для migration compatibility.

Legacy route без `NEWSLETTER_INBOUND_ALLOWED_FINGERPRINTS` не приймає листи.

Ніколи не ставте wildcard allowed senders у production без окремого ізольованого security design.
