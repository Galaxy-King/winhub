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

Mailbox, IMAP credentials, folders, allowed senders, signer fingerprints і target lists/groups налаштовуються через **Newsletter → Settings → Mail Profiles / Inbound Relay**. Застарілі `NEWSLETTER_INBOUND_*` mailbox variables автоматично прибираються з `/etc/winhub/winhub.env` під час update, коли UI route вже існує або legacy mailbox вимкнений. Активна legacy-конфігурація без UI route тимчасово зберігається з warning, щоб не перервати доставку. Інтервал перевірки маршрутів задає актуальна змінна `NEWSLETTER_ROUTE_POLL_SECONDS`.

Ніколи не ставте wildcard allowed senders у production без окремого ізольованого security design.
