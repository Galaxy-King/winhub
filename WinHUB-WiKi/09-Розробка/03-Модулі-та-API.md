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
