# Audit і Production Readiness

## Audit Log

Використовуйте фільтри й export для розслідування адміністративних дій. Export може містити sensitive metadata, тому зберігайте його відповідно до data classification.

## System Logs

System Logs допомагають діагностувати backend, integrations і task processing. Перед передаванням третій стороні виконайте redaction.

## Production Readiness

Перевірка оцінює:

- production mode і сильні secrets;
- PostgreSQL;
- signed agent requests і Task v2;
- enrollment window;
- secure cookies та HSTS;
- outbound policy;
- CSP nonce;
- isolated renderer;
- permissions env/key files;
- наявність runtime encryption keys;
- свіжий backup;
- активного адміністратора та agent identities.

Critical failures виправляйте до production rollout. Warning не ігноруйте без зафіксованого risk acceptance.

[Докладний посібник пошуку історії](../guides/features/AUDIT_SEARCH_GUIDE_UA.md).
