# Security hardening

Fresh install одразу використовує strict defaults. Для legacy server hardening виконуйте поетапно, щоб не відключити старі агенти й integrations.

## Перевірка

```bash
sudo /opt/winhub/deploy/debian/security_smoke_test.sh
```

Smoke test перевіряє production health, strict env values, renderer isolation, sandbox/XSS protections, DNS rebinding controls, CSP nonce і signature regressions.

## Для існуючого сервера

1. Оновіть server без вимкнення сумісності різко.
2. Оновіть агенти хвилями.
3. Перевірте Task v2 badge.
4. Налаштуйте outbound allowlist.
5. Переведіть CSP/outbound/signature modes у enforce.
6. Запустіть smoke test.

Rollback має стосуватися лише проблемного control і бути обмеженим у часі.

[Hardening v3](../guides/security/SECURITY_HARDENING_V3_UA.md) · [Security rollout](../guides/security/SECURITY_ROLLOUT_UA.md).
