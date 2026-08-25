# Щоденний checklist

- `/api/health` успішний;
- `winhub`, `nginx`, `postgresql`, `winhub-renderer.socket` активні;
- немає різкого росту failed tasks;
- disk space достатній;
- backup молодший за 24 години;
- немає неочікуваних Pending/Rejected endpoint-вузлів;
- agent versions і Outdated count контрольовані;
- Audit Log не містить неочікуваних admin actions;
- SMTP/LDAP/Confluence failures розглянуті;
- certificate expiry не наближається.

Проблеми фіксуйте у monitoring/ticket system без секретних значень.
