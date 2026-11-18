# Налаштування Zabbix Agent 2

Імпортуйте `zabbix_agent2_winhub_pack.json` у Template Library. Джерела: `configure_psk.ps1`, `template_definition.json`; перегенерація — `python build_pack.py`.

[Інструкція й обмеження](../../../../WinHUB-WiKi/guides/features/ZABBIX_AGENT2_CONFIGURATION_UA.md).

Форма: 13 основних полів з англомовними labels/help; TLS завжди PSK. Після повторного імпорту погодьте шаблон і створіть нову задачу, щоб прибрати старі поля.

Для імпорту вибирайте лише `zabbix_agent2_winhub_pack.json`. `template_definition.json` — службове джерело без скрипта, не імпортний пакет. Якщо в Code з’явився JSON із `__variable_schema`, повторно імпортуйте повний пакет, погодьте шаблон і створіть нову задачу. Стару задачу не повторюйте.
