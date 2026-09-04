# WinHUB: Endpoint Compliance Audit

Ця папка містить окремі файли для ручного імпорту в WinHUB:

- `endpoint_compliance_audit.ps1` - action script для Windows endpoint-агента.
- `endpoint_compliance_report.jinja` - report template для агрегації результатів.
- `endpoint_compliance_pack.json` - готовий import pack з обома шаблонами.

Рекомендований імпорт: Infrastructure -> Deploy / Templates -> Import templates -> вибрати `endpoint_compliance_pack.json`.

Після імпорту запускай action template `Endpoint Compliance Audit` на потрібній групі/хостах і в Post-Execution обирай report template `Endpoint Compliance Audit Report`.

Скрипт не потребує Script Variables Required. Він автономно:

- визначає публічну інтернет-локацію через HTTPS geolocation service;
- перевіряє активацію Windows та Office;
- збирає Windows timezone, culture, system locale, UI language, user languages і home location;
- збирає DNS, WinHTTP proxy і VPN-like network adapters;
- порівнює public IP country/UTC offset з регіональними та часовими сигналами Windows;
- формує `needs attention`, якщо бачить невідповідності або технічні проблеми перевірки.

Неактивовані Windows/Office або невідповідність локації не вважаються помилкою виконання task. Вони потрапляють у звіт як remediation list, щоб їх можна було далі виправляти.

Перевірка локації є аудитом консистентності налаштувань, а не інструкцією для обходу правил сторонніх сервісів.
