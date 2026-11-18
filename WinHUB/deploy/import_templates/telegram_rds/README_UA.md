# Telegram Desktop для Windows / RDS

Готовий файл ручного імпорту: `telegram_rds_pack.json`. Пакет не встановлюється автоматично; після імпорту перевірте код і погодьте шаблон штатним механізмом WinHUB.

Використання та обмеження: [посібник у Wiki](../../../../WinHUB-WiKi/guides/features/TELEGRAM_RDS_UA.md).

`telegram_rds.ps1` — джерело для локального запуску з параметрами `-Action` та `-AutoUpdate`. Після його зміни запустіть `python build_pack.py`, щоб оновити JSON. Builder замінює початковий `param()` на валідовані присвоєння змінних: Windows-агент додає перед action службовий код кодування, після якого script-level `param()` недопустимий. Для ручного імпорту використовуйте JSON, а не копію локального PS1. Потрібні Windows x64, PowerShell 5.1 x64 і права адміністратора / LocalSystem. Скрипт не запускає Telegram від імені служби.
