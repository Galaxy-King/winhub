# OpenVPN AS Inventory

Імпортуйте `openvpn_as_inventory_pack.json` у бібліотеку шаблонів WinHUB і запустіть `OpenVPN AS Inventory` одним job на потрібних Debian/OpenVPN AS endpoint. Результати агрегуються в один HTML report.

Шаблон read-only: використовує `sacli`, `logdba`, systemd та системні команди інвентаризації. Історія останнього підключення запитується за останні 365 днів. Якщо log database очищена або недоступна, користувач позначається сірим як `History unavailable / never connected`, а не помилково неактивним.
