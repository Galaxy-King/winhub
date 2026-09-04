# Proxmox Inventory для WinHUB

Для багатьох незалежних Proxmox-хостів виберіть усі відповідні endpoint в одному запуску — WinHUB об'єднає їх у єдиний report. Для Proxmox-кластера вибирайте лише **одну** ноду кожного кластера: `pvesh /cluster/resources` уже повертає всі VM/LXC та ноди кластера, тому запуск на кожній ноді створить дублікати.

1. Імпортуйте `proxmox_inventory_pack.json` у бібліотеку шаблонів WinHUB.
2. Запустіть `Proxmox Cluster Inventory` на схваленому Linux endpoint.
3. Відкрийте сформований report та опублікуйте його на Wiki через наявний механізм WinHUB з форматом `storage_html`.

Скрипт не використовує SSH, Confluence API або зовнішні секрети. Потрібні лише штатні `pvesh` і `python3` на Proxmox VE.
