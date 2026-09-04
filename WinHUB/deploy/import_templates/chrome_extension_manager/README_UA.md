# Chrome Extension Manager для WinHUB Agent

Цей пакет призначений для ручного імпорту у WinHUB Workspace / Deployment Builder. Він не додається в систему автоматично.

## Файли

- `chrome_extension_manager_pack.json` - готовий import pack.
- `chrome_extension_manager.ps1` - PowerShell action-скрипт для Windows агентів.
- `chrome_extension_report.jinja` - report-шаблон для зведення результатів.

## Що робить action

Скрипт керує Chrome або Edge enterprise policy на локальному хості, де запущений агент:

- `ExtensionInstallForcelist` - примусове встановлення розширення.
- `ExtensionInstallBlocklist` - блокування розширень або всіх розширень через `*`.
- `ExtensionInstallAllowlist` - лише читається для виявлення конфліктів.
- `ExtensionSettings` - читається для виявлення конфліктів; при `PinExtension=true` додає `toolbar_pin=force_pinned`.

Скрипт не видаляє сторонні існуючі policy-записи і не перетирає персональні політики користувачів. Якщо бачить конфлікт, він пише це в результат і report.

## Випадаючі списки

Після імпорту шаблон має typed variables:

- `Action`: `Audit`, `Install`, `Remove`, `Block`, `Unblock`.
- `Browser`: `Chrome`, `Edge`.
- `Scope`: `Machine`, `AllUsers`, `SpecificUsers`, `DefaultUser`, `AllUsersAndDefault`.
- `BlockOthers`: `false`, `true`.
- `PinExtension`: `false`, `true`.

Інші поля:

- `ExtensionIds` - один або кілька extension ID, через кому або з нового рядка. Можна також вказувати повний force-install формат `extension_id;https://.../update2/crx`.
- `TargetUsers` - використовується тільки при `Scope=SpecificUsers`; можна вводити `DOMAIN\User`, локальний username або SID.
- `UpdateUrl` - за замовчуванням `https://clients2.google.com/service/update2/crx`.

## Рекомендований порядок

1. Імпортуй `chrome_extension_manager_pack.json`.
2. Запусти `Chrome Extension Manager` з `Action=Audit` на 1-2 тестових хостах.
3. Відкрий report `Chrome Extension Manager Report` і перевір:
   - `CONFLICTS`
   - `WARNINGS`
   - `POLICY SNAPSHOT`
4. Якщо конфліктів немає, запускай `Action=Install`.
5. Якщо є `ExtensionInstallBlocklist=*`, дивись warning/conflict. Така policy може блокувати всі розширення, які не дозволені allowlist або forcelist.

## Важливо про глобальні і персональні розширення

`Scope=Machine` пише політики в `HKLM` і працює глобально для всіх користувачів. Воно не видаляє персональні extension policy користувачів, але machine policy має вищий пріоритет у Chrome/Edge.

Якщо у користувачів уже є персональні розширення, вони не зникають тільки через force-install нового розширення. Вони можуть бути заблоковані лише якщо існує `ExtensionInstallBlocklist=*` або інша blocking policy.

Для terminal/RDP серверів, де в різних користувачів можуть бути різні персональні policy-розширення, рекомендований режим:

- `Scope=AllUsersAndDefault`
- `BlockOthers=false`

Цей режим додає розширення у всі існуючі профілі користувачів і в шаблон `C:\Users\Default\NTUSER.DAT`. Нові користувачі, створені після цього, отримають ті самі user-level policy записи автоматично.

`Scope=DefaultUser` змінює тільки шаблон нових користувачів і не чіпає існуючі профілі.

Report має окремий верхній блок `IMPORTANT WARNINGS / CONFLICTS`. Він спеціально показує ситуації, де machine-level policy може перекривати user-level policy навіть якщо action або audit технічно завершився успішно.

## Як зрозуміти конфлікт

Report явно покаже такі ситуації:

- `ExtensionInstallBlocklist=*` - усе не дозволене може блокуватися.
- target extension є в blocklist.
- allowlist існує, але target extension не входить у нього.
- `ExtensionSettings` містить wildcard/blocked hints.
- invalid extension IDs були проігноровані.

Ці записи не приховуються як помилки виконання: задача може завершитися успішно, але report покаже `Conflicts detected`.
