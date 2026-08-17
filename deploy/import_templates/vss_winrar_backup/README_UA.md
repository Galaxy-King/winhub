# WinHUB: VSS + WinRAR backup на SMB

Цей комплект призначений для ручного імпорту у WinHUB. Він повторює метод із наданого прикладу:

1. на цільовому Windows-сервері створюється VSS snapshot;
2. папки читаються зі snapshot, а не з «живої» файлової системи;
3. для кожної папки створюється зашифрований RAR;
4. WinHUB Agent тимчасово підключається до SMB share;
5. архіви копіюються, перевіряються і локальні тимчасові файли видаляються;
6. WinHUB формує report, який можна відправити поштою штатними засобами WinHUB.

У скрипті немає SMTP, GPG або власної відправки пошти.

## Файли

- `vss_winrar_backup_pack.json` — готовий import pack (action + report).
- `vss_winrar_backup.ps1` — окремий action script для перегляду/редагування.
- `vss_winrar_backup_report.jinja` — окремий report template.
- `build_pack.py` — повторно збирає JSON pack із двох вихідних файлів.

## Важлива схема виконання

Шаблон потрібно запускати на тому Windows endpoint, дані якого треба бекапити. На цьому сервері має бути встановлений WinHUB Agent. Додатковий WinRM/PSSession і master credential із початкового прикладу тут не потрібні: агент уже є захищеним каналом виконання WinHUB.

WinHUB Agent зазвичай працює як `LocalSystem`, тому має права для VSS. Якщо сервіс переведений на інший обліковий запис, він повинен бути локальним адміністратором і мати право читати всі джерела.

## Перед імпортом: Template Secrets

У WinHUB відкрийте `Infrastructure -> Workspace -> Template Secrets` і створіть рівно три secrets:

| Secret | Значення |
|---|---|
| `vss_backup_smb_username_b64` | SMB username у UTF-8 Base64, наприклад `DOMAIN\backup-user` |
| `vss_backup_smb_password_b64` | SMB password у UTF-8 Base64 |
| `vss_backup_archive_password_b64` | пароль шифрування RAR у UTF-8 Base64 |

Base64 тут не є шифруванням. Воно лише гарантує безпечну передачу довільних символів усередині PowerShell template. Самі значення Template Secrets WinHUB зберігає зашифрованими та підставляє лише під час dispatch task.

Згенерувати значення можна в PowerShell:

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('DOMAIN\backup-user'))
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('SMB-password-here'))
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('RAR-password-here'))
```

Для іншого NAS або іншого набору credentials створіть копію action template і змініть у коді назви трьох secrets.

## Вимоги на сервері-джерелі

- Windows Server/Windows із доступним `diskshadow.exe` та VSS.
- WinHUB Agent запущений з адміністративними правами.
- WinRAR встановлений; типовий шлях — `C:\Program Files\WinRAR\WinRAR.exe`.
- Достатньо вільного місця у `C:\ProgramData\WinHUB\BackupTemp` для всіх архівів одного запуску.
- Із сервера є маршрут до NAS, DNS (якщо використовується hostname) і відкритий TCP 445.
- SMB account має `Create/Write/Read`. Для retention також потрібне право `Delete` у цільовій папці.

## Імпорт

1. Відкрийте `Infrastructure -> Workspace`.
2. Натисніть `Import`.
3. Виберіть `vss_winrar_backup_pack.json`.
4. Після імпорту з’являться:
   - `VSS WinRAR Backup to SMB`;
   - `VSS WinRAR Backup Report`.

Report уже прив’язаний до action template. Окремо додавати поштовий код не потрібно.

## Поля шаблону

| Поле | Що вказувати |
|---|---|
| `Project / customer` | Назва клієнта або проєкту для report. |
| `Backup task name` | Зрозуміла назва конкретного бекапу. |
| `SMB destination (UNC)` | Тільки UNC, наприклад `\\192.168.36.201\2Scope_backup\term36_101`. Не вказуйте `Z:`. |
| `Recursive source folders` | По одному локальному шляху в рядку. Архівуються всі підпапки (`WinRAR -r`). |
| `Single-level source folders` | По одному локальному шляху в рядку. Підпапки не обходяться (`WinRAR -r-`). |
| `Archive filename prefix` | Префікс файлів; retention видаляє тільки архіви з цим префіксом і hostname. |
| `WinRAR executable` | Повний шлях до `WinRAR.exe` на endpoint. |
| `Local temporary root` | Виділена локальна папка, не корінь диска. Для кожного запуску створюється окрема `run_*` папка. |
| `Compression level` | `5` відповідає методу з прикладу; `0` швидше, але без стискання. |
| `Verification` | `Size` рекомендовано; `SHA256` надійніше, але повторно читає великі файли через мережу. |
| `Retention` | Типове значення `0` вимикає видалення. `30` видаляє архіви цього endpoint/prefix старші за 30 днів. |
| `Fail when source is missing` | Увімкнено: task завершується помилкою; вимкнено: папка пропускається з warning. |

Один task підтримує джерела з кількох локальних томів (наприклад, `C:` і `D:`): усі томи входять в один VSS snapshot set і тимчасово expose-яться на вільні літери.

## Як реалізоване підключення до мережевого диска

Скрипт не створює постійний mapped drive. Він:

1. розбирає UNC на share root (`\\server\share`) і вкладену папку;
2. створює тимчасовий PowerShell PSDrive з credentials із Template Secrets;
3. за потреби створює вкладену цільову папку;
4. копіює та перевіряє архіви;
5. у `finally` відключає PSDrive навіть після помилки.

Це важливо для сервісного запуску: диск, який вручну підключив інтерактивний користувач, не видно процесу `LocalSystem`. Тому в полі завжди використовуйте UNC і не покладайтеся на Explorer drive mappings.

Якщо з’являється Windows error 1219, на сервері вже є SMB session до того самого NAS під іншим користувачем. Не додавайте в backup script глобальне `net use * /delete`: це може обірвати чужі з’єднання. Усуньте конфлікт саме в контексті облікового запису WinHUB Agent або використайте єдиний NAS account для цього сервера.

## Scheduler

1. Спочатку виконайте action вручну на одному endpoint і перевірте report та файли на NAS.
2. Відкрийте `Infrastructure -> Scheduler -> New Schedule`.
3. Виберіть `VSS WinRAR Backup to SMB`.
4. Target має бути саме сервер-джерело або група серверів із однаковими шляхами/призначенням.
5. Заповніть ті самі поля variables і задайте cron/час.
6. Для великих бекапів встановіть достатній `Execution time limit`. Pack задає agent timeout 24 години; поточний Windows Agent також обмежує один task максимум 24 годинами.

Не плануйте два одночасні VSS backup task на одному endpoint. Після завершення скрипт видаляє тільки створені ним exposed shadows і власну тимчасову `run_*` папку.

## Report і пошта

Action повертає компактний JSON. Звіт показує створені архіви, розмір, перевірку, retention, warnings, етап помилки та UNC destination. Відправку налаштовуйте у WinHUB через report/email workflow або Post-Execution — SMTP/GPG логіки в PowerShell немає.
