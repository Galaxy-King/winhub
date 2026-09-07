# Windows/Linux RC3: підпис релізу та ручне приймання

Це інструкція для адміністратора. Агент розробки не підключався до клієнтів і не виконував deployment. RC3 не закриває весь production-план: актуальні обмеження — у [статусі реалізації](PRODUCTION_PIN_AGENTS_UA.md). Масово не розгортати до canary-перевірок. Linux потребує systemd + cgroup v2 з cpu/memory/pids; старий Proxmox/LXC із відсутніми controllers може не підтримувати новий runner.

## 1. Три різні ключі — не плутати

- TLS certificate pin: довіра до HTTPS WinHUB, однакова для агентів цього сервера.
- Ключі ідентичності та Task v2: індивідуальні для endpoint; не копіювати між хостами.
- Release publisher: окремий адміністративний ключ для Windows/Linux пакетів. На агенті — лише public PEM; private PEM **ніколи** не передавати на агенти, сервер, Git, OpenCloud або в чат.

RSA-PSS/SHA-256 використовує 32-byte salt, SPKI key ID = SHA-256 DER public key. Підписуються точні bytes JSON payload у `release-manifest.json`, не повторно серіалізований JSON. Публічний ключ має надходити довіреним адміністративним каналом, а не з пакета або першої мережевої відповіді. Алгоритм реалізовано штатними [.NET API](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsasignaturepadding.pss) та [cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/).

## 2. Створення свого ключа — один раз

На захищеному Windows build/signing комп'ютері, у **інтерактивному PowerShell адміністратора**, з кореня Git. Python environment WinHUB вже має `cryptography`. Каталог ключа має бути новим; виберіть несинхронізований захищений диск/каталог. Наведений приклад створить `C:\WinHUB-ReleaseKeys`, а не файл у проєкті:

```powershell
& .\WinHUB\.venv\Scripts\python.exe .\WinHUBLinuxAgent\tools\sign-release.py init-key --directory C:\WinHUB-ReleaseKeys
if ($LASTEXITCODE -ne 0) { throw 'Key creation failed; do not continue.' }
```

Програма запитає довгу парольну фразу (мінімум 20 bytes) без відображення та запише encrypted PKCS8 RSA-4096 private key, public PEM і покаже public key ID. Збережіть окрему захищену резервну копію private key та окремо пароль. Не вводьте пароль як аргумент/змінну середовища; не запускайте init-key повторно для кожного релізу. Інструмент відмовляється перезаписувати каталог або працювати з private key у Git/синхронізованих каталогах. Якщо змінюєте ключ, це окрема контрольована ротація public trust, не звичайний update.

## 3. Підписування вже зібраних RC3

З кореня Git, в тому ж інтерактивному PowerShell. Джерело — **publish directory**, не ZIP і не встановлений агент із конфігом. Значення serial є вашим реєстром релізів: для наступної підписаної збірки збільшуйте, ніколи не перевикористовуйте для інших bytes. У прикладі два різні serial; не використовуйте їх повторно після успішного підписування.

```powershell
$version = '2.0.0-rc.3'
$windowsManifest = Get-Content ".\WinHUBAgentWindows\dist-agent\WinHUBAgent-v$version-win-x64.manifest.json" -Raw | ConvertFrom-Json
$linuxManifest = Get-Content ".\WinHUBLinuxAgent\dist-agent\WinHUBLinuxAgent-v$version-linux-x64.tar.gz.manifest.json" -Raw | ConvertFrom-Json
$windowsSource = Join-Path (Resolve-Path .\WinHUBAgentWindows) $windowsManifest.publish_directory
$linuxSource = Join-Path (Resolve-Path .\WinHUBLinuxAgent\dist-agent) (Split-Path -Leaf $linuxManifest.publish_directory)
$publisher = '.\WinHUBLinuxAgent\tools\sign-release.py'
$python = '.\WinHUB\.venv\Scripts\python.exe'

& $python $publisher sign --source $windowsSource --output ".\WinHUBAgentWindows\dist-agent\signed\WinHUBAgent-v$version-win-x64.zip" --key C:\WinHUB-ReleaseKeys\release-signing-private.pem --platform windows --architecture x64 --version $version --serial 2026090401
if ($LASTEXITCODE -ne 0) { throw 'Windows signing failed.' }
& $python $publisher sign --source $linuxSource --output ".\WinHUBLinuxAgent\dist-agent\signed\WinHUBLinuxAgent-v$version-linux-x64.tar.gz" --key C:\WinHUB-ReleaseKeys\release-signing-private.pem --platform linux --architecture x64 --version $version --serial 2026090402
if ($LASTEXITCODE -ne 0) { throw 'Linux signing failed.' }
```

Signer перевіряє paths, відсутність runtime config/секретів і запаковує ті самі bytes, які хешує. Не підписуйте невідому збірку: підпис означає ваше схвалення коду. `version` має відповідати реально зібраному executable. Для нової збірки спочатку build із новою version, потім sign із тією ж version і новим serial. Нові output-файли не перезаписуються. Для Fleet Center використовуйте архів із **`dist-agent/signed/`** і його новий SHA-256, не SHA unsigned build.

## 4. Перший перехід та public trust

Windows `1.2.21` і RC2 не знають publisher signature. Перше оновлення спирається на старий довірений канал, Task v2, SHA вибраного пакета й підготовлений updater; воно не є доказом незалежної publisher verification. Спочатку сервер має містити нові updater assets. До переходу збережіть snapshot/backup, версію, конфіг і state **цього** endpoint. Не копіюйте їх на інші хости.

На період canary/update/recovery зупиніть звичайну видачу задач цьому endpoint: його schedules/triggers, API/ручні запуски; дочекайтеся завершення вже запущених задач. Залиште лише підготовку й update. Updater може автоматично перезапустити старий код після failed start, а старі версії не читають RC3 archive. До ручного підтвердження нової версії не відновлюйте звичайну чергу. Координація всіх watchdog/recovery races і безперервне навантаження під час upgrade залишаються production gate, не доведеним тестом.

На canary новий кандидат перевіряють `--version`, `--self-test`, `--validate-config EXISTING_CONFIG`, `--check-update-server EXISTING_CONFIG` до зупинки старого агента. Остання команда — HTTPS health і Linux prerequisites, не перевірка enrollment. Ніколи не передавайте нові CLI-флаги старому `1.2.21`: він може запуститися як ще один агент.

Після контрольованої інсталяції RC3 його служба захищає каталог даних. Відсутній release public key не блокує звичайні задачі/зв'язок, але блокує наступний `agent_update`. Доставте **тільки** `release-signing-public.pem` довіреним способом і звірте SHA-256 файла з оригіналом на signing-комп'ютері. Не використовуйте PEM, отриманий із недовіреної відповіді сервера.

Windows, PowerShell адміністратора (приклад джерела потрібно замінити своїм файлом):

```powershell
$source = 'C:\AdminTransfer\release-signing-public.pem'
$destination = 'C:\ProgramData\WinHUB\release-signing-public.pem'
if (Test-Path -LiteralPath $destination) { throw 'Trust already exists; rotation requires a separate review.' }
Get-Acl 'C:\ProgramData\WinHUB' | Format-List Owner,AccessToString
# Продовжуйте лише якщо каталог доступний на запис виключно SYSTEM/Administrators.
Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
Get-FileHash -LiteralPath $destination -Algorithm SHA256
```

Linux, root, після перевірки `stat -c '%U %G %a' /var/lib/winhub-agent` (очікується `root root 700`):

```bash
(
  set -e
  test ! -e /var/lib/winhub-agent/release-signing-public.pem
  install -o root -g root -m 0600 /root/AdminTransfer/release-signing-public.pem /var/lib/winhub-agent/release-signing-public.pem
  sha256sum /var/lib/winhub-agent/release-signing-public.pem
)
```

Для read-only перевірки **новим RC3 executable** розпакованого підписаного пакета:

```text
NEW_AGENT --verify-release EXTRACTED_PACKAGE PUBLIC_PEM RELEASE_STATE_PATH INSTALLED_VERSION EXPECTED_VERSION
```

Параметри позиційні. `RELEASE_STATE_PATH`: Windows `C:\ProgramData\WinHUB\release-state.json`, Linux `/var/lib/winhub-agent/release-state.json`; до першого signed update файл може не існувати. Команда не змінює стан і не встановлює пакет. Під час справжнього update Worker перевіряє manifest і файли та атомарно резервує serial **до** updater. Помилка підпису/довіри не повинна зупинити стару службу. Видалення `release-state.json` для обходу downgrade заборонено.

## 5. Ручне приймання: по одному Windows і Linux

Не тестуйте disk-full, аварійне вимкнення, погані пакети чи rollback на робочому сервері. Використовуйте snapshot/backup із перевіреним відновленням. Позначайте кожний пункт як пройдено/не пройдено, з версією ОС та агента; не передавайте токени, private keys або повний конфіг у звіті.

| Перевірка | Очікуваний результат |
|---|---|
| Перехід зі старої версії через Fleet Center | Prepare Success → update; той самий endpoint, нова version, Task v2; одна звичайна задача Success |
| Reboot ОС/служби | Не створюється дубль endpoint; key ID незмінний, sequence не зменшується |
| Немає public key / unsigned пакет / неправильний ключ | agent_update Error до зупинки service; звичайні задачі продовжують працювати |
| Коректний підписаний новіший пакет | Update успішний, release-state serial збільшився; приватного ключа на хості немає |
| Змінений файл або старіший signed release | Пакет відхилено; installed code/identity не змінені |
| Недоступний сервер / невірний pin перед update | Preflight Error; старий агент не замінено |
| Перезапуск під час звичайної задачі | Не повторює скрипт; UNKNOWN/Error пояснює можливі часткові ефекти |
| Обрив мережі після виконання | Результат збережений локально й доставлений після відновлення; скрипт не повторюється |
| Timeout і дочірні процеси | Задача Error, її процеси припинені; сам агент лишається online |
| Реальний backup/адмінський шаблон | Успіх із підібраними resource limits; результат і лог збережені |
| Failed start нового процесу, code rollback | Старий код відновлений, live config/token/sequence/journal/release-state не відмотані; Fleet підтверджено вручну |
| Disk-full/power-loss в ізольованій VM | Немає повторного автоматичного виконання; пошкоджений state не замінюється новою identity; recovery за backup |

Windows перевірка стану (не друкує секретів):

```powershell
Get-Service WinHUBAgent
& 'C:\Program Files\WinHUBAgent\WinHUBAgent.exe' --version
Get-Acl 'C:\ProgramData\WinHUB' | Format-List Owner,AccessToString
Get-Content 'C:\ProgramData\WinHUB\logs\agent.log' -Tail 80
```

Linux, root:

```bash
systemctl status winhub-linux-agent --no-pager --full
/opt/winhub-linux-agent/WinHUBLinuxAgent --version
cat /sys/fs/cgroup/cgroup.controllers
journalctl -u winhub-linux-agent --since '15 minutes ago' --no-pager
systemctl list-units --all 'winhub-task-*.service'
```

Поки довга тестова задача працює, для її конкретного unit із попередньої команди:

```bash
systemctl show WINHUB_TASK_UNIT.service -p MemoryMax -p MemorySwapMax -p TasksMax -p CPUQuotaPerSecUSec -p RuntimeMaxUSec -p BindsTo -p ControlGroup
```

Очікувано default memory 2147483648 bytes, swap 0, tasks 32, ненульові CPU quota/deadline і BindsTo winhub-linux-agent.service. Після завершення temporary unit прибирається. Для backup із високими RAM/threads спочатку налаштуйте локальні `TaskMemoryLimitMb`, `TaskProcessLimit`, `TaskCpuPercent`, перевірте `--validate-config`, перезапустіть службу; не вимикайте підписи/TLS. Ліміти не забороняють довіреному root/SYSTEM адміністратору створювати інші служби через systemd/SCM.

## Перевірено локально, не на клієнтських VM

- Windows managed self-contained RC3: build, 85 self-tests, включно з native Job Object cleanup і відмовою надмірного виділення пам'яті.
- Linux NativeAOT x64 у WSL Debian: build, 83 self-tests. Linux cgroup runner перевірено контрактно; справжній task service не запускався.
- Publisher Python → .NET verifier: валідний ZIP/TAR, чужий ключ, tamper, missing/extra files, version/platform/architecture/serial, floor corruption; також реальний Linux AOT verifier.
- Сервер: 158 tests, OK, 13 environment/platform skips; окремо Linux updater 14 tests, OK, 3 Windows skips. Windows PowerShell fixtures виконано в окремому процесі з явно дозволеним Bypass, без зміни системної policy.
- macOS managed compatibility build/self-test та NuGet vulnerable-package audit Windows/Linux (відомих vulnerable packages за поточними feeds не знайдено). Це не аудит вбудованого runtime/ОС або native Mac release.

Жодна з цих перевірок не замінює ваші service install/update/rollback/power-loss випробування та незалежну security-перевірку. Commit/push/deployment автоматично не виконувалися.
