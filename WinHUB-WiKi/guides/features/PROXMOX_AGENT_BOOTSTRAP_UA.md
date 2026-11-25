# Proxmox → Windows VM → WinHUB Agent: тестування

Використовуємо **Software → Agent Bootstrap** та наявний HTTPS WinHUB. Окремий файловий сервіс і
доступ Windows до інтернету не потрібні. Образ Windows 9006 не змінюється: потрібні Cloudbase-Init та QEMU Guest Agent.

## 1. Оновити сервер із цієї робочої копії

Зміни ще не означають, що віддалений Git/production оновлено. Підготовлено локальний архів:

~~~text
WinHUB/dist/agent-bootstrap-20261124/winhub-v0.1.237.tar.gz
WinHUB/dist/agent-bootstrap-20261124/winhub-v0.1.237.manifest.json
~~~

Для повторного пакування у WSL:

~~~bash
cd /mnt/c/Users/spock/OpenCloud/Personal/WinHUB_Project/WinHUB
OUT_DIR="$PWD/dist/agent-bootstrap-20261124" bash deploy/create_release.sh
~~~

Звірте SHA-256 із manifest до та після доставки. На сервері застосуйте штатний updater, який
робить backup і міграції. Приклад після доставки архіву під окремим ім’ям:

~~~bash
sudo bash /opt/winhub/deploy/debian/update_winhub.sh /root/winhub-bootstrap-20261124.tar.gz
~~~

Міграція **20261124_01** додає agent_bootstrap_grants. Версію сервера навмисно не підвищено:
це тестова збірка робочої копії, не опублікований release. Перевірте успіх міграції/healthcheck,
потім Ctrl+F5. Новий маршрут вкладений у вже проксований /api/public/software-delivery/.
Agent proxy має пропускати цей prefix, /api/agent/enroll, poll, result та /api/health.

## 2. Підписати пакети

Native self-contained builds **2.0.1-rc.4** підготовлені, але ще не підписані вашим ключем.
Windows bootstrap source:

~~~text
WinHUBAgentWindows/dist-agent/bootstrap-publish-2.0.1-rc.4/
~~~

Він містить рівно шість файлів до підписування:

~~~text
WinHUBAgent.exe
appsettings.json
install-service.ps1
uninstall-service.ps1
update-service.ps1
update-protocol.json
~~~

Signer додає release-signing-public.pem і release-manifest.json. Саме цей мінімальний inventory
потрібен поточному Windows installer. Не завантажуйте звичайний unsigned dist ZIP, README,
runtime .conf або enrollment secrets. Для наступної збірки створіть новий native publish,
скопіюйте шість файлів у новий мінімальний каталог і підпишіть нові version/serial.

У локальному інтерактивному PowerShell виконуйте по черзі:

~~~powershell
Set-Location 'C:\Users\spock\OpenCloud\Personal\WinHUB_Project'
[long]$windowsSerial = Read-Host 'Новий невикористаний Windows release serial'
& .\WinHUB\.venv\Scripts\python.exe .\WinHUBLinuxAgent\tools\sign-release.py sign --source .\WinHUBAgentWindows\dist-agent\bootstrap-publish-2.0.1-rc.4 --output .\WinHUBAgentWindows\dist-agent\signed\bootstrap\WinHUBAgent-v2.0.1-rc.4-win-x64.zip --key C:\WinHUB-ReleaseKeys\release-signing-private.pem --platform windows --architecture x64 --version 2.0.1-rc.4 --serial $windowsSerial --bundle-public-key
if ($LASTEXITCODE -ne 0) { throw 'Windows signing failed' }
~~~

Linux source визначається через build manifest:

~~~powershell
$lm = Get-Content .\WinHUBLinuxAgent\dist-agent\WinHUBLinuxAgent-v2.0.1-rc.4-linux-x64.tar.gz.manifest.json -Raw | ConvertFrom-Json
$linuxSource = Join-Path (Resolve-Path .\WinHUBLinuxAgent\dist-agent).Path (Split-Path -Leaf $lm.publish_directory)
[long]$linuxSerial = Read-Host 'Новий невикористаний Linux release serial'
& .\WinHUB\.venv\Scripts\python.exe .\WinHUBLinuxAgent\tools\sign-release.py sign --source $linuxSource --output .\WinHUBLinuxAgent\dist-agent\signed\WinHUBLinuxAgent-v2.0.1-rc.4-linux-x64.tar.gz --key C:\WinHUB-ReleaseKeys\release-signing-private.pem --platform linux --architecture x64 --version 2.0.1-rc.4 --serial $linuxSerial --bundle-public-key
if ($LASTEXITCODE -ne 0) { throw 'Linux signing failed' }
~~~

Serial мають бути новими й більшими за вже використані. Passphrase вводиться приховано самому
signer. Private key не передається на сервери. Збережіть SHA-256 signed архівів; готові output не перезаписуються.

## 3. Оновити Linux Agent на одному тестовому Proxmox

Доставте signed Linux 2.0.1-rc.4 через Fleet Center або штатний SSH rollout. Перевірте версію,
online/poll і просту підписану задачу. Token/identity/pinned task key зберігайте.
Старий 2.0.1-rc.3 не підтримує capability **proxmox-bootstrap-v1**: така задача має чекати оновлення,
а не запускатися частково. Для Linux-задач потрібен дозволений run_script.
macOS цей режим не підтримує і capability не рекламує.

## 4. Додати Software → Agent Bootstrap

1. Відкрийте **Software → Agent Bootstrap** із manage_software.
2. Name: WinHUB Windows Agent; version: **2.0.1-rc.4**.
3. Upload: signed Windows ZIP із dist-agent/signed/bootstrap/.
4. Expected SHA-256: хеш саме signed ZIP.
5. Trusted PUBLIC key: вміст C:\WinHUB-ReleaseKeys\release-signing-public.pem.
6. Clean runtime JSON: реальний HTTPS ServerUrl, доступний із Windows, та trusted TLS pin.
7. Superadmin переглядає дані, ставить **Review and approve**, зберігає.
8. Скопіюйте показаний **package ID**.

Мінімальна конфігурація (замініть placeholders):

~~~json
{
  "ServerUrl": "https://WINHUB_INTERNAL_HOST:55555",
  "ServerCertificateSha256": "TRUSTED_CERTIFICATE_SHA256_64_HEX",
  "ServerCertificateSha256Next": "",
  "IgnoreTlsCertificateErrors": false,
  "RequireTaskSignature": true,
  "GlobalApiKey": "",
  "TaskHmacSecret": "",
  "TaskSigningPublicKeyPem": "",
  "TaskSigningKeyId": "",
  "TaskSigningLastSequence": 0,
  "StartupSpreadSeconds": 0
}
~~~

Не вставляйте глобальний AGENT_API_KEY, endpoint identity або task signing keys іншого агента.
ServerUrl/pin візьміть із перевіреного підключення; TLS pin не є хешем publisher key.
WinHUB видає окремий обмежений enrollment token для нової ВМ.
Сервер перевіряє ZIP-підпис, inventory, платформу, версію, hash/size. Зміна пакета/config/key
скасовує approval. Bootstrap-пакети не потрапляють до звичайних застосунків чи sets.

## 5. Імпорт шаблону та Validate

Імпортуйте актуальний [proxmox_vm_create_pack.json](../../../WinHUB/deploy/import_templates/proxmox_vm_create/proxmox_vm_create_pack.json).
Перегляньте й затвердьте action **Proxmox — Create Windows VM**.
Виберіть один тестовий Proxmox endpoint:

| Поле | Значення |
| --- | --- |
| Source template VMID | 9006 |
| Proxmox VM name | Наприклад term-192.168.38.240 |
| Windows hostname | Порожньо або коротке ім’я до 15 символів |
| New VM ID | Порожньо — перший вільний від 100 |
| Operation | Validate |
| Target storage | local |
| IP/mask/gateway/DNS | Параметри з новою вільною IP |
| Agent Bootstrap package ID | ID зі вкладки Agent Bootstrap |

CPU/RAM/disk/bridge/VLAN можна успадкувати. Timeout задачі — **45–60 хвилин**, з урахуванням
full clone, до 15 хвилин очікування Windows і до 11 хвилин установки/реєстрації.
Validate перевіряє approval пакета на сервері та параметри ВМ на Proxmox, але не створює ВМ,
не видає enrollment token і не перевіряє мережевий доступ майбутньої Windows.

## 6. Create та критерії успіху

Змініть Operation на **Create**. Bootstrap дозволений лише для інтерактивного ручного запуску
із run_tasks/manage_software, доступом до одного Linux endpoint та чинними approvals.
API keys, Scheduler і Triggers для цього режиму не допускаються.

Порядок: Full Clone → ConfigDrive/мережа → запуск → перевірка завершення Cloudbase-Init через QGA →
передача короткого сценарію/descriptor через stdin → завантаження ZIP самою Windows із WinHUB →
перевірка pinned HTTPS/hash/signature → встановлення служби/public key → підтвердження реєстрації сервером.

У результаті:

~~~json
{
  "agent_installed": true,
  "agent_registered": true,
  "endpoint_id": "NEW_ENDPOINT_ID",
  "approval_status": "Pending",
  "agent_version": "2.0.1-rc.4",
  "bootstrap_package_id": "SELECTED_PACKAGE_ID"
}
~~~

Перевірте новий хост, виконайте **Approval**, призначте групи. Запустіть hostname через Windows-агент,
потім одну звичайну Software installation. Перевірте RDP, змініть тимчасовий Administrator password.
На Windows перевірте службу WinHUBAgent та public key у C:\ProgramData\WinHUB\release-signing-public.pem.
Запущена служба без agent_registered=true не є успішним завершенням.

## 7. Негативні тести й відновлення

- Порожній package ID → звичайне створення, без агента.
- Непідписаний/змінений ZIP, чужий public key → відмова при збереженні пакета.
- Пакет/config без актуального approval → grant не видається.
- Старий Linux Agent → upgrade_required до запуску.
- Cloudbase-Init ERROR або немає QGA → установка не починається, ВМ зберігається.
- Неправильний pin/недоступний HTTPS → download failure без TLS bypass.
- Enrollment source ACL не дозволяє нову мережу → фаза enrollment неуспішна, навіть якщо служба active.
- Скасована/прострочена parent task, блокування Proxmox або відкликані права → capabilities відхиляються.
- Enrollment token допускає лише один hw_id + RSA fingerprint і hostname. Повтор відповіді — лише для тієї самої ідентичності.

Grant діє **60 хвилин від dispatch**. Якщо прострочений до виконання, Create не починає клонування.
Після помилки спочатку перевірте частково створену ВМ та зайняту IP. Generic Retry failed не копіює
старі bootstrap credentials. Автоматичного resume установки на вже створеній ВМ немає.
Повторний Create із тією самою IP без огляду може створити конфлікт.

Безпечні фази помилки: preflight, download, signature, install, enrollment.
На Windows перевіряйте Get-Service WinHUBAgent і Application event log; tokens/descriptor у чат не надсилайте.
Вже наявний агент/identity bootstrap автоматично не перевстановлює.

## Межі перевірки

Локальні тести й native builds не підтверджують повний QGA → PowerShell → installation на живій ВМ.
Production upgrade/install і native macOS signing у цій задачі не виконувалися.
Для першого тесту потрібен ізольований стенд, вільні IP/VMID і доступ до консолі.
ConfigDrive у цій реалізації автоматично не вилучається.
