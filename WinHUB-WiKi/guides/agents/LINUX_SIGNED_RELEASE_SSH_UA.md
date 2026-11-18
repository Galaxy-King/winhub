# Linux release: підписування, public key та встановлення через SSH

## Перевірений локальний стан

На початку цієї задачі найновіші локальні Windows/Linux build packages мали версію
2.0.1-rc.1 (2026-10-23), unsigned. Локальний сервер VERSION — 0.1.237.
Версії server/agent не мають збігатися чисельно: сумісність визначає протокол.
Linux і Windows підтримують RSA-PSS task v2, signed requests, identity-session/split,
lean poll, execution journal та publisher-signed updates із anti-rollback.
Linux має Bash/root + systemd/cgroup limits; Windows — PowerShell/Job Object та Software delivery.
Windows-specific Software delivery не додається до Linux заради однакових capabilities.
Це перевірка локального checkout; версія встановленого віддаленого сервера не перевірялася.

Для Linux підготовлено 2.0.1-rc.3 із поточних sources, оновленим installer і runtime/AOT 8.0.33.
Проміжний unsigned 2.0.1-rc.2 з runtime 8.0.29 не встановлювати/не підписувати.
Старі пакети збережено. RC залишається кандидатом до приймання на тестовому endpoint.

## Підписування на Windows

Виконуйте з кореня репозиторію в інтерактивному PowerShell. Приватний ключ і passphrase
не передаються в SSH, WinHUB, змінні середовища чи чат. Новий ключ не генеруйте.

```powershell
$version = '2.0.1-rc.3'
$manifestPath = ".\WinHUBLinuxAgent\dist-agent\WinHUBLinuxAgent-v$version-linux-x64.tar.gz.manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$source = Join-Path (Resolve-Path '.\WinHUBLinuxAgent\dist-agent').Path (Split-Path -Leaf $manifest.publish_directory)
$output = Join-Path (Get-Location).Path "WinHUBLinuxAgent\dist-agent\signed\WinHUBLinuxAgent-v$version-linux-x64.tar.gz"
[long]$serial = Read-Host 'Наступний невикористаний release serial, більший за всі попередні'
& .\WinHUB\.venv\Scripts\python.exe .\WinHUBLinuxAgent\tools\sign-release.py sign --source $source --output $output --key C:\WinHUB-ReleaseKeys\release-signing-private.pem --platform linux --architecture x64 --version $version --serial $serial --bundle-public-key
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
Get-FileHash -LiteralPath $output -Algorithm SHA256
Get-FileHash -LiteralPath C:\WinHUB-ReleaseKeys\release-signing-public.pem -Algorithm SHA256
scp $output root@t51ps:/root/
ssh root@t51ps
```

Passphrase запитає сам signer у вашому терміналі. `--bundle-public-key` виводить public key
з private signing key, додає його до підписаного inventory, не копіює private PEM.
Це не механізм автоматичного затвердження невідомого ключа: спочатку довірена доставка/checksum.
Signer не перезаписує готовий output. Не змінюйте publish folder після підписування.

## На Proxmox через SSH

```bash
sha256sum /root/WinHUBLinuxAgent-v2.0.1-rc.3-linux-x64.tar.gz
```

Звірте SHA-256 із PowerShell. Продовжуйте лише при точному збігу.

```bash
umask 077
agent_stage=$(mktemp -d /root/winhub-agent-install.XXXXXX)
tar -xzf /root/WinHUBLinuxAgent-v2.0.1-rc.3-linux-x64.tar.gz -C "$agent_stage"
cd "$agent_stage"
sha256sum release-signing-public.pem
```

Звірте public PEM SHA-256 із оригіналом у C:\WinHUB-ReleaseKeys (signer генерує public SPKI PEM).
Для першого встановлення готуйте конфіги за
[інструкцією Proxmox](../features/PROXMOX_VM_CREATE_UA.md#копіювання-та-встановлення):
HTTPS ServerUrl, trusted certificate pin, bootstrap enrollment key, root-only permissions.
Це окремі credentials: release public key не замінює TLS pin/enrollment key/task signing identity.
Наявні runtime config, token, RSA identity та release-state не видаляйте й не замінюйте.

```bash
./WinHUBLinuxAgent --version
./WinHUBLinuxAgent --self-test
./WinHUBLinuxAgent --validate-config /etc/winhub-agent/winhub_agent.conf
./WinHUBLinuxAgent --check-update-server /etc/winhub-agent/winhub_agent.conf
bash ./install-linux-agent.sh
systemctl is-active winhub-linux-agent
journalctl -u winhub-linux-agent -n 50 --no-pager
stat -c '%U:%G %a %n' /var/lib/winhub-agent/release-signing-public.pem
sha256sum /var/lib/winhub-agent/release-signing-public.pem
```

Після встановлення очікуємо root:root 600, той самий SHA-256 public PEM та версію 2.0.1-rc.3
у WinHUB. Інший наявний release key призводить до відмови до зупинки служби; це окрема
процедура ротації, а не привід видалити trust-файл. Якщо unsigned пакет не має bundled PEM,
installer зберігає стару поведінку; для цього сценарію використовуйте саме signed output.

## Наступні оновлення

Кожний наступний пакет потрібно підписувати тим самим private key з новими version/serial.
У Fleet Center завантажуйте signed archive та SHA-256 саме signed archive.
Agent updater перевіряє пакет за вже встановленим public key; bundled key наступного пакета
не підміняє trust у data directory. Signed `agent_update` також потребує чинного TLS pin та прав.
Public key сам по собі не вмикає автоматичний пошук чи розгортання нових версій.

Native Linux self-test не дорівнює перевірці встановлення/upgrade через systemd на реальному Proxmox.
Підписування чинним зашифрованим private key виконує власник інтерактивно; агент розробки
не має passphrase, не читає private key та не повідомляє unsigned build як підписаний.
