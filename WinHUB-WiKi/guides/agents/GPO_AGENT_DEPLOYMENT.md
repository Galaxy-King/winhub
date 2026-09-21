# Розгортання Windows Agent через GPO/DC

Канонічні deployment scripts лежать у `WinHUBAgentWindows/deploy/gpo/`. Вони призначені для Computer Startup policy і є ідемпотентними: встановлюють відсутній агент, транзакційно оновлюють старіший, ремонтують службу та запускають її, якщо вона зупинена.

## Межі довіри

- `NETLOGON`/SYSVOL є адміністративним каналом: змінювати каталог можуть лише Domain/Enterprise Admins; цільові computer accounts мають тільки `Read & Execute`.
- Агентський ZIP має бути підписаний offline publisher за [процедурою приймання релізу](AGENT_RELEASE_ACCEPTANCE_UA.md). Unsigned build ZIP не підходить.
- Deployment manifest фіксує SHA-256 ZIP і public key. Installer додатково перевіряє signed `release-manifest.json` та повний inventory файлів.
- TLS pin береться лише з довіреного leaf certificate сервера. Не отримуйте pin через з’єднання, яке саме ще не перевірено.
- Private release key, TLS private key та endpoint identity ніколи не потрапляють у SYSVOL.

## Каталог DC

Скопіюйте до `\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy`:

```text
deployment-manifest.json
install-winhub-agent.cmd
install-winhub-agent.ps1
release-signing-public.pem
WinHUBAgent-v<VERSION>-win-x64.zip
winhub_agent.conf
winhub_agent.bootstrap.conf
```

Візьміть `.cmd` і `.ps1` із `WinHUBAgentWindows/deploy/gpo/`, замініть лише default UNC у `.cmd` або передавайте його через `-SourceDir`. `deployment-manifest.example.json` скопіюйте як `deployment-manifest.json` і внесіть точні значення:

```powershell
$package = '\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\WinHUBAgent-v<VERSION>-win-x64.zip'
$publicKey = '\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\release-signing-public.pem'
Get-FileHash -LiteralPath $package -Algorithm SHA256
Get-FileHash -LiteralPath $publicKey -Algorithm SHA256
```

`server_identity_epoch` зазвичай лишається порожнім. Після навмисного server host-data reset задайте **один новий UUID** (`[guid]::NewGuid()`), опублікуйте manifest лише після reset і більше не змінюйте цей UUID для звичайних agent releases. На кожному endpoint значення застосовується один раз: старий server token, task signing state і недоставлений journal переносяться в локальний protected backup; hardware ID, RSA identity, runtime config і publisher floor зберігаються; bootstrap дозволяє fresh enrollment у нову server inventory. Без epoch старий DPAPI token не може автоматично зареєструватися після видалення server endpoint rows.

У ZIP не повинно бути runtime config, bootstrap secret, PEM trust або state. Це забезпечує offline signer.

## Конфігурація

`winhub_agent.conf` не містить enrollment secret:

```json
{
  "ServerUrl": "https://winhub.example.com",
  "GlobalApiKey": "",
  "PollIntervalSeconds": 30,
  "PollJitterSeconds": 30,
  "StartupSpreadSeconds": 120,
  "TaskHmacSecret": "",
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false,
  "ServerCertificateSha256": "64_HEX_LEAF_CERTIFICATE_SHA256",
  "ServerCertificateSha256Next": "",
  "RequireTaskSignature": true,
  "RestartAfterConsecutivePollFailures": 10
}
```

`winhub_agent.bootstrap.conf` містить тільки тимчасовий enrollment key:

```json
{
  "GlobalApiKey": "ADMINISTRATOR_PROVISIONED_ENROLLMENT_TOKEN"
}
```

Bootstrap копіюється лише коли endpoint ще не має DPAPI secret store. Після enrollment агент видаляє bootstrap. GPO installer не копіює його повторно на enrolled endpoint.

## ACL каталогу

Приклад на DC (перед виконанням звірте локалізовані назви груп):

```powershell
$path = 'C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy'
icacls $path /inheritance:r
icacls $path /grant 'Domain Admins:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'Domain Computers:(OI)(CI)RX'
icacls $path
```

Не надавайте write звичайним користувачам або target computer group.

## GPO

1. Створіть security group, наприклад `WinHUB_Agent_Deploy_Canary`, і додайте computer accounts (`PC01$`).
2. Створіть GPO та прив’яжіть до OU з комп’ютерами.
3. У Security Filtering дайте canary group `Read` + `Apply group policy`; Domain Computers — `Read`, без `Apply`.
4. Увімкніть `Always wait for the network at computer startup and logon`.
5. Додайте `install-winhub-agent.cmd` у `Computer Configuration → Policies → Windows Settings → Scripts → Startup`.
6. Спочатку перезавантажте 1–5 canary endpoint-ів.

Wrapper чекає SYSVOL до 10 хвилин. PowerShell installer використовує global mutex, приватну копію ZIP, SHA-256, signature/inventory verification, offline config validation і pinned HTTPS preflight до зупинки чинної служби.

## Поведінка

- **Немає агента:** config + одноразовий bootstrap, підписаний код, service install, delayed automatic start.
- **Версія старіша:** штатний `update-service.ps1`, backup, preflight, stop/copy/start, rollback при невдалому старті.
- **Версія збігається:** код не переписується; відновлюються service recovery, watchdog і Running state.
- **Версія новіша:** downgrade блокується.
- **Новий `server_identity_epoch`:** server-bound state архівується один раз, bootstrap повертається для нового enrollment; повторний запуск із тим самим epoch нічого не скидає.
- **Інший publisher key, поганий hash/signature/pin/config:** fail closed; чинний service не зупиняється.

Watchdog працює від SYSTEM кожні 5 хвилин і не запускає service, поки transactional updater тримає lock. Логи:

```text
C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log
C:\ProgramData\WinHUB\gpo-install\install.log
C:\ProgramData\WinHUB\logs\agent.log
```

## Canary acceptance

На тестовому endpoint:

```powershell
Get-Service WinHUBAgent | Format-List Name,Status,StartType
& 'C:\Program Files\WinHUBAgent\WinHUBAgent.exe' --version
Get-ScheduledTask -TaskName 'WinHUBAgent Watchdog'
Get-Acl 'C:\Program Files\WinHUBAgent' | Format-List Owner,AccessToString
Get-Acl 'C:\ProgramData\WinHUB' | Format-List Owner,AccessToString
Get-Content 'C:\ProgramData\WinHUB\logs\agent.log' -Tail 100
```

Перевірте: один endpoint без дубля, Pending → manual Approved, Task v2, звичайна задача, reboot, stop/self-heal, upgrade і rollback у disposable VM. Масове розгортання починайте малими хвилями. Поточний RC залишається release candidate, доки не пройдені живі gates із [production status](PRODUCTION_PIN_AGENTS_UA.md).

## Оновлення пакета

1. Спочатку оновіть сервер і перевірте healthcheck.
2. Зберіть та offline-підпишіть нову версію з новим monotonic release serial.
3. Покладіть новий ZIP у deployment folder.
4. Атомарно замініть `deployment-manifest.json` останнім, коли ZIP вже повністю реплікований усіма DC.
5. Canary → хвилі → domain rollout.

Не замінюйте publisher public key під час звичайного релізу. Його ротація — окрема процедура.

Для сценарію server reset порядок жорсткий: server backup/update → `reset_host_data.sh` → перевірка health → відкрити enrollment window → встановити новий `server_identity_epoch` у manifest → canary reboot/GPO → manual approve → хвилі → закрити enrollment. Не публікуйте новий epoch до server reset.
