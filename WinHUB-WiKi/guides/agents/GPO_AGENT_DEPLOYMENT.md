# Windows Agent deployment through GPO/DC

[Українська версія](#українська-версія)

The canonical deployment scripts are stored in `WinHUBAgentWindows/deploy/gpo/`. They are designed for a Computer Startup policy and are idempotent: they install a missing agent, transactionally update an older one, repair its service policy, and start a stopped service.

## Trust boundaries

- Treat `NETLOGON`/SYSVOL as an administrative channel. Only Domain/Enterprise Admins may modify the deployment directory; target computer accounts receive `Read & Execute` only.
- The agent ZIP must be signed by the offline release publisher according to the [release acceptance procedure](AGENT_RELEASE_ACCEPTANCE_UA.md). An unsigned build ZIP is not accepted.
- `deployment-manifest.json` pins the ZIP and publisher public-key SHA-256 values. The installer also verifies the signed `release-manifest.json` and complete file inventory.
- Obtain the TLS pin only from a trusted server leaf certificate. Never learn the pin through the same connection that has not yet been authenticated.
- Never place the private release key, TLS private key, or endpoint identity in SYSVOL.

## Domain controller directory

Copy these files to `\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy`:

```text
deployment-manifest.json
install-winhub-agent.cmd
install-winhub-agent.ps1
release-signing-public.pem
WinHUBAgent-v<VERSION>-win-x64.zip
winhub_agent.conf
winhub_agent.bootstrap.conf
```

Take the `.cmd` and `.ps1` files from `WinHUBAgentWindows/deploy/gpo/`. Replace the placeholder UNC in the `.cmd` with the real domain/DC path, using exactly two leading backslashes, or pass the source through `-SourceDir`. Copy `deployment-manifest.example.json` as `deployment-manifest.json` and calculate exact hashes:

```powershell
$package = '\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\WinHUBAgent-v<VERSION>-win-x64.zip'
$publicKey = '\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\release-signing-public.pem'
Get-FileHash -LiteralPath $package -Algorithm SHA256
Get-FileHash -LiteralPath $publicKey -Algorithm SHA256
```

Normally, leave `server_identity_epoch` empty. After an intentional server host-data reset, generate one UUID with `[guid]::NewGuid()`, publish it only after the reset, and keep the same UUID for ordinary agent releases. Each endpoint applies a new epoch once: it archives its old server token, task-signing state, and undelivered journal while preserving hardware/RSA identity, runtime configuration, and publisher trust floor. The bootstrap file then permits fresh enrollment into the new server inventory.

The ZIP must not contain runtime configuration, bootstrap secrets, PEM trust files, or mutable state.

## Configuration

`winhub_agent.conf` contains no enrollment secret:

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

`winhub_agent.bootstrap.conf` contains only the temporary enrollment key:

```json
{
  "GlobalApiKey": "ADMINISTRATOR_PROVISIONED_ENROLLMENT_TOKEN"
}
```

The installer copies the bootstrap only when an endpoint has no DPAPI secret store. The agent removes it after enrollment; an ordinary upgrade does not overwrite an enrolled endpoint's identity.

## Directory ACL

Example for a domain controller; verify localized group names first:

```powershell
$path = 'C:\Windows\SYSVOL\sysvol\<DOMAIN_FQDN>\scripts\WinHUBAgentDeploy'
icacls $path /inheritance:r
icacls $path /grant 'Domain Admins:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'Domain Computers:(OI)(CI)RX'
icacls $path
```

Do not grant write access to regular users or the target computer group.

## GPO configuration

1. Create a security group such as `WinHUB_Agent_Deploy_Canary` and add computer accounts such as `PC01$`.
2. Link the GPO to the OU containing those computers.
3. Grant the canary group `Read` and `Apply group policy`. Keep `Domain Computers` as `Read` only if the rollout must remain canary-scoped.
4. Enable `Always wait for the network at computer startup and logon`.
5. Add `install-winhub-agent.cmd` under `Computer Configuration → Policies → Windows Settings → Scripts → Startup`.
6. Reboot 1–5 canary endpoints first. `gpupdate /force` refreshes the policy but does not itself execute a Startup script.

The wrapper waits for SYSVOL for up to ten minutes. Before stopping an installed service, the PowerShell installer uses a global mutex, copies the ZIP to a private staging directory, verifies SHA-256, publisher signature and inventory, validates configuration offline, and performs a pinned HTTPS health preflight.

## Installer behavior

- **No agent:** install signed code, runtime configuration and one-time bootstrap; create a delayed-auto service.
- **Older version:** run the transactional updater with backup, stop/copy/start, and rollback on failed startup.
- **Same version:** preserve code and repair service recovery, watchdog, and running state.
- **Newer installed version:** block downgrade.
- **New `server_identity_epoch`:** archive server-bound state once and restore bootstrap for fresh enrollment. The same epoch does not reset the endpoint twice.
- **Wrong publisher key, hash, signature, TLS pin, or invalid configuration:** fail closed without stopping the existing service.

Logs are stored at:

```text
C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log
C:\ProgramData\WinHUB\gpo-install\install.log
C:\ProgramData\WinHUB\logs\agent.log
```

If the wrapper reports `deployment source is unavailable`, check that the `.cmd` no longer contains the literal `DC_FQDN`, the UNC starts with exactly `\\`, the deployment files exist, and the computer account has read access.

## Canary acceptance and rollout

```powershell
Get-Service WinHUBAgent | Format-List Name,Status,StartType
& 'C:\Program Files\WinHUBAgent\WinHUBAgent.exe' --version
Get-ScheduledTask -TaskName 'WinHUBAgent Watchdog'
Get-Content 'C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log' -Tail 50
Get-Content 'C:\ProgramData\WinHUB\gpo-install\install.log' -Tail 100
Get-Content 'C:\ProgramData\WinHUB\logs\agent.log' -Tail 100
```

Verify a single endpoint identity, Pending → manual Approved enrollment, Task v2, an ordinary task, reboot, watchdog self-heal, upgrade, and rollback in a disposable VM. Then roll out in small waves.

For an ordinary package update: update and health-check the server, publish the signed ZIP and public metadata, wait for DC replication, replace `deployment-manifest.json` last, then reboot canary endpoints followed by rollout waves. Do not rotate the publisher key during an ordinary release.

For server inventory reset, keep the strict order: server backup/update → `reset_host_data.sh` → health check → open enrollment window → publish one new `server_identity_epoch` → canary reboot/GPO → manual approval → rollout waves → close enrollment. Never publish the new epoch before resetting the server.

---

## Українська версія: розгортання Windows Agent через GPO/DC

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
