# Production macOS Agent: збірка, підпис і notarization на MacBook M4

Цей документ описує повний шлях від чистого MacBook до production-релізу, першого
встановлення, MDM-rollout і штатного оновлення WinHUB Agent. Цільова платформа — Apple
Silicon `arm64`, macOS 14 або новіша, .NET 10 LTS Native AOT.

## 1. Що саме будується

Агент є системним `LaunchDaemon`, а не GUI-застосунком. Він працює від `root`, тому що має
збирати системний inventory, виконувати явно дозволені адміністративні задачі й оновлювати
власні root-owned файли. Постійного вхідного порту немає: агент сам відкриває вихідне HTTPS-
з’єднання до WinHUB.

Production release містить три різні артефакти:

| Артефакт | Для чого потрібен |
| --- | --- |
| `macos-arm64.tar.gz` + SHA-256 | Кероване self-update через WinHUB. Агент перевіряє SHA-256, версію, Apple-підпис і Team ID. |
| `macos-arm64.pkg` + SHA-256 | Перше встановлення або MDM. Пакет підписаний `Developer ID Installer`, notarized і має stapled ticket. |
| `macos-arm64-installer.zip` + SHA-256 | Зручний комплект: notarized `.pkg`, setup-скрипт і приклади конфігів. |

Не завантажуйте `.pkg` у **Infrastructure → Agent Packages**: цей розділ очікує update-
архів `.tar.gz`. `.pkg` призначений для Apple Installer/MDM.

## 2. Навіщо потрібні підпис і notarization

Є два незалежні підписи:

- `Developer ID Application` підписує виконуваний Mach-O файл агента. Він дає macOS сталу
  identity: Apple Team ID + code-signing identifier `com.winhub.agent`. Цю identity updater
  використовує, щоб не прийняти binary від іншого розробника.
- `Developer ID Installer` підписує весь `.pkg`, включно зі скриптами й системними шляхами.
  Gatekeeper може перевірити, хто створив інсталятор і чи не змінили його після підпису.

Notarization — окрема автоматична перевірка Apple на malware і помилки code signing.
`stapler` прикріплює ticket до `.pkg`, тому Gatekeeper може підтвердити його навіть коли
служба Apple тимчасово недоступна. Apple вимагає Developer ID, secure timestamp і Hardened
Runtime для прямого розповсюдження; актуальний процес використовує `notarytool`, не
застарілий `altool`.

Офіційні джерела:

- [Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Packaging Mac software for distribution](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)

Code signing не надає Full Disk Access, Screen Recording, Accessibility або інші TCC-
дозволи. Вони керуються користувачем або MDM PPPC-профілем окремо.

## 3. Підготовка MacBook M4

### 3.1. Захист build host

1. Оновіть macOS і ввімкніть FileVault. Це захищає приватні ключі сертифікатів на диску.
2. Створіть окремого локального build-користувача з довгим паролем. Не використовуйте цей
   профіль для повсякденного browsing/mail.
3. Якщо потрібен SSH, увімкніть **System Settings → General → Sharing → Remote Login** лише
   для build-користувача й використовуйте SSH key authentication.
4. Не синхронізуйте Keychain, `.p12`, `.p8`, provisioning configs або checkout із публічною
   хмарною папкою. Репозиторій ніколи не повинен містити production secrets.
5. Увімкніть Time Machine або інший encrypted backup. Окремо збережіть encrypted backup
   signing keys у контрольованому password vault.

### 3.2. Xcode та command-line tools

Встановіть актуальний Xcode з App Store, запустіть його один раз, прийміть license, потім:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
xcode-select -p
xcrun --find clang
xcrun notarytool --version
codesign --version
pkgbuild --version
```

Clang потрібен Native AOT linker-у. `codesign`, `pkgbuild`, `notarytool` і `stapler` потрібні
для Apple supply chain. Для повного notarized release використовуйте актуальний повний
Xcode; лише Command Line Tools залиште для локальних development-збірок.

### 3.3. .NET 10 SDK Arm64

Встановіть останній **.NET 10 SDK for macOS Arm64**, не x64 Runtime:

```bash
uname -m
dotnet --info
dotnet --list-sdks | grep '^10\.'
```

`uname -m` має повернути `arm64`. Проєкт має локальний `WinHUBMacAgent/global.json`, який
вибирає останній встановлений stable .NET 10 feature band. Агент self-contained, тому на
endpoint Mac встановлювати .NET не потрібно.

.NET 10 — чинний LTS до 14 листопада 2028 року; .NET 8 завершує підтримку 10 листопада
2026 року. Перевіряйте security patch перед кожним release:

- [.NET support policy](https://dotnet.microsoft.com/platform/support/policy/dotnet-core)
- [Install .NET on macOS](https://learn.microsoft.com/dotnet/core/install/macos)

## 4. Apple Developer Program і сертифікати

Потрібне активне членство організації в Apple Developer Program. Account Holder створює
два сертифікати в **Certificates, Identifiers & Profiles → Certificates → + → Developer ID**:

1. `Developer ID Application` — для `WinHUBMacAgent` і всіх вкладених Mach-O файлів.
2. `Developer ID Installer` — для фінального `.pkg`.

### 4.1. Створення CSR

На build Mac відкрийте **Keychain Access → Certificate Assistant → Request a Certificate
From a Certificate Authority**, введіть Apple Account email, виберіть **Saved to disk** і
завантажте `.certSigningRequest` у Developer Portal. Після завантаження `.cer` відкрийте його
на тому самому Mac. У Keychain сертифікат повинен мати вкладений private key.

Не створюйте CSR на випадковому комп’ютері: без приватного ключа на build Mac сертифікат
не зможе підписувати.

### 4.2. Перевірка identities

```bash
security find-identity -v
security find-identity -v -p codesigning
```

Очікуйте записи на кшталт:

```text
Developer ID Application: Example Corp (ABCDE12345)
Developer ID Installer: Example Corp (ABCDE12345)
```

`ABCDE12345` — Apple Team ID. Обидві identity повинні належати одній команді. Якщо однакових
імен декілька, у release variables використовуйте SHA-1 fingerprint identity з виводу
`security find-identity`, щоб вибір був однозначним.

Для SSH-сесії може знадобитися розблокувати login Keychain. Не передавайте пароль у
командному рядку:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Підписуйте звичайним build-користувачем, не запускайте `codesign` через `sudo`: Apple прямо
застерігає, що зміна user context створює проблеми з доступом до signing identity.

## 5. Облікові дані notarization

Release script приймає лише ім’я Keychain profile, а не Apple password/API secret.

### Варіант A — App Store Connect API key (краще для CI)

Створіть API key в App Store Connect, безпечно перенесіть `AuthKey_<KEY_ID>.p8` на build Mac,
поставте mode `0600` і один раз збережіть profile:

```bash
chmod 600 ~/Secure/AuthKey_KEYID.p8
xcrun notarytool store-credentials "winhub-notary" \
  --key ~/Secure/AuthKey_KEYID.p8 \
  --key-id "KEYID" \
  --issuer "ISSUER_UUID"
```

### Варіант B — Apple Account + app-specific password

Створіть app-specific password в Apple Account і виконайте інтерактивне збереження profile:

```bash
xcrun notarytool store-credentials "winhub-notary" \
  --apple-id "build@example.com" \
  --team-id "ABCDE12345"
```

`notarytool` запросить secret і збереже його в Keychain. Якщо ваша версія Xcode вимагає
`--password`, використовуйте app-specific password, не основний пароль Apple Account, і не
комітьте команду з password у shell history.

Перевірка profile:

```bash
xcrun notarytool history --keychain-profile "winhub-notary"
```

## 6. Checkout на build Mac

Повний серверний стек не потрібен. Достатньо sparse checkout:

```bash
mkdir -p ~/Build
cd ~/Build
git clone --filter=blob:none --no-checkout git@github.com:Galaxy-King/winhub.git WinHUB-agent-build
cd WinHUB-agent-build
git sparse-checkout init --no-cone
git sparse-checkout set --no-cone \
  /WinHUB/VERSION \
  /global.json \
  /.gitignore \
  /.gitattributes \
  /WinHUBMacAgent/ \
  /WinHUBLinuxAgent/Worker.cs
git checkout main
```

Перед release:

```bash
git pull --ff-only origin main
git status --short
git log -1 --show-signature
```

`git status --short` має бути порожнім. Release script також блокує dirty tracked worktree;
це пов’язує binary з review-нутим commit. `WINHUB_ALLOW_DIRTY_BUILD=1` існує лише для
не-релізного тесту.

## 7. Повна production-збірка

У `WinHUB/VERSION` має бути потрібна semver-версія. Потім:

```bash
cd ~/Build/WinHUB-agent-build/WinHUBMacAgent

WINHUB_CODESIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
WINHUB_INSTALLER_IDENTITY="Developer ID Installer: Example Corp (ABCDE12345)" \
WINHUB_NOTARY_PROFILE="winhub-notary" \
  ./create-macos-agent-release.sh
```

Скрипт послідовно:

1. Перевіряє macOS/arm64, .NET 10, Xcode, clean Git і Bash syntax. Це відсікає неправильний
   build host і неповний checkout до появи артефактів.
2. Виконує self-contained Native AOT publish. Endpoint не залежить від установленого .NET і
   має меншу поверхню runtime deployment.
3. Підписує кожний Mach-O з secure timestamp і Hardened Runtime, а main binary — зі сталою
   identity `com.winhub.agent`. Підпис вкладених бібліотек запобігає частково підписаному
   релізу.
4. Перевіряє `arm64`, embedded version, code signature і запускає protocol self-test. Версія
   в UI/rollout і binary не можуть випадково розійтися.
5. Створює update archive та SHA-256 для WinHUB control plane.
6. Створює `.pkg` із LaunchDaemon, updater/uninstaller/diagnostics і `newsyslog` policy;
   підписує його `Developer ID Installer` тієї самої Team ID.
7. Відправляє `.pkg` у Apple через `notarytool --wait`, вимагає `Accepted`, прикріплює ticket
   через `stapler` і запускає Gatekeeper assessment.
8. Створює installer bundle і SHA-256 для передачі адміністратору/MDM.

Артефакти з’являться в `WinHUBMacAgent/dist-agent/`.

### Лише signed update archive

Коли `.pkg` для цього релізу не потрібен:

```bash
WINHUB_UPDATE_ONLY=1 \
WINHUB_CODESIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
  ./create-macos-agent-release.sh
```

### Локальна development-збірка

```bash
WINHUB_ALLOW_UNSIGNED_BUILD=1 WINHUB_ALLOW_DIRTY_BUILD=1 \
  ./create-macos-agent-release.sh
```

Вона ad-hoc signed, не notarized і придатна лише для ізольованого test Mac. Не завантажуйте
її до production WinHUB і не роздавайте користувачам.

## 8. Незалежна перевірка release

```bash
cd dist-agent
shasum -a 256 -c WinHUBMacAgent-v*-macos-arm64.tar.gz.sha256
shasum -a 256 -c WinHUBMacAgent-v*-macos-arm64.pkg.sha256
shasum -a 256 -c WinHUBMacAgent-v*-macos-arm64-installer.zip.sha256

pkgutil --check-signature WinHUBMacAgent-v*-macos-arm64.pkg
xcrun stapler validate WinHUBMacAgent-v*-macos-arm64.pkg
spctl --assess --type install --verbose=2 WinHUBMacAgent-v*-macos-arm64.pkg
```

Перевіряйте release також на окремому чистому Mac, де немає build certificates і попередньої
інсталяції. Це виявляє приховані залежності від build environment.

## 9. Перше production-встановлення

Передайте endpoint-адміністратору installer ZIP і його SHA-256 захищеним каналом. Після
перевірки SHA-256:

```bash
unzip WinHUBMacAgent-v<VERSION>-macos-arm64-installer.zip
cd WinHUBMacAgent-v<VERSION>-macos-arm64-installer
WINHUB_EXPECTED_TEAM_ID="ABCDE12345" ./setup-macos-agent.sh
```

Setup:

- спочатку перевіряє `Developer ID Installer`, Team ID і Gatekeeper;
- читає Server URL/enrollment/HMAC secrets без echo і shell history;
- створює root-only provisioning stage в `/private/var/tmp/com.winhub.agent.provisioning`;
- запускає Apple Installer;
- package postinstall переносить конфіги з mode `0600`, видаляє stage і запускає service;
- setup чекає до 10 секунд, що daemon залишається в стані `running`.

Після успішного enrollment агент видаляє enrollment key зі свого secret state. Якщо пізніше
потрібен контрольований re-enrollment, адміністратор має знову надати короткоживучий
bootstrap config; це безпечніше, ніж безстроково зберігати fleet-wide enrollment credential
на кожному endpoint.

Потім:

```bash
sudo launchctl print system/com.winhub.agent
sudo /Library/PrivilegedHelperTools/com.winhub.agent/diagnose-macos-agent.sh
tail -n 100 /Library/Logs/WinHUB/agent.log
```

Endpoint з’явиться у WinHUB Review Center. Перевірте hostname, IP, OS, FileVault, Team ID
deployment source і лише після цього підтвердьте enrollment.

## 10. Unattended/MDM deployment

`.pkg` навмисно не містить tenant secrets. Для MDM є два безпечні сценарії:

1. MDM доставляє root-owned `winhub_agent.conf` і `winhub_agent.bootstrap.conf`, запускає
   `setup-macos-agent.sh --pkg ... --config ... --bootstrap-config ...`, після чого видаляє
   deployment copies.
2. MDM створює root-owned directory `/private/var/tmp/com.winhub.agent.provisioning` з mode
   `0700`, кладе два конфіги з mode `0600`, потім встановлює `.pkg`. Postinstall приймає лише
   regular root-owned JSON files і видаляє directory до запуску агента.

Приклад другого сценарію:

```bash
sudo install -d -o root -g wheel -m 0700 /private/var/tmp/com.winhub.agent.provisioning
sudo install -o root -g wheel -m 0600 winhub_agent.conf \
  /private/var/tmp/com.winhub.agent.provisioning/winhub_agent.conf
sudo install -o root -g wheel -m 0600 winhub_agent.bootstrap.conf \
  /private/var/tmp/com.winhub.agent.provisioning/winhub_agent.bootstrap.conf
sudo installer -pkg WinHUBMacAgent-v<VERSION>-macos-arm64.pkg -target /
```

Використовуйте короткоживучий enrollment window/token, обмеження source IP і окремий rollout
batch. Не використовуйте один довгоживучий bootstrap file у загальнодоступній SMB-папці.

### TCC/PPPC

Baseline enrollment, network/volume inventory, FileVault status, telemetry і self-update не
потребують Full Disk Access. Якщо дозволені scripts читають TCC-захищені каталоги або
керують UI, створіть PPPC profile у вашому MDM для:

- path: `/Library/PrivilegedHelperTools/com.winhub.agent/WinHUBMacAgent`;
- identifier: `com.winhub.agent`;
- Team ID: ваша Apple Team ID;
- designated requirement на основі `codesign -dr -` production binary.

Надавайте лише конкретні потрібні services. Не додавайте Full Disk Access «про всяк випадок».

## 11. Execution policy

Runtime config:

```text
/Library/Application Support/WinHUB/Config/winhub_agent.conf
```

Рекомендований default:

```json
{
  "ExecutionMode": "allowlist",
  "AllowedActions": ["agent_update"]
}
```

- `disabled` — inventory/telemetry без виконання жодних задач.
- `allowlist` — виконуються лише явно перелічені actions.
- `full` — довільний WinHUB script виконується від `root`; потрібне окреме security approval.

Після зміни:

```bash
sudo launchctl kickstart -k system/com.winhub.agent
sudo /Library/PrivilegedHelperTools/com.winhub.agent/diagnose-macos-agent.sh
```

Не редагуйте `TaskSigningPublicKeyPem`, `TaskSigningKeyId` або sequence вручну: це pinned
per-endpoint state для захисту від replay/downgrade.

## 12. TLS і certificate pinning

`ServerUrl` завжди має бути `https://`. `IgnoreTlsCertificateErrors=true` на macOS агент
примусово ігнорує як небезпечний параметр.

`ServerCertificateSha256` можна використати як додатковий pin. Він зменшує ризик
скомпрометованого CA, але вимагає синхронної ротації: спочатку доставте новий pin, потім
замініть server certificate. Якщо certificate часто ротує ACME, краще використовуйте
нормальну system trust chain без leaf pin або окремий стабільний reverse-proxy certificate.

## 13. Managed update rollout

1. Завантажте **тільки** `WinHUBMacAgent-v<VERSION>-macos-arm64.tar.gz` у Agent Packages і
   вкажіть точну версію з `VERSION`.
2. Перевірте визначену платформу `macos` і server-computed SHA-256.
3. Запустіть canary на 1–3 тестових Mac, потім хвилі 5% → 25% → 100% із паузою на telemetry.
4. Контролюйте task result, agent version, heartbeat, error log і duplicate enrollment.

Updater приймає package лише коли збігаються task signature, HTTPS policy, SHA-256,
`target_version`, `arm64`, `com.winhub.agent`, Hardened Runtime і Team ID. Він перевіряє
LaunchDaemon plist, робить backup, замінює runtime, очікує стабільний запуск і виконує
rollback при помилці.

Backup-и:

```text
/Library/Application Support/WinHUB/Data/backups/
```

Після стабільного rollout старі backup-и видаляйте за retention policy, але збережіть
щонайменше один попередній production release і його SHA-256 поза endpoint.

## 14. Діагностика

```bash
sudo /Library/PrivilegedHelperTools/com.winhub.agent/diagnose-macos-agent.sh
sudo launchctl print system/com.winhub.agent
tail -n 200 /Library/Logs/WinHUB/agent.log
tail -n 200 /Library/Logs/WinHUB/agent-error.log
```

Diagnostics перевіряє platform/architecture, Apple signature, Team ID, Bundle ID, Hardened
Runtime, embedded version, plist, HTTPS config, security flags, ownership, enrollment state,
service state, network reachability і log rotation.

Типові причини:

- `Gatekeeper rejected` — package не notarized/stapled, пошкоджений після підпису або
  certificate revoked/expired.
- `TeamIdentifier mismatch` — update/installer підписаний іншою Apple Team.
- `signature_expired` — неправильний system time; увімкніть automatic time/NTP.
- `pending_approval` — endpoint ще не підтверджений у Review Center.
- `Task signature verification failed` — server signing state/secret не збігається; не
  вимикайте перевірку, проведіть контрольований re-enrollment/rotation.
- service запускається й падає — перевірте `agent-error.log`, config JSON, HTTPS DNS/TLS і
  architecture.

## 15. Видалення

Зберегти enrollment identity/config/logs для контрольованого reinstall:

```bash
sudo /Library/PrivilegedHelperTools/com.winhub.agent/uninstall-macos-agent.sh
```

Повністю й незворотно видалити local state:

```bash
sudo /Library/PrivilegedHelperTools/com.winhub.agent/uninstall-macos-agent.sh --purge
```

Перед `--purge` заблокуйте або видаліть endpoint record у WinHUB відповідно до incident/change
procedure. Після purge наступна інсталяція створить нову agent identity.

## 16. Ротація та компрометація signing key

- Не передавайте `.p12` через chat/email і не тримайте його в репозиторії.
- Обмежте доступ до build account, Keychain і notary profile.
- Ведіть журнал: commit, VERSION, SHA-256, Team ID, certificate fingerprint, notary submission
  ID, build operator і час.
- До завершення certificate validity випустіть новий Developer ID тієї самої Team ID і
  протестуйте canary: updater пінить Team ID, а не конкретний certificate fingerprint.
- При підозрі на витік зупиніть releases, відкличте certificate в Apple, заблокуйте rollout,
  перевірте notary history, перевидайте identities і підпишіть чистий recovery release.

## 17. Production checklist

- [ ] macOS/Xcode/.NET 10 оновлені до security patch.
- [ ] FileVault увімкнений; build account і SSH обмежені.
- [ ] Git commit review-нутий, worktree чистий, `VERSION` унікальний.
- [ ] Developer ID Application і Installer належать очікуваній Team ID.
- [ ] `notarytool` повернув `Accepted`; stapler і `spctl` успішні.
- [ ] Усі три SHA-256 перевірені після копіювання артефактів.
- [ ] Clean-Mac install і `diagnose-macos-agent.sh` успішні.
- [ ] Endpoint identity перевірена до approval.
- [ ] `ExecutionMode=allowlist`; `full` не ввімкнений без security approval.
- [ ] Canary update та автоматичний rollback протестовані.
- [ ] MDM PPPC надає тільки необхідні TCC permissions.
- [ ] Попередній release, ключові метадані й recovery procedure доступні операторам.
