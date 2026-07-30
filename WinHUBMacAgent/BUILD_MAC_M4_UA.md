# Збірка WinHUB macOS Agent на MacBook M4

MacBook використовується лише як `osx-arm64` build/sign host. Python, Node.js, база даних,
Redis, Nginx і серверна частина WinHUB на ньому не потрібні.

## 1. Що встановити

1. Увімкніть **System Settings → General → Sharing → Remote Login** і дозвольте вхід лише
   своєму build-користувачу.
2. Встановіть останні Xcode Command Line Tools:

   ```bash
   xcode-select --install
   xcode-select -p
   xcrun --find clang
   ```

3. Встановіть **.NET 8 SDK for macOS Arm64** з
   [офіційного інсталятора Microsoft](https://learn.microsoft.com/en-us/dotnet/core/install/macos).
   Потрібен саме SDK, а не лише Runtime:

   ```bash
   uname -m
   dotnet --info
   dotnet --list-sdks | grep '^8\.'
   ```

   `uname -m` має повернути `arm64`, а список SDK — містити `8.0.x`.

4. Git і системні утиліти `codesign`, `security`, `tar`, `shasum`, `plutil` уже доступні
   у macOS/Xcode Command Line Tools. Перевірка:

   ```bash
   git --version
   codesign --version
   ```

Для Native AOT достатньо Command Line Tools. Повний Xcode потрібен, якщо ви будете
нотаризувати зовнішній `.pkg` через `notarytool`.

Поточний проект цілеспрямовано збирається на .NET 8. Microsoft завершує підтримку .NET 8
10 листопада 2026 року, тому перехід усіх WinHUB agent-проектів на .NET 10 треба виконати
окремим узгодженим релізом до цієї дати.

## 2. Мінімальний checkout без серверного проекту

На Mac потрібні лише `WinHUBMacAgent`, спільний Unix worker, `VERSION`, `global.json`,
`.gitignore` і `.gitattributes`:

```bash
mkdir -p ~/Build
cd ~/Build
git clone --filter=blob:none --no-checkout git@github.com:Galaxy-King/winhub.git WinHUB-agent-build
cd WinHUB-agent-build
git sparse-checkout init --no-cone
git sparse-checkout set --no-cone \
  /VERSION \
  /global.json \
  /.gitignore \
  /.gitattributes \
  /WinHUBMacAgent/ \
  /WinHUBLinuxAgent/Worker.cs
git checkout main
```

Перед кожною збіркою:

```bash
cd ~/Build/WinHUB-agent-build
git pull --ff-only origin main
git status --short
```

`git status --short` перед збіркою має бути порожнім. `bin/`, `obj/` і `dist-agent/`
ігноруються та не потрапляють у Git.

Якщо репозиторій приватний, створіть для Mac окремий SSH-ключ або read-only deploy key.
Приватний ключ з Windows копіювати на Mac не потрібно.

## 3. Віддалений доступ з Windows через VS Code

1. На Windows встановіть розширення
   [Remote - SSH](https://code.visualstudio.com/docs/remote/ssh).
2. Спочатку перевірте з PowerShell:

   ```powershell
   ssh mac-user@MAC_IP
   ```

3. У VS Code натисніть `Ctrl+Shift+P` → `Remote-SSH: Connect to Host...` і введіть ту саму
   адресу `mac-user@MAC_IP`.
4. Відкрийте на Mac папку `~/Build/WinHUB-agent-build`.

Термінал цього VS Code-вікна виконує команди безпосередньо на Mac. Доступ до всього
серверного дерева не потрібен завдяки sparse checkout.

## 4. Developer ID для production

Для production-пакета потрібні членство в Apple Developer Program, сертифікат
`Developer ID Application` і його приватний ключ у Keychain цього Mac.

Перевірте доступні identity:

```bash
security find-identity -v -p codesigning
```

Якщо SSH-сесія не бачить закритий login keychain, розблокуйте його без передавання пароля
в аргументі команди:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

## 5. Production-збірка

```bash
cd ~/Build/WinHUB-agent-build
git pull --ff-only origin main
cd WinHUBMacAgent
WINHUB_CODESIGN_IDENTITY="Developer ID Application: YOUR NAME (TEAMID)" \
  ./create-macos-agent-release.sh
```

Скрипт автоматично:

- виконує Native AOT publish для `osx-arm64`;
- підписує всі Mach-O файли з Hardened Runtime і secure timestamp;
- перевіряє `arm64`, версію та Apple Team ID;
- запускає `WinHUBMacAgent --self-test` проти контракту WinHUB server;
- створює архів і SHA-256 у `WinHUBMacAgent/dist-agent/`.

Очікувані файли:

```text
WinHUBMacAgent-v<VERSION>-macos-arm64.tar.gz
WinHUBMacAgent-v<VERSION>-macos-arm64.tar.gz.sha256
```

Контроль:

```bash
cd dist-agent
shasum -a 256 -c WinHUBMacAgent-v*-macos-arm64.tar.gz.sha256
```

Завантажуйте `.tar.gz` у **WinHUB → Infrastructure → Agent Packages**, а в полі версії
вказуйте точне значення з кореневого `VERSION`. Назва містить `macos`, тому сервер правильно
визначить платформу й надсилатиме пакет лише macOS endpoint-ам.

## 6. Локальна тестова збірка без Apple-сертифіката

```bash
WINHUB_ALLOW_UNSIGNED_BUILD=1 ./create-macos-agent-release.sh
```

Вона буде ad-hoc signed і придатна лише для тестового Mac:

```bash
sudo WINHUB_ALLOW_UNSIGNED=1 ./install-macos-agent.sh
```

Такий архів не можна завантажувати на production WinHUB.

## 7. Встановлення production-агента

Після розпакування релізу:

```bash
cd /path/to/unpacked-agent
WINHUB_EXPECTED_TEAM_ID="TEAMID" ./setup-macos-agent.sh
sudo launchctl print system/com.winhub.agent
tail -f /Library/Logs/WinHUB/agent.log
```

На першому запуску `setup-macos-agent.sh` безпечно запитає HTTPS URL сервера, enrollment key
і Task HMAC secret. Після enrollment endpoint з’явиться в WinHUB для підтвердження.

За замовчуванням дозволене лише безпечне self-update. Якщо цей Mac має виконувати скрипти
та reboot-завдання, явно додайте потрібні дії до `AllowedActions` або встановіть
`"ExecutionMode": "full"` у:

```text
/Library/Application Support/WinHUB/Config/winhub_agent.conf
```

Потім перезапустіть:

```bash
sudo launchctl kickstart -k system/com.winhub.agent
```

`full` означає віддалене виконання команд від `root`; вмикайте його лише для довіреного
WinHUB server. Для доступу скриптів до TCC-захищених даних, Screen Recording або Accessibility
окремо потрібні відповідні macOS/MDM PPPC дозволи. Для enrollment, inventory, telemetry та
self-update ці дозволи не потрібні.
