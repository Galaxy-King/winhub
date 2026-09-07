# Tests і release

## Перед release

- Python tests;
- security regression tests;
- agent self-tests;
- installer shell syntax;
- database migration на копії production-like schema;
- update/rollback test;
- UI smoke test;
- package version і SHA-256;
- documentation link/command review.

## Agent release

Кожна platform має власний build script. Release artifact повинен бути versioned, architecture-specific, без debug symbols і без production configs.

Windows/Linux strict agents відокремлюють build від адміністративного підписування: build scripts створюють unsigned candidate та publish directory; `WinHUBLinuxAgent/tools/sign-release.py` створює новий signed artifact. Причина — private publisher key не повинен бути в CI checkout, Git, sync storage або на сервері, який видає задачі. Manifest підписує inventory, platform/architecture/version/serial; public trust доставляється окремо. Anti-rollback floor записується до запуску updater, щоб невдала спроба не дозволяла непомітно повернути нижчий пакет. Повтор тієї самої підписаної збірки допустимий.

Активні записи execution journal відокремлені від постійних sharded tombstones: це обмежує RAM при запуску без видалення старих task IDs. Міграція та acknowledgement записують tombstone до видалення active result; втрата останнього результату через archive write failure не допускається. Зворотне повернення до агента, який не розуміє формат архіву, не є звичайним downgrade і потребує контрольованого recovery без видачі нових задач.

Windows запускає wrapper, приєднує його до Job Object, лише потім передає launch frame через stdin. Це уникає вікна між запуском task code і накладанням лімітів. Linux використовує transient systemd service з cgroup v2 та прив'язкою до endpoint service; unrestricted fallback немає. Ці механізми обмежують ресурси й прибирають звичайних нащадків, але не є privilege separation: повний root/SYSTEM скрипт залишається довіреним кодом.

Деталі, окремі невиконані production gates і команди: [стан hardening](../guides/agents/PRODUCTION_PIN_AGENTS_UA.md), [підписування/приймання](../guides/agents/AGENT_RELEASE_ACCEPTANCE_UA.md). Архітектуру non-privileged transport/broker, типізовані параметри та scoped enrollment не слід вважати завершеними цими змінами.

## Server release

Після merge/tag перевірте fresh install із Git, upgrade існуючого test server, backup/restore і security smoke test. Оновіть `WinHUB/VERSION`, release notes і WiKi.


## Команди після поділу каталогів

З кореня репозиторію:

```bash
cd WinHUB
python -m unittest discover -s tests -v
bash deploy/create_release.sh
cd ..
python -m unittest discover -s WinHUBMacAgent/tests -v
dotnet build WinHUBAgentWindows/WinHUBAgentWindows.csproj -c Release
dotnet build WinHUBLinuxAgent/WinHUBLinuxAgent.csproj -c Release -p:PublishAot=false
cd WinHUBMacAgent
dotnet build WinHUBMacAgent.csproj -c Release -p:PublishAot=false -p:RuntimeIdentifier=win-x64 -p:SelfContained=false
```

Остання команда — managed-перевірка на Windows із .NET 10; production NativeAOT для macOS збирайте на Mac. Windows build також потребує Windows. Server release використовує `WinHUB/VERSION`, `deploy/server-files.txt` і `server-excludes.txt`; перевірки пакування виконуються на Linux/WSL з GNU tar і rsync.
