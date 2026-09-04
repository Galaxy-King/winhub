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
