# GPO deployment files

Скрипти актуальні для підписаних Windows x64 пакетів. Наданий старий manifest
для `2.0.0-rc.4` не обирає новий ZIP `2.0.1-rc.3` автоматично.

## Підготовка

1. У локальну папку підготовки скопіюйте файли цього каталогу, підписаний ZIP,
   `release-signing-public.pem`, робочий `winhub_agent.conf` та bootstrap config.
2. Якщо оновлюєте існуючу GPO, скопіюйте туди її чинний `deployment-manifest.json`:
   це потрібно для збереження `server_identity_epoch`. Не генеруйте новий epoch
   для звичайного оновлення агента.
3. У PowerShell із цієї папки виконайте:

```powershell
.\prepare-gpo-manifest.ps1 -PackagePath '.\WinHUBAgent-v2.0.1-rc.3-win-x64-key1-signed.zip'
```

Helper читає версію з release manifest, звіряє key ID та обчислює SHA-256 ZIP
і public key; зберігає старий manifest у backup. Це підготовка метаданих,
не криптографічна перевірка підпису: її виконує installer на endpoint.
Для нового deployment manifest створюється з порожнім epoch.

4. Опублікуйте в `\\<DC>\NETLOGON\WinHUBAgentDeploy`:

```text
install-winhub-agent.cmd
install-winhub-agent.ps1
deployment-manifest.json
release-signing-public.pem
winhub_agent.conf
winhub_agent.bootstrap.conf
WinHUBAgent-v2.0.1-rc.3-win-x64-key1-signed.zip
```

Публікуйте manifest останнім, після копіювання ZIP та реплікації DC.
Helper, example, README і backup-файли endpoint-ам не потрібні.
В GPO Computer Startup вкажіть UNC-шлях до `.cmd`. Wrapper бере файли з
власної папки; не копіюйте лише `.cmd` до іншої папки SYSVOL. Для іншого
джерела PS1 підтримує явний `-SourceDir`. Computer accounts: Read & Execute;
змінювати deployment можуть лише уповноважені адміністратори.

## Що всередині ZIP

Мінімальний підписаний Native AOT пакет із bundled public key містить у корені:

```text
WinHUBAgent.exe
appsettings.json
install-service.ps1
uninstall-service.ps1
update-service.ps1
update-protocol.json
release-manifest.json
release-signing-public.pem
```

Папки-обгортки `publish/` чи `WinHUBAgent/` над цими файлами не повинно бути.
Public PEM всередині ZIP додає signer через `--bundle-public-key`; для GPO
його копія все одно потрібна поряд із ZIP. Старий підписаний пакет без
bundled public key підтримується з зовнішнім ключем.
Для інших publish-режимів можливі додаткові runtime-файли, включені signer
до inventory. Не видаляйте й не додавайте файли після підписування.

У ZIP не додавайте `winhub_agent.conf`, `winhub_agent.bootstrap.conf`,
приватний ключ, `agent.secrets`, `release-state.json`, журнали чи GPO wrapper.
Ці GPO-скрипти не замінюють `install-service.ps1` усередині пакета.

Почніть із одного тестового хоста. Після перезавантаження перевірте
`C:\ProgramData\WinHUB\gpo-install\startup-wrapper.log` та `install.log`.
Саме копіювання ZIP не запускає startup policy на вже ввімкнених хостах.

Докладно: [GPO guide](../../../WinHUB-WiKi/guides/agents/GPO_AGENT_DEPLOYMENT.md).
