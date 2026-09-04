# WinHUBLinuxAgent

Системний агент WinHUB для Debian 12/13, Ubuntu Server 22.04/24.04 та Proxmox VE 8/9. Він використовує протокол сервера enrollment/poll/telemetry/result, підписані RSA-запити агента та per-agent RSA-PSS v2 підпис задач. Поточні strict-pin зміни — **кандидат релізу**, а не завершення всього production-плану: [стан, перехід та release gates](../WinHUB-WiKi/guides/agents/PRODUCTION_PIN_AGENTS_UA.md).

Агент працює через вихідні HTTPS-з'єднання до WinHUB: вхідний порт не потрібен. Обов'язковий SHA-256 pin leaf-сертифіката, отриманий адміністратором із довіреного джерела. `ServerCertificateSha256Next` дозволяє заздалегідь додати майбутній pin. TLS bypass, HTTP, redirects і cross-host update downloads заборонені. Токени, ключ і стан захищаються правами `0600/0700`.

## Build

Install the .NET 8 SDK, then build a self-contained package:

```bash
cd WinHUBLinuxAgent
./create-linux-agent-release.sh 1.3.0 linux-x64
```

For ARM servers or SBC endpoints:

```bash
./create-linux-agent-release.sh 1.3.0 linux-arm64
```

## Install

До запуску інсталятора підготуйте `/etc/winhub-agent/winhub_agent.conf` із довіреним pin. Новий installer перевіряє конфігурацію до зміни наявної служби; приклад із placeholder не є готовим конфігом. Перший перехід зі старого updater має окремі вимоги в [посібнику](../WinHUB-WiKi/guides/agents/PRODUCTION_PIN_AGENTS_UA.md).

Copy the release archive to the endpoint:

```bash
sudo mkdir -p /tmp/winhub-linux-agent
sudo tar -xzf WinHUBLinuxAgent-v1.4.0-linux-x64.tar.gz -C /tmp/winhub-linux-agent
cd /tmp/winhub-linux-agent
sudo ./install-linux-agent.sh
```

## Масове керування через SSH

Підготуйте пакет агента, робочі конфіги та список серверів:

```bash
cp winhub_agent.conf.example winhub_agent.conf
cp winhub_agent.bootstrap.conf.example winhub_agent.bootstrap.conf
cp linux_hosts.txt.example linux_hosts.txt
# Відредагуйте три створені файли перед запуском.
```

```text
WinHUBLinuxAgent-v1.4.0-linux-x64.tar.gz
winhub_agent.conf
winhub_agent.bootstrap.conf
linux_hosts.txt
deploy-linux-agents.sh
```

Приклад `linux_hosts.txt`:

```text
192.168.1.10
192.168.1.11
root@192.168.1.12
```

SSH-користувач повинен бути `root` або мати passwordless sudo (`sudo -n`). Запустіть скрипт без параметрів, щоб інтерактивно вибрати встановлення, видалення або перевстановлення:

```bash
chmod +x deploy-linux-agents.sh
./deploy-linux-agents.sh
```

Для неінтерактивного запуску режим і список можна задати параметрами:

```bash
# Встановити відсутні агенти та оновити старіші
./deploy-linux-agents.sh --action install --hosts linux_hosts.txt --identity ~/.ssh/id_ed25519 --yes

# Видалити службу та бінарники, але зберегти конфіг, токен і стан
./deploy-linux-agents.sh --action uninstall --hosts linux_hosts.txt --identity ~/.ssh/id_ed25519 --yes

# Примусово перевстановити агент зі збереженням enrollment-ідентичності
./deploy-linux-agents.sh --action reinstall --hosts linux_hosts.txt --identity ~/.ssh/id_ed25519 --yes
```

Скрипт перевіряє SSH, Debian/Ubuntu-сумісність і архітектуру кожного сервера, виконує операцію послідовно та наприкінці показує загальний результат і список проблемних хостів. Для встановлення він перевіряє `/opt/winhub-linux-agent/WinHUBLinuxAgent --version`, автоматично оновлює лише старіші версії та після операції вимагає стан systemd-служби `active`.

Звичайні `uninstall` і `reinstall` зберігають `/etc/winhub-agent` та `/var/lib/winhub-agent`, тому агент не втрачає enrollment-токен та ідентичність. Параметр `--purge` додатково видаляє ці каталоги; використовуйте його лише коли потрібне повне очищення або нова реєстрація агента.

Runtime-конфіг синхронізується на всі сервери. Bootstrap-конфіг копіюється лише якщо сервер ще не має enrollment token. Щоб залишити наявні конфіги без змін, додайте `--no-config-sync`. Для ARM64 явно задайте відповідний пакет через `--package`; один запуск працює з однією архітектурою.

Повна довідка:

```bash
./deploy-linux-agents.sh --help
```

Edit the runtime config:

```bash
sudo nano /etc/winhub-agent/winhub_agent.conf
```

Create the first-enrollment bootstrap config:

```bash
sudo cp /opt/winhub-linux-agent/winhub_agent.bootstrap.conf.example /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo nano /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo chmod 0600 /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo systemctl restart winhub-linux-agent
```

After successful migration the agent deletes `winhub_agent.bootstrap.conf`. Runtime state is stored under:

```text
/var/lib/winhub-agent
```

Нові задачі та невідправлені результати зберігаються у `/var/lib/winhub-agent/execution-journal` з правами `0600/0700`. Повторюється доставка, не виконання. Після аварії перервана задача повертає `UNKNOWN` у журналі помилки: можливі часткові зміни на хості. Старий `/var/lib/winhub-agent/pending-results` також читається для доставки результатів попередньої версії. Межі місткості, архівація та rollback описані в release gates. `RestartAfterConsecutivePollFailures` задає кількість невдалих poll перед перезапуском через systemd; `0` вимикає цю поведінку.

Enrollment key видаляється після збереження токена, а shared TaskHmacSecret — при старті strict-v2 агента. Після відкликання доступу потрібне відновлення адміністратором. Для виконання та прибирання дочірніх процесів потрібен `/usr/bin/setsid` із `util-linux`.

## Підпис задач і запитів

Кожен enrollment, poll, telemetry і result містить SHA-256 хеш canonical JSON body, унікальний nonce, timestamp та RSA-підпис ключем ідентичності агента. Сервер перевіряє прив'язку тіла, допустиме відхилення часу та повторне використання nonce. Якщо системний час відрізняється, агент читає timestamp лише з перевіреного HTTPS-з'єднання, коригує час для наступних підписів і не плутає `signature_expired` із недійсним enrollment token.

У poll агент повідомляє capability `rsa-pss-sha256-v2`. Сервер підписує для конкретного endpoint поля `endpoint_id`, `task_id`, `action`, `payload_hash`, timeout, строк дії та монотонний sequence. Після першої успішної перевірки агент пінить per-agent public key, зберігає останній sequence у root-only `/var/lib/winhub-agent/task-signing-state.json`, видаляє перехідний HMAC secret і надалі відхиляє downgrade до HMAC. Окремий state-файл захищає pin та sequence від перезапису під час масової синхронізації runtime-конфігу. У Fleet Center endpoint підтверджує міграцію badge `Task v2` після успішного result.

Локальна перевірка canonical JSON, HMAC-контракту та Python/.NET RSA-PSS сумісності:

```bash
/opt/winhub-linux-agent/WinHUBLinuxAgent --self-test
```

## Політика виконання

За замовчуванням `ExecutionMode` дорівнює `allowlist`, і дозволено лише підписане оновлення агента. Доступні режими:

- `disabled` — не виконувати жодних команд;
- `allowlist` — виконувати лише дії з `AllowedActions`;
- `full` — виконувати всі підписані Bash-завдання як root.

Для керування Proxmox VM (`qm`, `pct`, `pvesh`), OpenVPN AS (`sacli`) та повного адміністрування встановіть у `/etc/winhub-agent/winhub_agent.conf`:

```json
"ExecutionMode": "full",
"AllowedActions": []
```

Потім виконайте `sudo systemctl restart winhub-linux-agent`. Режим `full` навмисно еквівалентний віддаленому root-доступу: залишайте `RequireTaskSignature: true`, не вимикайте TLS, обмежте право `run_tasks` у WinHUB і регулярно перевіряйте журнал аудиту.

## Task execution

Завдання WinHUB запускаються як тимчасові `/bin/bash`-скрипти під root, з обмеженням часу та розміру результату. Непідписані завдання відхиляються до запуску. Тимчасовий каталог сервісу ізольовано через systemd, а `NoNewPrivileges` забороняє отримати більше прав, ніж уже має root-процес.

Supported built-in actions:

- `reboot`: calls `systemctl reboot`.
- `agent_update`: перевіряє обов'язковий SHA-256 пакета та запускає `update-linux-agent.sh` в окремому transient systemd unit, щоб updater не був завершений разом зі старим процесом агента.

## Logs

```bash
sudo systemctl status winhub-linux-agent
sudo journalctl -u winhub-linux-agent -f
```

Перевірка після інсталяції:

```bash
sudo systemctl is-active winhub-linux-agent
sudo systemctl status winhub-linux-agent --no-pager
sudo journalctl -u winhub-linux-agent -n 50 --no-pager
```
