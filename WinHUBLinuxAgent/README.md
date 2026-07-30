# WinHUBLinuxAgent

Безпечний системний агент WinHUB для Debian 12/13, Ubuntu Server 22.04/24.04 та Proxmox VE 8/9. Він використовує той самий протокол enrollment/poll/telemetry/result, HMAC-підпис завдань і RSA-ідентичність, що й Windows Agent.

Агент працює лише через вихідні HTTPS-з'єднання до WinHUB: відкривати вхідний порт на Linux-сервері не потрібно. TLS-перевірка увімкнена, а для приватного CA можна задати SHA-256 pin сертифіката. Токени, ключ і стан мають права `0600/0700` та належать root.

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

Copy the release archive to the endpoint:

```bash
sudo mkdir -p /tmp/winhub-linux-agent
sudo tar -xzf WinHUBLinuxAgent-v1.3.0-linux-x64.tar.gz -C /tmp/winhub-linux-agent
cd /tmp/winhub-linux-agent
sudo ./install-linux-agent.sh
```

## Bulk SSH rollout

Put these files in one directory:

```text
WinHUBLinuxAgent-v1.3.0-linux-x64.tar.gz
winhub_agent.conf
winhub_agent.bootstrap.conf
linux_hosts.txt
deploy-linux-agents.sh
```

Example `linux_hosts.txt`:

```text
192.168.1.10
192.168.1.11
root@192.168.1.12
```

Run:

```bash
chmod +x deploy-linux-agents.sh
./deploy-linux-agents.sh --hosts linux_hosts.txt --user root --identity ~/.ssh/id_ed25519
```

Скрипт приймає IP/hostname по одному на рядок, перевіряє SSH, порівнює версію, встановлює або оновлює агент і перевіряє активність systemd-сервісу. Bootstrap-конфіг копіюється в `/etc` лише якщо сервер ще не має enrollment token; тимчасові файли після успішної перевірки видаляються.

The script checks `/opt/winhub-linux-agent/WinHUBLinuxAgent --version` on every host. It installs or updates only when the agent is absent, older than the package version, or `--force` is used. Runtime and bootstrap configs are synchronized to `/etc/winhub-agent` and the service is restarted.

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
- `agent_update`: downloads a `.tar.gz` Linux agent release and launches `update-linux-agent.sh`.

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
