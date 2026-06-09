# WinHUBLinuxAgent

Debian/Ubuntu endpoint agent for WinHUB. It uses the same `/api/agent/enroll`, `/api/agent/poll`, `/api/agent/telemetry`, and `/api/agent/result` protocol as the Windows agent.

## Build

Install the .NET 8 SDK, then build a self-contained package:

```bash
cd WinHUBLinuxAgent
./create-linux-agent-release.sh 1.2.14 linux-x64
```

For ARM servers or SBC endpoints:

```bash
./create-linux-agent-release.sh 1.2.14 linux-arm64
```

## Install

Copy the release archive to the endpoint:

```bash
sudo mkdir -p /tmp/winhub-linux-agent
sudo tar -xzf WinHUBLinuxAgent-v1.2.14-linux-x64.tar.gz -C /tmp/winhub-linux-agent
cd /tmp/winhub-linux-agent
sudo ./install-linux-agent.sh
```

## Bulk SSH rollout

Put these files in one directory:

```text
WinHUBLinuxAgent-v1.2.18-linux-x64.tar.gz
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

## Task execution

Normal WinHUB tasks run as `/bin/bash` scripts under the service account. The default unit runs as `root`, matching the Windows service's administrative behavior. Restrict who can dispatch tasks from the WinHUB UI.

Supported built-in actions:

- `reboot`: calls `systemctl reboot`.
- `agent_update`: downloads a `.tar.gz` Linux agent release and launches `update-linux-agent.sh`.

## Logs

```bash
sudo systemctl status winhub-linux-agent
sudo journalctl -u winhub-linux-agent -f
```
