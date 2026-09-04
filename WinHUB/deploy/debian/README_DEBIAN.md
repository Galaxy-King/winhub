# WinHUB Debian production deployment

Recommended target:

- Debian 12
- PostgreSQL
- Nginx on `443`
- WinHUB Debian backend bound to `127.0.0.1:8443` over local HTTP
- External users and agents connect to `https://SERVER_IP`
- Optional agent-only public listener controlled by `AGENT_PUBLIC_PORT`

## 1. Clone the Git project

Clone as the normal SSH/deploy-key user. The installer copies only `WinHUB/` server components to `/opt/winhub`; Git, agents and Wiki stay in the checkout:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/Galaxy-King/winhub.git ~/winhub
cd ~/winhub/WinHUB
```

Keep the source checkout outside `/opt/winhub`, so updates can back up the installed version before replacing it.

## 2. Run the interactive end-to-end installer

```bash
sudo bash deploy/debian/install_debian.sh
```

For a fresh installation the script:

- asks for the public DNS name or IPv4 address;
- installs Debian dependencies;
- creates `winhub` and separate isolated `winhub-renderer` / `winhub-validator` users;
- generates independent session, database, enrollment, task-signing and history-search secrets with the OS CSPRNG;
- creates/reconciles the local PostgreSQL role and database;
- creates a self-signed TLS certificate with the selected host in SAN when no certificate exists;
- installs Python dependencies, systemd units, Nginx and logrotate configuration;
- applies Alembic migrations;
- starts services and runs the backend/renderer/code-validator healthcheck;
- creates the first administrator with a random password and TOTP seed;
- creates a one-time recovery bundle in `/run`.

Fresh installation requires an interactive terminal: choose the public host, confirm setup, then save the recovery bundle. An interrupted initial setup can be resumed by rerunning the installer; `.installation-pending` in `/etc/winhub` records unfinished setup and existing generated secrets are retained.

## 3. Save the one-time recovery bundle

After the healthcheck succeeds, the installer prints the bundle path and SHA-256. Copy it to an encrypted password manager or encrypted off-host/offline storage and verify its checksum. Then type:

```text
SAVED
```

The bundle contains the initial admin credentials, `/etc/winhub/winhub.env`, TLS certificate/private key, `master_key.enc`, `sys_secret.enc` and checksums. It grants control over the installation and must never be stored in Git, Confluence, tickets, chat, ordinary cloud folders or email.

After confirmation the script removes the temporary archive and duplicate admin recovery file. The server retains only secrets required for runtime operation.

The complete Ukrainian procedure is in [the installation Wiki](../../../WinHUB-WiKi/02-Сервер/01-Встановлення-з-нуля.md).

## 4. Installed topology

The Debian service starts `/opt/winhub/server_debian.py`. Nginx terminates TLS on `443` and proxies to the local backend on `127.0.0.1:8443`. PostgreSQL is local. By default agents also use `443`.

AI code drafts use a separate Unix-socket validator with no application secrets or network. Install `pwsh` from the trusted Microsoft Debian package source to enable PowerShell syntax checks; ShellCheck and PSScriptAnalyzer are optional linters. Without the native parser, applying/saving generated code is blocked. See the [AI editor setup guide](../../../WinHUB-WiKi/guides/features/AI_TEMPLATE_EDITOR_UA.md). No generated script runs during validation.

## Agent polling cadence

WinHUB returns scheduling hints in `/api/agent/poll`. New agents use them; older agents safely ignore them.

Recommended defaults:

```ini
AGENT_IDLE_POLL_SECONDS=30
AGENT_TASK_POLL_SECONDS=30
AGENT_PENDING_POLL_SECONDS=30
AGENT_POLL_JITTER_SECONDS=30
AGENT_TELEMETRY_SECONDS=300
AGENT_PENDING_TASK_MISS_CACHE_SECONDS=10
```

For large local fleets, increase idle poll and jitter, for example:

```ini
AGENT_IDLE_POLL_SECONDS=120
AGENT_POLL_JITTER_SECONDS=90
AGENT_TELEMETRY_SECONDS=300
AGENT_PENDING_TASK_MISS_CACHE_SECONDS=15
```

## Agent public port

By default:

```ini
AGENT_PUBLIC_PORT=443
```

With this value, agents and the web UI both use the main HTTPS listener:

```text
https://SERVER_IP
```

For a server where agents must enter through a separate public port, set for example:

```ini
AGENT_PUBLIC_PORT=55555
```

If one WinHUB instance manages both local agents and agents behind a public proxy, use relative agent package URLs:

```ini
AGENT_PACKAGE_URL_MODE=relative
```

With this mode, each agent downloads self-update packages from its own configured `ServerUrl`. Local agents use the local WinHUB URL, while public agents use the proxy URL. Keep `AGENT_PACKAGE_URL_MODE=absolute` only when every agent can reach the same public package URL.

Then run the update script or regenerate nginx manually:

```bash
sudo /opt/winhub/deploy/debian/render_nginx_config.sh
sudo nginx -t
sudo systemctl reload nginx
```

When `AGENT_PUBLIC_PORT` is not `443`, the generated listener exposes only:

- `/api/agent/`
- `/api/public/agent-packages/`
- `/api/public/software-packages/`
- `/api/health`

Everything else on that port returns `404`, so the web UI is not available through the agent-only port. Configure agents with:

```json
{
  "ServerUrl": "https://SERVER_IP:55555"
}
```

## 5. Certificates for IP-based access

The fresh installer creates a certificate with the selected DNS/IP in SAN. Replace the self-signed certificate with a trusted/internal-CA certificate when available. For manual replacement, the certificate must contain the public DNS name or IP in SAN.

Example self-signed certificate for `192.168.37.223`:

```bash
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout /etc/winhub/certs/key.pem \
  -out /etc/winhub/certs/cert.pem \
  -subj "/CN=192.168.37.223" \
  -addext "subjectAltName=IP:192.168.37.223"
sudo chown root:winhub /etc/winhub/certs/*.pem
sudo chmod 0640 /etc/winhub/certs/*.pem
```

Use the same certificate fingerprint in the agent config if TLS pinning is enabled.

## 6. Verify the completed installation

```bash
sudo systemctl status winhub --no-pager
sudo systemctl status winhub-renderer.socket --no-pager
sudo nginx -t
sudo /opt/winhub/deploy/debian/healthcheck_winhub.sh
```

Check status:

```bash
sudo systemctl status winhub
sudo journalctl -u winhub -f
sudo tail -f /var/log/winhub/winhub_prod.log
```

Open:

```text
https://SERVER_IP
```

Do not expose `8443` to the network on Debian. It is an internal backend port.

The first admin credentials are in the off-host recovery bundle. On a successful fresh install the temporary `/var/lib/winhub/admin_recovery.txt` copy has already been removed.

## 7. Updates

Before updating, the project should live in Git or be deployed as a release archive. Runtime files stay outside the code tree:

- `/etc/winhub/winhub.env`
- `/etc/winhub/certs`
- `/var/lib/winhub`
- `/var/log/winhub`

Update from a Git checkout:

```bash
git -C ~/winhub pull --ff-only
sudo bash ~/winhub/WinHUB/deploy/debian/update_winhub.sh ~/winhub/WinHUB
```

Select a tag/commit in the separate checkout first when required. The updater accepts a source directory or server release archive; it does not pull Git into the installed runtime. For the first transition from the old layout, run the **new updater from the new checkout**, not the old script in `/opt/winhub`.

Update from a release archive:

```bash
bash deploy/create_release.sh
scp dist/winhub-v0.1.0.tar.gz SERVER:/tmp/
ssh SERVER 'sudo /opt/winhub/deploy/debian/update_winhub.sh /tmp/winhub-v0.1.0.tar.gz'
```

The update script creates a PostgreSQL/runtime backup, updates code, appends missing variables from `deploy/debian/winhub.env.example` to `/etc/winhub/winhub.env` without overwriting existing values, refreshes dependencies, runs Alembic migrations, restarts WinHUB and checks `/api/health`.

Manual backup:

```bash
sudo /opt/winhub/deploy/debian/backup_winhub.sh
```

Rollback to the latest backup:

```bash
sudo /opt/winhub/deploy/debian/rollback_winhub.sh
```

Rollback to a specific backup:

```bash
sudo /opt/winhub/deploy/debian/rollback_winhub.sh /var/lib/winhub/backups/20260522_120000
```

Restore a backup on a clean server:

```bash
sudo /opt/winhub/deploy/debian/restore_winhub.sh /var/lib/winhub/backups/20260522_120000
```

## 8. Database migrations

Schema changes should be shipped as Alembic revisions in `migrations/versions`.

Create a migration after changing SQLAlchemy models:

```bash
cd /opt/winhub
sudo /opt/winhub/deploy/debian/migrate_winhub.sh revision -m "describe change"
```

Apply migrations manually:

```bash
cd /opt/winhub
sudo /opt/winhub/deploy/debian/migrate_winhub.sh upgrade
```

`update_winhub.sh` applies migrations automatically.

## 9. Multi-server rollout

For several WinHUB servers, use the same release tag/archive on every host:

```bash
for host in winhub-a winhub-b winhub-c; do
  scp dist/winhub-v0.1.0.tar.gz "$host":/tmp/
  ssh "$host" 'sudo bash /opt/winhub/deploy/debian/update_winhub.sh /tmp/winhub-v0.1.0.tar.gz'
done
```

For production, prefer an Ansible playbook that updates one server at a time and stops when a healthcheck fails.

## 10. Agent config

If Nginx is used as above, agents should use:

```json
{
  "ServerUrl": "https://SERVER_IP",
  "ServerCertificateSha256": "SHA256_FINGERPRINT_OF_CERT",
  "PollIntervalSeconds": 30,
  "DefaultTaskTimeoutSeconds": 1800,
  "MaxResultLogBytes": 262144,
  "IgnoreTlsCertificateErrors": false
}
```

Bootstrap config for first enrollment only:

```json
{
  "GlobalApiKey": "same-value-as-AGENT_API_KEY",
  "TaskHmacSecret": "same-value-as-AGENT_TASK_HMAC_SECRET"
}
```

## 10.1 Debian/Ubuntu endpoint agent

The Debian server files above run the WinHUB backend. Debian/Ubuntu endpoints are handled by the separate Linux endpoint agent in:

```text
WinHUBLinuxAgent
```

Build a Linux package on a Debian/Ubuntu machine with the .NET 8 SDK installed:

```bash
cd ~/winhub/WinHUBLinuxAgent
./create-linux-agent-release.sh 1.2.14 linux-x64
```

Install on an endpoint:

```bash
sudo mkdir -p /tmp/winhub-linux-agent
sudo tar -xzf WinHUBLinuxAgent-v1.2.14-linux-x64.tar.gz -C /tmp/winhub-linux-agent
cd /tmp/winhub-linux-agent
sudo ./install-linux-agent.sh
```

Configure:

```bash
sudo nano /etc/winhub-agent/winhub_agent.conf
sudo cp /opt/winhub-linux-agent/winhub_agent.bootstrap.conf.example /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo nano /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo chmod 0600 /etc/winhub-agent/winhub_agent.bootstrap.conf
sudo systemctl restart winhub-linux-agent
```

Check logs:

```bash
sudo journalctl -u winhub-linux-agent -f
```

## 11. Firewall

For Nginx deployment:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Do not expose PostgreSQL publicly.
