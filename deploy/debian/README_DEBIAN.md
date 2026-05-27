# WinHUB Debian production deployment

Recommended target:

- Debian 12
- PostgreSQL
- Nginx on `443`
- WinHUB Debian backend bound to `127.0.0.1:8443` over local HTTP
- External users and agents connect to `https://SERVER_IP`
- Optional agent-only public listener controlled by `AGENT_PUBLIC_PORT`

## 1. Copy project

Clone the Git repository to the Debian server:

```bash
sudo mkdir -p /opt/winhub
sudo git clone git@github.com:Galaxy-King/winhub.git /opt/winhub
cd /opt/winhub
```

## 2. Install runtime files

```bash
sudo bash deploy/debian/install_debian.sh
```

The installer creates:

- `/etc/winhub/winhub.env`
- `/etc/winhub/certs/cert.pem`
- `/etc/winhub/certs/key.pem`
- `/var/lib/winhub`
- `/var/log/winhub`
- `/etc/systemd/system/winhub.service`
- `/etc/nginx/sites-available/winhub`

The Debian service starts:

```text
/opt/winhub/server_debian.py
```

Nginx terminates TLS on `443` and proxies to the local backend on `127.0.0.1:8443`.
By default agents also use `443`, so existing deployments keep working.

## 3. PostgreSQL

Create database and user:

```bash
sudo -u postgres psql
```

```sql
CREATE USER winhub WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE winhub OWNER winhub;
\q
```

Then edit:

```bash
sudo nano /etc/winhub/winhub.env
```

Set:

```ini
POSTGRES_DB=winhub
POSTGRES_USER=winhub
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD
```

## 4. Generate production secrets

```bash
openssl rand -base64 48
openssl rand -base64 48
openssl rand -base64 48
```

Put different values into:

```ini
SECRET_KEY=
AGENT_API_KEY=
AGENT_TASK_HMAC_SECRET=
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

Because the server is accessed by IP, the certificate must contain the server IP in SAN.

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

## 6. Start

```bash
sudo systemctl enable --now winhub
sudo systemctl reload nginx
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

The first admin credentials are written to:

```text
/var/lib/winhub/admin_recovery.txt
```

## 7. Updates

Before updating, the project should live in Git or be deployed as a release archive. Runtime files stay outside the code tree:

- `/etc/winhub/winhub.env`
- `/etc/winhub/certs`
- `/var/lib/winhub`
- `/var/log/winhub`

Update from a Git checkout:

```bash
cd /opt/winhub
sudo /opt/winhub/deploy/debian/update_winhub.sh v0.1.0
```

If no version/tag is passed, the script runs `git pull --ff-only`.

Update from a release archive:

```bash
./deploy/create_release.sh
scp dist/winhub-v0.1.0.tar.gz SERVER:/tmp/
ssh SERVER 'sudo /opt/winhub/deploy/debian/update_winhub.sh /tmp/winhub-v0.1.0.tar.gz'
```

The update script creates a PostgreSQL/runtime backup, updates code, refreshes dependencies, runs Alembic migrations, restarts WinHUB and checks `/api/health`.

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
  ssh "$host" 'sudo /opt/winhub/deploy/debian/update_winhub.sh v0.1.0'
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

## 11. Firewall

For Nginx deployment:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Do not expose PostgreSQL publicly.
