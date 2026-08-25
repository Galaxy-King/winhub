# TLS і мережа

## Базова схема

- Nginx: `0.0.0.0:443`;
- HTTP redirect: `0.0.0.0:80`;
- WinHUB backend: `127.0.0.1:8443`;
- PostgreSQL: локальне підключення;
- агент: лише вихідний HTTPS до WinHUB.

Порт `8443` не відкривайте у зовнішньому firewall.

## Сертифікат

Файли:

```text
/etc/winhub/certs/cert.pem
/etc/winhub/certs/key.pem
```

Private key має бути доступний лише root і групі служби. Після заміни:

```bash
sudo chown root:winhub /etc/winhub/certs/*.pem
sudo chmod 0640 /etc/winhub/certs/*.pem
sudo nginx -t
sudo systemctl reload nginx
```

## Довіра агентів

Використовуйте один із варіантів:

1. сертифікат від trusted CA;
2. internal CA, встановлений у trust store endpoint-вузлів;
3. SHA-256 certificate pin у runtime config агента.

`IgnoreTlsCertificateErrors=true` не використовується у production.

## Окремий порт агентів

`AGENT_PUBLIC_PORT` може створити agent-only listener. На ньому доступні лише agent API, downloads і health endpoint; web UI повертає `404`. Відкривайте цей порт у firewall лише після перевірки Nginx-конфігурації.
