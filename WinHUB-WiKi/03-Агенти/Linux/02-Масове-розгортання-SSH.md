# Масове розгортання Linux Agent через SSH

## Підготуйте

```text
WinHUBLinuxAgent-v<VERSION>-linux-x64.tar.gz
winhub_agent.conf
winhub_agent.bootstrap.conf
linux_hosts.txt
deploy-linux-agents.sh
```

Приклад списку:

```text
192.0.2.10
admin@192.0.2.11
root@192.0.2.12
```

SSH-user повинен бути root або мати passwordless `sudo -n`. Один запуск працює з одним package architecture.

## Install/update

```bash
chmod +x deploy-linux-agents.sh
./deploy-linux-agents.sh \
  --action install \
  --hosts linux_hosts.txt \
  --identity ~/.ssh/id_ed25519 \
  --yes
```

## Reinstall зі збереженням identity

```bash
./deploy-linux-agents.sh --action reinstall --hosts linux_hosts.txt --yes
```

## Правила rollout

- починайте з окремого тестового списку;
- використовуйте окремий SSH key з мінімальними правами;
- runtime config можна синхронізувати масово;
- bootstrap config копіюється лише за відсутності enrollment token;
- не залишайте реальний bootstrap config у загальнодоступній папці;
- перевіряйте summary і список failed hosts після кожної хвилі.
