# Масове розгортання Linux Agent із WSL

Скрипт: `WinHUBLinuxAgent/deploy-linux-agents.sh`. Працює послідовно зі списком IP/hostname,
підтримує `install`, `reinstall`, `uninstall`, показує підсумок та проблемні хости.
Для встановлення використовуйте підписаний пакет із bundled public key.
Скрипт не потрібно повторно включати в підписаний пакет: запускайте актуальний файл із checkout.

## 1. Підготувати робочі файли у WSL

```bash
mkdir -p ~/winhub-deploy
chmod 700 ~/winhub-deploy
cd ~/winhub-deploy
nano hosts.txt
```

Один IP на рядок; дозволені коментарі, порожні рядки та `user@host`.
Підтримуються CRLF і UTF-8 BOM. Повторні однакові рядки обробляються один раз.

```text
# Proxmox/Linux servers
192.0.2.10
192.0.2.11
root@192.0.2.12
```

SSH-користувач має бути root або мати passwordless `sudo -n`.
SSH host keys перевіряються: нові приймаються через accept-new, змінені відхиляються.
SSH-ключ тримайте у Linux filesystem WSL (наприклад ~/.ssh), не у загальнодоступній папці Windows.
Без --identity використовуються стандартні SSH keys/agent; можливі інтерактивні запити SSH-пароля.

## 2. Підготувати конфігурації

```bash
cp /mnt/c/Users/spock/OpenCloud/Personal/WinHUB_Project/WinHUBLinuxAgent/winhub_agent.conf.example ./winhub_agent.conf
cp /mnt/c/Users/spock/OpenCloud/Personal/WinHUB_Project/WinHUBLinuxAgent/winhub_agent.bootstrap.conf.example ./winhub_agent.bootstrap.conf
chmod 600 winhub_agent.conf winhub_agent.bootstrap.conf
nano winhub_agent.conf
nano winhub_agent.bootstrap.conf
```

Runtime config: реальні HTTPS ServerUrl та trusted ServerCertificateSha256, RequireTaskSignature=true,
IgnoreTlsCertificateErrors=false. GlobalApiKey в runtime порожній.
Для Proxmox задач задайте ExecutionMode=allowlist та AllowedActions=["agent_update","run_script"].
Дозвіл run_script відкриває підписані Bash-задачі від root, а не тільки qm.
Bootstrap: GlobalApiKey — чинний enrollment key WinHUB. Не вставляйте secrets у командний рядок.
Не копіюйте token/identity/state з іншого агента.

## 3. Встановлення

Запускайте з WSL. Команда нижче використовує підписаний у цій сесії пакет і його SHA-256.
Для іншої збірки змініть шлях та checksum на результат підписувача.

```bash
bash /mnt/c/Users/spock/OpenCloud/Personal/WinHUB_Project/WinHUBLinuxAgent/deploy-linux-agents.sh --action install --hosts "$HOME/winhub-deploy/hosts.txt" --package /mnt/c/Users/spock/OpenCloud/Personal/WinHUB_Project/WinHUBLinuxAgent/dist-agent/signed/WinHUBLinuxAgent-v2.0.1-rc.3-linux-x64.tar.gz --sha256 b52bac561e80c545f5a366ed9494110350ba693b8671051685db30d233f74e8d --config "$HOME/winhub-deploy/winhub_agent.conf" --bootstrap "$HOME/winhub-deploy/winhub_agent.bootstrap.conf" --user root
```

Додайте `--identity ~/.ssh/id_ed25519` для конкретного ключа або `--port PORT` для іншого SSH-порту.
Почніть зі списку на один тестовий хост. Після перевірки додайте решту адрес.

Скрипт перевіряє checksum до SSH та повторно після передачі, ОС/архітектуру, підпис і inventory
пакета перед встановленням. Для першого trust використовується public key із довірено доставленого
пакета; наявний відмінний key не замінюється. Приватний release key не передається.
Публічний key встановлюється в /var/lib/winhub-agent/release-signing-public.pem, root:root 0600.

Наявна поточна/новіша версія не замінюється, але runtime config синхронізується за замовчуванням.
Token та identity залишаються на хості. Bootstrap застосовується лише за відсутності token.
Для збереження конфігурацій використовуйте `--no-config-sync` (на нових хостах конфіги тоді
потрібно підготувати заздалегідь). Reinstall/force не обходять перевірку signed downgrade.
Наявний updater перед заміною коду перевіряє pinned HTTPS /api/health, робить backup і rollback.
404 на health endpoint потрібно виправити у сервері/Nginx, не вимикати перевірку TLS.

## 4. Результат

Summary містить кількість успішних/невдалих операцій і failed hosts; код завершення 1 при помилках.
Несправний хост не перериває обробку решти списку. Active означає запущену службу, не enrollment.
У WinHUB перевірте появу нових хостів, версію та виконайте Approval.
Для діагностики на endpoint:

```bash
systemctl status winhub-linux-agent --no-pager
journalctl -u winhub-linux-agent -n 50 --no-pager
```

## 5. Інші режими

`--action reinstall` примусово встановлює пакет; за замовчуванням identity зберігається.
`--action uninstall` прибирає службу/бінарники, зберігаючи /etc/winhub-agent і /var/lib/winhub-agent.
`--purge` навмисно видаляє також конфігурацію, ключі й identity; для звичайного rollout не застосовуйте.
`--yes` прибирає підтвердження списку, але не SSH authentication prompts.

Локальні перевірки скрипта не є виконаним масовим rollout на реальних серверах.

Перед копіюванням runtime config на місце скрипт перевіряє запропонований конфіг та pinned HTTPS /api/health із тимчасового каталогу. При 404 синхронізація/міграція стану та зупинка агента не починаються. У попередній версії конфіг міг бути вже синхронізований до помилки healthcheck; перевірте такий хост окремо.
