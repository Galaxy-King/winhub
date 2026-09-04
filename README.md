# WinHUB

Сервер, агенти та документація розміщені в окремих каталогах одного Git-репозиторію.

```text
WinHUB_Project/                 # корінь Git; назва checkout може бути іншою
├── WinHUB/                     # Python-сервер, тести, міграції, deploy
├── WinHUBAgentWindows/         # Windows-агент (.NET 8)
├── WinHUBLinuxAgent/           # Linux-агент (.NET 8)
├── WinHUBMacAgent/             # macOS-агент (.NET 10), docs і тести
├── WinHUB-WiKi/                # документація всіх компонентів
│   └── guides/                 # докладні посібники: features, security, agents
├── .github/workflows/          # CI
├── AGENTS.md                   # спільні правила для Codex
└── global.json                # SDK для Windows/Linux; macOS має власний
```

## Встановлення сервера з нуля

У терміналі чистого Debian 12 із правами sudo:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/Galaxy-King/winhub.git ~/winhub
cd ~/winhub/WinHUB
sudo bash deploy/debian/install_debian.sh
```

Вкажіть DNS-ім'я або IPv4-адресу сервера. Інсталятор встановить залежності, налаштує PostgreSQL, TLS, Nginx, служби та міграції. Наприкінці скопіюйте recovery-архів у зашифроване сховище, перевірте SHA-256 і введіть `SAVED`. Перші дані входу містяться в цьому архіві.

Робоча програма встановлюється в `/opt/winhub`, конфігурація — `/etc/winhub`, дані — `/var/lib/winhub`. Git checkout залишається у `~/winhub`. [Повна процедура](WinHUB-WiKi/02-Сервер/01-Встановлення-з-нуля.md).

## Оновлення

```bash
git -C ~/winhub pull --ff-only
sudo bash ~/winhub/WinHUB/deploy/debian/update_winhub.sh ~/winhub/WinHUB
```

Можна також передати серверний `winhub-v*.tar.gz`. Оновлення спочатку створює backup установленої версії. [Оновлення й перехід зі старої структури](WinHUB-WiKi/02-Сервер/05-Оновлення-сервера.md).

## Розробка і документація

- [Сервер і перевірки](WinHUB/README.md)
- [Windows-агент](WinHUBAgentWindows/README.md)
- [Linux-агент](WinHUBLinuxAgent/README.md)
- [macOS-агент](WinHUBMacAgent/README.md)
- [Wiki](WinHUB-WiKi/README.md) і [докладні посібники](WinHUB-WiKi/guides/README.md)

Папка й файл проєкту Windows мають назву `WinHUBAgentWindows`; установлені служба, `WinHUBAgent.exe` і формат пакетів зберігають сумісні назви. macOS використовує спільний `WinHUBLinuxAgent/Worker.cs`.

Спільний security-код у `WinHUBLinuxAgent/Security/` підключений також Windows/macOS. Для складання потрібен повний checkout. [Strict pin: стан реалізації та критерії production-релізу](WinHUB-WiKi/guides/agents/PRODUCTION_PIN_AGENTS_UA.md).

## Що належить до Git

Кореневий `.gitignore` дозволяє лише перелічені компоненти й службові файли репозиторію. Локальні резервні копії, сторонні checkout-и й архіви поруч із ними не додаються. Кеші, virtual environments, `bin`, `obj`, `dist`, `dist-agent`, runtime-конфігурації та ключі також виключені. Новий компонент у корені потрібно явно додати до `.gitignore`.

Перед комітом перевіряйте `git status --short` і `git diff --cached --stat`. Release-файли зберігайте як артефакти релізу. Склад серверного архіву визначають `WinHUB/deploy/server-files.txt` і `server-excludes.txt`.

## Нові задачі в Codex

Відкривайте задачу в корені цього репозиторію (`WinHUB_Project`) або його компоненті. Спільну карту, правила розміщення файлів, роботи з Git і перевірок записано в [AGENTS.md](AGENTS.md). Codex підхоплює цей файл на початку роботи; [порядок завантаження інструкцій](https://learn.chatgpt.com/docs/agent-configuration/agents-md) описано в документації OpenAI.

Для наступного чату достатньо описати задачу. Нові сталі домовленості додавайте до `AGENTS.md`, а деталі функцій та архітектури — до відповідної Wiki. Якщо створюєте окремий checkout/worktree або працюєте на іншому комп'ютері, використовуйте гілку, у якій ці файли вже закомічені. Незакомічені правила доступні в поточному локальному checkout.
