# Proxmox: Linux Agent через SSH та створення Windows VM

Агент встановлюється на Proxmox-вузол. Windows-шаблон агента Linux не потребує.
Використовуйте перевірений self-contained linux-x64 release свого WinHUB, не source zip.
.NET SDK/runtime на Proxmox для self-contained пакета встановлювати не потрібно.
SSH-приклади нижче — для PowerShell Windows та root на t51ps; шлях/ім’я архіву замініть своїми.

## Копіювання та встановлення

На своєму комп’ютері:

```powershell
scp "C:\Downloads\WinHUBLinuxAgent-YOUR-VERSION-linux-x64.tar.gz" root@t51ps:/root/
ssh root@t51ps
```

На Proxmox, у SSH-сеансі:

```bash
umask 077
agent_stage=$(mktemp -d /root/winhub-agent-install.XXXXXX)
tar -xzf /root/WinHUBLinuxAgent-YOUR-VERSION-linux-x64.tar.gz -C "$agent_stage"
cd "$agent_stage"
test -x ./WinHUBLinuxAgent
command -v python3 systemd-run flock setsid
cat /sys/fs/cgroup/cgroup.controllers
```

Потрібні systemd, cgroup v2 з cpu/memory/pids, python3 та util-linux.
Якщо архів має вкладений каталог, перейдіть у каталог з install-linux-agent.sh.
Пакет/контрольну суму перевіряйте через довірений канал постачання.

Для нового endpoint (наявні конфіги не перезаписувати):

```bash
install -d -m 0700 /etc/winhub-agent
test -e /etc/winhub-agent/winhub_agent.conf || install -m 0600 winhub_agent.conf.example /etc/winhub-agent/winhub_agent.conf
nano /etc/winhub-agent/winhub_agent.conf
```

У runtime JSON задайте реальні `ServerUrl` (HTTPS) та `ServerCertificateSha256`
(SHA-256 leaf-сертифіката без двокрапок, із довіреного джерела адміністратора WinHUB).
Залиште TLS verification та `RequireTaskSignature: true`. Runtime `GlobalApiKey` залиште порожнім.
Для цього пакета достатньо:

```json
"ExecutionMode": "allowlist",
"AllowedActions": ["agent_update", "run_script"]
```

Це дозволяє підписані Bash-скрипти від root, а не лише qm. Обмежте право запуску задач
і доступ до Proxmox endpoint у WinHUB; `full` для цього пакета не потрібен.
DefaultTaskTimeoutSeconds залиште 1800; у задачі також задавайте 1800 секунд або більше для повного клона.

Для першої реєстрації, якщо endpoint ще не має identity/token:

```bash
test -e /etc/winhub-agent/winhub_agent.bootstrap.conf || install -m 0600 winhub_agent.bootstrap.conf.example /etc/winhub-agent/winhub_agent.bootstrap.conf
nano /etc/winhub-agent/winhub_agent.bootstrap.conf
```

У bootstrap `GlobalApiKey` задайте enrollment key свого WinHUB (`AGENT_API_KEY` сервера).
Не надсилайте ключ у чат. Не копіюйте `/var/lib/winhub-agent` з іншого вузла.

```bash
./WinHUBLinuxAgent --validate-config /etc/winhub-agent/winhub_agent.conf
bash ./install-linux-agent.sh
systemctl is-active winhub-linux-agent
journalctl -u winhub-linux-agent -n 50 --no-pager
```

Після enrollment знайдіть t51ps у WinHUB. Bootstrap видаляється агентом після успішного перенесення.
Додаткові вимоги та статус RC: [README Linux Agent](../../../WinHUBLinuxAgent/README.md).

## Тимчасовий пароль

Пароль Administrator задається безпосередньо у формі запуску в полі Temporary Administrator password.
Файл пароля на Proxmox більше не потрібен. Використовуйте 12..128 символів без переносів рядка.
Після створення змініть пароль у Windows. Шаблон сам не виконує подальшу ротацію.
Поточний WinHUB зберігає підставлені значення у payload задачі: це тимчасовий credential,
а не секрет, який автоматично стирається після виконання. Скрипт не друкує пароль у результат.

## Імпорт і тест

Імпортуйте [JSON](../../../WinHUB/deploy/import_templates/proxmox_vm_create/proxmox_vm_create_pack.json),
перегляньте та затвердьте action. Запускайте на одному вибраному Proxmox endpoint.
Спочатку Mode=Validate: TemplateID=114, Storage=local, вільний VMID, ім’я Windows,
IP, маска (24 або 255.255.255.0), шлюз, DNS. Temporary Administrator password — тимчасовий пароль.
Пароль вводьте тільки у відповідне поле. CPU/RAM/диск/bridge/VLAN залиште порожніми для успадкування.
Після перевірки запустіть Mode=Create з тими самими параметрами.

Скрипт робить full clone, застосовує Cloud-Init та ресурси, оновлює ConfigDrive і запускає VM.
Успіх задачі означає лише запуск, не готовність RDP. Перевірте консоль, RDP, hostname та ipconfig /all,
а також збереження налаштувань після перезавантаження. Не перезаписуйте початковий шаблон 9005.
На production hypervisor перший функціональний запуск неперевіреного пакета не проводьте:
спочатку окремий тестовий Proxmox/ізольований стенд із синтетичними параметрами.

Повний clone може тривати довше timeout. При будь-якому перериванні перевірте Proxmox task log
та VMID перед повтором. Автоматичного видалення/відновлення частково створеної VM немає.
Поточний шаблон Windows не розширює розділ C: автоматично при збільшенні диска.
DNS домену AD задавайте замість публічного DNS для доменних машин.

Назва action та поля англійською. Порядок: Source template VMID, New VM name, New VM ID, Operation, пароль, storage, мережа, ресурси. Числовий порядок також закодований у внутрішніх іменах змінних для старих UI з алфавітним сортуванням.

VMID можна залишити порожнім: Create знаходить перший вільний номер від 100, враховуючи VM, LXC і шаблони всього кластера. Явний зайнятий VMID відхиляється. Validate не резервує номер; Create перевіряє повторно. Якщо конкурентна операція зайняла номер до clone, помилка clone зупиняє задачу до set/start, без перезаписування чи видалення. Ім’я Windows обмежене 15 ASCII символами; наприклад test-winhub.

## Окремі імена Proxmox та Windows

Proxmox VM name підтримує term-192.168.38.234. Windows hostname задається окремо, наприклад term-38-234 (до 15 символів). Для ConfigDrive створюється окремий metadata snippet зі збереженням instance identity. Цільове Directory-сховище повинно підтримувати Images та Snippets: у Proxmox Datacenter → Storage → local → Edit → Content додайте Snippets, зберігши вже вибрані типи. Metadata snippet залишається потрібним для регенерації ConfigDrive; для міграції він має бути доступний на цільовому вузлі. Після видалення ВМ відповідний winhub-vm-VMID-meta.json прибирається вручну.

Windows hostname необов’язковий: порожнє поле генерує WIN- та 10 випадкових hex-символів (14 символів загалом). Ім’я показується в результаті задачі. Validate показує лише приклад; Create генерує нове ім’я і передає його у ConfigDrive до запуску Windows.

## Автоматичний тимчасовий пароль

Поточна версія вилучає поле AdminPassword. Create генерує криптографічно випадковий пароль із 24 символів (великі/малі літери, цифри, спеціальні символи). Після успішного qm set повертає username та temporary_password у результаті задачі, навіть якщо подальший запуск завершиться помилкою. Validate пароль не створює й не показує. Результат містить відкритий credential та зберігається у WinHUB; після входу змініть пароль. Це переданий пароль, не підтвердження його застосування Cloudbase-Init. Для раніше створеної VM пароль автоматично не змінюється.

Виправлення Windows ConfigDrive: custom metadata явно містить admin_username=Administrator та admin_pass зі згенерованим паролем. qm cloudinit dump meta може повертати загальні metadata без Windows credentials, тому їх не можна лише копіювати. Snippet містить відкритий тимчасовий пароль, створюється з umask 077; не публікуйте його.

Metadata snippets тепер мають випадковий суфікс: winhub-vm-VMID-RANDOM-meta.json. Залишок від видаленої VM не блокує повторне використання VMID. Файли створюються exclusive без перезапису. Після помилки Create перевірте частково створену VM перед повтором.
