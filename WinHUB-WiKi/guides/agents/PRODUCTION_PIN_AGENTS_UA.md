# Windows/Linux: strict certificate pinning — кандидат релізу

Статус: **реалізація повного production-плану ще не завершена**. RC3 додає незалежний підпис релізу, архів журналу і ОС-рівневі ліміти задач до strict TLS/v2 та безпечнішого updater. Непривілейований transport/broker і серверна міграція параметрів/enrollment ще не реалізовані. Не використовувати успішний self-test як дозвіл на масове оновлення. [Підписування та ручне приймання RC3](AGENT_RELEASE_ACCEPTANCE_UA.md).

## Реалізовано

- Windows/Linux вимагають HTTPS origin, TLS 1.2/1.3 і явно заданий `ServerCertificateSha256`; довіра не вивчається з мережі. Дозволено self-signed leaf certificate, якщо його точний SHA-256 збігається та строк дії чинний.
- `ServerCertificateSha256Next` — додатковий явно налаштований pin для перекриття під час заміни сертифіката. Він не завантажується автоматично з сервера.
- `IgnoreTlsCertificateErrors=true`, `RequireTaskSignature=false`, HTTP та cross-host update URL відхиляються. Redirects, cookies і неявні системні HTTP proxies вимкнені.
- Нові Windows/Linux агенти виконують тільки RSA-PSS v2 задачі. Перевіряють endpoint, task ID, дію, payload hash, timeout, строк дії, pin ключа й sequence. Приватний ключ підпису задач залишається на сервері; ключ ідентичності агента — окремий.
- Windows зберігає `task-signing-state.json` окремо від конфігурації. Обидва агенти відхиляють помилку збереження стану до запуску задачі. Запис через тимчасовий файл, flush і заміну; на Linux також fsync каталогу.
- Запис ключів, токенів і secret store зроблено атомарним. Windows встановлює точний DACL для SYSTEM/Administrators; Unix перевіряє встановлені права та власника. Невдала операція більше не означає успіх.
- Bootstrap/enrollment key видаляється з локального secret store після збереження токена; при оновленні вже зареєстрованого агента старий залишок також прибирається. Shared TaskHmacSecret у Windows/Linux більше не потрібен і не переноситься в новий bootstrap. Після відкликання доступу відновлення потребує адміністратора, а не приховано збереженого спільного enrollment key.
- Windows/Linux захоплюють stdout/stderr з лімітом під час читання. API responses обмежені 4 MiB, update download — 512 MiB із 10-хвилинним deadline; збережений result log — до 1 MiB.
- Скрипти Windows/Linux зберігаються у захищеному каталозі даних агента. Linux потребує `/usr/bin/setsid` (`util-linux`): завершення задачі прибирає її process group навіть після виходу початкового shell. `KillMode=control-group` явно задано для зупинки Linux-служби. Це не забороняє навмисному root-скрипту виходити з групи або змінювати ОС.
- `execution-journal` записує claim до запуску та до підтвердження sequence; результат зберігається до відправлення. HTTP 2xx без JSON `status=success` не вважається підтвердженням. Після обриву зв'язку повторюється доставка, не виконання. Після аварії claimed-задача повертає `Error` із явним `UNKNOWN`: вона могла частково виконатися, автоматичного повтору немає. Task ID залишається в журналі після доставки.
- Журнал має одного власника-процес і відхиляє чужий endpoint; запис/ACL помилка зупиняє виконання, а не маскується. Пошкоджені identity/token/state не замінюються новими автоматично. Старі Linux pending results не видаляються при HTTP error або пошкодженні файла.
- Safe extraction ZIP/TAR.GZ відхиляє traversal, links/special files, дублікати файлів та завеликі архіви (до 4096 entries, 512 MiB на файл, 2 GiB сумарно).
- Нові updater scripts перевіряють обов'язковий SHA-256 і запускають offline config preflight до заміни агента. Виправлено Windows rollback, який раніше переривався на `Write-Error`; Linux отримав спробу rollback після невдалого запуску.

SHA-256 із підписаної задачі сам по собі не є незалежним підписом видавця. У RC3 додано `release-manifest.json`: RSA-PSS/SHA-256, inventory/hash кожного файла, платформа/архітектура, version та serial. Довірений **публічний** `release-signing-public.pem` адміністратор доставляє до каталогу даних агента окремо. Приватний ключ лишається на захищеному build/signing комп'ютері поза Git, OpenCloud і сервером WinHUB. Підпис не береться з ключа, вкладеного в пакет. Відсутній ключ/manifest, підміна, downgrade або reused serial для іншого manifest блокують update до запуску updater. `release-state.json` резервує floor до запуску: повтор тієї самої спроби допустимий, нижчий release — ні. Code rollback не відкочує цей стан.

RC3 обмежує активний журнал 32 непідтвердженими задачами. Підтверджені task IDs зберігаються без log у `execution-journal/acknowledged/XX/` і не завантажуються всі в RAM при старті; попередньої lifetime-межі 10 000 немає. Запис архіву передує видаленню активного результату. Старі flat tombstones мігрують автоматично, включно з відновленням перерваної міграції; `.endpoint` прив'язує архів до агента. Архів **не видаляти**: він потрібен для dedup і поступово займає диск. Помилки запису/disk-full блокують нове виконання або залишають result для повторної доставки. Потрібен моніторинг вільного місця. Це не exactly-once довільних зовнішніх ефектів скрипта. Старі агенти не знають нового архіву: rollback нижче RC3 — лише recovery з зупиненою видачею задач, не безпечне продовження роботи.

RC3 Windows виконує скрипти у Job Object: wrapper отримує команду тільки після приєднання до job, `KILL_ON_JOB_CLOSE` прибирає нащадків. Linux виконує задачі через `systemd-run` із cgroup v2, CPU/memory/pids controllers, runtime deadline, `MemorySwapMax=0`, `OOMPolicy=kill` і прив'язкою життя task unit до `winhub-linux-agent.service`. Якщо потрібних можливостей немає, unrestricted fallback **відсутній**. Тести без служб не доводять застосування Linux limits на хості.

Локальні defaults: `TaskMemoryLimitMb=2048`, `TaskProcessLimit=32`, `TaskCpuPercent=50`; допустимі межі — 128..131072 MiB, 4..1024, 1..100%. Linux TasksMax рахує також threads; Windows job включає wrapper/PowerShell. CPU percent відноситься до сумарної потужності доступних CPU. Для великих бекапів ліміти потрібно оцінити й явно налаштувати до rollout; нуль не вимикає захист. Сервіси/процеси, запущені окремо через SCM/systemd привілейованим скриптом, не стають безпечно ізольованими цими механізмами. SYSTEM/root завдання все ще може змінити ОС, агент або trust — воно має залишатися довіреним адміністративним кодом.

## Довірений pin

На самому сервері WinHUB, у довіреному root-сеансі, для штатного шляху сертифіката Nginx:

```bash
openssl x509 -in /etc/winhub/certs/cert.pem -noout -fingerprint -sha256 -dates
```

Якщо Nginx використовує інший сертифікат, потрібен відбиток саме його leaf certificate. Не читати та не передавати `key.pem`. Відбиток не є секретом, але його джерело має бути довіреним. Заборонено автоматично отримувати pin через з'єднання з вимкненою TLS-перевіркою.

У конфігурації агента (приклад, не робочий pin):

```json
{
  "ServerUrl": "https://WINHUB_SERVER",
  "ServerCertificateSha256": "PASTE_64_HEX_DIGITS_FROM_TRUSTED_SERVER",
  "ServerCertificateSha256Next": "",
  "IgnoreTlsCertificateErrors": false,
  "RequireTaskSignature": true
}
```

Не підміняти цим фрагментом увесь існуючий config: інші налаштування та identity/state потрібно зберегти. Не вставляти один host-specific task signing key/sequence у конфіги інших агентів.

Порядок ротації: на захищеному каналі доставити майбутній pin → перевірити застосування → замінити сертифікат на сервері → перевірити з'єднання → зробити новий pin основним і видалити старий. Протермінований сертифікат не приймається навіть зі збігом pin. Потрібні коректний системний час та завчасна ротація.

## Перехід без втрати наявного агента

1. Сервер уже має видавати Task v2; підтвердити звичайну задачу на старому агенті. Новий бінарник не підтримує HMAC fallback.
2. Зберегти backup установленого коду, конфігурації та локального state. Не копіювати identity між хостами і не скидати sequence при rollback.
3. Задати перевірений pin, вимкнути legacy bypass. Для Linux зберегти потрібний `ExecutionMode`; повне адміністрування потребує `full`.
4. **Спочатку оновити сервер, потім агентів.** Сервер має містити `core/agent_updates.py` та `deploy/agent-updaters/`. Новий сервер надсилає підписану підготовчу задачу з updater і SHA-256 саме вибраного пакета. Windows `1.2.21` передає лише `PackagePath`: підготовлений updater використовує авторизований SHA із цієї задачі. Нові агенти передають SHA окремим параметром. Установлений старий EXE не запускається з невідомими CLI-командами. Невдала/заборонена підготовка блокує видачу пов'язаної задачі оновлення; service залишається старою.
5. У тестовій VM запустити кандидат із `--validate-config PATH_TO_EXISTING_CONFIG` та `--self-test`. Перша команда перевіряє формат/policy offline, але не мережеву досяжність, застосовані ACL або справжність наданого pin.
6. На ізольованих canary перевірити service install, зв'язок, звичайні задачі, reboot, update/rollback і втрату мережі. Ці тести закривають лише частину release gates нижче. Масове розгортання можливе після завершення решти кодових етапів і перевірок та окремого погодження.

## Що ще блокує фінальний production-реліз за повним планом

- Відокремлений непривілейований transport та привілейований broker із незалежною перевіркою IPC і bootstrap trust. Зараз Worker усе ще працює привілейовано; TLS pin перевіряється саме ним.
- End-to-end міграція/тривале навантаження архіву, реальні power-loss/disk-full випробування durability. Локальні тести покривають restart/claim/ack/dedup і змодельовані I/O помилки, не аварійне вимкнення VM.
- Ручна перевірка Linux cgroups/systemd та ресурсних лімітів реальних Windows/Linux workloads. Windows Job Objects перевірено локальними процесами, але не service token на клієнтській VM.
- Адміністратор має створити й захистити свій release-signing key, доставити public trust і підписати пакети. Інструмент і перевірка manifest/anti-rollback реалізовані; робочий приватний ключ не генерувався. Перший перехід зі старого агента не отримує перевірку підпису заднім числом.
- Типізовані параметри, окремі від тексту скрипту; сумісна міграція template packs і server dispatch. Наявну підстановку рядків цей етап не змінює.
- Scoped одноразовий enrollment та усунення server-side обходів identity/permissions. Pin сам по собі не виправляє серверні проблеми з попереднього аудиту.
- Реальні Windows service token/ACL та Linux systemd tests, перша інсталяція, перехід зі старої версії, аварійний rollback, power-loss/disk-full, перевірка секретів у пакетах і незалежна повторна security-перевірка.
- Автоматична координація звичайної черги, watchdog і service recovery під час update/rollback під навантаженням. Поки canary проводять із зупиненою звичайною видачею задач; старий код після rollback не повинен одразу отримувати нові задачі.

Пакети `2.0.0-rc.1`, `rc.2` і `rc.3` — кандидати, не фінальні production-релізи. RC1 не має потрібного updater descriptor; RC2 ще не перевіряє publisher signature. Build ZIP/TAR.GZ RC3 **не підписані**: для оновлення strict агента потрібен окремий підписаний пакет із offline publisher. Не відмічати решту production-плану виконаною за самою наявністю коду.

## Сумісне оновлення RC2

- Канонічні updater scripts — у серверному `deploy/agent-updaters/`. Агентські `.csproj` копіюють саме їх до ZIP/TAR.GZ; короткі scripts у вихідних каталогах агентів — лише wrappers для повного checkout. Серверний release включає updater assets без вихідного коду агентів.
- Windows ZIP має плоский корінь: `WinHUBAgent.exe`, `update-service.ps1`, `install-service.ps1`, `update-protocol.json`. Linux TAR.GZ — `WinHUBLinuxAgent`, updater, systemd unit і descriptor. Сторонні/старі формати без descriptor відхиляються до зупинки service. SHA із signed task авторизує весь пакет, включно з descriptor; descriptor не є криптографічним підписом видавця.
- Linux потребує `python3` та `util-linux` (`flock`, `setsid`). Підготовча задача потребує дозволеного `run_script`: у локальному `allowlist` лише з `agent_update` вона буде відхилена, а update не запуститься. Адміністратор може окремо дозволити `run_script` на canary або встановити новий updater через довірений локальний/SSH-сеанс; автоматичного розширення `ExecutionMode` немає.
- Updater перевіряє SHA приватної копії пакета, paths/links/size, descriptor, offline config, а потім виконує **новим** бінарником `--check-update-server CONFIG_PATH`. Ця read-only команда робить тільки bounded `GET /api/health` через перевірений pin, без enrollment, poll, token або зміни sequence. Невірний pin, expired certificate, redirect чи недоступність сервера блокують заміну до зупинки старої служби.
- Далі — зупинка служби, захищений backup коду, заміна, запуск і перевірка, що служба лишилася запущеною. При невдачі виконується спроба code rollback. Живий config, token, identity та journal не відновлюються поверх новішого стану зі старої копії. Це не гарантує автоматичного recovery після power loss чи доводить успішну автентифікацію нового процесу: у Fleet Center потрібно підтвердити нову версію та виконати звичайну задачу.
- Паралельні updater processes блокуються локальним lock. Дві одночасні підготовки різних пакетів для одного старого агента можуть завершитися SHA mismatch: це безпечна відмова, не дозвіл підмінити пакет. Не запускати паралельні rollout на один endpoint.

Canary-порядок: backup → сервер із новими assets → завантажити RC2 ZIP/TAR.GZ через Fleet Center → один тестовий Windows `1.2.21` та один Linux → перевірити `Task v2`, нову версію, одну звичайну задачу, повторне оновлення й recovery → окремо погодити ширше розгортання. Не завантажувати папку publish або лише EXE замість пакета.

Локальні тести RC2: справжні synthetic HTTPS probes з правильним/неправильним pin, redirect та завеликою/помилковою відповіддю; перевірка серверної залежності prepare → update; Linux adversarial archives і транзакції updater із замоканим `systemctl` у TEMP (legacy/new args, bad SHA, bad preflight, failed start/rollback, збереження config/state). Це **не** реально виконане оновлення Windows `1.2.21` або Linux systemd у VM. Windows PowerShell runtime fixtures додані; якщо локальна Execution Policy їх блокує, потрібен окремо дозволений тестовий процес, а не автоматична зміна системної політики.

## Локальні перевірки кандидата

- Windows: build + offline self-tests; self-contained x64 кандидат. NativeAOT Windows не підтверджено цією збіркою.
- Linux: managed і NativeAOT x64 збірки та self-tests у WSL Debian 13; додатково перевіряються symlink, journal lock і дочірній процес після виходу shell.
- macOS: managed compatibility build та наявний protocol self-test для спільного коду; це не native macOS випробування.
- PowerShell parser і Bash syntax checks; CI доповнений self-test Windows та окремим Linux-platform job.
- Жодного встановлення служб, deployment на робочі хости або тесту справжнього TLS pin не виконано. Робочий pin і ключ підпису релізів не створюються/не вивчаються з мережі автоматично.
