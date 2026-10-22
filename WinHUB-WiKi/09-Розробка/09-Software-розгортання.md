# Software: доставка через WinHUB та черга розгортання

## Рішення

OMV є джерелом пакетів для сервера, а не публічним API агентів. Підготовка у scheduler завантажує один файл за раз, з обмеженням розміру/часу, чинним TLS, точним origin без redirects і central outbound policy у режимі enforce. Після підготовки immutable blob адресується SHA-256. Source URLs не потрапляють у задачі.

Каталог перенесено з JSON у `SoftwarePackage` із encrypted record, налаштування — у singleton `SoftwareControl`. Старий JSON імпортується без видалення. Шифрування спільне з рештою payload БД; це не окремий secret store із власними grants.

`SoftwareDeployment` зберігає актора, причину, паралельність і строк очікування. `SoftwareStep` зберігає encrypted snapshot програми/точного коду, позицію на хості, task ID та download lease. Зміна каталогу не змінює чергу.

Короткі транзакції з `SELECT FOR UPDATE` singleton-row серіалізують admission, queue controls і download leases між PostgreSQL-процесами. Локальний RLock підтримує потоковий доступ у тестовому SQLite; глобальний admission перевірено окремим PostgreSQL integration test із чотирма незалежними процесами. Мережеве завантаження OMV відбувається поза queue lock, із lease claim та перевіркою preparation ID перед записом результату.

## Виконання та безпека

Використовується наявний `run_script`, чинний task-signing і agent timeout; C# protocol не змінюється. Windows PowerShell downloader використовує системний TLS trust store, а не agent strict pin. Потрібен довірений сертифікат WinHUB на хості. Linux/macOS явно відхиляються цим каталогом Windows-рецептів.

Рецепт погоджується superadmin за hash. Посилання на Workspace приймає лише чинний approved `action/run_script`, без runtime variables/Jinja/AI marker. Inline code і detection command — виконуваний адміністративний код, не sandbox. Зафіксовані рецепти працюють із правами служби агента.

GET `/api/public/software-delivery/<step_id>` не є анонімним публічним каталогом: потрібен випадковий bearer token у Authorization, hash якого зберігається на активному step. Він видається при admission, передається всередині signed/encrypted-at-rest payload і діє не довше agent timeout + 300 секунд; сервер також перевіряє task status і блокування хоста. Capability не прив’язана криптографічно до пристрою під час GET; її витік дає тимчасовий доступ до одного snapshot blob. Token не додається в URL/логи. Range/resume не підтримується; повторний повний GET допускається до завершення строку, паралельний GET того самого step відхиляється.

Download lease поновлюється під час стримінгу; при аварійному обриві звільняється після 2 хвилин. Сервер обмежує число потоків та консервативну сумарну швидкість. Nginx buffering/cache вимкнено для маршруту.

## Межі та експлуатація

Черга гарантує послідовність саме Software, не виключає задачі інших підсистем, створені пізніше. Початок чекає відсутності інших активних задач на хості. Офлайн-хости не займають слот; непідтверджений результат виконання утримує слот, бо повторний інсталятор може конфліктувати з попереднім. Ручне завершення — лише superadmin після перевірки припинення процесів, з причиною та аудитом. Generic retry/cancel/finalize не повинні обходити ці правила.

Reboot-required зупиняє наступні програми, без автоматичного restart або resume. Немає автоматичного rollback, dependency solver, content publisher signature, cache GC чи загальної дискової квоти. Порядок задається числом на програмі та назвою; окремий порядок однієї програми для різних наборів не підтримується.

Тестування використовує isolated Flask/SQLite і синтетичні байти: жодних реальних інсталяторів на endpoints. Nginx-конфігурацію перевірено на тимчасових сертифікатах і непривілейованих портах; synthetic PowerShell перевіряє коди завершення без реального встановлення. Потрібні окремі приймальні перевірки OMV, production Nginx, Windows trust store, реального MSI exit/reboot та встановлення на canary перед production rollout.

[Інструкція оператора](../04-Endpoint-Management/07-Software.md).
