# API endpoints

## Core

- `/api/health`;
- `/api/auth/login`;
- `/api/auth/forgot`;
- `/api/auth/reset`;
- `/api/session/ping`.

## Agent Gateway

- `/api/agent/enroll`;
- `/api/agent/poll`;
- `/api/agent/telemetry`;
- `/api/agent/result`.

## Administration

Users, groups, modules, API keys, audit/system logs, production readiness і GPG endpoints використовують `/api/admin/...`.

## Infrastructure

Hosts, groups, templates, tasks, reports, software packages, agent packages, scheduler, triggers і fleet використовують `/api/infrastructure/...`.

### Обов’язкова причина запуску

POST-запити на такі endpoints повинні містити JSON-поле `launch_reason`: непорожній рядок, до 2000 символів після `strip`, без неприпустимих керувальних символів. Невалідне/відсутнє значення повертає HTTP 400 без створення задачі.

- `/api/infrastructure/tasks/create`;
- `/api/infrastructure/templates/<template_id>/run`;
- `/api/infrastructure/software/install` (install/uninstall);
- `/api/infrastructure/fleet/update`;
- `/api/infrastructure/job/<job_id>/retry-failed` (лише інтерактивний оператор; API-key retry залишається забороненим);
- `/api/infrastructure/schedule/<tid>/run-now`;
- `/api/infrastructure/schedule` та `/api/infrastructure/triggers` (створення/редагування автоматизації).

Для API-клієнтів це обов’язкове доповнення запиту після міграції `20260904_02`. Причина не входить до `payload`/`variables`. GET `/api/infrastructure/task/<task_id>` повертає `data.launch_reason`, GET `/api/infrastructure/tasks/all` — `jobs[].launch_reason`. Для старих записів значення `null`. Читання підпорядковується наявним правам і scope; відображення маскує типові секрети.

GET `/api/infrastructure/jobs/<job_id>/status` також повертає `launch_reason` разом зі статусом, без коду чи результатів виконання.

## Newsletter

Configuration, SMTP, tests, lists, inbound routes та send використовують `/api/newsletter/...`.

Детальна схема request/response має генеруватися з коду поточної версії. Не вставляйте live bearer/API tokens у приклади.
