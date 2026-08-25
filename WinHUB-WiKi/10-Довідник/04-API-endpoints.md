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

## Newsletter

Configuration, SMTP, tests, lists, inbound routes та send використовують `/api/newsletter/...`.

Детальна схема request/response має генеруватися з коду поточної версії. Не вставляйте live bearer/API tokens у приклади.
