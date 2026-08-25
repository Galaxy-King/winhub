# Стани та permissions

## Endpoint

`Pending`, `Approved`, `Rejected`, `Blocked`; activity — `Live` або `Passive`.

## Task/Job

Основні стани: `Pending`, `Running`, `Completed`, `Failed`, `Cancelled`. Конкретний UI може показувати додаткові rollout/report states.

## Основні permissions

| Категорія | Permissions |
| --- | --- |
| View | hosts, groups, queue, reports, sensitive reports |
| Tasks | run tasks, cleanup history |
| Hosts | approve/reject/block/delete/re-enroll |
| Content | templates, reports, software |
| Automation | scheduler, triggers |
| Delivery | SMTP, send reports |

Effective access визначається поєднанням module grants, granular permissions і group access.
