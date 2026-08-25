# Groups

Групи використовуються для доступу, bulk tasks, software rollout, scheduler, triggers та block/unblock.

## Створення

1. Відкрийте `Groups`.
2. Натисніть `Create Group`.
3. Вкажіть name і description.
4. Додайте перевірені endpoint-вузли.

## Рекомендації

- групуйте за функцією, середовищем або власником;
- відділяйте `Test`, `Pilot` і `Production`;
- не використовуйте одну групу одночасно як security boundary і тимчасовий список;
- перед видаленням перевірте scheduler, trigger і user-access dependencies;
- використовуйте OS groups для platform-specific templates.

Bulk block є аварійною дією. Після неї зафіксуйте причину та перевірте Audit Log.
