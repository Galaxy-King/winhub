# Software

Software Package містить versioned archive або download source, platform metadata та recipes встановлення/видалення.

## Додавання пакета

- вкажіть name, version, platform і architecture;
- зафіксуйте SHA-256;
- визначте install/uninstall recipe;
- використовуйте variables для non-secret inputs;
- secrets зберігайте у відповідному secret store;
- перевірте silent/non-interactive behavior.

## Rollout

Перед кожним встановленням або видаленням ПЗ з’являється обов’язкове вікно причини запуску. Скасування вікна не створює задач. Причина буде в деталях кожного цільового хоста, окремо від install/uninstall script.

1. Test endpoint.
2. Pilot group.
3. Production waves.
4. Перевірка version і exit codes.
5. Rollback або uninstall plan.

Не завантажуйте пакети з довільного стороннього host. За замовчуванням agent downloads мають повертатися до власного WinHUB ServerUrl.
