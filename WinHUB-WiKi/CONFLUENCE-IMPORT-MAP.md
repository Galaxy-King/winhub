# Карта імпорту до Confluence

Якщо імпортер Markdown не відтворює каталоги як parent-child pages, використайте цю карту.

| Parent page | Дочірні сторінки |
| --- | --- |
| `WinHUB` | `Головна`, `Загальна інформація`, `Сервер WinHUB`, `Агенти WinHUB`, `Endpoint Management`, `Newsletter`, `Адміністрування WinHUB`, `Безпека WinHUB`, `Експлуатація WinHUB`, `Розробка WinHUB`, `Довідник` |
| `Загальна інформація` | Усі інші `.md` із `01-Загальна-інформація` |
| `Сервер WinHUB` | Усі інші `.md` із `02-Сервер` |
| `Агенти WinHUB` | `Загальні налаштування агентів`, `Enrollment і безпека агентів`, `Windows Agent`, `Linux Agent`, `macOS Agent` |
| `Windows Agent` | Усі інші `.md` із `03-Агенти/Windows` |
| `Linux Agent` | Усі інші `.md` із `03-Агенти/Linux` |
| `macOS Agent` | Усі інші `.md` із `03-Агенти/macOS` |
| `Endpoint Management` | Усі інші `.md` із `04-Endpoint-Management` |
| `Newsletter` | Усі інші `.md` із `05-Newsletter` |
| `Адміністрування WinHUB` | Усі інші `.md` із `06-Адміністрування` |
| `Безпека WinHUB` | Усі інші `.md` із `07-Безпека` |
| `Експлуатація WinHUB` | Усі інші `.md` із `08-Експлуатація` |
| `Розробка WinHUB` | Усі інші `.md` із `09-Розробка` |
| `Довідник` | Усі інші `.md` із `10-Довідник` |

## Рекомендований порядок

1. Створіть root page `WinHUB`.
2. Імпортуйте index page кожного розділу з префіксом `00-`.
3. Імпортуйте дочірні сторінки в числовому порядку.
4. Перенесіть pages під відповідний parent.
5. Приберіть числові префікси з назв, якщо імпортер використав filename замість `H1`.
6. Перевірте links, tables, code blocks і permissions Confluence space.

Recovery bundle, production env, logs і screenshots із sensitive data не імпортуються.
