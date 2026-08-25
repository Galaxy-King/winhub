# Reports

Reports формуються з task results у відокремленому `winhub-renderer` service.

## Дії

- перегляд і download;
- edit дозволеного тексту;
- dismiss або delete;
- email delivery;
- publish до Confluence;
- scheduled send;
- finalize grouped job.

## Sensitive values

Право `view_sensitive_reports` відокремлено від звичайного `view_reports`. Не вставляйте секрети у report template або необроблений HTML.

## Перед відправленням

1. Перевірте recipients/Confluence target.
2. Перевірте masking.
3. Переконайтеся, що вкладення не перевищує limit.
4. Для sensitive email використовуйте затверджене GPG-шифрування.
5. Перевірте Audit Log після відправлення.
