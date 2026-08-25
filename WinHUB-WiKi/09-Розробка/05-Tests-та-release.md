# Tests і release

## Перед release

- Python tests;
- security regression tests;
- agent self-tests;
- installer shell syntax;
- database migration на копії production-like schema;
- update/rollback test;
- UI smoke test;
- package version і SHA-256;
- documentation link/command review.

## Agent release

Кожна platform має власний build script. Release artifact повинен бути versioned, architecture-specific, без debug symbols і без production configs.

## Server release

Після merge/tag перевірте fresh install із Git, upgrade існуючого test server, backup/restore і security smoke test. Оновіть `VERSION`, release notes і WiKi.
