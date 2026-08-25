# Host Details і Telemetry

Host Details містить:

- hostname, display name та endpoint ID;
- connection IP і network interfaces;
- OS, agent version та last pulse;
- approval/access status;
- inventory і security state;
- group membership;
- custom metrics;
- task history;
- telemetry та IP history.

## Адміністративні дії

`Approve`, `Reject`, `Block`, `Unblock`, `Allow Re-enroll`, `Edit Name` і `Delete Record` потребують відповідних permissions. Для destructive actions перевіряйте endpoint ID, а не лише display name.

## Telemetry

Графіки доступні за періоди 1, 7 і 30 днів. Вони допомагають оцінити resource usage, disk space, online/offline періоди й зміни connection IP.

Custom metrics відображають останні значення `Metric Item` templates. Sensitive metrics не повинні містити plaintext secrets.
