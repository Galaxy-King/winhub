# Встановлення Windows Agent через GPO

## Рекомендована схема

- файли deployment зберігаються у `NETLOGON`;
- GPO прив’язується до OU з цільовими комп’ютерами;
- Security Filtering застосовується до AD security group із computer accounts;
- Computer Startup `.cmd` запускає PowerShell installer;
- rollout починається з тестової групи.

## Файли deployment

```text
\\<DC_FQDN>\NETLOGON\WinHUBAgentDeploy\
  WinHUBAgent-v<VERSION>-win-x64.zip
  winhub_agent.conf
  winhub_agent.bootstrap.conf
  install-winhub-agent.ps1
  install-winhub-agent.cmd
```

Real configs зберігайте поруч із ZIP, а не всередині архіву. Target computer accounts повинні мати лише `Read & Execute`. Regular users не повинні мати write access.

## Security Filtering

1. Створіть групу, наприклад `WinHUB_Agent_Deploy_Test`.
2. Додайте computer accounts із суфіксом `$`.
3. Дайте групі `Read` і `Apply group policy`.
4. `Domain Computers` залиште `Read` без `Apply`.
5. Перезавантажте endpoint після зміни group membership.

## Startup policy

```text
Computer Configuration
→ Policies
→ Windows Settings
→ Scripts (Startup/Shutdown)
→ Startup
```

Увімкніть очікування мережі під час startup. Використовуйте `.cmd` wrapper, який веде окремий installation log.

## Production rollout

1. 1–5 тестових машин.
2. Перевірка service, ACL, logs, enrollment і Task v2.
3. Розширення групи невеликими хвилями.
4. Після завершення припиніть повторне розповсюдження bootstrap config.
5. Закрийте enrollment window на сервері.

[Повна інструкція GPO](../../guides/agents/GPO_AGENT_DEPLOYMENT.md).
