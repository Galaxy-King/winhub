# Automation Scheduler: durable occurrences and script outcomes

Рішення від 2026-10-28. Задачі виконуються на керованих хостах, а не на сервері WinHUB.

- Calendar specification з часовою зоною зберігається окремо від legacy cron. Підтримуються once, daily, anchored weekly, monthly, elapsed interval і cron. Старі cron/DATE розклади читаються без примусового перетворення.
- ScheduleRun фіксує спрацювання до dispatch. Унікальний ключ schedule_id/occurrence_key та блокування рядка розкладу серіалізують автоматичні claims і queued dispatch між процесами. Після перезапуску прострочений next_run_at зберігається; backlog згортається до одного спрацювання. Перерваний claim не запускається повторно автоматично.
- Окремі delivery_deadline і result_deadline відрізняють неотриману задачу від невідомого результату після pickup. Повтори дозволені лише до pickup, для того самого AgentTask. Невідомий результат блокує overlap до автентифікованого завершення або явного адміністративного resolution після перевірки хоста.
- Сервер формує обгортку лише навколо вже схваленого run_script. Дочірній PowerShell/Bash повертає код; nonce-bound trailer читається як дані з автентифікованого результату. Вивід не eval-иться. Підписи, TLS та перевірки доступу не вимикаються. Числовий код не є доказом цілісності backup: скрипт має сам перевірити потрібний результат.
- Legacy tasks без контракту зберігають native agent status. Для ввімкнення numeric exit contract старий розклад слід відкрити та зберегти новою формою. Нескриптові дії не отримують вигаданих кодів.
- Нові dispatch перевіряють активність і поточні права власника розкладу; автоматичне виконання не позичає права першого адміністратора. History API інтерактивний, з обмеженнями видимості хостів, masking і текстовим DOM rendering.
- Міграція additive, runtime-файли входять у чинні server manifests. Агентський протокол не змінено; оновлення агентів лише для цієї функції не потрібне. Розгортання сервера має йти штатним updater із backup, міграціями та healthcheck.

Користувацькі інструкції: [English](../guides/features/AUTOMATION_SCHEDULER_EN.md), [Українська](../guides/features/AUTOMATION_SCHEDULER_UA.md). Такий самий Guide доступний у Scheduler.
