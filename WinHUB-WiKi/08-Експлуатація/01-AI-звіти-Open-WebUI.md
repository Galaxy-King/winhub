# AI-звіти через Open WebUI

WinHUB може виконати звичайний PowerShell/Bash-скрипт на декількох endpoint-ах, зібрати його результати та передати їх у власний Open WebUI для формування звіту за короткою інструкцією оператора. Окремий Jinja-шаблон звіту для кожного скрипту не потрібен.

## Потік даних

1. Оператор запускає action template або ручний скрипт та вмикає **Form report with AI**.
2. Агенти виконують тільки скрипт. AI-промт агентам не передається.
3. WinHUB створює стандартний резервний звіт, маскує типові паролі, токени, API keys і private keys у результатах.
4. Фоновий worker надсилає у Open WebUI системну інструкцію, промт оператора та обмежений JSON результатів.
5. Markdown-відповідь перетворюється в безпечний HTML без raw HTML, зовнішніх посилань або scripts і зберігається як нова незмінна revision.

Якщо AI недоступний, резервний звіт не втрачається. Статус AI буде **Error**, а автоматична відправка email/Confluence не виконається, доки AI-запит не буде успішним.

## Open WebUI

У Open WebUI створіть окремого неадміністративного service user, наприклад `winhub-ai`. Надайте йому доступ лише до потрібної моделі, увімкніть API keys і створіть ключ у **Settings → Account**. Не використовуйте ключ адміністратора.

За можливості обмежте ключ endpoint-ами:

```env
ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS=true
API_KEYS_ALLOWED_ENDPOINTS=/api/models,/api/chat/completions
```

## WinHUB

Для HTTPS Open WebUI додаткові параметри не потрібні. Для поточної приватної адреси `http://10.200.0.188:3000` додайте у `/etc/winhub/winhub.env`:

```env
AI_ALLOW_INSECURE_HTTP=true
OUTBOUND_ALLOWED_HOSTS=10.200.0.188
```

Якщо `OUTBOUND_ALLOWED_HOSTS` уже містить інші інтеграції, додайте адресу через кому, не замінюючи список. HTTP використовуйте лише всередині захищеної мережі/WireGuard; рекомендований фінальний варіант — HTTPS.

Перезапустіть WinHUB, відкрийте **Infrastructure → Administration → AI / Open WebUI** і заповніть:

- URL: `http://10.200.0.188:3000`;
- Model ID: точний ID моделі з `/api/models`;
- Service account API key;
- **Enable AI reports**.

Натисніть **Save**, потім **Test saved config**. Дозволи `use_ai_reports` і `manage_ai` призначаються окремо: оператору зазвичай потрібен тільки перший, адміністратору інтеграції — другий.

## Приклад

PowerShell-скрипт може повернути на кожному хості компактний JSON із WireGuard-конфігурацією. При запуску достатньо промту:

> Цей скрипт повертає параметри WireGuard. Сформуй коротку таблицю з колонками Host та endpoint:port. Невідомі значення познач як «немає даних».

У Reports буде звичайна generated revision і наступна `ai_generated` revision. Кнопка **Regenerate with AI** дозволяє створити інший варіант без повторного запуску скрипта, доки збережені його результати.
