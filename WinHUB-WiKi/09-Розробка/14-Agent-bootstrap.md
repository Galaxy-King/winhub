# Agent Bootstrap через Software та Proxmox

Звичайна Software delivery потребує вже схваленого Windows endpoint. Первинне встановлення
не повинно послаблювати цю вимогу чи передавати глобальний enrollment key у код скриптів.

Рішення: окремий kind agent_bootstrap у SoftwarePackage, ті самі immutable software_blobs,
окрема AgentBootstrapGrant. Видача grant — лише ручна інтерактивна dispatch approved template
для одного approved Linux endpoint, із run_tasks/manage_software. Validate не створює capabilities.

Grant зберігає зашифрований package/config snapshot, хеші двох різних токенів, parent_task_id,
expected hostname та expiry 60 хвилин. Структурований descriptor передається у signed task payload;
виконуваний Bash/PowerShell-код токенів не містить. History search і task UI descriptor не розкривають.

Linux capability proxmox-bootstrap-v1 означає root-only 0600 sidecar у data directory.
Шлях передається окремим аргументом у Bash/Python; файл видаляється після задачі.
При аварії root-only залишок має лише обмежені строком capabilities. macOS capability не рекламує.
Task Signature v2 продовжує підписувати весь остаточний payload, включно з descriptor.

Guest secrets передаються через QGA stdin у захищений каталог Windows. ZIP завантажується самою
Windows із наявного WinHUB HTTPS з leaf pin, validity, hash/size та publisher signature.
Поточному Windows installer потрібен точний мінімальний signed inventory.
Існуюча identity не перезаписується; автоматичного Approval немає.

Enrollment token обмежений expected hostname та одним hw_id/RSA fingerprint із signed body proof,
enrollment source ACL і поточним станом parent task/прав оператора. Повтор дозволено тій самій
ідентичності для відновлення втраченої відповіді. Звичайний global enrollment не змінюється.

Новий шлях вкладений у /api/public/software-delivery/bootstrap/: додаткових service/port/location немає.
Bootstrap download має lease, ліміт паралельності, часу/розміру, перевірку скасування під час stream.
Готовність Cloudbase-Init — актуальний завершений прохід без ERROR, password plugin, потрібні IP/hostname;
самого Stopped недостатньо. Успіх — сервер підтвердив enrollment, а не лише запуск служби.

Відновлення часткових операцій явне: Generic Retry failed не копіює capabilities; нова Create
потребує огляду адміністратора, бо може створити іншу VM з тією самою IP.
Деталі та тест: [посібник](../guides/features/PROXMOX_AGENT_BOOTSTRAP_UA.md).
