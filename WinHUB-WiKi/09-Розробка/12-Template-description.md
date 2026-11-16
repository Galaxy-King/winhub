# Template documentation as metadata

Рішення від 2026-11-16: TaskTemplate.description зберігає plain text окремо від executable payload та approval hash. Nullable EncryptedText і additive migration залишають старі code seals чинними. Description не передається в agent protocol і не входить у template variable extraction чи AI validation.

Editor використовує наявне модальне вікно CodeMirror в plain-text mode. Документ завантажується лише при відкритті; бібліотека не отримує десятки великих описів у HTML datasets. Для існуючого template окремий PATCH зберігає тільки metadata, тому незбережені зміни коду/схеми не застосовуються разом із нотатками. Для нового template документ додається до звичайного save. API перевіряє library visibility, manage_templates та edit policy; API keys не можуть використовувати metadata PATCH. Read-only документація доступна й коли executable code hidden.

Опис переноситься clone/export/import. Відсутнє поле в старому save/import означає keep existing, порожній рядок — clear. Межа 32 000 Unicode characters перевіряється перед записом; NUL та invalid UTF-8 відхиляються. У DOM використовуються textarea.value, CodeMirror.setValue та textContent; HTML/Jinja/скрипти всередині документа є даними.

[Користувацька інструкція](../04-Endpoint-Management/04-Templates-та-Deploy.md#description--usage-guide-третє-поле-editor).
