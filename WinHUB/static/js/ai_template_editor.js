/* Private draft assistant. All untrusted content is displayed as text. */
let aiEditorEpoch = 0;
let aiEditorPoll = null;
let aiEditorDraft = null;
let aiEditorOriginal = '';
let aiEditorView = 'code';
let aiEditorReturnFocus = null;
window.aiTemplateAppliedDraftId = null;

async function aiEditorRequest(path, method = 'GET', data) {
    const response = await fetch('/api/infrastructure/ai-editor/' + path, {
        method, headers: {'Content-Type': 'application/json'},
        ...(data !== undefined ? {body: JSON.stringify(data)} : {})
    });
    const result = await response.json();
    if (!response.ok || !result.success) throw new Error(result.message || 'AI editor request failed');
    return result;
}

function aiEditorStatus(message) {
    document.getElementById('aiEditorStatus').textContent = message;
}

function openAiTemplateEditor() {
    if (!payloadEditor || templateCodeEditorTarget !== 'payload') return;
    aiEditorEpoch++;
    clearTimeout(aiEditorPoll);
    aiEditorOriginal = payloadEditor.getValue();
    aiEditorReturnFocus = document.activeElement;
    aiEditorView = 'code';
    aiEditorDraft = null;
    const report = document.querySelector('input[name="depTemplateType"]:checked')?.value === 'report';
    const language = document.getElementById('aiEditorLanguage');
    language.value = report ? 'jinja' : currentPayloadEditorMode === 'shell' ? 'bash' : 'powershell';
    language.querySelector('option[value="jinja"]').disabled = !report;
    language.querySelector('option[value="powershell"]').disabled = report;
    language.querySelector('option[value="bash"]').disabled = report;
    language.disabled = report;
    document.getElementById('aiEditorReport').checked = !report;
    document.getElementById('aiEditorReport').disabled = report;
    document.getElementById('aiEditorSource').checked = false;
    document.getElementById('aiEditorGenerate').disabled = false;
    document.getElementById('aiTemplateEditorModal').classList.remove('hidden');
    document.getElementById('aiEditorPrompt').focus();
    renderAiEditorDraft();
    aiEditorStatus('Чернетка не запускає задачі. Перевірте код перед використанням.');
    refreshAiEditorHistory();
}

function closeAiTemplateEditor() {
    aiEditorEpoch++;
    clearTimeout(aiEditorPoll);
    document.getElementById('aiTemplateEditorModal').classList.add('hidden');
    if (aiEditorReturnFocus?.isConnected) aiEditorReturnFocus.focus();
}

// This dialog is above the existing code editor; keep keyboard focus inside it.
document.addEventListener('keydown', event => {
    const modal = document.getElementById('aiTemplateEditorModal');
    if (!modal || modal.classList.contains('hidden')) return;
    if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeAiTemplateEditor();
    } else if (event.key === 'Tab') {
        const fields = [...modal.querySelectorAll('button:not(:disabled),textarea:not(:disabled),select:not(:disabled),input:not(:disabled)')];
        const first = fields[0], last = fields[fields.length - 1];
        if ((event.shiftKey && document.activeElement === first) || (!event.shiftKey && document.activeElement === last)) {
            event.preventDefault();
            (event.shiftKey ? last : first)?.focus();
        }
    }
}, true);

async function checkCurrentAiEditorCode() {
    const epoch = ++aiEditorEpoch;
    clearTimeout(aiEditorPoll);
    const previous = aiEditorDraft?.result;
    const language = document.getElementById('aiEditorLanguage').value;
    const bundle = {
        name: document.getElementById('depTitle')?.value?.trim() || previous?.name || 'Checked template',
        language, code: payloadEditor.getValue(),
        report_template: language !== 'jinja' ? previous?.report_template || '' : '',
        sample_result: previous?.sample_result || {}, explanation: 'Статична перевірка поточного коду; модель не викликалась.', warnings: []
    };
    aiEditorStatus('Перевіряю поточний код без запиту до моделі…');
    try {
        const result = await aiEditorRequest('check', 'POST', bundle);
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft = result.draft;
        renderAiEditorDraft();
        refreshAiEditorHistory();
    } catch (error) { if (epoch === aiEditorEpoch) aiEditorStatus(error.message); }
}

async function refreshAiEditorHistory() {
    const epoch = aiEditorEpoch;
    try {
        const result = await aiEditorRequest('drafts');
        if (epoch !== aiEditorEpoch) return;
        const select = document.getElementById('aiEditorHistory');
        select.replaceChildren(new Option('Останні чернетки (30 днів)', ''));
        result.drafts.forEach(d => select.add(new Option(`${d.created_at} · ${d.language} · ${d.status}`, d.id)));
    } catch (error) { if (epoch === aiEditorEpoch) aiEditorStatus(error.message); }
}

async function generateAiTemplate() {
    const prompt = document.getElementById('aiEditorPrompt').value.trim();
    if (!prompt) return aiEditorStatus('Напишіть, який скрипт або звіт потрібен.');
    const epoch = ++aiEditorEpoch;
    clearTimeout(aiEditorPoll);
    document.getElementById('aiEditorGenerate').disabled = true;
    aiEditorDraft = null;
    renderAiEditorDraft();
    aiEditorStatus('Запит передано в чергу…');
    try {
        const result = await aiEditorRequest('drafts', 'POST', {
            prompt, language: document.getElementById('aiEditorLanguage').value,
            include_report: document.getElementById('aiEditorReport').checked,
            source_code: document.getElementById('aiEditorSource').checked ? payloadEditor.getValue() : ''
        });
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft = result.draft;
        renderAiEditorDraft();
        pollAiEditorDraft(result.draft.id, epoch);
    } catch (error) {
        if (epoch === aiEditorEpoch) aiEditorStatus(error.message);
    } finally {
        if (epoch === aiEditorEpoch) document.getElementById('aiEditorGenerate').disabled = false;
    }
}

async function pollAiEditorDraft(id, epoch) {
    try {
        const result = await aiEditorRequest('drafts/' + encodeURIComponent(id));
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft = result.draft;
        renderAiEditorDraft();
        if (['Queued', 'Running', 'Validating'].includes(aiEditorDraft.status)) {
            aiEditorPoll = setTimeout(() => pollAiEditorDraft(id, epoch), 2500);
        } else refreshAiEditorHistory();
    } catch (error) { if (epoch === aiEditorEpoch) aiEditorStatus(error.message); }
}

function loadAiEditorHistory() {
    const id = document.getElementById('aiEditorHistory').value;
    if (!id) return;
    clearTimeout(aiEditorPoll);
    document.getElementById('aiEditorGenerate').disabled = false;
    pollAiEditorDraft(id, ++aiEditorEpoch);
}

function showAiEditorView(view) {
    aiEditorView = view;
    renderAiEditorDraft();
}

function renderAiEditorDraft() {
    const draft = aiEditorDraft;
    const result = draft?.result;
    const checked = draft?.status === 'Ready' && draft?.validation?.ok === true;
    document.getElementById('aiEditorApply').disabled = !checked;
    document.getElementById('aiEditorSave').disabled = !checked;
    document.getElementById('aiEditorValidate').disabled = !result || draft.status !== 'Ready';
    document.getElementById('aiEditorCancel').disabled = !draft || !['Queued', 'Running', 'Validating'].includes(draft.status);
    const code = result?.code || '';
    const content = aiEditorView === 'report' ? result?.report_template || 'Окремий шаблон звіту не запитано.'
        : aiEditorView === 'diff' ? reportLineDiff(aiEditorOriginal, code) : code;
    document.getElementById('aiEditorOutput').value = content;
    document.querySelectorAll('[data-ai-editor-view]').forEach(button => {
        button.setAttribute('aria-pressed', String(button.dataset.aiEditorView === aiEditorView));
    });
    const messages = [result?.explanation || '', ...(result?.warnings || []),
        ...(draft?.validation?.diagnostics || []).map(d => `${d.severity}: ${d.message}`)];
    document.getElementById('aiEditorDiagnostics').textContent = messages.filter(Boolean).join('\n\n');
    if (draft) aiEditorStatus(draft.error || `${draft.status} · ${draft.model} · ${checked ? 'Синтаксис перевірено; код НЕ виконувався. Це не гарантія безпеки.' : 'Не застосовуйте код без успішної перевірки та перегляду.'}`);
}

async function validateAiEditorDraft() {
    if (!aiEditorDraft) return;
    const epoch = aiEditorEpoch;
    document.getElementById('aiEditorValidate').disabled = true;
    aiEditorStatus('Ізольована статична перевірка…');
    try {
        const result = await aiEditorRequest(`drafts/${encodeURIComponent(aiEditorDraft.id)}/validate`, 'POST', {});
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft = result.draft;
        renderAiEditorDraft();
    } catch (error) { if (epoch === aiEditorEpoch) { renderAiEditorDraft(); aiEditorStatus(error.message); } }
}

async function cancelAiEditorDraft() {
    if (!aiEditorDraft) return;
    const epoch = ++aiEditorEpoch;
    clearTimeout(aiEditorPoll);
    try {
        const result = await aiEditorRequest(`drafts/${encodeURIComponent(aiEditorDraft.id)}`, 'DELETE');
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft = result.draft;
        renderAiEditorDraft();
    } catch (error) { if (epoch === aiEditorEpoch) aiEditorStatus(error.message); }
}

function applyAiEditorDraft() {
    if (!aiEditorDraft?.validation?.ok || aiEditorDraft.status !== 'Ready') return;
    const result = aiEditorDraft.result;
    const report = document.querySelector('input[name="depTemplateType"]:checked')?.value === 'report';
    if (report !== (result.language === 'jinja')) return aiEditorStatus('Мова чернетки не відповідає типу відкритого редактора. Збережіть її окремо.');
    showAiEditorView('diff');
    if (!confirm('Перегляньте вкладку «Зміни». Замінити текст у редакторі цією чернеткою? Збереження та запуск не виконуються.')) return;
    payloadEditor.setValue(result.code);
    payloadEditor.setOption('mode', result.language === 'jinja' ? 'htmlmixed' : result.language === 'bash' ? 'shell' : 'powershell');
    window.aiTemplateAppliedDraftId = aiEditorDraft.id;
    const approved = document.getElementById('depIsApproved');
    if (approved) approved.checked = false;
    const title = document.getElementById('depTitle');
    if (title && !title.value) title.value = result.name;
    closeAiTemplateEditor();
    setTemplateCodeEditorError('AI-чернетку вставлено. Збережіть після перегляду; зміни коду потребують нової перевірки. Для збереження пари скрипт + звіт скористайтеся «Зберегти нові шаблони» в AI-вікні.');
}

async function saveAiEditorDraft() {
    if (!aiEditorDraft?.validation?.ok || !confirm('Створити нові незатверджені шаблони в категорії AI drafts? Жодна задача не запуститься.')) return;
    const epoch = aiEditorEpoch;
    document.getElementById('aiEditorSave').disabled = true;
    try {
        const result = await aiEditorRequest(`drafts/${encodeURIComponent(aiEditorDraft.id)}/save`, 'POST', {});
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft.saved_template_ids = result.template_ids;
        aiEditorStatus('Збережено незатверджені шаблони. Оновіть бібліотеку. Якщо є звіт — спершу затвердіть його, потім скрипт.');
    } catch (error) { if (epoch === aiEditorEpoch) { document.getElementById('aiEditorSave').disabled = false; aiEditorStatus(error.message); } }
}
