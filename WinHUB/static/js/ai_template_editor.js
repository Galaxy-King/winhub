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

function openNewAiTemplateGenerator() {
    if (typeof startNewTemplate !== 'function' || typeof openTemplateCodeEditor !== 'function') {
        return aiEditorStatus('The template workspace is unavailable. Refresh the page and try again.');
    }
    if (!startNewTemplate()) return;
    openTemplateCodeEditor('payload');
    // Let CodeMirror finish opening before the AI dialog takes focus above it.
    setTimeout(() => openAiTemplateEditor(), 120);
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
    aiEditorStatus('AI drafts cannot start tasks. Review and validate the code before saving it.');
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
        sample_result: previous?.sample_result || {}, explanation: 'Static validation of the current code; the AI model was not called.', warnings: []
    };
    aiEditorStatus('Validating the current code without calling the AI model…');
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
        select.replaceChildren(new Option('Recent drafts (30 days)', ''));
        result.drafts.forEach(d => select.add(new Option(`${d.created_at} · ${d.language} · ${d.status}`, d.id)));
    } catch (error) { if (epoch === aiEditorEpoch) aiEditorStatus(error.message); }
}

async function generateAiTemplate() {
    const prompt = document.getElementById('aiEditorPrompt').value.trim();
    if (!prompt) return aiEditorStatus('Describe the script or report you want to generate.');
    const epoch = ++aiEditorEpoch;
    clearTimeout(aiEditorPoll);
    document.getElementById('aiEditorGenerate').disabled = true;
    aiEditorDraft = null;
    renderAiEditorDraft();
    aiEditorStatus('The generation request has been queued…');
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
    const savedTemplateIds = Array.isArray(draft?.saved_template_ids) ? draft.saved_template_ids : [];
    const saved = savedTemplateIds.length > 0;
    document.getElementById('aiEditorApply').disabled = !checked;
    const saveButton = document.getElementById('aiEditorSave');
    saveButton.disabled = !checked || saved;
    saveButton.textContent = saved ? 'Saved to Template Library' : 'Save to Template Library';
    const openSavedButton = document.getElementById('aiEditorOpenSaved');
    openSavedButton.classList.toggle('hidden', !saved);
    openSavedButton.disabled = !saved;
    document.getElementById('aiEditorValidate').disabled = !result || draft.status !== 'Ready';
    document.getElementById('aiEditorCancel').disabled = !draft || !['Queued', 'Running', 'Validating'].includes(draft.status);
    const code = result?.code || '';
    const content = aiEditorView === 'report' ? result?.report_template || 'A separate report template was not requested.'
        : aiEditorView === 'diff' ? reportLineDiff(aiEditorOriginal, code) : code;
    document.getElementById('aiEditorOutput').value = content;
    document.querySelectorAll('[data-ai-editor-view]').forEach(button => {
        button.setAttribute('aria-pressed', String(button.dataset.aiEditorView === aiEditorView));
    });
    const messages = [result?.explanation || '', ...(result?.warnings || []),
        ...(draft?.validation?.diagnostics || []).map(d => `${d.severity}: ${d.message}`)];
    document.getElementById('aiEditorDiagnostics').textContent = messages.filter(Boolean).join('\n\n');
    if (draft) {
        const validationStatus = checked
            ? 'Syntax validated; the code was NOT executed. Validation is not a safety guarantee.'
            : 'Do not apply or save code until validation succeeds and you have reviewed it.';
        const savedStatus = saved
            ? `Saved ${savedTemplateIds.length} private template${savedTemplateIds.length === 1 ? '' : 's'} to Template Library. Separate approval is still required.`
            : validationStatus;
        aiEditorStatus(draft.error || `${draft.status} · ${draft.model} · ${savedStatus}`);
    }
}

async function validateAiEditorDraft() {
    if (!aiEditorDraft) return;
    const epoch = aiEditorEpoch;
    document.getElementById('aiEditorValidate').disabled = true;
    aiEditorStatus('Running isolated static validation…');
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
    if (report !== (result.language === 'jinja')) return aiEditorStatus('The draft language does not match the open editor type. Save it as a separate template instead.');
    showAiEditorView('diff');
    if (!confirm('Review the Changes view. Replace the editor content with this draft? This does not save or run the code.')) return;
    payloadEditor.setValue(result.code);
    payloadEditor.setOption('mode', result.language === 'jinja' ? 'htmlmixed' : result.language === 'bash' ? 'shell' : 'powershell');
    window.aiTemplateAppliedDraftId = aiEditorDraft.id;
    const approved = document.getElementById('depIsApproved');
    if (approved) approved.checked = false;
    const title = document.getElementById('depTitle');
    if (title && !title.value) title.value = result.name;
    closeAiTemplateEditor();
    setTemplateCodeEditorError('The AI draft was applied. Review it before saving; any code change requires a new validation. To save a script and report pair, use Save to Template Library in the AI window.');
}

async function saveAiEditorDraft() {
    if (!aiEditorDraft?.validation?.ok || !confirm('Save the generated result as new private templates in the AI drafts category? No task will be started.')) return;
    const epoch = aiEditorEpoch;
    document.getElementById('aiEditorSave').disabled = true;
    try {
        const result = await aiEditorRequest(`drafts/${encodeURIComponent(aiEditorDraft.id)}/save`, 'POST', {});
        if (epoch !== aiEditorEpoch) return;
        aiEditorDraft.saved_template_ids = result.template_ids;
        renderAiEditorDraft();
        aiEditorStatus(`Saved ${result.template_ids.length} private template${result.template_ids.length === 1 ? '' : 's'} to Template Library. Use Open saved template to review it. Approval is required before execution.`);
        refreshAiEditorHistory();
    } catch (error) { if (epoch === aiEditorEpoch) { document.getElementById('aiEditorSave').disabled = false; aiEditorStatus(error.message); } }
}

function openSavedAiTemplate() {
    const ids = Array.isArray(aiEditorDraft?.saved_template_ids) ? aiEditorDraft.saved_template_ids : [];
    const primaryTemplateId = ids[ids.length - 1];
    if (!primaryTemplateId) return aiEditorStatus('No saved template is available for this draft.');
    localStorage.setItem('infra_vfinal_view', 'deploy');
    localStorage.setItem('infra_workspace_tab', 'builder');
    localStorage.setItem('infra_selected_template', primaryTemplateId);
    const url = new URL(window.location.href);
    url.search = '';
    url.searchParams.set('view', 'deploy');
    window.location.assign(url.pathname + url.search);
}
