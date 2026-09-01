// Infrastructure uses lightweight polling for live updates. Keep this separate
// from Socket.IO; Newsletter owns sockets.

let allQueueJobs = [];
let allReports = [];
let smtpProfiles = [];
let confluenceProfiles = [];
let scheduledReports = [];
let currentJobTasks = [];
let currentViewedJobId = null;
let currentJobStatusFilter = 'all';
let currentViewedHostId = null;
let currentViewedHostData = null;
let currentViewedGroupId = null;
let currentGroupNonMembers = [];
let currentReportId = null;
let reportPage = 1;
let reportPagination = { page: 1, total: 0, has_more: false };
let selectedReportSnapshot = null;
let selectedReportSnapshotLabel = '';
let aiProviderSettings = null;

let selectedTemplateId = null;
let editingTemplateId = null;
let pendingTemplateDeletion = null;
let currentTemplateVariables = [];
let currentTemplateVariableSchema = {};
let currentScheduleVariables = {};
let teleChart = null;
let diskChart = null;
let activityChart = null;
let currentHostStatus = 'all';
let queueTypeFilter = 'ALL';
let queueStatusFilter = 'ALL';
let queuePage = 1;
let queuePagination = { page: 1, total: 0, has_more: false };
let queueSearchTimer = null;
const infraPermissions = window.WinhubPermissions || {};
let infraLivePollTimer = null;
let infraLivePollStarted = false;
let infraLivePollInFlight = false;
let infraLiveState = null;
let infraLiveRefreshTimers = {};
let payloadEditor = null;
let templateCodeEditorTarget = null;
let templateCodeEditorInitialValue = '';
let currentPayloadEditorMode = 'powershell';
const scheduleWheelScrollTimers = new WeakMap();
const infraStateKeys = {
    view: 'infra_vfinal_view',
    nodeTab: 'infra_nodes_active_tab',
    reviewTab: 'winhub_infra_review_tab',
    fleetStatus: 'infra_fleet_status',
    fleetSearch: 'infra_fleet_search',
    fleetGroups: 'infra_fleet_groups',
    fleetGroupMatch: 'infra_fleet_group_match',
    fleetPage: 'infra_fleet_page',
    fleetPageSize: 'infra_fleet_page_size',
    fleetSort: 'infra_fleet_sort',
    queueType: 'infra_queue_type',
    queueStatus: 'infra_queue_status',
    queueSearch: 'infra_queue_search',
    queueUser: 'infra_queue_user',
    queueContent: 'infra_queue_content',
    queueDateFrom: 'infra_queue_date_from',
    queueDateTo: 'infra_queue_date_to',
    workspaceTab: 'infra_workspace_tab',
    categories: 'infra_open_categories',
    template: 'infra_selected_template'
};
let workspaceTab = 'builder';
let guideLanguage = localStorage.getItem('infra_workspace_guide_lang') || 'en';
let multiHostSelectedIds = new Set();
let pendingTemplateImport = [];

function currentInfraView() {
    return infraUrlParam('view') || localStorage.getItem(infraStateKeys.view) || 'hosts';
}

function infraUrlParam(name) {
    try {
        return new URL(window.location.href).searchParams.get(name);
    } catch (e) {
        return null;
    }
}

function readInfraState(param, storageKey, fallback = '') {
    const value = infraUrlParam(param);
    if (value !== null && value !== undefined) return value;
    return localStorage.getItem(storageKey) ?? fallback;
}

function writeInfraState(params = {}, replace = true) {
    if (!window.location.pathname.includes('/module/infrastructure')) return;
    const url = new URL(window.location.href);
    Object.entries(params).forEach(([key, value]) => {
        if (value === null || value === undefined || value === '') url.searchParams.delete(key);
        else url.searchParams.set(key, String(value));
    });
    const next = url.pathname + (url.search ? url.search : '') + url.hash;
    if (replace) window.history.replaceState(null, '', next);
    else window.history.pushState(null, '', next);
}

function scopedInfraState(view, params = {}) {
    return {
        view,
        nodeTab: null,
        reviewTab: null,
        fleetStatus: null,
        fleetSearch: null,
        fleetGroups: null,
        fleetGroupMatch: null,
        fleetPage: null,
        fleetPageSize: null,
        fleetSort: null,
        queueType: null,
        queueStatus: null,
        queueSearch: null,
        queueUser: null,
        queueContent: null,
        queueDateFrom: null,
        queueDateTo: null,
        workspaceTab: null,
        ...params,
    };
}

function isNewTabNavigationEvent(event) {
    return !!(event && (event.button === 1 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey));
}

function handleInfraNavClick(event, view) {
    if (isNewTabNavigationEvent(event)) return;
    if (event) event.preventDefault();
    switchView(view);
    closeInfraMenus();
}

function handleNodeTabClick(event, tab) {
    if (isNewTabNavigationEvent(event)) return;
    if (event) event.preventDefault();
    switchNodeTab(tab);
}

function handleReviewTabClick(event, tab) {
    if (isNewTabNavigationEvent(event)) return;
    if (event) event.preventDefault();
    switchReviewTab(tab);
}

function hasReviewSelections() {
    return pendingApprovalSelection().length > 0 || rejectedSelection().length > 0 || duplicateSelection().length > 0;
}

function scheduleInfraLiveRefresh(section, delay = 700) {
    clearTimeout(infraLiveRefreshTimers[section]);
    infraLiveRefreshTimers[section] = setTimeout(() => refreshInfraLiveSection(section), delay);
}

function refreshInfraLiveSection(section) {
    const view = currentInfraView();
    if (section === 'nodes') {
        if (view === 'hosts' && !document.getElementById('nodesApprovedPanel')?.classList.contains('hidden')) {
            loadFleetCenter();
        }
        return;
    }
    if (section === 'review') {
        if (view === 'hosts' && !document.getElementById('nodesReviewPanel')?.classList.contains('hidden')) {
            if (hasReviewSelections()) return;
            reloadKeepingNodeContext('review');
        }
        return;
    }
    if (section === 'queue' && view === 'queue') {
        loadQueue();
        if (currentViewedJobId) {
            setTimeout(() => {
                const job = allQueueJobs.find(j => j.job_id === currentViewedJobId);
                if (job) {
                    currentJobTasks = job.tasks || [];
                    renderJobStatusFilters();
                    renderJobTaskRows();
                }
            }, 450);
        }
        return;
    }
    if (section === 'reports' && view === 'reports') {
        loadReports();
    }
}

function handleInfraLiveState(nextState, fromFallback = false) {
    if (!nextState) return;
    if (!infraLiveState) {
        infraLiveState = nextState;
        return;
    }
    ['nodes', 'review', 'queue', 'reports'].forEach(section => {
        const previousRevision = infraLiveState?.[section]?.revision;
        const nextRevision = nextState?.[section]?.revision;
        if (nextRevision && previousRevision && nextRevision !== previousRevision) {
            scheduleInfraLiveRefresh(section, fromFallback ? 250 : 700);
        }
    });
    infraLiveState = nextState;
}

async function pollInfraLiveState() {
    if (infraLivePollInFlight) {
        scheduleInfraLivePoll();
        return;
    }
    infraLivePollInFlight = true;
    try {
        const res = await fetch('/api/infrastructure/live/state');
        const data = await res.json();
        if (res.ok && data.success) handleInfraLiveState(data.state, true);
    } catch (e) {
        console.warn('WinHUB live polling failed:', e);
    } finally {
        infraLivePollInFlight = false;
        scheduleInfraLivePoll();
    }
}

function infraLivePollDelay() {
    if (document.hidden) return 120000;
    return currentInfraView() === 'queue' ? 20000 : 45000;
}

function scheduleInfraLivePoll(delay = infraLivePollDelay()) {
    clearTimeout(infraLivePollTimer);
    infraLivePollTimer = setTimeout(pollInfraLiveState, delay);
}

function startInfraLiveRefresh() {
    if (!window.location.pathname.includes('/module/infrastructure')) return;
    if (infraLivePollStarted) return;
    infraLivePollStarted = true;
    setTimeout(() => {
        const fleetPanel = document.getElementById('nodesFleetPanel');
        const approvedPanel = document.getElementById('nodesApprovedPanel');
        const stillLoading = Array.from(document.querySelectorAll('.fleet-pagination')).some(box => box.innerText.includes('Loading nodes'));
        if (fleetPanel && !fleetPanel.classList.contains('hidden') && approvedPanel && !approvedPanel.classList.contains('hidden') && stillLoading) {
            loadFleetCenter(1);
        }
    }, 1000);
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            scheduleInfraLivePoll();
            return;
        }
        pollInfraLiveState();
    });
    pollInfraLiveState();
}

function getPayloadValue() {
    return document.getElementById('depPayload')?.value || '';
}

function setPayloadValue(value) {
    const nextValue = value || '';
    const textarea = document.getElementById('depPayload');
    if (textarea) textarea.value = nextValue;
    if (payloadEditor && templateCodeEditorTarget === 'payload') {
        payloadEditor.setValue(nextValue);
    }
    updateTemplateEditorSummaries();
}

function editorContentStats(value) {
    const text = String(value || '');
    return {
        characters: text.length,
        lines: text ? text.split(/\r?\n/).length : 0,
    };
}

function updateTemplateEditorSummaries() {
    const payloadSummary = document.getElementById('payloadEditorSummary');
    if (payloadSummary) {
        const stats = editorContentStats(document.getElementById('depPayload')?.value || '');
        payloadSummary.textContent = stats.characters ? `${stats.lines} lines · ${stats.characters} characters` : 'No code yet';
    }

    const schemaSummary = document.getElementById('variableSchemaEditorSummary');
    if (schemaSummary) {
        const schemaText = document.getElementById('depVariableSchema')?.value?.trim() || '';
        if (!schemaText) {
            schemaSummary.textContent = 'No schema configured';
        } else {
            try {
                const schema = JSON.parse(schemaText);
                const fields = schema && typeof schema === 'object' && !Array.isArray(schema) ? Object.keys(schema).length : 0;
                schemaSummary.textContent = `${fields} variable field${fields === 1 ? '' : 's'} configured`;
            } catch(e) {
                schemaSummary.textContent = 'Schema needs JSON correction';
            }
        }
    }
}

function setEditorMode(mode) {
    currentPayloadEditorMode = mode || 'powershell';
    if (payloadEditor && templateCodeEditorTarget === 'payload') payloadEditor.setOption('mode', currentPayloadEditorMode);
}

function refreshPayloadEditor() {
    const modal = document.getElementById('templateCodeEditorModal');
    if (payloadEditor && modal && !modal.classList.contains('hidden')) {
        setTimeout(() => {
            payloadEditor.refresh();
            payloadEditor.setOption('lineNumbers', true);
        }, 40);
    }
}

function templateCodeEditorConfig(target) {
    if (target === 'schema') {
        return {
            sourceId: 'depVariableSchema',
            title: 'Variable Field Schema',
            description: 'Define optional generated fields using valid JSON.',
            language: 'JSON',
            mode: {name: 'javascript', json: true},
        };
    }

    const templateType = document.querySelector('input[name="depTemplateType"]:checked')?.value || 'action';
    if (templateType === 'report') {
        return {
            sourceId: 'depPayload',
            title: 'Jinja2 Email / Report Format',
            description: 'Edit the HTML or text template used to build the report.',
            language: 'Jinja2 / HTML',
            mode: 'htmlmixed',
        };
    }
    return {
        sourceId: 'depPayload',
        title: 'Execution Script / Code Content',
        description: templateType === 'metric'
            ? 'Edit the metric script. It must return JSON data.'
            : 'Edit the PowerShell, Bash, or shell script executed by the agent.',
        language: templateType === 'metric' ? 'Metric Script' : 'PowerShell / Shell',
        mode: currentPayloadEditorMode,
    };
}

function setTemplateCodeEditorError(message = '') {
    const error = document.getElementById('templateCodeEditorError');
    if (!error) return;
    error.textContent = message;
    error.classList.toggle('hidden', !message);
}

function updateTemplateCodeEditorStats() {
    const statsLabel = document.getElementById('templateCodeEditorStats');
    if (!statsLabel) return;
    const stats = editorContentStats(payloadEditor?.getValue() || '');
    statsLabel.textContent = `${stats.lines} lines · ${stats.characters} characters`;
}

function openTemplateCodeEditor(target) {
    if (!['payload', 'schema'].includes(target)) return;
    initPayloadEditor();
    if (!payloadEditor) return alert('Code editor is unavailable. Refresh the page and try again.');

    const config = templateCodeEditorConfig(target);
    const source = document.getElementById(config.sourceId);
    if (!source) return;

    templateCodeEditorTarget = target;
    templateCodeEditorInitialValue = source.value || '';
    payloadEditor.setOption('mode', config.mode);
    payloadEditor.setValue(templateCodeEditorInitialValue);

    const title = document.getElementById('templateCodeEditorTitle');
    const description = document.getElementById('templateCodeEditorDescription');
    const language = document.getElementById('templateCodeEditorLanguage');
    if (title) title.textContent = config.title;
    if (description) description.textContent = config.description;
    if (language) language.textContent = config.language;
    setTemplateCodeEditorError();
    updateTemplateCodeEditorStats();
    openModal('templateCodeEditorModal');
    document.body.classList.add('overflow-hidden');
    setTimeout(() => {
        payloadEditor.refresh();
        payloadEditor.focus();
        payloadEditor.setCursor(0, 0);
    }, 80);
}

function closeTemplateCodeEditor(force = false) {
    const modal = document.getElementById('templateCodeEditorModal');
    if (!modal || modal.classList.contains('hidden')) return;
    if (!force && payloadEditor && payloadEditor.getValue() !== templateCodeEditorInitialValue &&
        !confirm('Discard the unapplied editor changes?')) return;

    closeModal('templateCodeEditorModal');
    document.body.classList.remove('overflow-hidden');
    templateCodeEditorTarget = null;
    templateCodeEditorInitialValue = '';
    setTemplateCodeEditorError();
}

function applyTemplateCodeEditor() {
    if (!payloadEditor || !templateCodeEditorTarget) return;
    const config = templateCodeEditorConfig(templateCodeEditorTarget);
    const source = document.getElementById(config.sourceId);
    if (!source) return;
    const value = payloadEditor.getValue();

    if (templateCodeEditorTarget === 'schema' && value.trim()) {
        try {
            const parsed = JSON.parse(value);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Schema must be a JSON object.');
        } catch(e) {
            setTemplateCodeEditorError(e.message || 'Variable schema must contain valid JSON.');
            return;
        }
    }

    source.value = value;
    if (templateCodeEditorTarget === 'schema') {
        currentTemplateVariableSchema = normalizeVariableSchema(value);
    }
    updateVariablesUI();
    updateTemplateEditorSummaries();
    templateCodeEditorInitialValue = value;
    closeTemplateCodeEditor(true);
}

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
        const modal = document.getElementById('templateCodeEditorModal');
        if (modal && !modal.classList.contains('hidden')) closeTemplateCodeEditor();
    }
});

function closeInfraMenus() {
    document.querySelectorAll('.infra-dropdown').forEach(menu => menu.classList.add('hidden'));
}

function toggleInfraMenu(id) {
    const menu = document.getElementById(id);
    if (!menu) return;
    const wasHidden = menu.classList.contains('hidden');
    closeInfraMenus();
    menu.classList.toggle('hidden', !wasHidden);
}

document.addEventListener('click', (event) => {
    if (!event.target.closest('.infra-nav-menu')) closeInfraMenus();
});

function initPayloadEditor() {
    const textarea = document.getElementById('templateCodeEditorTextarea');
    if (!textarea || payloadEditor || typeof CodeMirror === 'undefined') return;

    payloadEditor = CodeMirror.fromTextArea(textarea, {
        mode: 'powershell',
        theme: 'winhub-studio',
        lineNumbers: true,
        lineWrapping: true,
        indentUnit: 4,
        tabSize: 4,
        smartIndent: true,
        matchBrackets: true,
        viewportMargin: Infinity,
        extraKeys: {
            Tab(cm) {
                if (cm.somethingSelected()) cm.indentSelection('add');
                else cm.replaceSelection('    ', 'end');
            }
        }
    });

    payloadEditor.on('change', updateTemplateCodeEditorStats);
}

function switchWorkspaceTab(tab) {
    workspaceTab = tab || 'builder';
    localStorage.setItem(infraStateKeys.workspaceTab, workspaceTab);
    writeInfraState(scopedInfraState('deploy', { workspaceTab: workspaceTab === 'builder' ? null : workspaceTab }));
    const builder = document.getElementById('workspaceBuilderPanel');
    const guide = document.getElementById('workspaceGuidePanel');
    const builderBtn = document.getElementById('workspaceTabBuilder');
    const guideBtn = document.getElementById('workspaceTabGuide');
    if (builder) builder.classList.toggle('hidden', workspaceTab !== 'builder');
    if (guide) guide.classList.toggle('hidden', workspaceTab !== 'guide');
    if (builderBtn) builderBtn.className = workspaceTab === 'builder' ? "px-4 py-2 bg-white text-indigo-700 rounded-lg text-[10px] font-black uppercase shadow-sm" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
    if (guideBtn) guideBtn.className = workspaceTab === 'guide' ? "px-4 py-2 bg-white text-indigo-700 rounded-lg text-[10px] font-black uppercase shadow-sm" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
    if (workspaceTab === 'builder') refreshPayloadEditor();
}

function restoreWorkspaceStateFromLocation() {
    workspaceTab = readInfraState('workspaceTab', infraStateKeys.workspaceTab, 'builder') || 'builder';
}

function setGuideLanguage(lang) {
    guideLanguage = lang === 'ua' ? 'ua' : 'en';
    localStorage.setItem('infra_workspace_guide_lang', guideLanguage);
    const en = document.getElementById('guideContentEn');
    const ua = document.getElementById('guideContentUa');
    const enBtn = document.getElementById('guideLangEn');
    const uaBtn = document.getElementById('guideLangUa');
    if (en) en.classList.toggle('hidden', guideLanguage !== 'en');
    if (ua) ua.classList.toggle('hidden', guideLanguage !== 'ua');
    if (enBtn) enBtn.className = guideLanguage === 'en' ? "px-4 py-2 bg-slate-900 text-white rounded-lg text-[10px] font-black uppercase" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
    if (uaBtn) uaBtn.className = guideLanguage === 'ua' ? "px-4 py-2 bg-slate-900 text-white rounded-lg text-[10px] font-black uppercase" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[ch]));
}

function escapeInlineJs(value) {
    return escapeHtml(String(value ?? '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n')
        .replace(/</g, '\\x3c'));
}

function parseJsonObject(value, fallback = {}) {
    if (!value) return fallback;
    try {
        const parsed = typeof value === 'string' ? JSON.parse(value) : value;
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : fallback;
    } catch(e) {
        return fallback;
    }
}

function normalizeVariableSchema(raw) {
    const source = parseJsonObject(raw, {});
    const schema = {};
    Object.entries(source).forEach(([name, spec]) => {
        if (!name) return;
        if (Array.isArray(spec)) {
            schema[name] = { type: 'select', options: spec };
        } else if (spec && typeof spec === 'object') {
            schema[name] = { ...spec };
        } else if (typeof spec === 'string') {
            schema[name] = { type: 'text', label: spec };
        }
    });
    return schema;
}

function variableSpecFor(name, schema = {}) {
    const spec = schema[name] ? { ...schema[name] } : {};
    if (!spec.type) spec.type = /folders|paths|list|users|ids/i.test(name) ? 'textarea' : 'text';
    if (!spec.label) spec.label = name;
    if (!spec.options && spec.choices) spec.options = spec.choices;
    if (typeof spec.options === 'string') {
        spec.options = spec.options.split(/\r?\n|,/).map(item => item.trim()).filter(Boolean);
    }
    return spec;
}

function renderVariableField(name, spec, currentValue, inputClass) {
    const safeName = escapeHtml(name);
    const type = String(spec.type || 'text').toLowerCase();
    const placeholder = escapeHtml(spec.placeholder || `Enter value for ${name}...`);
    const value = currentValue !== undefined && currentValue !== null && currentValue !== '' ? currentValue : (spec.default ?? '');
    const baseClass = `${inputClass} w-full p-4 bg-slate-950/80 border border-cyan-400/25 rounded-2xl text-sm font-bold text-slate-50 shadow-sm outline-none focus:ring-2 focus:ring-cyan-400/40 focus:border-cyan-300`;

    if (type === 'select') {
        const options = Array.isArray(spec.options) ? spec.options : [];
        const html = options.map(option => {
            const optionValue = typeof option === 'object' ? (option.value ?? option.label ?? '') : option;
            const optionLabel = typeof option === 'object' ? (option.label ?? option.value ?? '') : option;
            const selected = String(optionValue) === String(value) ? ' selected' : '';
            return `<option value="${escapeHtml(optionValue)}"${selected}>${escapeHtml(optionLabel)}</option>`;
        }).join('');
        return `<select data-var="${safeName}" class="${baseClass}">${html}</select>`;
    }

    if (type === 'textarea') {
        return `<textarea data-var="${safeName}" class="${baseClass} min-h-28" placeholder="${placeholder}">${escapeHtml(value)}</textarea>`;
    }

    if (type === 'checkbox' || type === 'boolean') {
        const checked = String(value).toLowerCase() === 'true' || value === true || value === 1 ? ' checked' : '';
        return `
            <label class="flex items-center gap-3 p-4 bg-slate-950/80 border border-cyan-400/25 rounded-2xl text-sm font-black text-slate-50">
                <input type="checkbox" data-var="${safeName}" class="${inputClass} h-5 w-5 rounded border-cyan-400 bg-slate-900 text-cyan-400 focus:ring-cyan-400/40"${checked}>
                <span>${escapeHtml(spec.checkbox_label || spec.label || name)}</span>
            </label>`;
    }

    const inputType = type === 'number' ? 'number' : 'text';
    return `<input type="${inputType}" data-var="${safeName}" value="${escapeHtml(value)}" class="${baseClass}" placeholder="${placeholder}">`;
}

function collectVariableInputs(selector) {
    const variables = {};
    document.querySelectorAll(selector).forEach(inp => {
        const key = inp.dataset.var;
        if (!key) return;
        variables[key] = inp.type === 'checkbox' ? (inp.checked ? 'true' : 'false') : inp.value;
    });
    return variables;
}

function escapeJsString(value) {
    return String(value ?? '').replace(/[\\'"\n\r\u2028\u2029]/g, ch => ({
        '\\': '\\\\',
        "'": "\\'",
        '"': '\\"',
        '\n': '\\n',
        '\r': '\\r',
        '\u2028': '\\u2028',
        '\u2029': '\\u2029'
    }[ch]));
}

function filterTemplateLibrary() {
    const q = (document.getElementById('templateLibrarySearch')?.value || '').trim().toLowerCase();
    document.querySelectorAll('.template-category-block').forEach(block => {
        let visibleCount = 0;
        block.querySelectorAll('.template-card').forEach(card => {
            const haystack = [
                card.dataset.name,
                card.dataset.category,
                card.dataset.type,
                card.dataset.action
            ].join(' ').toLowerCase();
            const visible = !q || haystack.includes(q);
            card.classList.toggle('hidden', !visible);
            if (visible) visibleCount += 1;
        });
        block.classList.toggle('hidden', visibleCount === 0 && !!q);
        const list = block.querySelector('[id^="cat_"]');
        const chevron = block.querySelector('.cat-chevron');
        if (q && visibleCount > 0 && list) {
            list.classList.remove('hidden');
            list.classList.add('block');
            if (chevron) chevron.classList.add('rotate-180');
        }
    });
}

// --- ГЛОБАЛЬНІ ФУНКЦІЇ ---
function checkIsAdmin() {
    if (Object.prototype.hasOwnProperty.call(infraPermissions, 'manage_templates')) {
        return !!infraPermissions.manage_templates;
    }
    const wrap = document.getElementById('depIsApprovedWrapper');
    return wrap ? !wrap.classList.contains('hidden') : false;
}

// Завантажуємо SMTP пошти ГЛОБАЛЬНО, щоб вони були доступні всім і скрізь
async function fetchSmtpProfilesGlobally() {
    try {
        const res = await fetch('/api/infrastructure/smtp');
        const data = await res.json();
        if (data.success) {
            smtpProfiles = data.profiles;

            // Наповнюємо дропдаун в розділі Workspace
            const selDep = document.getElementById('depAutoEmailSender');
            if (selDep) {
                const currentVal = selDep.value;
                selDep.innerHTML = '<option value="">-- Select Sender Profile --</option>' +
                    smtpProfiles.map(p => `<option value="${escapeHtml(p.email)}">${escapeHtml(p.email)}</option>`).join('');
                if (currentVal) selDep.value = currentVal;
            }

            // Наповнюємо дропдаун в модалці Reports
            const selRep = document.getElementById('reportSenderEmail');
            if (selRep) {
                const currentVal = selRep.value;
                selRep.innerHTML = '<option value="">-- Select Sender Profile --</option>' +
                    smtpProfiles.map(p => `<option value="${escapeHtml(p.email)}">${escapeHtml(p.email)}</option>`).join('');
                if (currentVal) selRep.value = currentVal;
            }
        }
    } catch (e) { console.error("Error fetching SMTP", e); }
}

async function fetchConfluenceProfilesGlobally() {
    try {
        const res = await fetch('/api/infrastructure/confluence');
        const data = await res.json();
        if (data.success) {
            confluenceProfiles = data.profiles || [];
            renderConfluenceProfileOptions();
        }
    } catch (e) { console.error("Error fetching Confluence profiles", e); }
}

async function fetchAiProviderSettings() {
    if (!infraPermissions.use_ai_reports && !infraPermissions.manage_ai) return null;
    const response = await fetch('/api/infrastructure/ai-provider');
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success) throw new Error(data.message || 'Could not load AI provider settings');
    aiProviderSettings = data.provider || {};
    updateAiReportControls();
    return aiProviderSettings;
}

function updateAiReportControls() {
    const available = !!aiProviderSettings?.enabled;
    ['depAiReportToggle', 'quickLaunchAiToggle'].forEach(id => {
        const toggle = document.getElementById(id);
        if (!toggle) return;
        toggle.disabled = !available;
        toggle.title = available ? '' : 'The Open WebUI provider is not enabled';
        if (!available) toggle.checked = false;
    });
    if (!available) {
        document.getElementById('depAiReportSettings')?.classList.add('hidden');
        document.getElementById('quickLaunchAiPrompt')?.classList.add('hidden');
    }
}

async function openAiProviderManager() {
    try {
        const provider = await fetchAiProviderSettings() || {};
        document.getElementById('aiProviderEnabled').checked = !!provider.enabled;
        document.getElementById('aiProviderBaseUrl').value = provider.base_url || '';
        document.getElementById('aiProviderModel').value = provider.model || '';
        document.getElementById('aiProviderApiKey').value = '';
        document.getElementById('aiProviderApiKey').placeholder = provider.has_api_key ? 'Stored securely — leave blank to keep' : 'Open WebUI API key';
        document.getElementById('aiProviderStatus').textContent = provider.enabled ? 'Configured' : 'Disabled';
        openModal('aiProviderModal');
    } catch (error) {
        alert(error.message);
    }
}

async function saveAiProviderSettings() {
    const payload = {
        enabled: document.getElementById('aiProviderEnabled')?.checked || false,
        base_url: document.getElementById('aiProviderBaseUrl')?.value?.trim() || '',
        model: document.getElementById('aiProviderModel')?.value?.trim() || '',
        api_key: document.getElementById('aiProviderApiKey')?.value || '',
    };
    const response = await fetch('/api/infrastructure/ai-provider', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success) return alert(data.message || 'Could not save AI provider');
    aiProviderSettings = data.provider;
    updateAiReportControls();
    document.getElementById('aiProviderApiKey').value = '';
    document.getElementById('aiProviderApiKey').placeholder = 'Stored securely — leave blank to keep';
    document.getElementById('aiProviderStatus').textContent = 'Saved';
}

async function testAiProviderSettings() {
    const status = document.getElementById('aiProviderStatus');
    if (status) status.textContent = 'Testing…';
    const response = await fetch('/api/infrastructure/ai-provider/test', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
            base_url: document.getElementById('aiProviderBaseUrl')?.value?.trim() || '',
            api_key: document.getElementById('aiProviderApiKey')?.value || '',
            model: document.getElementById('aiProviderModel')?.value?.trim() || '',
        }),
    });
    const data = await response.json().catch(() => ({}));
    const models = Array.isArray(data.models) ? data.models : [];
    const datalist = document.getElementById('aiProviderModels');
    if (datalist) datalist.innerHTML = models.map(model => `<option value="${escapeHtml(model)}"></option>`).join('');
    const modelInput = document.getElementById('aiProviderModel');
    if (data.success && modelInput && !modelInput.value && models.length === 1) modelInput.value = models[0];
    if (status) status.textContent = data.success
        ? `${data.message}; ${models.length} model(s) found${models.length ? ': ' + models.slice(0, 3).join(', ') : ''}`
        : (data.message || 'Connection failed');
}

// Перехоплювач для безпечного збереження розширених налаштувань
const originalFetch = window.fetch;
window.fetch = async function() {
    if (arguments[0] && arguments[0].includes('/api/infrastructure/templates') && arguments[1] && arguments[1].method === 'POST') {
        try {
            let body = JSON.parse(arguments[1].body);
            let reportTplId = document.getElementById('depReportTemplate').value;
            if (body.payload) {
                if (reportTplId) {
                    body.payload.__report_template_id = reportTplId;
                    body.report_template_id = reportTplId;
                }
                let autoEmailToggle = document.getElementById('depAutoEmailToggle')?.checked;
                if (autoEmailToggle) {
                    body.payload.__auto_email_toggle = true;
                    body.payload.__auto_email_sender = document.getElementById('depAutoEmailSender')?.value || '';
                    body.payload.__auto_email_recipients = document.getElementById('depAutoEmailRecipients')?.value || '';
                    body.payload.__auto_email_use_gpg = document.getElementById('depAutoEmailUseGpg')?.checked !== false;
                } else {
                    delete body.payload.__auto_email_toggle;
                    delete body.payload.__auto_email_sender;
                    delete body.payload.__auto_email_recipients;
                    delete body.payload.__auto_email_use_gpg;
                }
                applyAutoConfluencePayload(body.payload);
            }
            arguments[1].body = JSON.stringify(body);
        } catch(e) {}
    }

    if (arguments[0] && arguments[0].includes('/api/infrastructure/tasks/create') && arguments[1] && arguments[1].method === 'POST') {
        try {
            let body = JSON.parse(arguments[1].body);
            let autoEmailToggle = document.getElementById('depAutoEmailToggle')?.checked;
            if (autoEmailToggle) {
                body.auto_email_sender = document.getElementById('depAutoEmailSender')?.value || '';
                body.auto_email_recipients = document.getElementById('depAutoEmailRecipients')?.value || '';
                body.auto_email_use_gpg = document.getElementById('depAutoEmailUseGpg')?.checked !== false;
                body.auto_email_toggle = true;
            } else {
                body.auto_email_toggle = false;
            }
            const autoConfluence = collectAutoConfluenceSettings();
            body.auto_confluence_toggle = autoConfluence.enabled;
            body.auto_confluence_profile = autoConfluence.profile;
            body.auto_confluence_page_id = autoConfluence.page_id;
            body.auto_confluence_title = autoConfluence.title;
            body.auto_confluence_body_format = autoConfluence.body_format;
            body.auto_confluence_note = autoConfluence.note;
            arguments[1].body = JSON.stringify(body);
        } catch(e) {}
    }

    return originalFetch.apply(this, arguments);
};

// --- ДИНАМІЧНІ ЗМІННІ (VARIABLES) ---
function updateVariablesUI() {
    const payload = document.getElementById('depPayload');
    if (!payload) return;
    const scriptText = getPayloadValue();

    const regex = /\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g;
    let match;
    const vars = new Set();

    const checkedType = document.querySelector('input[name="depTemplateType"]:checked');
    if (checkedType && checkedType.value === 'report') {
        document.getElementById('templateVariablesArea')?.classList.add('hidden');
        return;
    }

    currentTemplateVariables.forEach(v => vars.add(v));
    Object.keys(currentTemplateVariableSchema || {}).forEach(v => vars.add(v));
    while ((match = regex.exec(scriptText)) !== null) {
        vars.add(match[1]);
    }

    const varArea = document.getElementById('templateVariablesArea');
    const varContainer = document.getElementById('variablesContainer');
    if(!varArea || !varContainer) return;

    if (vars.size > 0) {
        varArea.classList.remove('hidden');

        const currentValues = {};
        Object.assign(currentValues, collectVariableInputs('.tpl-var-input'));

        varContainer.innerHTML = Array.from(vars).map(v => {
            const spec = variableSpecFor(v, currentTemplateVariableSchema);
            const field = renderVariableField(v, spec, currentValues[v], 'tpl-var-input');
            return `
            <div>
                <label class="text-[10px] font-black text-cyan-200 uppercase tracking-widest block mb-2 ml-2">${escapeHtml(spec.label || v)}</label>
                ${field}
            </div>
        `;
        }).join('');
    } else {
        varArea.classList.add('hidden');
        varContainer.innerHTML = '';
    }
}


// --- REPORTS (BUFFER) & SMTP LOGIC ---
async function loadReports(requestedPage = reportPage) {
    try {
        reportPage = Math.max(1, Number(requestedPage) || 1);
        const params = new URLSearchParams({page: String(reportPage), per_page: '50'});
        const filterValues = {
            q: document.getElementById('reportSearch')?.value?.trim(),
            content: document.getElementById('reportContentSearch')?.value?.trim(),
            content_field: document.getElementById('reportContentField')?.value,
            actor: document.getElementById('reportActorFilter')?.value?.trim(),
            source: document.getElementById('reportSourceFilter')?.value,
            status: document.getElementById('reportStatusFilter')?.value,
            date_from: document.getElementById('reportDateFrom')?.value,
            date_to: document.getElementById('reportDateTo')?.value,
        };
        Object.entries(filterValues).forEach(([key, value]) => { if(value) params.set(key, value); });
        if(document.getElementById('reportHasErrors')?.checked) params.set('has_errors', '1');
        const res = await fetch('/api/infrastructure/reports/all?' + params.toString());
        if (!res.ok) throw new Error(`Reports request failed: ${res.status}`);
        const data = await res.json();
        if (data.success) {
            allReports = data.data;
            reportPagination = data.pagination || {page: reportPage, total: allReports.length, has_more: false};
            renderReports();
            const pageInfo = document.getElementById('reportPageInfo');
            if(pageInfo) pageInfo.innerText = `Page ${reportPage} · ${reportPagination.total || 0} matching reports`;
            const prev = document.getElementById('reportPrev');
            const next = document.getElementById('reportNext');
            if(prev) prev.disabled = reportPage <= 1;
            if(next) next.disabled = !reportPagination.has_more;
        }
    } catch(e) { console.error("Error loading reports", e); }
}

function changeReportPage(delta) {
    const requested = reportPage + Number(delta || 0);
    if(requested < 1 || (delta > 0 && !reportPagination.has_more)) return;
    loadReports(requested);
}

function renderReports() {
    const container = document.getElementById('reportsList');
    if(!container) return;

    if(!allReports || allReports.length === 0) {
        container.innerHTML = `<div class="col-span-full py-20 text-center"><p class="text-slate-400 font-bold uppercase tracking-widest text-sm mb-2">No Reports Found</p><p class="text-slate-400 text-xs">Completed multi-host tasks will appear here.</p></div>`;
        return;
    }

    container.innerHTML = allReports.map(r => {
        let statusCls = r.status === 'Waiting Review' ? 'report-status-badge report-status-waiting' : (r.status.startsWith('Sent') ? 'report-status-badge report-status-sent' : 'report-status-badge report-status-default');
        let dotColor = r.error > 0 ? 'bg-rose-500' : (r.success > 0 ? 'bg-emerald-500' : 'bg-slate-300');

        return `
        <div class="infra-report-card p-5 rounded-2xl border shadow-sm hover:shadow-lg transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between cursor-pointer gap-4" onclick="viewReport('${escapeInlineJs(r.id)}')">
            <div class="flex items-center gap-4 w-full sm:w-auto">
                <div class="w-1.5 h-12 rounded-full ${dotColor} shrink-0 shadow-sm"></div>
                <div class="min-w-0">
                    <h3 class="text-sm font-black text-slate-800 tracking-tight truncate">${escapeHtml(r.title)}</h3>
                    <div class="flex gap-2 items-center mt-1">
                        <span class="text-[10px] text-slate-400 font-bold uppercase tracking-widest">${escapeHtml(r.created_at)}</span>
                        <span class="text-slate-300">•</span>
                        <span class="text-[10px] text-slate-500 font-bold">Total: ${r.total} | <span class="text-emerald-500">Succ: ${r.success}</span> | <span class="text-rose-500">Err: ${r.error}</span></span>
                    </div>
                    <div class="text-[10px] text-slate-400 mt-1">By ${escapeHtml(r.created_by || 'System')} · ${escapeHtml(r.source || 'system')} · revision ${escapeHtml(r.revision || 1)}${r.ai_report?.requested ? ` · <span class="font-black text-violet-600">AI: ${escapeHtml(r.ai_report.status || 'Pending')}</span>` : ''}</div>
                </div>
            </div>
            <div class="shrink-0">
                <span class="px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border shadow-sm ${statusCls}">${escapeHtml(r.status)}</span>
            </div>
        </div>`;
    }).join('');
}

async function viewReport(id) {
    const r = allReports.find(x => x.id === id);
    if(!r) return;
    currentReportId = id;
    window.currentReportId = id;

    document.getElementById('vrTitle').innerText = r.title;

    let statusCls = r.status === 'Waiting Review' ? 'report-status-badge report-status-waiting' : (r.status.startsWith('Sent') ? 'report-status-badge report-status-sent' : 'report-status-badge report-status-default');
    const stEl = document.getElementById('vrStatus');
    if(stEl) {
        stEl.innerText = r.status;
        stEl.className = `px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest border shadow-sm ${statusCls}`;
    }

    const bodyEl = document.getElementById('vrBody');
    renderReportAiStatus(r.ai_report);
    if(bodyEl) bodyEl.value = r.report_data_loaded ? (r.report_data || "") : "Loading report body...";
    selectedReportSnapshot = null;
    selectedReportSnapshotLabel = '';
    const compare = document.getElementById('vrCompareToggle');
    if(compare) compare.checked = false;

    const saveBtn = document.getElementById('btnSaveReportText');
    if(saveBtn) {
        saveBtn.innerText = "Save Changes";
        saveBtn.className = "px-6 py-3 bg-emerald-50 text-emerald-600 border border-emerald-200 hover:bg-emerald-100 rounded-2xl text-xs font-black uppercase transition-all shadow-sm";
    }

    openModal('reportViewModal');

    if (!r.report_data_loaded) {
        try {
            const res = await fetch(`/api/infrastructure/reports/${id}`);
            if (!res.ok) throw new Error(`Report body request failed: ${res.status}`);
            const data = await res.json();
            if (!data.success) throw new Error(data.message || 'Report body request failed');
            Object.assign(r, data.data || {}, { report_data_loaded: true });
            renderReportAiStatus(r.ai_report);
            if (currentReportId === id && bodyEl) {
                bodyEl.value = r.report_data || "";
            }
        } catch(e) {
            console.error("Error loading report body", e);
            if (currentReportId === id && bodyEl) {
                bodyEl.value = "Failed to load report body.";
            }
        }
    }
    if(currentReportId === id) {
        showCurrentReportVersion();
        loadReportTrail();
    }
}

function renderReportAiStatus(aiReport) {
    const badge = document.getElementById('vrAiStatus');
    if (!badge) return;
    const requested = !!aiReport?.requested;
    badge.classList.toggle('hidden', !requested);
    if (requested) {
        badge.textContent = `AI: ${aiReport.status || 'Pending'}`;
        badge.title = aiReport.error || '';
    }
}

async function regenerateCurrentReportWithAi() {
    if (!currentReportId) return;
    const instruction = window.prompt('How should AI format this report?', 'Create a concise report with a table. Use only facts from the endpoint results.');
    if (instruction === null) return;
    if (!instruction.trim()) return alert('AI report instruction is required.');
    const response = await fetch(`/api/infrastructure/reports/${encodeURIComponent(currentReportId)}/ai-regenerate`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({prompt: instruction.trim()}),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success) return alert(data.message || 'Could not queue AI report');
    renderReportAiStatus({requested: true, status: data.status});
    alert('AI regeneration queued. The result will be stored as a new immutable revision.');
}

function reportLineDiff(snapshot, current) {
    const before = String(snapshot || '').split('\n');
    const after = String(current || '').split('\n');
    const result = ['--- selected immutable snapshot', '+++ current working copy'];
    const count = Math.max(before.length, after.length);
    for(let index = 0; index < count; index++) {
        if(before[index] === after[index]) result.push(`  ${before[index] ?? ''}`);
        else {
            if(before[index] !== undefined) result.push(`- ${before[index]}`);
            if(after[index] !== undefined) result.push(`+ ${after[index]}`);
        }
    }
    return result.join('\n');
}

function renderSelectedReportVersion() {
    const report = allReports.find(item => item.id === currentReportId);
    const body = document.getElementById('vrBody');
    if(!report || !body) return;
    if(selectedReportSnapshot === null) {
        body.value = report.report_data || '';
        body.readOnly = !infraPermissions.edit_reports || !infraPermissions.view_sensitive_reports;
        return;
    }
    const compare = document.getElementById('vrCompareToggle')?.checked;
    body.value = compare ? reportLineDiff(selectedReportSnapshot, report.report_data || '') : selectedReportSnapshot;
    body.readOnly = true;
}

function showCurrentReportVersion() {
    const report = allReports.find(item => item.id === currentReportId);
    if(!report) return;
    selectedReportSnapshot = null;
    selectedReportSnapshotLabel = 'Current working copy';
    const label = document.getElementById('vrVersionLabel');
    if(label) label.innerText = `Current revision ${report.revision || 1}`;
    const compare = document.getElementById('vrCompareToggle');
    if(compare) compare.checked = false;
    const save = document.getElementById('btnSaveReportText');
    if(save) save.disabled = false;
    renderSelectedReportVersion();
}

async function loadReportTrail() {
    if(!currentReportId) return;
    const list = document.getElementById('vrVersionList');
    if(list) list.innerHTML = '<div class="p-4 text-xs text-slate-400">Loading immutable history…</div>';
    try {
        const [revisionResponse, deliveryResponse] = await Promise.all([
            fetch(`/api/infrastructure/reports/${currentReportId}/revisions`),
            fetch(`/api/infrastructure/reports/${currentReportId}/deliveries`),
        ]);
        const revisions = await revisionResponse.json();
        const deliveries = await deliveryResponse.json();
        if(!revisionResponse.ok || !revisions.success) throw new Error(revisions.message || 'Revision history failed');
        const revisionHtml = (revisions.revisions || []).map(item => `<button onclick="viewReportRevision('${escapeInlineJs(item.id)}')" class="w-full text-left p-3 rounded-xl border border-slate-200 bg-white hover:border-indigo-300 transition-colors"><div class="flex justify-between gap-2"><span class="text-xs font-black text-slate-700">Revision ${item.number}${item.is_original ? ' · Original' : ''}</span><span class="text-[9px] uppercase font-black text-indigo-600">${escapeHtml(item.kind)}</span></div><div class="text-[10px] text-slate-400 mt-1">${escapeHtml(item.actor)} · ${escapeHtml(item.created_at)}</div><div class="text-[9px] font-mono text-slate-400 truncate mt-1" title="${escapeHtml(item.content_hash)}">${escapeHtml(item.content_hash)}</div>${item.reason ? `<div class="text-[10px] text-slate-500 mt-1">${escapeHtml(item.reason)}</div>` : ''}</button>`).join('');
        const deliveryHtml = (deliveries.deliveries || []).map(item => `<button onclick="viewReportDelivery('${escapeInlineJs(item.id)}')" class="w-full text-left p-3 rounded-xl border border-sky-200 bg-sky-50 hover:border-sky-400 transition-colors"><div class="flex justify-between gap-2"><span class="text-xs font-black text-sky-800">Sent snapshot · ${escapeHtml(item.channel)}</span><span class="text-[9px] uppercase font-black ${item.status === 'Success' ? 'text-emerald-600' : 'text-rose-600'}">${escapeHtml(item.status)}</span></div><div class="text-[10px] text-slate-500 mt-1">${escapeHtml(item.actor)} · ${escapeHtml(item.created_at)}</div><div class="text-[9px] font-mono text-slate-400 truncate mt-1" title="${escapeHtml(item.content_hash)}">${escapeHtml(item.content_hash)}</div></button>`).join('');
        if(list) list.innerHTML = `${revisionHtml || '<div class="p-3 text-xs text-slate-400">No revisions</div>'}${deliveryHtml ? '<div class="pt-3 mt-3 border-t border-slate-200 text-[10px] font-black uppercase tracking-widest text-slate-400">Deliveries</div>' + deliveryHtml : ''}`;
    } catch(error) {
        if(list) list.innerHTML = `<div class="p-3 text-xs text-rose-500">${escapeHtml(error.message)}</div>`;
    }
}

async function viewReportRevision(revisionId) {
    const response = await fetch(`/api/infrastructure/reports/${currentReportId}/revisions/${revisionId}`);
    const data = await response.json();
    if(!response.ok || !data.success) return alert(data.message || 'Could not load revision');
    selectedReportSnapshot = data.revision.content || '';
    selectedReportSnapshotLabel = `Revision ${data.revision.number}${data.revision.kind === 'generated' ? ' · Original' : (data.revision.kind === 'recovered' ? ' · Migration baseline' : '')}`;
    const label = document.getElementById('vrVersionLabel'); if(label) label.innerText = selectedReportSnapshotLabel;
    const save = document.getElementById('btnSaveReportText'); if(save) save.disabled = true;
    renderSelectedReportVersion();
}

async function viewReportDelivery(deliveryId) {
    const response = await fetch(`/api/infrastructure/reports/${currentReportId}/deliveries/${deliveryId}`);
    const data = await response.json();
    if(!response.ok || !data.success) return alert(data.message || 'Could not load sent snapshot');
    selectedReportSnapshot = data.delivery.content || '';
    selectedReportSnapshotLabel = `Exact ${data.delivery.channel} delivery · ${data.delivery.status}`;
    const label = document.getElementById('vrVersionLabel'); if(label) label.innerText = selectedReportSnapshotLabel;
    const save = document.getElementById('btnSaveReportText'); if(save) save.disabled = true;
    renderSelectedReportVersion();
}

async function saveReportChanges() {
    const bodyEl = document.getElementById('vrBody');
    if(!bodyEl) return;
    const newText = bodyEl.value;
    if(selectedReportSnapshot !== null) return;
    const currentReport = allReports.find(item => item.id === currentReportId);
    if(currentReport && newText === (currentReport.report_data || '')) return true;
    const reason = window.prompt('Short reason for this immutable report revision:', 'Manual report edit');
    if(reason === null) return;

    const btn = document.getElementById('btnSaveReportText');
    if(btn) btn.innerText = "Saving...";

    try {
        const response = await fetch(`/api/infrastructure/reports/${currentReportId}/action`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'save', report_data: newText, reason: reason || 'Manual report edit', expected_content_hash: currentReport?.content_hash || ''})
        });
        const data = await response.json();
        if(!response.ok || !data.success) throw new Error(data.message || 'Failed to save report revision');

        const r = allReports.find(x => x.id === currentReportId);
        if(r) { r.report_data = newText; r.revision = data.revision || r.revision; r.content_hash = data.content_hash || r.content_hash; }
        const label = document.getElementById('vrVersionLabel'); if(label) label.innerText = `Current revision ${data.revision || ''}`;
        loadReportTrail();

        if(btn) {
            btn.innerText = "Saved!";
            btn.classList.replace('text-emerald-600', 'text-indigo-600');
            btn.classList.replace('bg-emerald-50', 'bg-indigo-50');
            btn.classList.replace('border-emerald-200', 'border-indigo-200');
            setTimeout(() => {
                btn.innerText = "Save Changes";
                btn.classList.replace('text-indigo-600', 'text-emerald-600');
                btn.classList.replace('bg-indigo-50', 'bg-emerald-50');
                btn.classList.replace('border-indigo-200', 'border-emerald-200');
            }, 2000);
        }
        return true;
    } catch(e) { console.error("Error saving report", e); alert(e.message || 'Error saving report'); return false; }
}

async function dismissCurrentReport() {
    try {
        await fetch(`/api/infrastructure/reports/${currentReportId}/action`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'dismiss'})
        });
        closeModal('reportViewModal');
        loadReports();
    } catch(e) { alert("Error dismissing report."); }
}

async function deleteCurrentReport() {
    if(confirm("Permanently delete this report?")) {
        try {
            await fetch(`/api/infrastructure/reports/${currentReportId}`, { method: 'DELETE' });
            closeModal('reportViewModal');
            loadReports();
        } catch(e) { alert("Error deleting report."); }
    }
}

async function openReportEmailModal(id) {
    const resolvedId = id || currentReportId || window.currentReportId;
    if (!resolvedId || resolvedId === 'undefined') {
        alert('Cannot send this report: report id is missing. Please reopen the report and try again.');
        return;
    }
    currentReportId = resolvedId;
    window.currentReportId = resolvedId;
    const modal = document.getElementById('reportEmailModal');
    if (modal) modal.dataset.reportId = resolvedId;
    await saveReportChanges();

    const r = allReports.find(x => x.id === resolvedId);
    const subjInput = document.getElementById('reportEmailSubject');
    if(subjInput) subjInput.value = r ? r.title : 'WinHUB Report';

    const senderSelect = document.getElementById('reportSenderEmail');
    if (senderSelect) {
        await fetchSmtpProfilesGlobally();
        if(smtpProfiles.length === 0) {
            senderSelect.innerHTML = '<option value="">No SMTP profiles configured!</option>';
        }
    }

    const input = document.getElementById('reportEmailInput');
    if(input) input.value = '';

    const customMsg = document.getElementById('reportCustomMessage');
    if(customMsg) customMsg.value = '';

    const btn = document.getElementById('btnSendReport');
    if(btn) {
        btn.innerHTML = `<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg> Send Securely`;
        btn.disabled = false;
        btn.classList.remove('bg-emerald-600', 'hover:bg-emerald-700');
        btn.classList.add('bg-indigo-600', 'hover:bg-indigo-700');
    }

    openModal('reportEmailModal');
}

async function sendReportEmail() {
    const reportId = document.getElementById('reportEmailModal')?.dataset.reportId || currentReportId || window.currentReportId;
    if (!reportId || reportId === 'undefined') {
        alert('Cannot send this report: report id is missing. Please reopen the report and try again.');
        return;
    }
    const email = document.getElementById('reportEmailInput').value;
    const sender = document.getElementById('reportSenderEmail').value;

    const subjectInput = document.getElementById('reportEmailSubject');
    const customMsgInput = document.getElementById('reportCustomMessage');
    const gpgInput = document.getElementById('reportUseGpg');

    const subject = subjectInput ? subjectInput.value : '';
    const customMsg = customMsgInput ? customMsgInput.value : '';
    const useGpg = gpgInput ? gpgInput.checked : false;

    if (!email || !sender) {
        alert('Please select a sender profile and enter recipient email(s).');
        return;
    }

    const btn = document.getElementById('btnSendReport');
    const origContent = btn.innerHTML;
    btn.innerHTML = '<svg class="animate-spin h-5 w-5 mx-auto text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';

    try {
        const res = await fetch(`/api/infrastructure/reports/${reportId}/action`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                action: 'send',
                sender: sender,
                email: email,
                subject: subject,
                custom_message: customMsg,
                use_gpg: useGpg
            })
        });
        const data = await res.json().catch(() => ({success: false, message: 'Server returned an invalid response'}));
        if (data.success) {
            alert(data.message || 'Report email sent successfully.');
            closeModal('reportEmailModal');
            if (typeof loadReports === 'function') loadReports();
        } else {
            alert('Error sending email: ' + (data.message || 'Unknown error'));
        }
    } catch(e) {
        console.error(e);
        alert('Error sending email: ' + (e.message || 'Network/server error'));
    } finally {
        btn.innerHTML = origContent;
    }
}

function renderSmtpList() {
    const list = document.getElementById('smtpListContainer');
    if(!list) return;
	    list.innerHTML = smtpProfiles.map(p => `
	        <div class="flex justify-between items-center bg-slate-50 p-4 rounded-xl border border-slate-100">
	            <div>
	                <p class="font-black text-slate-800 text-sm">${escapeHtml(p.email || '')}</p>
	                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">${escapeHtml(p.host || '')} : ${escapeHtml(String(p.port || ''))}</p>
	                ${p.keyserver ? `<p class="text-[10px] font-mono font-bold text-sky-500 mt-1">${escapeHtml(p.keyserver)}</p>` : ''}
	            </div>
	            <button onclick="deleteSmtpProfile('${escapeJsString(p.email || '')}')" class="p-2 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </button>
        </div>
    `).join('') || '<p class="text-center text-slate-400 text-sm font-bold p-6">No SMTP profiles configured.</p>';
}

function openSmtpManager() {
    renderSmtpList();
    openModal('smtpManagerModal');
}

async function saveSmtpProfile() {
    const email = document.getElementById('smtpEmail').value;
    const host = document.getElementById('smtpHost').value;
    const port = document.getElementById('smtpPort').value;
    const password = document.getElementById('smtpPass').value;
    const keyserver = document.getElementById('smtpKeyserver')?.value || '';

    if(!email || !host || !password) return alert("Fill all fields (Email, Host, App Password).");

    try {
	        await fetch('/api/infrastructure/smtp', {
	            method: 'POST', headers: {'Content-Type': 'application/json'},
	            body: JSON.stringify({email, host, port, password, keyserver})
	        });
	        document.getElementById('smtpEmail').value = '';
	        document.getElementById('smtpHost').value = '';
	        document.getElementById('smtpPass').value = '';
	        if(document.getElementById('smtpKeyserver')) document.getElementById('smtpKeyserver').value = '';

        await fetchSmtpProfilesGlobally();
        renderSmtpList();
    } catch(e) { alert("Error saving SMTP profile."); }
}

async function deleteSmtpProfile(email) {
    if(!confirm(`Delete profile ${email}?`)) return;
    try {
        await fetch('/api/infrastructure/smtp', {
            method: 'DELETE', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email})
        });
        await fetchSmtpProfilesGlobally();
        renderSmtpList();
    } catch(e) { alert("Error deleting SMTP profile."); }
}

function renderConfluenceList() {
    const list = document.getElementById('confluenceListContainer');
    if(!list) return;
    list.innerHTML = confluenceProfiles.map(p => `
        <div class="flex justify-between items-start gap-4 bg-slate-50 p-4 rounded-xl border border-slate-100">
            <div class="min-w-0">
                <p class="font-black text-slate-800 text-sm truncate">${escapeHtml(p.name || '')}</p>
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1 truncate">${escapeHtml(p.base_url || '')}</p>
                <p class="text-[10px] font-mono font-bold text-sky-500 mt-1">Page: ${escapeHtml(p.default_page_id || '-')} / ${escapeHtml((p.auth_type || 'bearer').toUpperCase())}</p>
                ${p.last_status ? `<p class="text-[10px] font-bold text-slate-500 mt-1 truncate">${escapeHtml(p.last_status)}</p>` : ''}
            </div>
            <div class="flex gap-2 shrink-0">
                <button onclick="testConfluenceProfile('${escapeJsString(p.name || '')}')" class="px-3 py-2 text-[10px] font-black uppercase rounded-xl bg-sky-50 text-sky-700 border border-sky-100 hover:bg-sky-100">Test</button>
                <button onclick="deleteConfluenceProfile('${escapeJsString(p.name || '')}')" class="p-2 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                </button>
            </div>
        </div>
    `).join('') || '<p class="text-center text-slate-400 text-sm font-bold p-6">No Confluence profiles configured.</p>';
    renderConfluenceProfileOptions();
}

function renderConfluenceProfileOptions() {
    const publishSelect = document.getElementById('reportConfluenceProfile');
    const deploySelect = document.getElementById('depAutoConfluenceProfile');
    const options = confluenceProfiles.length
        ? confluenceProfiles.map(p => `<option value="${escapeHtml(p.name || '')}">${escapeHtml(p.name || '')}</option>`).join('')
        : '<option value="">No Confluence profile configured</option>';
    if (publishSelect) {
        const current = publishSelect.value;
        publishSelect.innerHTML = options;
        if (current) publishSelect.value = current;
        updateConfluencePublishDefaults();
    }
    if (deploySelect) {
        const current = deploySelect.value;
        deploySelect.innerHTML = options;
        if (current) deploySelect.value = current;
        updateDeploymentConfluenceDefaults(false);
    }
}

function openConfluenceManager() {
    renderConfluenceList();
    openModal('confluenceManagerModal');
    fetchConfluenceProfilesGlobally().then(renderConfluenceList);
}

async function saveConfluenceProfile() {
    const name = document.getElementById('confluenceName')?.value.trim() || '';
    const baseUrl = document.getElementById('confluenceBaseUrl')?.value.trim() || '';
    const authType = document.getElementById('confluenceAuthType')?.value || 'bearer';
    const username = document.getElementById('confluenceUsername')?.value.trim() || '';
    const token = document.getElementById('confluenceToken')?.value || '';
    const pageId = document.getElementById('confluenceDefaultPageId')?.value.trim() || '';

    if(!name || !baseUrl) return alert("Fill profile name and Confluence URL.");
    if(authType === 'basic' && !username) return alert("Basic auth requires username/email.");

    try {
        const res = await fetch('/api/infrastructure/confluence', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name,
                base_url: baseUrl,
                auth_type: authType,
                username,
                token,
                default_page_id: pageId
            })
        });
        const data = await res.json();
        if(!data.success) return alert(data.message || "Failed to save Confluence profile.");
        document.getElementById('confluenceToken').value = '';
        await fetchConfluenceProfilesGlobally();
        renderConfluenceList();
    } catch(e) {
        alert("Error saving Confluence profile: " + (e.message || e));
    }
}

async function deleteConfluenceProfile(name) {
    if(!confirm(`Delete Confluence profile ${name}?`)) return;
    try {
        const res = await fetch('/api/infrastructure/confluence', {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const data = await res.json();
        if(!data.success) return alert(data.message || "Failed to delete Confluence profile.");
        await fetchConfluenceProfilesGlobally();
        renderConfluenceList();
    } catch(e) {
        alert("Error deleting Confluence profile.");
    }
}

async function testConfluenceProfile(name) {
    try {
        const res = await fetch('/api/infrastructure/confluence/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const data = await res.json();
        alert(data.message || (data.success ? 'Confluence OK' : 'Confluence test failed'));
        await fetchConfluenceProfilesGlobally();
        renderConfluenceList();
    } catch(e) {
        alert("Error testing Confluence profile: " + (e.message || e));
    }
}

function openReportConfluenceModal(id) {
    const resolvedId = id || currentReportId || window.currentReportId;
    if (!resolvedId || resolvedId === 'undefined') {
        alert('Cannot publish this report: report id is missing. Please reopen the report and try again.');
        return;
    }
    currentReportId = resolvedId;
    window.currentReportId = resolvedId;
    const modal = document.getElementById('reportConfluenceModal');
    if (modal) modal.dataset.reportId = resolvedId;
    fetchConfluenceProfilesGlobally();

    const r = allReports.find(x => x.id === resolvedId);
    const titleInput = document.getElementById('reportConfluenceTitle');
    if(titleInput) titleInput.value = r ? r.title : 'WinHUB Report';
    const noteInput = document.getElementById('reportConfluenceNote');
    if(noteInput) noteInput.value = '';
    const pageInput = document.getElementById('reportConfluencePageId');
    if(pageInput) pageInput.value = '';
    const formatSelect = document.getElementById('reportConfluenceBodyFormat');
    if(formatSelect) formatSelect.value = 'escaped_pre';
    openModal('reportConfluenceModal');
}

function updateConfluencePublishDefaults(force = false) {
    const select = document.getElementById('reportConfluenceProfile');
    const pageInput = document.getElementById('reportConfluencePageId');
    if (!select || !pageInput) return;
    const profile = confluenceProfiles.find(p => p.name === select.value);
    if (profile && (force || !pageInput.value)) {
        pageInput.value = profile.default_page_id || '';
    }
}

function updateDeploymentConfluenceDefaults(force = false) {
    const select = document.getElementById('depAutoConfluenceProfile');
    const pageInput = document.getElementById('depAutoConfluencePageId');
    if (!select || !pageInput) return;
    const profile = confluenceProfiles.find(p => p.name === select.value);
    if (profile && (force || !pageInput.value)) {
        pageInput.value = profile.default_page_id || '';
    }
}

function collectAutoConfluenceSettings() {
    return {
        enabled: document.getElementById('depAutoConfluenceToggle')?.checked || false,
        profile: document.getElementById('depAutoConfluenceProfile')?.value || '',
        page_id: document.getElementById('depAutoConfluencePageId')?.value || '',
        title: document.getElementById('depAutoConfluenceTitle')?.value || '',
        body_format: document.getElementById('depAutoConfluenceBodyFormat')?.value || 'storage_html',
        note: document.getElementById('depAutoConfluenceNote')?.value || ''
    };
}

function applyAutoConfluencePayload(payload, settings = collectAutoConfluenceSettings()) {
    if (!payload) return payload;
    if (settings.enabled) {
        payload.__auto_confluence_toggle = true;
        payload.__auto_confluence_profile = settings.profile;
        payload.__auto_confluence_page_id = settings.page_id;
        payload.__auto_confluence_title = settings.title;
        payload.__auto_confluence_body_format = settings.body_format;
        payload.__auto_confluence_note = settings.note;
    } else {
        delete payload.__auto_confluence_toggle;
        delete payload.__auto_confluence_profile;
        delete payload.__auto_confluence_page_id;
        delete payload.__auto_confluence_title;
        delete payload.__auto_confluence_body_format;
        delete payload.__auto_confluence_note;
    }
    return payload;
}

async function publishReportToConfluence() {
    const reportId = document.getElementById('reportConfluenceModal')?.dataset.reportId || currentReportId || window.currentReportId;
    const profile = document.getElementById('reportConfluenceProfile')?.value || '';
    const pageId = document.getElementById('reportConfluencePageId')?.value || '';
    const title = document.getElementById('reportConfluenceTitle')?.value || '';
    const customNote = document.getElementById('reportConfluenceNote')?.value || '';
    const bodyFormat = document.getElementById('reportConfluenceBodyFormat')?.value || 'escaped_pre';

    if (!reportId || reportId === 'undefined') return alert('Cannot publish this report: report id is missing.');
    if (!profile || !pageId) return alert('Select Confluence profile and page ID.');

    const btn = document.getElementById('btnPublishConfluence');
    const origContent = btn ? btn.innerHTML : '';
    if(btn) {
        btn.disabled = true;
        btn.innerHTML = 'Publishing...';
    }

    try {
        const res = await fetch(`/api/infrastructure/reports/${reportId}/confluence`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                profile,
                page_id: pageId,
                title,
                custom_note: customNote,
                body_format: bodyFormat
            })
        });
        const data = await res.json().catch(() => ({success: false, message: 'Server returned an invalid response'}));
        if (data.success) {
            alert(data.url ? `${data.message}\n${data.url}` : data.message);
            closeModal('reportConfluenceModal');
            if (typeof loadReports === 'function') loadReports();
        } else {
            alert('Confluence publish failed: ' + (data.message || 'Unknown error'));
        }
    } catch(e) {
        alert('Confluence publish failed: ' + (e.message || e));
    } finally {
        if(btn) {
            btn.disabled = false;
            btn.innerHTML = origContent;
        }
    }
}

Object.assign(window, {
    openConfluenceManager,
    fetchConfluenceProfilesGlobally,
    saveConfluenceProfile,
    deleteConfluenceProfile,
    testConfluenceProfile,
    openReportConfluenceModal,
    updateConfluencePublishDefaults,
    updateDeploymentConfluenceDefaults,
    publishReportToConfluence,
});

function renderScheduledReportSenderOptions() {
    const select = document.getElementById('scheduledReportSender');
    if (!select) return;
    select.innerHTML = smtpProfiles.length
        ? smtpProfiles.map(p => `<option value="${escapeHtml(p.email)}">${escapeHtml(p.email)}</option>`).join('')
        : '<option value="">No SMTP profile configured</option>';
}

async function fetchScheduledReports() {
    try {
        const res = await fetch('/api/infrastructure/scheduled-reports');
        const data = await res.json();
        scheduledReports = data.success ? (data.reports || []) : [];
    } catch(e) {
        scheduledReports = [];
    }
}

function renderScheduledReportsList() {
    const list = document.getElementById('scheduledReportsList');
    if (!list) return;
    list.innerHTML = scheduledReports.map(report => {
        const enabledClass = report.enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-100' : 'bg-slate-100 text-slate-500 border-slate-200';
        const status = report.last_status || 'Never sent';
        return `
            <div class="bg-white border border-slate-200 rounded-3xl p-4 shadow-sm">
                <div class="flex items-start justify-between gap-3">
                    <div>
                        <h4 class="font-black text-slate-900">${escapeHtml(report.name || 'Regular Report')}</h4>
                        <p class="text-[10px] font-black text-slate-500 uppercase tracking-widest mt-1">${escapeHtml(report.frequency || 'daily')} / ${escapeHtml(report.period || 'day')} / ${escapeHtml(report.sender || '-')}</p>
                    </div>
                    <span class="px-2.5 py-1 rounded-lg border text-[9px] font-black uppercase ${enabledClass}">${report.enabled ? 'Enabled' : 'Paused'}</span>
                </div>
                <p class="text-xs font-bold text-slate-500 mt-3">${escapeHtml(status)}</p>
                <div class="flex gap-2 mt-4">
                    <button onclick="editScheduledReport('${escapeHtml(report.id)}')" class="px-3 py-2 bg-blue-600 text-white rounded-xl text-[10px] font-black uppercase">Edit</button>
                    <button onclick="sendScheduledReportNow('${escapeHtml(report.id)}')" class="px-3 py-2 bg-white border border-blue-200 text-blue-700 rounded-xl text-[10px] font-black uppercase">Send</button>
                    <button onclick="deleteScheduledReport('${escapeHtml(report.id)}')" class="px-3 py-2 bg-rose-50 text-rose-600 rounded-xl text-[10px] font-black uppercase">Delete</button>
                </div>
            </div>
        `;
    }).join('') || '<div class="p-6 text-center text-sm font-bold text-slate-400">No regular reports configured.</div>';
}

function getScheduledReportFormPayload() {
    return {
        id: document.getElementById('scheduledReportId')?.value || '',
        name: document.getElementById('scheduledReportName')?.value || '',
        sender: document.getElementById('scheduledReportSender')?.value || '',
        recipients: document.getElementById('scheduledReportRecipients')?.value || '',
        frequency: document.getElementById('scheduledReportFrequency')?.value || 'daily',
        period: document.getElementById('scheduledReportPeriod')?.value || 'day',
        hour: parseInt(document.getElementById('scheduledReportHour')?.value || '8', 10),
        weekday: parseInt(document.getElementById('scheduledReportWeekday')?.value || '0', 10),
        enabled: !!document.getElementById('scheduledReportEnabled')?.checked,
        use_gpg: !!document.getElementById('scheduledReportUseGpg')?.checked,
        report_types: Array.from(document.querySelectorAll('.scheduled-report-type:checked')).map(el => el.value)
    };
}

function setScheduledReportForm(report = {}) {
    document.getElementById('scheduledReportId').value = report.id || '';
    document.getElementById('scheduledReportName').value = report.name || 'Daily Endpoint Summary';
    document.getElementById('scheduledReportRecipients').value = report.recipients || '';
    document.getElementById('scheduledReportFrequency').value = report.frequency || 'daily';
    document.getElementById('scheduledReportPeriod').value = report.period || (report.frequency === 'weekly' ? 'week' : 'day');
    document.getElementById('scheduledReportHour').value = report.hour ?? 8;
    document.getElementById('scheduledReportWeekday').value = report.weekday ?? 0;
    document.getElementById('scheduledReportEnabled').checked = report.enabled !== false;
    document.getElementById('scheduledReportUseGpg').checked = !!report.use_gpg;
    renderScheduledReportSenderOptions();
    if (report.sender && document.getElementById('scheduledReportSender')) {
        document.getElementById('scheduledReportSender').value = report.sender;
    }
    const selectedTypes = new Set(report.report_types || ['summary', 'tasks', 'audit']);
    document.querySelectorAll('.scheduled-report-type').forEach(el => {
        el.checked = selectedTypes.has(el.value);
    });
    toggleScheduledReportWeekday();
}

function resetScheduledReportForm() {
    setScheduledReportForm({});
}

function toggleScheduledReportWeekday() {
    const wrap = document.getElementById('scheduledReportWeekdayWrap');
    const frequency = document.getElementById('scheduledReportFrequency')?.value || 'daily';
    if (wrap) wrap.classList.toggle('hidden', frequency !== 'weekly');
    const period = document.getElementById('scheduledReportPeriod');
    if (period && frequency === 'weekly' && !period.dataset.userTouched) period.value = 'week';
}

async function openScheduledReportsManager() {
    await fetchSmtpProfilesGlobally();
    await fetchScheduledReports();
    renderScheduledReportSenderOptions();
    renderScheduledReportsList();
    setScheduledReportForm(scheduledReports[0] || {});
    openModal('scheduledReportsModal');
}

function editScheduledReport(id) {
    const report = scheduledReports.find(item => item.id === id);
    if (report) setScheduledReportForm(report);
}

async function saveScheduledReport() {
    const payload = getScheduledReportFormPayload();
    if (!payload.name || !payload.sender || !payload.recipients) {
        return alert('Fill report name, SMTP sender, and recipients.');
    }
    try {
        const res = await fetch('/api/infrastructure/scheduled-reports', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) return alert(data.message || 'Failed to save regular report.');
        await fetchScheduledReports();
        renderScheduledReportsList();
        setScheduledReportForm(data.report || {});
    } catch(e) {
        alert('Error saving regular report.');
    }
}

async function deleteScheduledReport(id) {
    if (!confirm('Delete this regular report?')) return;
    try {
        await fetch('/api/infrastructure/scheduled-reports/' + encodeURIComponent(id), { method: 'DELETE' });
        await fetchScheduledReports();
        renderScheduledReportsList();
        resetScheduledReportForm();
    } catch(e) {
        alert('Error deleting regular report.');
    }
}

async function sendScheduledReportNow(id = null) {
    const targetId = id || document.getElementById('scheduledReportId')?.value;
    if (!targetId) {
        await saveScheduledReport();
        const savedId = document.getElementById('scheduledReportId')?.value;
        if (!savedId) return;
        return sendScheduledReportNow(savedId);
    }
    try {
        const res = await fetch('/api/infrastructure/scheduled-reports/' + encodeURIComponent(targetId) + '/send-now', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(getScheduledReportFormPayload())
        });
        const data = await res.json();
        alert(data.message || (data.success ? 'Report sent.' : 'Failed to send report.'));
        await fetchScheduledReports();
        renderScheduledReportsList();
    } catch(e) {
        alert('Error sending regular report.');
    }
}

// Перезаписуємо closeModal, щоб при закритті вікна SMTP гарантовано оновлювати списки пошт
let templateSecrets = [];

async function fetchTemplateSecrets() {
    try {
        const res = await fetch('/api/infrastructure/secrets');
        const data = await res.json();
        templateSecrets = data.success ? (data.secrets || []) : [];
    } catch(e) {
        templateSecrets = [];
    }
}

function renderSecretsList() {
    const list = document.getElementById('secretsListContainer');
    if(!list) return;
    list.innerHTML = templateSecrets.map(s => `
        <div class="template-secret-row flex justify-between items-center bg-slate-50 p-4 rounded-xl border border-slate-100">
            <div>
                <p class="font-black text-slate-800 text-sm">${escapeHtml(s.name)}</p>
                <p class="text-[10px] font-mono text-indigo-600 mt-1">${escapeHtml(s.placeholder)}</p>
            </div>
            <button onclick="deleteTemplateSecret('${escapeInlineJs(s.name)}')" class="p-2 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </button>
        </div>
    `).join('') || '<p class="template-secret-empty text-center text-slate-400 text-sm font-bold p-6">No template secrets configured.</p>';
}

async function openSecretsManager() {
    await fetchTemplateSecrets();
    renderSecretsList();
    openModal('secretsManagerModal');
}

async function saveTemplateSecret() {
    const name = document.getElementById('secretName').value.trim();
    const value = document.getElementById('secretValue').value;
    if(!name || !value) return alert('Secret name and value are required.');

    try {
        const res = await fetch('/api/infrastructure/secrets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name, value })
        });
        const data = await res.json();
        if(!data.success) return alert(data.message || 'Failed to save secret.');
        document.getElementById('secretName').value = '';
        document.getElementById('secretValue').value = '';
        await fetchTemplateSecrets();
        renderSecretsList();
    } catch(e) {
        alert('Error saving template secret.');
    }
}

async function deleteTemplateSecret(name) {
    if(!confirm(`Delete template secret "${name}"?`)) return;
    try {
        await fetch('/api/infrastructure/secrets/' + encodeURIComponent(name), { method: 'DELETE' });
        await fetchTemplateSecrets();
        renderSecretsList();
    } catch(e) {
        alert('Error deleting template secret.');
    }
}

const origCloseModal = window.closeModal;
window.closeModal = function(id) {
    if (origCloseModal) origCloseModal(id);
    else document.getElementById(id)?.classList.add('hidden');

    if (id === 'smtpManagerModal') fetchSmtpProfilesGlobally();
    if (id === 'confluenceManagerModal') fetchConfluenceProfilesGlobally();
};

// --- CATEGORY MANAGER ---
const defaultCategories = ["General", "Scheduled", "Metrics", "Reports"];
let customCategories = ["Maintenance", "Security", "Software"];
try {
    const savedCats = localStorage.getItem('winhub_custom_categories');
    if (savedCats) customCategories = JSON.parse(savedCats);
} catch(e) { console.warn("Failed to load custom categories", e); }

function getAllCategories() {
    let templatesCats = Array.from(document.querySelectorAll('.template-card')).map(el => el.dataset.category);
    let combined = [...new Set([...defaultCategories, ...customCategories, ...templatesCats])];
    return combined.filter(c => c && c.trim() !== '').sort();
}

function renderCategoryListUI() {
    const listEl = document.getElementById('categoryListUI');
    const datalist = document.getElementById('catList');

    const allCats = getAllCategories();
    if(datalist) datalist.innerHTML = '';
    if(listEl) listEl.innerHTML = '';

    allCats.forEach(cat => {
        if(datalist) {
            const opt = document.createElement('option');
            opt.value = cat;
            datalist.appendChild(opt);
        }

        if(listEl) {
            const isDefault = defaultCategories.includes(cat);
            listEl.innerHTML += `
                <div class="flex justify-between items-center p-4 bg-white rounded-2xl border border-slate-100 shadow-sm mb-2">
                    <span class="font-bold text-slate-700 text-sm">${escapeHtml(cat)}</span>
                    ${!isDefault
                        ? `<button onclick="deleteCategoryUI('${escapeInlineJs(cat)}')" class="text-rose-400 hover:text-rose-600 hover:bg-rose-50 p-2 rounded-xl transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>`
                        : `<span class="text-[8px] uppercase font-black text-slate-400 tracking-widest bg-slate-100 px-2 py-1 rounded">System</span>`}
                </div>
            `;
        }
    });
}

function openCategoryManager() { renderCategoryListUI(); openModal('categoryModal'); }

function addCategoryUI() {
    const input = document.getElementById('newCategoryName');
    if(!input) return;
    const val = input.value.trim();
    if(!val) return;
    if(getAllCategories().includes(val)) { alert("Category already exists!"); return; }
    customCategories.push(val);
    localStorage.setItem('winhub_custom_categories', JSON.stringify(customCategories));
    input.value = '';
    renderCategoryListUI();
}

function deleteCategoryUI(cat) {
    const inUse = Array.from(document.querySelectorAll('.template-card')).some(el => el.dataset.category === cat);
    if(inUse) { alert("Cannot delete category! There are scripts using it. Please move or delete them first."); return; }
    customCategories = customCategories.filter(c => c !== cat);
    localStorage.setItem('winhub_custom_categories', JSON.stringify(customCategories));
    renderCategoryListUI();
}

function toggleCategory(catId, btn) {
    const el = document.getElementById(catId);
    if(!el) return;
    const chevron = btn.querySelector('.cat-chevron') || btn.querySelector('.sch-chevron') || btn.querySelector('.trg-chevron');

    if (el.classList.contains('hidden')) {
        el.classList.remove('hidden');
        el.classList.add('block');
        if(chevron) chevron.classList.add('rotate-180');
    } else {
        el.classList.add('hidden');
        el.classList.remove('block');
        if(chevron) chevron.classList.remove('rotate-180');
    }
    saveOpenCategories();
}

function saveOpenCategories() {
    const openIds = Array.from(document.querySelectorAll('[id^="cat_"], [id^="sch_cat_"], [id^="trg_cat_"]'))
        .filter(el => !el.classList.contains('hidden'))
        .map(el => el.id);
    localStorage.setItem(infraStateKeys.categories, JSON.stringify(openIds));
}

function restoreOpenCategories() {
    let openIds = [];
    try {
        openIds = JSON.parse(localStorage.getItem(infraStateKeys.categories) || '[]');
    } catch(e) {
        openIds = [];
    }
    openIds.forEach(catId => {
        const el = document.getElementById(catId);
        if (!el) return;
        el.classList.remove('hidden');
        el.classList.add('block');
        const btn = Array.from(document.querySelectorAll('button')).find(item => (item.getAttribute('onclick') || '').includes(catId));
        const chevron = btn?.querySelector('.cat-chevron') || btn?.querySelector('.sch-chevron') || btn?.querySelector('.trg-chevron');
        if (chevron) chevron.classList.add('rotate-180');
    });
}

function scrollInfraNav(direction) {
    const scroller = document.getElementById('infraNavScroller');
    if (!scroller) return;
    const step = Math.max(180, Math.floor(scroller.clientWidth * 0.7));
    scroller.scrollBy({ left: direction * step, behavior: 'smooth' });
    setTimeout(updateInfraNavArrows, 180);
}

function updateInfraNavArrows() {
    const scroller = document.getElementById('infraNavScroller');
    const left = document.getElementById('infraNavLeft');
    const right = document.getElementById('infraNavRight');
    if (!scroller || !left || !right) return;
    const hasOverflow = scroller.scrollWidth > scroller.clientWidth + 4;
    left.classList.toggle('hidden', !hasOverflow);
    right.classList.toggle('hidden', !hasOverflow);
    if (!hasOverflow) return;
    const atStart = scroller.scrollLeft <= 4;
    const atEnd = scroller.scrollLeft + scroller.clientWidth >= scroller.scrollWidth - 4;
    left.classList.toggle('opacity-40', atStart);
    right.classList.toggle('opacity-40', atEnd);
}

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    try {
        if (!window.location.pathname.includes('/module/infrastructure')) return;

        const defaultView = ['hosts', 'groups', 'software', 'queue', 'reports', 'deploy', 'scheduler', 'triggers']
            .find(v => document.getElementById('view-' + v)) || 'hosts';
        restoreFleetCenterState();
        restoreQueueState();
        restoreWorkspaceStateFromLocation();

        const saved = infraUrlParam('view') || localStorage.getItem(infraStateKeys.view) || defaultView;
        switchView(document.getElementById('view-' + saved) ? saved : defaultView, false);
        renderCategoryListUI();
        restoreOpenCategories();
        updateInfraNavArrows();
        document.getElementById('infraNavScroller')?.addEventListener('scroll', updateInfraNavArrows);
        window.addEventListener('resize', updateInfraNavArrows);

        fetchSmtpProfilesGlobally(); // ГЛОБАЛЬНЕ ЗАВАНТАЖЕННЯ ПОШТ
        fetchConfluenceProfilesGlobally();
        if (infraPermissions.use_ai_reports || infraPermissions.manage_ai) fetchAiProviderSettings().catch(() => {
            aiProviderSettings = {enabled: false};
            updateAiReportControls();
        });
        initAvailableHostsData();

        const hostSearchEl = document.getElementById('hostSearch');
        if(hostSearchEl) hostSearchEl.addEventListener('input', applyHostFilters);
        ['queueSearch', 'queueContent', 'queueDateFrom', 'queueDateTo', 'qFilterUser'].forEach(id => {
            const element = document.getElementById(id);
            if (!element) return;
            const eventName = element.tagName === 'INPUT' && element.type === 'text' ? 'input' : 'change';
            element.addEventListener(eventName, () => {
                clearTimeout(queueSearchTimer);
                queueSearchTimer = setTimeout(() => {
                    persistQueueState();
                    loadQueue(1);
                }, eventName === 'input' ? 350 : 0);
            });
        });
        ['reportSearch', 'reportContentSearch', 'reportActorFilter', 'reportSourceFilter', 'reportStatusFilter', 'reportContentField', 'reportDateFrom', 'reportDateTo', 'reportHasErrors'].forEach(id => {
            const element = document.getElementById(id);
            if(!element) return;
            const eventName = element.tagName === 'INPUT' && element.type === 'text' ? 'input' : 'change';
            element.addEventListener(eventName, () => {
                clearTimeout(element._reportFilterTimer);
                element._reportFilterTimer = setTimeout(() => loadReports(1), eventName === 'input' ? 400 : 0);
            });
        });

        initPayloadEditor();
        initScheduleTimeWheels();
        initScheduleModalScroll();
        initScheduleTargetPicker();
        restoreWorkspaceState();
        setGuideLanguage(guideLanguage);
        const payloadEl = document.getElementById('depPayload');
        if(payloadEl) payloadEl.addEventListener('input', updateVariablesUI);

        // Перешкоджаємо перемиканню назви Terminal назад на Powershell
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((m) => {
                if (m.target.id === 'codeEditorHint' && m.target.innerText !== 'Terminal (PS/Bash/SH)' && !m.target.innerText.includes('Jinja2')) {
                    m.target.innerText = 'Terminal (PS/Bash/SH)';
                }
                if (m.target.id === 'codeEditorLabel' && m.target.innerText.includes('PowerShell')) {
                    m.target.innerText = 'Execution Script / Code Content';
                }
            });
        });
        const hintNode = document.getElementById('codeEditorHint');
        const labelNode = document.getElementById('codeEditorLabel');
        if (hintNode) observer.observe(hintNode, { childList: true, characterData: true, subtree: true });
        if (labelNode) observer.observe(labelNode, { childList: true, characterData: true, subtree: true });
        startInfraLiveRefresh();

    } catch(e) {
        console.error("Initialization error:", e);
    }
});

function switchView(view, save=true) {
    if(save) {
        localStorage.setItem(infraStateKeys.view, view);
        writeInfraState(scopedInfraState(view));
    }
    ['hosts', 'groups', 'group-detail', 'software', 'queue', 'deploy', 'scheduler', 'triggers', 'reports'].forEach(v => {
        const el = document.getElementById('view-' + v);
        const nav = document.getElementById('nav-' + v);
        if (el) el.classList.add('hidden');
        if (nav) {
            nav.classList.remove('active', 'bg-white', 'text-indigo-600', 'shadow-sm', 'border-slate-200/50');
            nav.classList.add('text-slate-500', 'border-transparent');
        }
    });

    const target = document.getElementById('view-' + view);
    if (!target) return;
    const navBtn = document.getElementById('nav-' + (view === 'group-detail' ? 'groups' : view));
    target.classList.remove('hidden');
    if (navBtn) {
        navBtn.classList.add('active', 'bg-white', 'text-indigo-600', 'shadow-sm', 'border-slate-200/50');
        navBtn.classList.remove('text-slate-500', 'border-transparent');
    }
    if(view === 'queue') loadQueue();
    if(view === 'reports') loadReports();
    if(view === 'deploy') {
        switchWorkspaceTab(readInfraState('workspaceTab', infraStateKeys.workspaceTab, workspaceTab || 'builder'));
        refreshPayloadEditor();
    }
    if(view === 'hosts') switchNodeTab(infraUrlParam('nodeTab') || localStorage.getItem(infraStateKeys.nodeTab) || 'approved', false);
    if(view === 'software') loadSoftwareRegistry();
    if(infraLivePollStarted) scheduleInfraLivePoll(1000);
}

// --- MULTI-HOST SELECTION LOGIC ---
let availableHostsData = [];

function initAvailableHostsData() {
    if(window.WinhubHosts) {
        availableHostsData = window.WinhubHosts;
    } else {
        availableHostsData = [];
        document.querySelectorAll('.hidden-host-item').forEach(span => {
            availableHostsData.push({ id: span.dataset.id, name: span.dataset.name });
        });
    }
}

function openMultiHostModal() {
    if(availableHostsData.length === 0) initAvailableHostsData();
    const searchEl = document.getElementById('multiHostSearch');
    if(searchEl) searchEl.value = '';
    const bulkEl = document.getElementById('multiHostBulkInput');
    if(bulkEl) bulkEl.value = '';
    const bulkStatus = document.getElementById('multiHostBulkStatus');
    if(bulkStatus) bulkStatus.textContent = '';
    const currentSelectedStr = document.getElementById('depTargetHostIds')?.value || "[]";
    try {
        multiHostSelectedIds = new Set(JSON.parse(currentSelectedStr).map(String));
    } catch(e) {
        multiHostSelectedIds = new Set();
    }
    renderMultiHostList('');
    renderSelectedMultiHosts();
    openModal('selectMultipleHostsModal');
}

function getMultiHostById(hostId) {
    const id = String(hostId);
    return availableHostsData.find(h => String(h.id) === id);
}

function isMultiHostSelectable(host) {
    if(!host) return false;
    const approval = host.approval_status || 'Approved';
    return approval === 'Approved' && !host.is_blocked;
}

function multiHostStatusBadge(host) {
    const isOnline = !!host?.is_online;
    const title = host?.last_seen ? `Last seen: ${escapeHtml(host.last_seen)}` : 'No telemetry received yet';
    const dotClass = isOnline ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400';
    const badgeClass = isOnline
        ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
        : 'bg-slate-100 text-slate-500 border-slate-200';
    return `<span title="${title}" class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg border text-[9px] font-black uppercase ${badgeClass}">
        <span class="w-1.5 h-1.5 rounded-full ${dotClass}"></span>${isOnline ? 'Live' : 'Offline'}
    </span>`;
}

function renderMultiHostList(query) {
    const list = document.getElementById('multiHostListContainer');
    if(!list) return;

    const q = query.toLowerCase();

    const filtered = availableHostsData.filter(h => {
        const text = `${h.name || ''} ${h.display_name || ''} ${h.hostname || ''} ${h.ip || ''} ${h.os_type || ''} ${h.agent_version || ''}`.toLowerCase();
        return text.includes(q);
    });

    list.innerHTML = filtered.map(h => {
        const hostId = String(h.id);
        const safeId = escapeHtml(hostId);
        const isChecked = multiHostSelectedIds.has(hostId) ? 'checked' : '';
        const blockedBadge = h.is_blocked ? '<span class="ml-2 px-2 py-0.5 rounded bg-rose-50 text-rose-600 border border-rose-100 text-[9px] font-black uppercase">Blocked</span>' : '';
        const approval = h.approval_status || 'Approved';
        const approvalBadge = approval !== 'Approved' ? `<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-600 border border-amber-100 text-[9px] font-black uppercase">${escapeHtml(approval)}</span>` : '';
        const versionBadge = h.agent_outdated ? '<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-100 text-[9px] font-black uppercase">Outdated</span>' : '';
        const statusBadge = multiHostStatusBadge(h);
        const disabled = approval !== 'Approved' || h.is_blocked ? 'disabled' : '';
        return `
        <label class="flex items-center gap-4 p-4 border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors group ${disabled ? 'opacity-60' : ''}">
            <input type="checkbox" value="${safeId}" ${isChecked} ${disabled} class="multi-host-cb w-5 h-5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" onchange="toggleMultiHostSelection(this.value, this.checked)">
            <span class="min-w-0">
                <span class="flex flex-wrap items-center gap-2 font-black text-slate-700 text-sm group-hover:text-indigo-600 transition-colors">${escapeHtml(endpointVisibleName(h))} ${statusBadge}${blockedBadge}${approvalBadge}${versionBadge}</span>
                ${endpointHostnameLine(h)}
                <span class="block text-[10px] text-slate-400 font-bold mt-1">${escapeHtml(h.ip || 'No IP')} / ${escapeHtml(h.os_type || 'Unknown OS')} / Agent ${escapeHtml(h.agent_version || 'unknown')} / Last seen ${escapeHtml(h.last_seen || '-')}</span>
            </span>
        </label>`;
    }).join('') || '<div class="p-10 text-center text-slate-400 font-bold">No endpoints match search</div>';

    updateMultiHostCount();
}

function filterMultiHostList() {
    const searchEl = document.getElementById('multiHostSearch');
    if(searchEl) renderMultiHostList(searchEl.value);
}

function toggleAllMultiHosts() {
    const checkboxes = document.querySelectorAll('.multi-host-cb');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => {
        cb.checked = !allChecked;
        toggleMultiHostSelection(cb.value, cb.checked, false);
    });
    updateMultiHostCount();
    renderSelectedMultiHosts();
}

function toggleMultiHostSelection(hostId, checked, updateLabel = true) {
    const id = String(hostId);
    const host = getMultiHostById(id);
    if(checked && isMultiHostSelectable(host)) {
        multiHostSelectedIds.add(id);
    } else {
        multiHostSelectedIds.delete(id);
    }
    if(updateLabel) {
        updateMultiHostCount();
        renderSelectedMultiHosts();
    }
}

function updateMultiHostCount() {
    const label = document.getElementById('multiHostSelCount');
    if(label) label.innerText = multiHostSelectedIds.size;
}

function renderSelectedMultiHosts() {
    updateMultiHostCount();
    const container = document.getElementById('multiHostSelectedContainer');
    if(!container) return;
    const selectedHosts = Array.from(multiHostSelectedIds)
        .map(id => getMultiHostById(id))
        .filter(Boolean)
        .sort((a, b) => String(endpointVisibleName(a)).localeCompare(String(endpointVisibleName(b))));

    container.innerHTML = selectedHosts.map(h => `
        <div class="flex items-start justify-between gap-3 p-3 bg-white border border-slate-200 rounded-2xl shadow-sm">
            <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2 font-black text-slate-800 text-sm">${escapeHtml(endpointVisibleName(h))} ${multiHostStatusBadge(h)}</div>
                ${endpointHostnameLine(h)}
                <div class="text-[10px] text-slate-400 font-bold mt-1 truncate">${escapeHtml(h.ip || 'No IP')} / Agent ${escapeHtml(h.agent_version || 'unknown')} / Last seen ${escapeHtml(h.last_seen || '-')}</div>
            </div>
            <button onclick="removeMultiHostSelection('${escapeHtml(String(h.id))}')" class="shrink-0 p-2 bg-slate-50 hover:bg-rose-50 text-slate-400 hover:text-rose-600 rounded-xl border border-slate-100 hover:border-rose-100 transition-colors" title="Remove endpoint">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" stroke-width="2.5" stroke-linecap="round"/></svg>
            </button>
        </div>
    `).join('') || '<div class="h-full min-h-[180px] flex items-center justify-center text-center text-slate-400 text-sm font-bold p-8">No endpoints selected yet.</div>';
}

function endpointVisibleName(host) {
    if (!host) return 'Unknown';
    return host.name || host.display_name || host.hostname || host.id || 'Unknown';
}

function endpointHostnameLine(host) {
    if (!host || !host.display_name || !host.hostname) return '';
    return `<span class="display-hostname-line block text-[10px] text-slate-400 font-mono mt-1">HOSTNAME: ${escapeHtml(host.hostname)}</span>`;
}

function removeMultiHostSelection(hostId) {
    multiHostSelectedIds.delete(String(hostId));
    const cb = Array.from(document.querySelectorAll('.multi-host-cb')).find(item => item.value === String(hostId));
    if(cb) cb.checked = false;
    renderSelectedMultiHosts();
}

function clearMultiHostSelection() {
    multiHostSelectedIds.clear();
    document.querySelectorAll('.multi-host-cb:checked').forEach(cb => { cb.checked = false; });
    renderSelectedMultiHosts();
}

function normalizeBulkHostToken(value) {
    return String(value || '').trim().toLowerCase();
}

function addBulkMultiHosts() {
    const input = document.getElementById('multiHostBulkInput');
    const status = document.getElementById('multiHostBulkStatus');
    const raw = input?.value || '';
    const tokens = raw.split(/[\s,;]+/).map(normalizeBulkHostToken).filter(Boolean);
    const uniqueTokens = Array.from(new Set(tokens));
    let added = 0;
    const missing = [];
    const blocked = [];

    uniqueTokens.forEach(token => {
        const matches = availableHostsData.filter(h => {
            const names = [
                h.id,
                h.name,
                h.hostname,
                h.ip,
                h.ip_address,
                ...(Array.isArray(h.interface_ips) ? h.interface_ips : [])
            ].map(normalizeBulkHostToken).filter(Boolean);
            return names.includes(token);
        });
        const selectable = matches.filter(isMultiHostSelectable);
        if(selectable.length > 0) {
            selectable.forEach(host => {
                const before = multiHostSelectedIds.size;
                multiHostSelectedIds.add(String(host.id));
                if(multiHostSelectedIds.size > before) added += 1;
            });
        } else if(matches.length > 0) {
            blocked.push(token);
        } else {
            missing.push(token);
        }
    });

    renderMultiHostList(document.getElementById('multiHostSearch')?.value || '');
    renderSelectedMultiHosts();
    if(status) {
        const parts = [`Added ${added}`];
        if(missing.length) parts.push(`not found: ${missing.slice(0, 8).join(', ')}${missing.length > 8 ? '...' : ''}`);
        if(blocked.length) parts.push(`not selectable: ${blocked.slice(0, 8).join(', ')}${blocked.length > 8 ? '...' : ''}`);
        status.textContent = parts.join(' | ');
        status.className = missing.length || blocked.length ? 'text-[11px] font-bold text-amber-600 min-h-[1rem]' : 'text-[11px] font-bold text-emerald-600 min-h-[1rem]';
    }
}

function confirmMultiHostSelection() {
    const selectedIds = Array.from(multiHostSelectedIds);

    const hiddenInput = document.getElementById('depTargetHostIds');
    if(hiddenInput) hiddenInput.value = JSON.stringify(selectedIds);

    const countLabel = document.getElementById('selectedHostsCount');
    if(countLabel) countLabel.innerText = selectedIds.length;

    const labelEl = document.getElementById('selectedHostsLabel');
    if(labelEl) {
        if(selectedIds.length === 0) {
            labelEl.innerText = "Click to select hosts...";
            labelEl.classList.remove('text-indigo-700', 'font-black');
        } else {
            labelEl.innerText = selectedIds.length + " endpoints selected";
            labelEl.classList.add('text-indigo-700', 'font-black');
        }
    }

    closeModal('selectMultipleHostsModal');
}

// --- WORKSPACE BUILDER ---
function setTemplateToolbarButtonState(id, enabled, enabledTitle, disabledTitle) {
    const button = document.getElementById(id);
    if (!button) return;
    button.disabled = !enabled;
    button.title = enabled ? enabledTitle : disabledTitle;
    button.setAttribute('aria-disabled', enabled ? 'false' : 'true');
    button.classList.toggle('opacity-40', !enabled);
    button.classList.toggle('cursor-not-allowed', !enabled);
}

function startNewTemplate() {
    const hasContent = !!(
        selectedTemplateId ||
        editingTemplateId ||
        document.getElementById('depTitle')?.value?.trim() ||
        document.getElementById('depCategory')?.value?.trim() ||
        document.getElementById('depVariableSchema')?.value?.trim() ||
        getPayloadValue().trim()
    );
    if (hasContent && !confirm('Start a new template? The current builder contents will be cleared.')) return;

    resetWorkspace(true);
    switchWorkspaceTab('builder');
    document.getElementById('depTitle')?.focus();
}

function resetWorkspace(clearPersistedState = true) {
    editingTemplateId = null; selectedTemplateId = null; currentTemplateVariables = []; currentTemplateVariableSchema = {};
    if (clearPersistedState) localStorage.removeItem(infraStateKeys.template);

    ['depTitle', 'depCategory', 'depReportTemplate', 'depVariableSchema', 'depTimeoutMinutes'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.value = '';
    });
    setPayloadValue('');

    const builderTitle = document.getElementById('builderTitle');
    if(builderTitle) builderTitle.innerText = "Deployment Builder";
    const saveTemplateBtn = document.getElementById('btnSaveTemplate');
    if(saveTemplateBtn) {
        saveTemplateBtn.disabled = false;
        saveTemplateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        saveTemplateBtn.title = 'Save template';
    }
    setTemplateToolbarButtonState('btnExportTemplate', false, 'Download selected template', 'Select a saved template to download');
    setTemplateToolbarButtonState('btnCloneTemplate', false, 'Clone selected template', 'Select an editable template to clone');
    setTemplateToolbarButtonState('btnDeleteTemplate', false, 'Delete selected template', 'Select a deletable template');

    const isAdmin = checkIsAdmin();
    const actionEl = document.getElementById('depAction');
    const approvedEl = document.getElementById('depIsApproved');
    if (approvedEl) approvedEl.checked = false;
    const autoEmailToggle = document.getElementById('depAutoEmailToggle');
    if (autoEmailToggle) autoEmailToggle.checked = false;
    const autoEmailSettings = document.getElementById('depAutoEmailSettings');
    if (autoEmailSettings) autoEmailSettings.classList.add('hidden');
    const autoEmailSender = document.getElementById('depAutoEmailSender');
    if (autoEmailSender) autoEmailSender.value = '';
    const autoEmailRecipients = document.getElementById('depAutoEmailRecipients');
    if (autoEmailRecipients) autoEmailRecipients.value = '';
    const autoEmailUseGpg = document.getElementById('depAutoEmailUseGpg');
    if (autoEmailUseGpg) autoEmailUseGpg.checked = true;
    const aiToggle = document.getElementById('depAiReportToggle');
    if (aiToggle) aiToggle.checked = false;
    const aiSettings = document.getElementById('depAiReportSettings');
    if (aiSettings) aiSettings.classList.add('hidden');
    const aiPrompt = document.getElementById('depAiReportPrompt');
    if (aiPrompt) aiPrompt.value = '';
    const autoConfluenceToggle = document.getElementById('depAutoConfluenceToggle');
    if (autoConfluenceToggle) autoConfluenceToggle.checked = false;
    const autoConfluenceSettings = document.getElementById('depAutoConfluenceSettings');
    if (autoConfluenceSettings) autoConfluenceSettings.classList.add('hidden');
    ['depAutoConfluenceProfile', 'depAutoConfluencePageId', 'depAutoConfluenceTitle', 'depAutoConfluenceNote'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.value = '';
    });
    const autoConfluenceFormat = document.getElementById('depAutoConfluenceBodyFormat');
    if (autoConfluenceFormat) autoConfluenceFormat.value = 'storage_html';
    ['depPolicyHideCode', 'depPolicyLockEdit', 'depPolicyLockDelete', 'depPolicyDisableRun'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.checked = false;
    });

    if(actionEl) actionEl.value = 'run_script';

    if(isAdmin) {
        const typeRadios = document.querySelectorAll('input[name="depTemplateType"]');
        if(typeRadios.length > 0) {
            typeRadios[0].checked = true;
            toggleCodeEditorMode();
        }
    }

    const hostIds = document.getElementById('depTargetHostIds');
    if(hostIds) hostIds.value = "[]";
    const hostsCount = document.getElementById('selectedHostsCount');
    if(hostsCount) hostsCount.innerText = "0";
    const hostsLabel = document.getElementById('selectedHostsLabel');
    if(hostsLabel) {
        hostsLabel.innerText = "Click to select hosts...";
        hostsLabel.classList.remove('text-indigo-700', 'font-black');
    }

    document.querySelectorAll('.template-card').forEach(c => c.classList.remove('active'));

    updateVariablesUI();
    toggleActionView();
}

function loadTemplate(el) {
    resetWorkspace(false);
    el.classList.add('active');

    const isAdmin = checkIsAdmin();
    selectedTemplateId = el.dataset.id;
    localStorage.setItem(infraStateKeys.template, selectedTemplateId);
    try { currentTemplateVariables = JSON.parse(el.dataset.vars || '[]'); } catch(e) { currentTemplateVariables = []; }
    currentTemplateVariableSchema = normalizeVariableSchema(el.dataset.varSchema || '{}');
    const schemaEl = document.getElementById('depVariableSchema');
    if (schemaEl) schemaEl.value = Object.keys(currentTemplateVariableSchema).length ? JSON.stringify(currentTemplateVariableSchema, null, 2) : '';

    const titleEl = document.getElementById('depTitle');
    if(titleEl) titleEl.value = el.dataset.name;
    const catEl = document.getElementById('depCategory');
    if(catEl) catEl.value = el.dataset.category || 'General';

    const tType = el.dataset.type || 'action';

    const canViewCode = el.dataset.canViewCode !== 'false';
    try {
        const payload = JSON.parse(el.dataset.payload);
        setPayloadValue(canViewCode ? (payload.script || el.dataset.payload) : '');
    } catch(e) { setPayloadValue(el.dataset.payload); }

    const actEl = document.getElementById('depAction');
    if(actEl) actEl.value = el.dataset.action || 'run_script';

    const canEditTemplate = el.dataset.canEdit !== 'false' && canViewCode;
    const canDeleteTemplate = el.dataset.canDelete !== 'false';
    setTemplateToolbarButtonState('btnExportTemplate', canViewCode, 'Download selected template', 'Template code export is blocked by policy');
    setTemplateToolbarButtonState('btnCloneTemplate', canEditTemplate, 'Clone selected template', 'Template cloning is blocked by policy');
    setTemplateToolbarButtonState('btnDeleteTemplate', canDeleteTemplate, 'Delete selected template', 'Template deletion is blocked by policy');
    if (isAdmin && canEditTemplate) {
        editingTemplateId = el.dataset.id;
        const saveTemplateBtn = document.getElementById('btnSaveTemplate');
        if(saveTemplateBtn) {
            saveTemplateBtn.disabled = false;
            saveTemplateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            saveTemplateBtn.title = 'Save template';
        }
        try {
            const policy = JSON.parse(el.dataset.policy || '{}');
            const hide = document.getElementById('depPolicyHideCode');
            const edit = document.getElementById('depPolicyLockEdit');
            const del = document.getElementById('depPolicyLockDelete');
            const run = document.getElementById('depPolicyDisableRun');
            if(hide) hide.checked = !!policy.hide_code;
            if(edit) edit.checked = !!policy.lock_edit;
            if(del) del.checked = !!policy.lock_delete;
            if(run) run.checked = !!policy.disable_run;
        } catch(e) {}

        const chkAppr = document.getElementById('depIsApproved');
        if(chkAppr) chkAppr.checked = (el.dataset.approved === 'true');

        const typeRadios = document.querySelectorAll('input[name="depTemplateType"]');
        if(typeRadios.length > 0) {
            typeRadios.forEach(r => r.checked = (r.value === tType));
            toggleCodeEditorMode();
        }

        const bTitle = document.getElementById('builderTitle');
        if(bTitle) bTitle.innerText = "Editing: " + el.dataset.name;
    } else {
        editingTemplateId = null;
        if(el.dataset.canRun === 'false') return alert("This template is disabled by superadmin policy.");
        if(tType === 'report') return alert("You cannot deploy a report format. Please select an Action or Item.");
        const lblSel = document.getElementById('selectedTemplateLabel');
        if(lblSel) lblSel.innerText = "Ready to deploy: " + el.dataset.name;
        if(!canViewCode && lblSel) lblSel.innerText = "Ready to deploy: " + el.dataset.name + " (code hidden by policy)";
        const bTitle = document.getElementById('builderTitle');
        if(bTitle) bTitle.innerText = "Deploy: " + el.dataset.name;
        const saveTemplateBtn = document.getElementById('btnSaveTemplate');
        if(isAdmin && saveTemplateBtn) {
            saveTemplateBtn.disabled = true;
            saveTemplateBtn.classList.add('opacity-50', 'cursor-not-allowed');
            saveTemplateBtn.title = "Editing is locked or code is hidden by template policy.";
        }
    }

    // Встановлюємо параметри Report та Auto-Email з payload шаблону
    setTimeout(() => {
        let payload = {};
        try {
            payload = JSON.parse(el.dataset.payload || '{}');
        } catch(e) {
            payload = {};
        }
        const rSelect = document.getElementById('depReportTemplate');
        if (rSelect) rSelect.value = payload.__report_template_id || '';

        const aeToggle = document.getElementById('depAutoEmailToggle');
        const aeSettings = document.getElementById('depAutoEmailSettings');
        const aeSender = document.getElementById('depAutoEmailSender');
        const aeRecipients = document.getElementById('depAutoEmailRecipients');
        const aeUseGpg = document.getElementById('depAutoEmailUseGpg');

        if (aeToggle) {
            aeToggle.checked = !!payload.__auto_email_toggle;
            if (aeSettings) aeSettings.classList.toggle('hidden', !aeToggle.checked);
            if (aeToggle.checked) {
                if (aeSender) aeSender.value = payload.__auto_email_sender || '';
                if (aeRecipients) aeRecipients.value = payload.__auto_email_recipients || '';
            }
            if (aeUseGpg) aeUseGpg.checked = payload.__auto_email_use_gpg !== false;
        }

        const acToggle = document.getElementById('depAutoConfluenceToggle');
        const acSettings = document.getElementById('depAutoConfluenceSettings');
        if (acToggle) {
            acToggle.checked = !!payload.__auto_confluence_toggle;
            if (acSettings) acSettings.classList.toggle('hidden', !acToggle.checked);
            const profile = document.getElementById('depAutoConfluenceProfile');
            const pageId = document.getElementById('depAutoConfluencePageId');
            const title = document.getElementById('depAutoConfluenceTitle');
            const format = document.getElementById('depAutoConfluenceBodyFormat');
            const note = document.getElementById('depAutoConfluenceNote');
            if (profile) profile.value = payload.__auto_confluence_profile || '';
            if (pageId) pageId.value = payload.__auto_confluence_page_id || '';
            if (title) title.value = payload.__auto_confluence_title || '';
            if (format) format.value = payload.__auto_confluence_body_format || 'storage_html';
            if (note) note.value = payload.__auto_confluence_note || '';
        }
    }, 50);

    updateVariablesUI();
    toggleActionView();
}

function restoreWorkspaceState() {
    const templateId = localStorage.getItem(infraStateKeys.template);
    if (!templateId) {
        if (document.getElementById('btnNewTemplate')) resetWorkspace(false);
        return;
    }

    const card = Array.from(document.querySelectorAll('.template-card')).find(item => item.dataset.id === templateId);
    if (!card) {
        localStorage.removeItem(infraStateKeys.template);
        if (document.getElementById('btnNewTemplate')) resetWorkspace(false);
        return;
    }

    const group = card.closest('[id^="cat_"]');
    if (group) {
        group.classList.remove('hidden');
        group.classList.add('block');
        const btn = Array.from(document.querySelectorAll('button')).find(item => (item.getAttribute('onclick') || '').includes(group.id));
        const chevron = btn?.querySelector('.cat-chevron');
        if (chevron) chevron.classList.add('rotate-180');
        saveOpenCategories();
    }
    loadTemplate(card);
}

function toggleCodeEditorMode() {
    const checkedRadio = document.querySelector('input[name="depTemplateType"]:checked');
    if(!checkedRadio) return;

    const type = checkedRadio.value;
    const lblTitle = document.getElementById('lblDepTitle');
    const lblCategory = document.getElementById('lblDepCategory');
    const settingsBlock = document.getElementById('deploymentSettingsBlock');
    const label = document.getElementById('codeEditorLabel');
    const hint = document.getElementById('codeEditorHint');
    const payload = document.getElementById('depPayload');
    const btnDeploy = document.getElementById('btnDeploy');

    if (type === 'report') {
        setEditorMode('htmlmixed');
        if(lblTitle) lblTitle.innerText = "Report Template Name";
        if(lblCategory) lblCategory.innerText = "Report Category";
        if(settingsBlock) settingsBlock.classList.add('hidden');
        if(label) label.innerText = "Jinja2 Email / Report Format";
        if(hint) hint.innerText = "HTML / Text Template";

        if(payload) {
            if(!payload.value || payload.value.includes('Write-Output')) {
                payload.value = "Звіт виконання задачі: {{" + " job_title " + "}}\n=================================\n\n{%" + " for res in results " + "%}\nHost: {{" + " res.host " + "}}\nStatus: {{" + " res.status " + "}}\nData: {{" + " res.data " + "}}\n\n{%" + " endfor " + "%}";
            }
        }
        if(payload) setPayloadValue(payload.value);
        if(btnDeploy) btnDeploy.classList.add('hidden');

    } else if (type === 'metric') {
        setEditorMode('powershell');
        if(lblTitle) lblTitle.innerText = "Metric Item Name (e.g. CPU Load)";
        if(lblCategory) lblCategory.innerText = "Metric Category";
        if(settingsBlock) settingsBlock.classList.remove('hidden');
        if(label) label.innerText = "Execution Script / Code Content";
        if(hint) hint.innerText = "Must output JSON data";

        if(payload) {
            if(payload.value.includes('{%' + ' for res in results ' + '%}')) payload.value = "";
        }
        if(payload) setPayloadValue(payload.value);
        if(btnDeploy) btnDeploy.classList.remove('hidden');

    } else {
        setEditorMode('powershell');
        if(lblTitle) lblTitle.innerText = "Action Script Name";
        if(lblCategory) lblCategory.innerText = "Script Category";
        if(settingsBlock) settingsBlock.classList.remove('hidden');
        if(label) label.innerText = "Execution Script / Code Content";
        if(hint) hint.innerText = "Terminal (PS/Bash/SH)";

        if(payload) {
            if(payload.value.includes('{%' + ' for res in results ' + '%}')) payload.value = "";
        }
        if(payload) setPayloadValue(payload.value);
        if(btnDeploy) btnDeploy.classList.remove('hidden');
    }

    updateVariablesUI();
    toggleActionView();
    refreshPayloadEditor();
}

function toggleActionView() {
    const actionEl = document.getElementById('depAction');
    if (!actionEl) return;

    const isAdmin = checkIsAdmin();
    const checkedType = document.querySelector('input[name="depTemplateType"]:checked')?.value || 'action';
    const showPayloadEditor = ['run_script', 'aggregation_report'].includes(actionEl.value) || ['action', 'metric', 'report'].includes(checkedType);

    const payArea = document.getElementById('payloadArea');
    const tplArea = document.getElementById('templateInfoArea');

    if (isAdmin) {
        if(payArea) payArea.classList.toggle('hidden', !showPayloadEditor);
        if(tplArea) tplArea.classList.toggle('hidden', showPayloadEditor);
    } else {
        if(payArea) payArea.classList.add('hidden');
        if(tplArea) tplArea.classList.remove('hidden');
    }
    refreshPayloadEditor();
}

function toggleDeployTarget() {
    const typeEl = document.getElementById('depType');
    if(!typeEl) return;
    const isHost = typeEl.value === 'hosts';
    const hostsWrap = document.getElementById('depTargetHostsWrapper');
    const groupSel = document.getElementById('depTargetGroup');
    if(hostsWrap) hostsWrap.classList.toggle('hidden', !isHost);
    if(groupSel) groupSel.classList.toggle('hidden', isHost);
}

function buildTemplatePayloadForSave() {
    const action = document.getElementById('depAction')?.value || 'run_script';
    const schemaText = document.getElementById('depVariableSchema')?.value?.trim() || '';
    let variableSchema = {};
    if (schemaText) {
        try {
            variableSchema = normalizeVariableSchema(JSON.parse(schemaText));
        } catch(e) {
            alert('Variable Field Schema must be valid JSON.');
            throw e;
        }
    }
    const policy = {
        hide_code: document.getElementById('depPolicyHideCode')?.checked || false,
        lock_edit: document.getElementById('depPolicyLockEdit')?.checked || false,
        lock_delete: document.getElementById('depPolicyLockDelete')?.checked || false,
        disable_run: document.getElementById('depPolicyDisableRun')?.checked || false
    };
    if (action === 'agent_update') {
        try {
            const payload = JSON.parse(getPayloadValue() || '{}');
            payload.__template_policy = policy;
            if (Object.keys(variableSchema).length) payload.__variable_schema = variableSchema;
            else delete payload.__variable_schema;
            return payload;
        } catch(e) {
            alert('Agent update template payload must be valid JSON.');
            throw e;
        }
    }
    const payload = {
        script: getPayloadValue(),
        __report_template_id: document.getElementById('depReportTemplate')?.value || '',
        __auto_email_toggle: document.getElementById('depAutoEmailToggle')?.checked || false,
        __auto_email_sender: document.getElementById('depAutoEmailSender')?.value || '',
        __auto_email_recipients: document.getElementById('depAutoEmailRecipients')?.value || '',
        __auto_email_use_gpg: document.getElementById('depAutoEmailUseGpg')?.checked !== false,
        ...applyAutoConfluencePayload({}),
        __template_policy: policy
    };
    if (Object.keys(variableSchema).length) payload.__variable_schema = variableSchema;
    return payload;
}

async function saveAsTemplate() {
    const name = document.getElementById('depTitle').value;
    const category = document.getElementById('depCategory').value || 'General';
    if(!name) return alert("Title is required");

    let tType = 'action';
    const checkedRadio = document.querySelector('input[name="depTemplateType"]:checked');
    if(checkedRadio) tType = checkedRadio.value;

    const data = {
        id: editingTemplateId,
        name,
        category,
        action: document.getElementById('depAction')?.value || 'run_script',
        type: tType,
        payload: buildTemplatePayloadForSave(),
        is_approved: document.getElementById('depIsApproved')?.checked || false
    };

    try {
        const res = await fetch('/api/infrastructure/templates', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        if(res.ok) window.location.reload();
        else alert("Failed to save.");
    } catch(e) { alert("Error connecting to server."); }
}

function exportTemplates() {
    window.location.href = '/api/infrastructure/templates/export';
}

function exportTemplate(id) {
    window.location.href = '/api/infrastructure/templates/' + encodeURIComponent(id) + '/export';
}

function exportSelectedTemplate() {
    if (!selectedTemplateId) return alert('Select a saved template to download.');
    exportTemplate(selectedTemplateId);
}

function cloneSelectedTemplate() {
    if (!selectedTemplateId) return alert('Select an editable template to clone.');
    cloneTemplate(selectedTemplateId);
}

async function cloneTemplate(id) {
    if (!id) return;
    try {
        const res = await fetch('/api/infrastructure/templates/' + encodeURIComponent(id) + '/clone', {
            method: 'POST'
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success || !data.template?.id) {
            return alert(data.message || 'Failed to clone template.');
        }

        localStorage.setItem(infraStateKeys.template, data.template.id);
        window.location.reload();
    } catch(e) {
        alert('Error cloning template.');
    }
}

async function importTemplates(input) {
    const file = input?.files?.[0];
    if (!file) return;
    try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const templates = Array.isArray(parsed) ? parsed : parsed.templates;
        if (!Array.isArray(templates) || templates.length === 0) {
            alert('No templates found in this file.');
            input.value = '';
            return;
        }
        pendingTemplateImport = templates.filter(item => item && item.name);
        renderTemplateImportModal();
        openModal('templateImportModal');
    } catch(e) {
        alert('Template import file is not valid JSON.');
        input.value = '';
    }
}

function renderTemplateImportModal() {
    const body = document.getElementById('templateImportList');
    const count = document.getElementById('templateImportCount');
    if (!body) return;
    if (count) count.innerText = pendingTemplateImport.length;
    body.innerHTML = pendingTemplateImport.map((tpl, index) => {
        const type = String(tpl.type || 'action').toLowerCase();
        const typeClass = type === 'report'
            ? 'bg-sky-400/15 text-sky-100 border-sky-300/30'
            : type === 'metric'
                ? 'bg-purple-400/15 text-purple-100 border-purple-300/30'
                : 'bg-cyan-400/15 text-cyan-100 border-cyan-300/30';
        const rowClass = type === 'report'
            ? 'bg-sky-950/70 border-sky-300/30 hover:border-sky-200/60'
            : type === 'metric'
                ? 'bg-purple-950/60 border-purple-300/30 hover:border-purple-200/60'
                : 'bg-teal-950/60 border-cyan-300/30 hover:border-cyan-200/60';
        return `
        <label class="flex items-start gap-3 p-4 border rounded-2xl shadow-sm hover:bg-slate-800/95 transition-colors cursor-pointer ${rowClass}">
            <input type="checkbox" class="template-import-cb mt-1 w-4 h-4 text-cyan-500 rounded border-cyan-300/50 focus:ring-cyan-500 bg-slate-950" value="${index}" checked onchange="updateTemplateImportSelection()">
            <span class="min-w-0 flex-1">
                <span class="block font-black text-cyan-50 text-sm truncate">${escapeHtml(tpl.name || 'Untitled')}</span>
                <span class="block text-[10px] font-black text-cyan-200/60 uppercase tracking-widest mt-1">${escapeHtml(tpl.category || 'Imported')} / ${escapeHtml(tpl.type || 'action')} / ${escapeHtml(tpl.action_type || tpl.action || 'run_script')}</span>
            </span>
            <span class="px-2.5 py-1 rounded-lg border text-[9px] font-black uppercase ${typeClass}">${escapeHtml(tpl.type || 'action')}</span>
            <span class="px-2.5 py-1 rounded-lg bg-amber-400/10 border border-amber-300/25 text-amber-100 text-[9px] font-black uppercase">${tpl.is_approved ? 'Shared' : 'Draft'}</span>
        </label>
    `;
    }).join('');
    updateTemplateImportSelection();
}

function updateTemplateImportSelection() {
    const selected = document.querySelectorAll('.template-import-cb:checked').length;
    const selectedEl = document.getElementById('templateImportSelectedCount');
    if (selectedEl) selectedEl.innerText = selected;
}

function toggleAllTemplateImports(checked) {
    document.querySelectorAll('.template-import-cb').forEach(cb => { cb.checked = checked; });
    updateTemplateImportSelection();
}

async function confirmTemplateImport() {
    const selected = Array.from(document.querySelectorAll('.template-import-cb:checked'))
        .map(cb => pendingTemplateImport[Number(cb.value)])
        .filter(Boolean);
    if (!selected.length) return alert('Select at least one template to import.');
    try {
        const res = await fetch('/api/infrastructure/templates/import', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({templates: selected})
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(data.message || 'Template import failed.');
            return;
        }
        alert(`Import complete. Added: ${data.imported || 0}, updated: ${data.updated || 0}.`);
        window.location.reload();
    } catch(e) {
        alert('Template import failed.');
    } finally {
        const input = document.getElementById('templateImportFile');
        if (input) input.value = '';
    }
}

function selectedTemplateCard() {
    if (!selectedTemplateId) return null;
    return Array.from(document.querySelectorAll('.template-card'))
        .find(card => card.dataset.id === selectedTemplateId) || null;
}

function templateImpactLabel(group) {
    const names = Array.isArray(group?.names) ? group.names.filter(Boolean) : [];
    if (!names.length) return 'None';
    return names.join(', ') + (group?.truncated ? ', ...' : '');
}

function setTemplateDeleteError(message = '') {
    const error = document.getElementById('templateDeleteImpactError');
    if (!error) return;
    error.textContent = message;
    error.classList.toggle('hidden', !message);
}

function updateTemplateDeleteConfirmation() {
    const input = document.getElementById('templateDeleteConfirmation');
    const button = document.getElementById('btnConfirmTemplateDelete');
    if (!button) return;
    const matches = !!pendingTemplateDeletion && input?.value === pendingTemplateDeletion.name;
    const enabled = matches && !!pendingTemplateDeletion.impactLoaded && !pendingTemplateDeletion.deleting;
    button.disabled = !enabled;
    button.classList.toggle('opacity-50', !enabled);
    button.classList.toggle('cursor-not-allowed', !enabled);
}

function closeTemplateDeleteModal() {
    pendingTemplateDeletion = null;
    const confirmation = document.getElementById('templateDeleteConfirmation');
    if (confirmation) confirmation.value = '';
    closeModal('templateDeleteModal');
}

async function openTemplateDeleteModal() {
    const card = selectedTemplateCard();
    if (!card || !selectedTemplateId) return alert('Select a saved template to delete.');
    if (card.dataset.canDelete === 'false') return alert('Template deletion is blocked by policy.');

    const requestTemplateId = selectedTemplateId;
    pendingTemplateDeletion = {
        id: requestTemplateId,
        name: card.dataset.name || 'Template',
        impactLoaded: false,
        deleting: false,
    };

    const name = document.getElementById('templateDeleteName');
    const confirmation = document.getElementById('templateDeleteConfirmation');
    const loading = document.getElementById('templateDeleteImpactLoading');
    const impactPanel = document.getElementById('templateDeleteImpact');
    if (name) name.textContent = pendingTemplateDeletion.name;
    if (confirmation) confirmation.value = '';
    if (loading) loading.classList.remove('hidden');
    if (impactPanel) impactPanel.classList.add('hidden');
    setTemplateDeleteError();
    updateTemplateDeleteConfirmation();
    openModal('templateDeleteModal');

    try {
        const res = await fetch('/api/infrastructure/templates/' + encodeURIComponent(requestTemplateId) + '/deletion-impact');
        const data = await res.json().catch(() => ({}));
        if (!pendingTemplateDeletion || pendingTemplateDeletion.id !== requestTemplateId) return;
        if (!res.ok || !data.success) throw new Error(data.message || 'Failed to check template dependencies.');

        const authoritativeName = String(data.template?.name || pendingTemplateDeletion.name);
        if (authoritativeName !== pendingTemplateDeletion.name && confirmation) confirmation.value = '';
        pendingTemplateDeletion.name = authoritativeName;
        pendingTemplateDeletion.impactLoaded = true;
        if (name) name.textContent = authoritativeName;

        const scheduled = data.impact?.scheduled_tasks || {};
        const triggers = data.impact?.trigger_rules || {};
        const scheduledCount = document.getElementById('templateDeleteSchedulesCount');
        const triggerCount = document.getElementById('templateDeleteTriggersCount');
        const scheduledNames = document.getElementById('templateDeleteSchedulesNames');
        const triggerNames = document.getElementById('templateDeleteTriggersNames');
        if (scheduledCount) scheduledCount.textContent = String(scheduled.count || 0);
        if (triggerCount) triggerCount.textContent = String(triggers.count || 0);
        if (scheduledNames) scheduledNames.textContent = templateImpactLabel(scheduled);
        if (triggerNames) triggerNames.textContent = templateImpactLabel(triggers);
        if (impactPanel) impactPanel.classList.remove('hidden');
    } catch(e) {
        setTemplateDeleteError(e.message || 'Failed to check template dependencies.');
    } finally {
        if (pendingTemplateDeletion?.id === requestTemplateId) {
            if (loading) loading.classList.add('hidden');
            updateTemplateDeleteConfirmation();
            confirmation?.focus();
        }
    }
}

async function confirmTemplateDelete() {
    const pending = pendingTemplateDeletion;
    const confirmation = document.getElementById('templateDeleteConfirmation');
    if (!pending || !pending.impactLoaded || confirmation?.value !== pending.name) return;

    pending.deleting = true;
    setTemplateDeleteError();
    updateTemplateDeleteConfirmation();
    const button = document.getElementById('btnConfirmTemplateDelete');
    const originalText = button?.textContent || 'Delete permanently';
    if (button) button.textContent = 'Deleting...';

    try {
        const res = await fetch('/api/infrastructure/templates/' + encodeURIComponent(pending.id), {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({confirm_name: confirmation.value}),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success) throw new Error(data.message || 'Failed to delete template.');

        localStorage.removeItem(infraStateKeys.template);
        pendingTemplateDeletion = null;
        closeModal('templateDeleteModal');
        window.location.reload();
    } catch(e) {
        if (pendingTemplateDeletion?.id === pending.id) pendingTemplateDeletion.deleting = false;
        setTemplateDeleteError(e.message || 'Failed to delete template.');
        updateTemplateDeleteConfirmation();
    } finally {
        if (button) button.textContent = originalText;
    }
}

let fleetCenterData = { hosts: [], packages: [] };
let fleetSelectedHostIds = new Set();
let fleetSortState = { key: 'hostname', direction: 'asc' };
let fleetPagination = { page: 1, page_size: 50, total: 0, pages: 1 };
let fleetSearchTimer = null;
const agentPackagePlatforms = [
    ['windows', 'Windows', 'from-sky-500/25 to-blue-500/10 border-sky-300/45 text-sky-50'],
    ['linux', 'Linux', 'from-emerald-500/25 to-teal-500/10 border-emerald-300/45 text-emerald-50'],
    ['macos', 'macOS', 'from-violet-500/25 to-fuchsia-500/10 border-violet-300/45 text-violet-50'],
];

function normalizeAgentPlatform(platform) {
    const value = String(platform || '').toLowerCase();
    if (value === 'mac' || value === 'darwin' || value === 'osx') return 'macos';
    if (value === 'windows' || value === 'linux' || value === 'macos') return value;
    return 'unknown';
}

function agentPlatformMeta(platform) {
    const normalized = normalizeAgentPlatform(platform);
    const found = agentPackagePlatforms.find(item => item[0] === normalized);
    if (found) return { key: found[0], label: found[1], className: found[2] };
    return { key: 'unknown', label: 'Unknown', className: 'from-slate-500/25 to-slate-700/10 border-slate-300/35 text-slate-100' };
}

function renderAgentLatestVersions(latestVersions = {}) {
    const box = document.getElementById('agentLatestVersionCards');
    if (!box) return;
    box.innerHTML = agentPackagePlatforms.map(([key]) => {
        const meta = agentPlatformMeta(key);
        const version = latestVersions?.[key] || 'No package';
        const muted = !latestVersions?.[key] ? 'opacity-75' : '';
        return `<div class="agent-latest-card min-w-[118px] px-3 py-2 rounded-xl border bg-gradient-to-br ${meta.className} ${muted} shadow-sm" data-platform="${escapeHtml(key)}">
            <div class="text-[9px] font-black uppercase tracking-widest opacity-70">${escapeHtml(meta.label)}</div>
            <div class="mt-0.5 text-sm font-black whitespace-nowrap">${escapeHtml(version)}</div>
        </div>`;
    }).join('');
}

function agentPlatformBadge(platform, isLatest = false) {
    const meta = agentPlatformMeta(platform);
    const latestClass = isLatest ? 'ring-1 ring-white/30 shadow-sm' : '';
    return `<span class="inline-flex whitespace-nowrap px-2.5 py-1 rounded-lg border bg-gradient-to-r ${meta.className} ${latestClass} text-[9px] font-black uppercase">${escapeHtml(meta.label)}${isLatest ? ' latest' : ''}</span>`;
}

function renderAgentPackageList(packages = []) {
    if (!packages.length) {
        return '<div class="p-4 rounded-xl bg-slate-900/70 border border-slate-700 text-xs font-bold text-slate-300">No packages uploaded yet.</div>';
    }
    return agentPackagePlatforms.map(([platform]) => {
        const meta = agentPlatformMeta(platform);
        const items = packages.filter(pkg => normalizeAgentPlatform(pkg.platform) === platform);
        const body = items.map(pkg => `
            <div class="p-4 rounded-2xl border border-slate-700/80 bg-slate-950/70 hover:bg-slate-900/90 transition-colors">
                <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0">
                        <div class="flex flex-wrap items-center gap-2">
                            <div class="font-black text-slate-50 text-sm truncate">${escapeHtml(pkg.version)}</div>
                            ${agentPlatformBadge(pkg.platform, Boolean(pkg.is_latest_for_platform))}
                        </div>
                        <div class="text-[10px] font-bold text-slate-400 uppercase mt-1">${Math.round((pkg.size || 0) / 1024 / 1024 * 10) / 10} MB / ${escapeHtml(pkg.original_filename || 'package')}</div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button onclick="navigator.clipboard.writeText('${escapeHtml(pkg.sha256)}')" class="px-3 py-1.5 rounded-xl bg-slate-800 border border-slate-600 text-[9px] font-black uppercase text-slate-200 hover:text-cyan-200 hover:border-cyan-400/60">SHA</button>
                        ${window.WinhubIsAdmin ? `<button onclick="deleteAgentPackage('${escapeHtml(pkg.id)}', '${escapeHtml(pkg.version)}')" class="px-3 py-1.5 rounded-xl bg-rose-950/70 border border-rose-500/35 text-[9px] font-black uppercase text-rose-200 hover:bg-rose-900/80">Delete</button>` : ''}
                    </div>
                </div>
                <div class="mt-2 text-[10px] font-mono text-slate-500 break-all">${escapeHtml(pkg.sha256 || '')}</div>
            </div>
        `).join('');
        return `<div class="rounded-2xl border border-slate-700/80 bg-gradient-to-br ${meta.className} p-3 space-y-2">
            <div class="flex items-center justify-between">
                <div class="text-[10px] font-black uppercase tracking-widest">${escapeHtml(meta.label)} packages</div>
                <div class="text-[10px] font-black uppercase opacity-70">${items.length}</div>
            </div>
            ${body || '<div class="p-3 rounded-xl bg-slate-950/45 border border-white/10 text-[10px] font-black uppercase opacity-70">No package for this OS</div>'}
        </div>`;
    }).join('');
}

function renderFleetStatusTabs(status = 'all') {
    document.querySelectorAll('.fleet-status-tab').forEach(btn => {
        const active = btn.dataset.fleetStatus === (status || 'all');
        btn.className = `fleet-status-tab px-4 py-2 rounded-xl text-[10px] font-black uppercase border transition-all ${active ? 'bg-[#0f3d8a] text-white border-[#75a7f7] shadow-sm' : 'bg-white text-slate-700 border-slate-200 hover:bg-blue-50 hover:text-[#0f3d8a]'}`;
    });
}

function restoreFleetCenterState() {
    const status = readInfraState('fleetStatus', infraStateKeys.fleetStatus, 'all') || 'all';
    const search = readInfraState('fleetSearch', infraStateKeys.fleetSearch, '');
    const groups = (readInfraState('fleetGroups', infraStateKeys.fleetGroups, '') || '').split(',').filter(Boolean);
    const groupMatch = readInfraState('fleetGroupMatch', infraStateKeys.fleetGroupMatch, 'contains') || 'contains';
    const page = Number(readInfraState('fleetPage', infraStateKeys.fleetPage, '1')) || 1;
    const pageSize = Number(readInfraState('fleetPageSize', infraStateKeys.fleetPageSize, '50')) || 50;
    const sortValue = readInfraState('fleetSort', infraStateKeys.fleetSort, 'hostname:asc') || 'hostname:asc';
    const [sortKey, sortDirection] = sortValue.split(':');

    const statusEl = document.getElementById('fleetStatusFilter');
    if (statusEl) statusEl.value = status;
    const searchEl = document.getElementById('fleetSearch');
    if (searchEl) searchEl.value = search;
    document.querySelectorAll('#fleetGroupFilters input[type="checkbox"]:not(#fleetExactGroupsOnly)').forEach(cb => {
        cb.checked = groups.includes(String(cb.value));
    });
    const exactGroupsOnly = document.getElementById('fleetExactGroupsOnly');
    if (exactGroupsOnly) exactGroupsOnly.checked = groupMatch === 'exact';
    fleetPagination.page = page;
    fleetPagination.page_size = pageSize;
    fleetSortState = {
        key: sortKey || 'hostname',
        direction: sortDirection === 'desc' ? 'desc' : 'asc',
    };
    renderFleetStatusTabs(status);
}

function persistFleetCenterState(page = fleetPagination.page || 1) {
    const status = document.getElementById('fleetStatusFilter')?.value || 'all';
    const search = (document.getElementById('fleetSearch')?.value || '').trim();
    const groups = fleetGroupFilterValues().join(',');
    const groupMatch = document.getElementById('fleetExactGroupsOnly')?.checked ? 'exact' : 'contains';
    const pageSize = Number(fleetPagination.page_size || 50);
    const sort = `${fleetSortState.key}:${fleetSortState.direction}`;

    localStorage.setItem(infraStateKeys.fleetStatus, status);
    localStorage.setItem(infraStateKeys.fleetSearch, search);
    localStorage.setItem(infraStateKeys.fleetGroups, groups);
    localStorage.setItem(infraStateKeys.fleetGroupMatch, groupMatch);
    localStorage.setItem(infraStateKeys.fleetPage, String(page || 1));
    localStorage.setItem(infraStateKeys.fleetPageSize, String(pageSize));
    localStorage.setItem(infraStateKeys.fleetSort, sort);
    writeInfraState(scopedInfraState('hosts', {
        nodeTab: 'approved',
        fleetStatus: status === 'all' ? null : status,
        fleetSearch: search || null,
        fleetGroups: groups || null,
        fleetGroupMatch: groupMatch === 'contains' ? null : groupMatch,
        fleetPage: Number(page || 1) === 1 ? null : page,
        fleetPageSize: pageSize === 50 ? null : pageSize,
        fleetSort: sort === 'hostname:asc' ? null : sort,
    }));
}

let softwareRegistryData = { packages: [] };
let softwareSelectedHostIds = new Set();
let softwareSelectedPackageId = null;
let softwareActiveTab = 'library';
let softwareInfoLanguage = localStorage.getItem('software_info_lang') || 'en';
let softwareOpenGroups = new Set(JSON.parse(localStorage.getItem('software_open_groups') || '[]'));
let softwareCodeEditors = new Map();

function fleetGroupFilterValues() {
    return Array.from(document.querySelectorAll('#fleetGroupFilters input[type="checkbox"]:checked:not(#fleetExactGroupsOnly)')).map(cb => String(cb.value));
}

function scheduleFleetLoad() {
    clearTimeout(fleetSearchTimer);
    fleetSearchTimer = setTimeout(() => loadFleetCenter(1), 350);
}

async function loadFleetCenter(page = fleetPagination.page || 1) {
    const body = document.getElementById('fleetHostsBody');
    if (!body) return;
    page = Number(page || 1) || 1;
    persistFleetCenterState(page);
    try {
        const params = new URLSearchParams({
            page: String(page || 1),
            page_size: String(fleetPagination.page_size || 50),
            search: (document.getElementById('fleetSearch')?.value || '').trim(),
            status: document.getElementById('fleetStatusFilter')?.value || 'all',
            groups: fleetGroupFilterValues().join(','),
            group_match: document.getElementById('fleetExactGroupsOnly')?.checked ? 'exact' : 'contains',
            sort: fleetSortState.key,
            direction: fleetSortState.direction,
        });
        const res = await fetch(`/api/infrastructure/fleet?${params.toString()}`);
        const contentType = res.headers.get('content-type') || '';
        const raw = await res.text();
        let data = null;
        if (contentType.includes('application/json')) {
            data = JSON.parse(raw || '{}');
        } else {
            const compact = raw.replace(/\s+/g, ' ').trim().slice(0, 180);
            throw new Error(res.status === 401
                ? 'Session expired. Please sign in again.'
                : `Fleet API returned ${res.status || 'non-JSON'} instead of JSON: ${compact || 'empty response'}`);
        }
        if (!res.ok || !data.success) throw new Error(data.message || 'Fleet load failed');
        fleetCenterData = data;
        fleetPagination = data.pagination || fleetPagination;
        renderAgentLatestVersions(data.latest_versions || {});
        renderFleetPagination();
        renderFleetCenter();
    } catch(e) {
        console.error('Fleet load failed:', e);
        const message = e.message || 'Failed to load fleet data.';
        body.innerHTML = `<tr><td colspan="10" class="p-12 text-center text-rose-400 font-black">${escapeHtml(message)}</td></tr>`;
        renderFleetPaginationError(message);
    }
}

function updateFleetSelectedCount() {
    const countEl = document.getElementById('fleetSelectedCount');
    if (countEl) countEl.innerText = fleetSelectedHostIds.size;
}

function toggleFleetHostSelection(id, checked) {
    if (checked) fleetSelectedHostIds.add(id);
    else fleetSelectedHostIds.delete(id);
    renderFleetPagination();
    updateFleetSelectedCount();
}

function toggleFleetSelectionAll(checkbox) {
    document.querySelectorAll('.fleet-host-cb').forEach(cb => {
        cb.checked = checkbox.checked;
        toggleFleetHostSelection(cb.value, cb.checked);
    });
}

window.togglePackageRegistry = function togglePackageRegistry() {
    const card = document.getElementById('packageRegistryCard');
    const button = document.getElementById('packageRegistryToggleBtn');
    if (!card) return;
    const opening = card.classList.contains('hidden');
    card.classList.toggle('hidden', !opening);
    if (button) button.innerText = opening ? 'Hide Package Registry' : 'Package Registry';
    document.body.classList.toggle('overflow-hidden', opening);
};

window.closePackageRegistry = function closePackageRegistry() {
    const card = document.getElementById('packageRegistryCard');
    const button = document.getElementById('packageRegistryToggleBtn');
    if (card) card.classList.add('hidden');
    if (button) button.innerText = 'Package Registry';
    document.body.classList.remove('overflow-hidden');
};

function ipSortValue(value) {
    const parts = String(value || '').split('.').map(part => Number(part));
    if (parts.length !== 4 || parts.some(part => Number.isNaN(part))) return 0;
    return (((parts[0] * 256) + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function fleetSortValue(host, key) {
    if (key === 'ip') return ipSortValue(host.ip);
    if (key === 'health') return Number(host.health?.score || 0);
    if (key === 'last_seen') return Date.parse(host.last_seen || '') || 0;
    if (key === 'hostname') return endpointVisibleName(host).toLowerCase();
    return String(host[key] || '').toLowerCase();
}

window.setFleetSort = function setFleetSort(key) {
    if (fleetSortState.key === key) {
        fleetSortState.direction = fleetSortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
        fleetSortState = { key, direction: 'desc' };
        if (key === 'hostname') fleetSortState.direction = 'asc';
    }
    persistFleetCenterState(1);
    loadFleetCenter(1);
};

window.setFleetStatusFilter = function setFleetStatusFilter(status) {
    const select = document.getElementById('fleetStatusFilter');
    if (select) select.value = status || 'all';
    renderFleetStatusTabs(status || 'all');
    persistFleetCenterState(1);
    loadFleetCenter(1);
};

window.setFleetPageSize = function setFleetPageSize(value) {
    fleetPagination.page_size = Number(value) || 50;
    persistFleetCenterState(1);
    loadFleetCenter(1);
};

window.changeFleetPage = function changeFleetPage(page) {
    const nextPage = Math.max(1, Math.min(Number(page) || 1, fleetPagination.pages || 1));
    if (nextPage === fleetPagination.page) return;
    loadFleetCenter(nextPage);
};

function renderFleetCenter() {
    const body = document.getElementById('fleetHostsBody');
    const packagesBox = document.getElementById('agentPackageList');
    const packageSelect = document.getElementById('fleetPackageSelect');
    if (!body) return;

    const hosts = fleetCenterData.hosts || [];

    body.innerHTML = hosts.map(host => {
        const health = host.health || {};
        const healthClass = health.status === 'Healthy'
            ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
            : (health.status === 'Warning' ? 'bg-amber-50 text-amber-700 border-amber-100' : 'bg-rose-50 text-rose-700 border-rose-100');
        const versionClass = health.outdated ? 'bg-amber-50 text-amber-700 border-amber-100' : 'bg-slate-100 text-slate-600 border-slate-200';
        const encryption = host.encryption || {};
        const encryptionClass = encryption.level === 'encrypted'
            ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
            : (encryption.level === 'partial' ? 'bg-amber-50 text-amber-700 border-amber-100' : (encryption.level === 'none' ? 'bg-rose-50 text-rose-700 border-rose-100' : 'bg-slate-100 text-slate-500 border-slate-200'));
        const encryptionTitle = (encryption.methods || []).join(', ') || encryption.summary || 'Encryption inventory is unavailable';
        const groups = (host.groups || []).map(group => `<span class="px-2 py-1 rounded-lg bg-slate-100 text-slate-500 border border-slate-200 text-[9px] font-black uppercase">${escapeHtml(group.name)}</span>`).join('');
        const keyClass = host.agent_identity_key_enrolled ? 'text-emerald-700 bg-emerald-50 border-emerald-100' : 'text-violet-700 bg-violet-50 border-violet-100';
        const keyLabel = host.agent_identity_key_enrolled ? 'Key OK' : 'No key';
        const taskKeyClass = host.task_signature_v2_ready ? 'text-emerald-700 bg-emerald-50 border-emerald-100' : 'text-amber-700 bg-amber-50 border-amber-100';
        const taskKeyLabel = host.task_signature_v2_ready ? 'Task v2' : 'Task legacy';
        const onlineClass = health.online ? 'bg-emerald-50 text-emerald-700 border-emerald-100' : 'bg-slate-100 text-slate-600 border-slate-200';
        const onlineLabel = health.online ? 'Online' : 'Offline';
        const healthReasons = (health.reasons || []).map(escapeHtml).join(', ') || 'current version, signed key, approved, unblocked';
        const checked = fleetSelectedHostIds.has(host.id) ? 'checked' : '';
        const duplicateMatches = (host.duplicate_matches || []).filter(match => match.strong_match);
        const duplicateSummary = duplicateMatches.map(match => `${match.hostname || match.id} / ${match.agent_version || 'unknown'} / ${(match.reasons || []).join(', ')}`).join(' | ');
        const duplicateBadge = host.possible_duplicate
            ? `<div class="mt-2 inline-flex px-2.5 py-1 rounded-lg bg-rose-50 text-rose-700 border border-rose-100 text-[9px] font-black uppercase" title="${escapeHtml(duplicateSummary || 'Same stable identity as another approved node')}">Duplicate identity</div>`
            : '';
        return `<tr class="${host.possible_duplicate ? 'bg-rose-50/35' : ''}">
            <td class="px-6 py-4">
                <input type="checkbox" value="${escapeHtml(host.id)}" ${checked} onchange="toggleFleetHostSelection('${escapeInlineJs(host.id)}', this.checked)" class="fleet-host-cb w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500">
            </td>
            <td class="px-6 py-4">
                <button onclick="viewHost('${escapeInlineJs(host.id)}')" class="font-black text-slate-800 hover:text-indigo-600 text-left">${escapeHtml(endpointVisibleName(host))}</button>
                ${endpointHostnameLine(host)}
                <div class="text-[10px] font-bold text-slate-400 uppercase mt-1">${escapeHtml(host.os || 'Windows')}</div>
                ${duplicateBadge}
            </td>
            <td class="px-6 py-4"><span class="inline-flex whitespace-nowrap px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${onlineClass}" title="Calculated from the last agent pulse">${onlineLabel}</span></td>
            <td class="px-6 py-4"><span class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${versionClass}">${escapeHtml(host.agent_version || 'unknown')}</span></td>
            <td class="px-6 py-4">
                <span title="${healthReasons}" class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${healthClass}">${health.score || 0}% ${escapeHtml(health.status || 'Unknown')}</span>
                <span class="ml-1 inline-flex whitespace-nowrap px-2 py-1 rounded-lg border text-[9px] font-black uppercase ${keyClass}" title="Agent request signing key exchange">${keyLabel}</span>
                <span class="ml-1 inline-flex whitespace-nowrap px-2 py-1 rounded-lg border text-[9px] font-black uppercase ${taskKeyClass}" title="Per-agent task signature migration">${taskKeyLabel}</span>
                <div class="text-[10px] font-bold text-slate-400 mt-1">${healthReasons}</div>
            </td>
            <td class="px-6 py-4"><span title="${escapeHtml(encryptionTitle)}" class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${encryptionClass}">${escapeHtml(encryption.status || 'Unknown')}</span></td>
            <td class="px-6 py-4"><div class="flex flex-wrap gap-1.5">${groups || '<span class="text-xs font-bold text-slate-300">No group</span>'}</div></td>
            <td class="px-6 py-4 font-bold text-slate-500">${escapeHtml(host.ip || '-')}</td>
            <td class="px-6 py-4 text-right text-xs font-bold text-slate-400">${escapeHtml(host.last_seen || '-')}</td>
            <td class="px-6 py-4 text-right">
                <button onclick="runFleetUpdate('${escapeHtml(host.id)}')" class="px-3 py-2 rounded-xl bg-white border border-slate-200 text-[10px] font-black uppercase text-slate-500 hover:text-indigo-600 hover:bg-indigo-50 transition-all">Update</button>
            </td>
        </tr>`;
    }).join('') || `<tr><td colspan="10" class="p-12 text-center text-slate-500 font-black">${escapeHtml(fleetCenterData.access_note || 'No fleet hosts match filters.')}</td></tr>`;
    updateFleetSelectedCount();

    if (packagesBox) {
        packagesBox.innerHTML = renderAgentPackageList(fleetCenterData.packages || []);
    }
    if (packageSelect) {
        packageSelect.innerHTML = (fleetCenterData.packages || []).map(pkg =>
            `<option value="${escapeHtml(pkg.id)}">${escapeHtml(pkg.version)} / ${escapeHtml(pkg.platform_label || pkg.platform || 'unknown')}${pkg.is_latest_for_platform ? ' / latest' : ''} (${escapeHtml(pkg.original_filename || 'package')})</option>`
        ).join('') || '<option value="">No packages available</option>';
    }
}

function renderFleetPagination() {
    const boxes = document.querySelectorAll('.fleet-pagination');
    if (!boxes.length) return;
    const total = Number(fleetPagination.total || 0);
    const page = Number(fleetPagination.page || 1);
    const pages = Number(fleetPagination.pages || 1);
    const pageSize = Number(fleetPagination.page_size || 50);
    const first = total ? ((page - 1) * pageSize) + 1 : 0;
    const last = Math.min(total, page * pageSize);
    const pageButtons = fleetPageNumbers(page, pages).map(item => {
        if (item === '...') {
            return '<span class="px-2 py-2 text-[10px] font-black text-slate-400">...</span>';
        }
        const active = item === page;
        return `<button onclick="changeFleetPage(${item})" class="px-3 py-2 rounded-xl border text-[10px] font-black uppercase transition-all ${active ? 'fleet-page-active' : ''}">${item}</button>`;
    }).join('');
    const html = `
        <div class="text-[10px] font-black uppercase tracking-widest text-slate-500">
            Showing ${first}-${last} of ${total} nodes
        </div>
        <div class="flex flex-wrap items-center gap-2">
            <select onchange="setFleetPageSize(this.value)" class="p-2 rounded-xl border text-[10px] font-black uppercase">
                ${[25, 50, 100].map(size => `<option value="${size}" ${size === pageSize ? 'selected' : ''}>${size} / page</option>`).join('')}
            </select>
            <button onclick="changeFleetPage(${page - 1})" ${page <= 1 ? 'disabled' : ''} class="px-3 py-2 rounded-xl border text-[10px] font-black uppercase disabled:opacity-40">Prev</button>
            ${pageButtons}
            <button onclick="changeFleetPage(${page + 1})" ${page >= pages ? 'disabled' : ''} class="px-3 py-2 rounded-xl border text-[10px] font-black uppercase disabled:opacity-40">Next</button>
        </div>
    `;
    boxes.forEach(box => { box.innerHTML = html; });
}

function renderFleetPaginationError(message) {
    document.querySelectorAll('.fleet-pagination').forEach(box => {
        box.innerHTML = `<div class="text-[10px] font-black uppercase tracking-widest text-rose-400">${escapeHtml(message || 'Failed to load nodes.')}</div>`;
    });
}

function fleetPageNumbers(page, pages) {
    if (pages <= 7) return Array.from({ length: pages }, (_, idx) => idx + 1);
    const items = [1];
    const start = Math.max(2, page - 1);
    const end = Math.min(pages - 1, page + 1);
    if (start > 2) items.push('...');
    for (let item = start; item <= end; item += 1) items.push(item);
    if (end < pages - 1) items.push('...');
    items.push(pages);
    return items;
}

async function uploadAgentPackage(event) {
    event.preventDefault();
    const form = document.getElementById('agentPackageForm');
    if (!form) return;
    const formData = new FormData(form);
    const progressWrap = document.getElementById('agentPackageProgressWrap');
    const progressBar = document.getElementById('agentPackageProgressBar');
    const progressText = document.getElementById('agentPackageProgressText');
    if (progressWrap) progressWrap.classList.remove('hidden');
    if (progressText) progressText.classList.remove('hidden');
    if (progressBar) progressBar.style.width = '0%';
    if (progressText) progressText.innerText = '0%';

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/infrastructure/agent-packages');
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.upload.onprogress = (event) => {
        if (!event.lengthComputable) return;
        const pct = Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100)));
        if (progressBar) progressBar.style.width = pct + '%';
        if (progressText) progressText.innerText = pct + '%';
    };
    xhr.onload = async () => {
        let data = {};
        try { data = xhr.responseText ? JSON.parse(xhr.responseText) : {}; } catch(e) { data = { message: xhr.responseText }; }
        if (xhr.status < 200 || xhr.status >= 300 || !data.success) {
            const sizeHint = xhr.status === 413 ? ' File is too large for current server/nginx upload limit.' : '';
            alert((data.message || `Package upload failed with HTTP ${xhr.status}.`) + sizeHint);
            return;
        }
        if (progressBar) progressBar.style.width = '100%';
        if (progressText) progressText.innerText = '100%';
        form.reset();
        await loadFleetCenter();
    };
    xhr.onerror = () => alert('Package upload failed: network error.');
    xhr.onloadend = () => {
        setTimeout(() => {
            if (progressWrap) progressWrap.classList.add('hidden');
            if (progressText) progressText.classList.add('hidden');
        }, 1200);
    };
    xhr.send(formData);
}

async function deleteAgentPackage(packageId, version='') {
    if (!packageId) return;
    const label = version ? ` ${version}` : '';
    if (!confirm(`Delete agent package${label}? Existing update tasks that already reference this package may no longer be able to download it.`)) return;
    const res = await fetch('/api/infrastructure/agent-packages/' + encodeURIComponent(packageId), { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) return alert(data.message || 'Package delete failed.');
    await loadFleetCenter();
}

async function runFleetUpdate(hostId=null) {
    const packageId = document.getElementById('fleetPackageSelect')?.value;
    if (!packageId) return alert('Upload or select an agent package first.');
    if (!confirm(hostId ? 'Update this single agent with the selected package?' : 'Start agent rollout with the selected package?')) return;
    const mode = hostId ? 'selected' : (document.getElementById('fleetTargetMode')?.value || 'outdated');
    const selectedIds = hostId ? [hostId] : Array.from(fleetSelectedHostIds);
    if (mode === 'selected' && selectedIds.length === 0) return alert('Check at least one agent in Fleet first.');
    const payload = {
        package_id: packageId,
        target_mode: mode,
        target_ids: mode === 'selected' ? selectedIds : [],
        group_id: document.getElementById('fleetGroupSelect')?.value || '',
        wave_size: hostId ? 1 : Number(document.getElementById('fleetWaveSize')?.value || 50),
        wave_delay_seconds: Number(document.getElementById('fleetWaveDelay')?.value || 0)
    };
    const res = await fetch('/api/infrastructure/fleet/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) return alert(data.message || 'Fleet update failed.');
    alert(`Rollout queued for ${data.targets} hosts in ${data.waves} wave(s).${data.skipped ? ` Skipped ${data.skipped} host(s) without a matching OS package.` : ''}`);
    switchView('queue');
}

async function loadSoftwareRegistry() {
    const list = document.getElementById('softwarePackageList');
    if (!list) return;
    try {
        const res = await fetch('/api/infrastructure/software-packages');
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || 'Software registry load failed');
        softwareRegistryData = data;
        if (!softwareSelectedPackageId && (data.packages || []).length) {
            softwareSelectedPackageId = data.packages[0].id;
        }
        renderSoftwareRegistry();
        renderSoftwareInstallPanel();
        renderSoftwareTargets();
    } catch(e) {
        list.innerHTML = '<div class="p-6 rounded-2xl bg-rose-50 text-xs font-bold text-rose-500">Failed to load software registry.</div>';
    }
}

function softwarePackageLabel(pkg) {
    return `${pkg.name || 'Software'} ${pkg.version || ''}`.trim();
}

function getSoftwarePackage(id=softwareSelectedPackageId) {
    return (softwareRegistryData.packages || []).find(pkg => String(pkg.id) === String(id));
}

function softwareCategory(pkg) {
    return (pkg.category || 'General').trim() || 'General';
}

function persistSoftwareOpenGroups() {
    localStorage.setItem('software_open_groups', JSON.stringify(Array.from(softwareOpenGroups)));
}

function toggleSoftwareGroup(category) {
    if (softwareOpenGroups.has(category)) softwareOpenGroups.delete(category);
    else softwareOpenGroups.add(category);
    persistSoftwareOpenGroups();
    renderSoftwareRegistry();
}

function destroySoftwareCodeEditors(form) {
    if (!form) return;
    form.querySelectorAll('textarea[data-software-code]').forEach(textarea => {
        const editor = softwareCodeEditors.get(textarea);
        if (editor) {
            editor.toTextArea();
            softwareCodeEditors.delete(textarea);
        }
    });
}

function initSoftwareCodeEditors(form) {
    if (!form || typeof CodeMirror === 'undefined') return;
    form.querySelectorAll('textarea[data-software-code]').forEach(textarea => {
        if (softwareCodeEditors.has(textarea)) return;
        const editor = CodeMirror.fromTextArea(textarea, {
            mode: 'powershell',
            theme: 'winhub-neon',
            lineNumbers: true,
            lineWrapping: true,
            indentUnit: 4,
            tabSize: 4,
            matchBrackets: true,
            viewportMargin: Infinity,
            extraKeys: {
                Tab(cm) {
                    if (cm.somethingSelected()) cm.indentSelection('add');
                    else cm.replaceSelection('    ', 'end');
                }
            }
        });
        editor.setSize(null, textarea.name === 'detection_value' ? 150 : 220);
        editor.on('change', () => editor.save());
        softwareCodeEditors.set(textarea, editor);
    });
    setTimeout(() => {
        form.querySelectorAll('textarea[data-software-code]').forEach(textarea => {
            const editor = softwareCodeEditors.get(textarea);
            if (editor) editor.refresh();
        });
    }, 60);
}

function syncSoftwareCodeEditors(form) {
    if (!form) return;
    form.querySelectorAll('textarea[data-software-code]').forEach(textarea => {
        const editor = softwareCodeEditors.get(textarea);
        if (editor) editor.save();
    });
}

function switchSoftwareTab(tab) {
    softwareActiveTab = tab || 'library';
    const library = document.getElementById('softwareLibraryPanel');
    const add = document.getElementById('softwareAddPanel');
    const info = document.getElementById('softwareInfoPanel');
    const libraryBtn = document.getElementById('softwareTab-library');
    const addBtn = document.getElementById('softwareTab-add');
    const infoBtn = document.getElementById('softwareTab-info');
    if (library) library.classList.toggle('hidden', softwareActiveTab !== 'library');
    if (add) add.classList.toggle('hidden', softwareActiveTab !== 'add');
    if (info) info.classList.toggle('hidden', softwareActiveTab !== 'info');
    if (libraryBtn) libraryBtn.className = softwareActiveTab === 'library' ? "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm" : "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-indigo-700";
    if (addBtn) addBtn.className = softwareActiveTab === 'add' ? "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm" : "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-indigo-700";
    if (infoBtn) infoBtn.className = softwareActiveTab === 'info' ? "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm" : "software-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-indigo-700";
    if (softwareActiveTab === 'add') initSoftwareCodeEditors(document.getElementById('softwarePackageForm'));
    if (softwareActiveTab === 'info') setSoftwareInfoLanguage(softwareInfoLanguage);
}

function setSoftwareInfoLanguage(lang) {
    softwareInfoLanguage = lang === 'ua' ? 'ua' : 'en';
    localStorage.setItem('software_info_lang', softwareInfoLanguage);
    document.querySelectorAll('.software-info-content').forEach(el => el.classList.add('hidden'));
    document.getElementById(`softwareInfoContent-${softwareInfoLanguage}`)?.classList.remove('hidden');
    const en = document.getElementById('softwareInfoLang-en');
    const ua = document.getElementById('softwareInfoLang-ua');
    if (en) en.className = softwareInfoLanguage === 'en' ? "px-4 py-2 bg-slate-900 text-white rounded-lg text-[10px] font-black uppercase" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
    if (ua) ua.className = softwareInfoLanguage === 'ua' ? "px-4 py-2 bg-slate-900 text-white rounded-lg text-[10px] font-black uppercase" : "px-4 py-2 text-slate-500 rounded-lg text-[10px] font-black uppercase";
}

function selectSoftwarePackage(id) {
    softwareSelectedPackageId = id;
    renderSoftwareRegistry();
    renderSoftwareInstallPanel();
}

function renderSoftwareRegistry() {
    const list = document.getElementById('softwarePackageList');
    if (!list) return;
    const q = (document.getElementById('softwareSearch')?.value || '').trim().toLowerCase();
    const packages = (softwareRegistryData.packages || []).filter(pkg => {
        const haystack = [pkg.name, pkg.version, pkg.vendor, pkg.category, pkg.package_type, pkg.architecture, pkg.notes, pkg.original_filename].join(' ').toLowerCase();
        return !q || haystack.includes(q);
    });
    const grouped = packages.reduce((acc, pkg) => {
        const category = softwareCategory(pkg);
        if (!acc[category]) acc[category] = [];
        acc[category].push(pkg);
        return acc;
    }, {});
    const categories = Object.keys(grouped).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    list.innerHTML = categories.map(category => {
        const open = softwareOpenGroups.has(category);
        const items = grouped[category].sort((a, b) => softwarePackageLabel(a).localeCompare(softwarePackageLabel(b), undefined, { numeric: true, sensitivity: 'base' }));
        const cards = items.map(pkg => {
            const active = String(pkg.id) === String(softwareSelectedPackageId);
            const sizeMb = Math.round((pkg.size || 0) / 1024 / 1024 * 10) / 10;
            const source = pkg.source === 'external_url' ? 'External URL' : `${sizeMb} MB`;
            const detection = pkg.detection_type && pkg.detection_type !== 'none' ? pkg.detection_type : 'No detection';
            const userRecipe = pkg.user_install_command ? '<span class="px-2 py-1 rounded-lg bg-indigo-50 text-indigo-700 border border-indigo-100 text-[9px] font-black uppercase">User scope</span>' : '';
            const uninstallReady = pkg.uninstall_command ? '<span class="px-2 py-1 rounded-lg bg-rose-50 text-rose-700 border border-rose-100 text-[9px] font-black uppercase">Uninstall</span>' : '';
        const adminButtons = window.WinhubCanManageSoftware ? `
                <button onclick="event.stopPropagation(); openSoftwareEditModal('${escapeHtml(pkg.id)}')" class="px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-[9px] font-black uppercase text-slate-500 hover:text-indigo-600">Edit</button>
                <button onclick="event.stopPropagation(); deleteSoftwarePackage('${escapeHtml(pkg.id)}')" class="px-3 py-1.5 rounded-xl bg-white border border-rose-100 text-[9px] font-black uppercase text-rose-500 hover:bg-rose-50">Delete</button>
            ` : '';
            return `<div onclick="selectSoftwarePackage('${escapeHtml(pkg.id)}')" class="software-package-row ${active ? 'software-package-row-active' : ''} group grid grid-cols-12 gap-3 items-center px-4 py-3 border-t border-slate-200 transition-all cursor-pointer">
                <div class="col-span-12 xl:col-span-4 min-w-0">
                    <div class="font-black text-slate-800 text-sm truncate">${escapeHtml(softwarePackageLabel(pkg))}</div>
                    <div class="text-[10px] font-bold text-slate-500 uppercase mt-1 truncate">${escapeHtml(pkg.vendor || 'Unknown vendor')}</div>
                </div>
                <div class="col-span-6 xl:col-span-2 text-[10px] font-black uppercase text-slate-600">${escapeHtml(pkg.package_type || 'custom')} / ${escapeHtml(pkg.architecture || 'any')}</div>
                <div class="col-span-6 xl:col-span-2"><span class="px-2 py-1 rounded-lg bg-slate-50 border border-slate-200 text-[9px] font-black uppercase text-slate-600">${escapeHtml(source)}</span></div>
                <div class="col-span-12 xl:col-span-2 flex flex-wrap gap-1.5">${userRecipe}${uninstallReady}<span class="px-2 py-1 rounded-lg bg-slate-50 border border-slate-200 text-[9px] font-black uppercase text-slate-600">${escapeHtml(detection)}</span></div>
                <div class="col-span-12 xl:col-span-2 flex justify-end gap-2">${adminButtons}</div>
                <div class="col-span-12 text-[10px] font-bold text-slate-500 truncate">${escapeHtml(pkg.notes || pkg.original_filename || pkg.external_url || 'No description')}</div>
            </div>`;
        }).join('');
        return `<div class="lg:col-span-2 rounded-2xl border border-slate-200 bg-slate-50/80 overflow-hidden">
            <button onclick="toggleSoftwareGroup('${escapeHtml(category)}')" class="w-full px-5 py-4 flex items-center justify-between gap-3 text-left">
                <span>
                    <span class="block text-xs font-black text-slate-800 uppercase tracking-widest">${escapeHtml(category)}</span>
                    <span class="block text-[10px] font-bold text-slate-500 mt-1">${items.length} package(s)</span>
                </span>
                <svg class="w-4 h-4 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
            <div class="${open ? 'block' : 'hidden'} border-t border-slate-200">${cards}</div>
        </div>`;
    }).join('') || '<div class="p-6 rounded-2xl bg-slate-50 text-xs font-bold text-slate-400">No software packages found.</div>';
}

function renderSoftwareInstallPanel() {
    const pkg = getSoftwarePackage();
    const hiddenId = document.getElementById('softwareInstallPackageId');
    const hint = document.getElementById('softwareSelectedPackageHint');
    if (hiddenId) hiddenId.value = pkg?.id || '';
    if (hint) hint.innerText = pkg ? `${softwarePackageLabel(pkg)} / ${pkg.vendor || 'Unknown vendor'}` : 'Select a package from the library.';
    const scope = document.getElementById('softwareInstallScope');
    if (scope && pkg && !pkg.user_install_command && scope.value === 'users') scope.value = 'all';
    renderSoftwareOperation();
    renderSoftwareInstallScope();
}

function renderSoftwareOperation() {
    const pkg = getSoftwarePackage();
    const operation = document.getElementById('softwareOperation')?.value || 'install';
    const scope = document.getElementById('softwareInstallScope');
    const runButton = document.getElementById('softwareRunButton');
    if (scope) {
        scope.options[0].text = operation === 'uninstall'
            ? 'Uninstall machine-wide / all users'
            : 'Install for all users / machine-wide';
        scope.options[1].text = operation === 'uninstall'
            ? 'Uninstall for specific users'
            : 'Install for specific users';
    }
    if (runButton) {
        runButton.innerText = operation === 'uninstall' ? 'Uninstall Selected Package' : 'Install Selected Package';
        runButton.className = operation === 'uninstall'
            ? 'w-full py-3 rounded-xl bg-rose-600 text-white text-[10px] font-black uppercase hover:bg-rose-700 shadow-lg shadow-rose-200 transition-all'
            : 'w-full py-3 rounded-xl bg-indigo-600 text-white text-[10px] font-black uppercase hover:bg-indigo-700 shadow-lg shadow-indigo-200 transition-all';
    }
    if (operation === 'uninstall' && pkg && !pkg.uninstall_command && runButton) {
        runButton.innerText = 'No Uninstall Command';
    }
}

function renderSoftwareInstallScope() {
    const pkg = getSoftwarePackage();
    const scope = document.getElementById('softwareInstallScope')?.value || 'all';
    const users = document.getElementById('softwareUserLogins');
    if (users) {
        users.classList.toggle('hidden', scope !== 'users');
        users.placeholder = pkg?.user_install_command
            ? 'User logins, one per line or comma-separated'
            : 'This package has no specific-user recipe yet. Edit package to add one.';
    }
}

function updateSoftwareSelectedCount() {
    const countEl = document.getElementById('softwareSelectedCount');
    if (countEl) countEl.innerText = softwareSelectedHostIds.size;
}

function toggleSoftwareTargetSelection(id, checked) {
    if (checked) softwareSelectedHostIds.add(id);
    else softwareSelectedHostIds.delete(id);
    updateSoftwareSelectedCount();
}

function renderSoftwareTargets() {
    const list = document.getElementById('softwareTargetsList');
    if (!list) return;
    const mode = document.getElementById('softwareInstallTargetMode')?.value || 'selected';
    const groupSelect = document.getElementById('softwareInstallGroupSelect');
    if (groupSelect) groupSelect.classList.toggle('hidden', mode !== 'group');
    const q = (document.getElementById('softwareTargetSearch')?.value || '').trim().toLowerCase();
    const hosts = (window.WinhubHosts || []).filter(host => {
        if ((host.approval_status || 'Approved') !== 'Approved') return false;
        const haystack = [host.name, host.ip, host.os_type, host.agent_version].join(' ').toLowerCase();
        return !q || haystack.includes(q);
    });
    list.innerHTML = hosts.map(host => {
        const checked = softwareSelectedHostIds.has(host.id) ? 'checked' : '';
        return `<label class="flex items-center gap-3 p-3 rounded-xl border border-slate-200 bg-slate-50 hover:bg-white transition-all">
            <input type="checkbox" value="${escapeHtml(host.id)}" ${checked} onchange="toggleSoftwareTargetSelection('${escapeHtml(host.id)}', this.checked)" class="w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500">
            <span class="min-w-0 flex-1">
                <span class="block text-xs font-black text-slate-700 truncate">${escapeHtml(host.name || host.id)}</span>
                <span class="block text-[10px] font-bold text-slate-400 truncate">${escapeHtml(host.ip || '-')} / ${escapeHtml(host.os_type || 'Windows')} / ${escapeHtml(host.agent_version || 'unknown')}</span>
            </span>
        </label>`;
    }).join('') || '<div class="p-4 rounded-xl bg-slate-50 text-xs font-bold text-slate-400">No target nodes found.</div>';
    updateSoftwareSelectedCount();
}

function submitSoftwareForm(form, url, method, onSuccess, onProgress=null, onEnd=null) {
    syncSoftwareCodeEditors(form);
    const formData = new FormData(form);
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.onload = async () => {
        let data = {};
        try { data = xhr.responseText ? JSON.parse(xhr.responseText) : {}; } catch(e) { data = { message: xhr.responseText }; }
        if (xhr.status < 200 || xhr.status >= 300 || !data.success) {
            const sizeHint = xhr.status === 413 ? ' File is too large for current server/nginx upload limit.' : '';
            alert((data.message || `Software save failed with HTTP ${xhr.status}.`) + sizeHint);
            return;
        }
        await onSuccess(data);
    };
    xhr.onerror = () => alert('Software save failed: network error.');
    if (onProgress) xhr.upload.onprogress = onProgress;
    if (onEnd) xhr.onloadend = onEnd;
    xhr.send(formData);
    return xhr;
}

async function uploadSoftwarePackage(event) {
    event.preventDefault();
    const form = document.getElementById('softwarePackageForm');
    if (!form) return;
    const progressWrap = document.getElementById('softwarePackageProgressWrap');
    const progressBar = document.getElementById('softwarePackageProgressBar');
    const progressText = document.getElementById('softwarePackageProgressText');
    if (progressWrap) progressWrap.classList.remove('hidden');
    if (progressText) progressText.classList.remove('hidden');
    if (progressBar) progressBar.style.width = '0%';
    if (progressText) progressText.innerText = '0%';
    submitSoftwareForm(form, '/api/infrastructure/software-packages', 'POST', async (data) => {
        if (progressBar) progressBar.style.width = '100%';
        if (progressText) progressText.innerText = '100%';
        form.reset();
        softwareSelectedPackageId = data.package?.id || softwareSelectedPackageId;
        switchSoftwareTab('library');
        await loadSoftwareRegistry();
    }, (event) => {
        if (!event.lengthComputable) return;
        const pct = Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100)));
        if (progressBar) progressBar.style.width = pct + '%';
        if (progressText) progressText.innerText = pct + '%';
    }, () => setTimeout(() => {
        if (progressWrap) progressWrap.classList.add('hidden');
        if (progressText) progressText.classList.add('hidden');
    }, 1200));
}

function fillSoftwareForm(form, pkg) {
    if (!form || !pkg) return;
    ['name', 'version', 'vendor', 'category', 'package_type', 'architecture', 'external_url', 'sha256', 'install_command', 'user_install_command', 'uninstall_command', 'detection_type', 'detection_value', 'expected_exit_codes', 'notes'].forEach(name => {
        const el = form.elements[name];
        if (el) {
            el.value = pkg[name] || '';
            const editor = softwareCodeEditors.get(el);
            if (editor) editor.setValue(el.value || '');
        }
    });
    if (form.elements.package_id) form.elements.package_id.value = pkg.id;
}

function openSoftwareEditModal(id) {
    const pkg = getSoftwarePackage(id);
    if (!pkg) return;
    const modal = document.getElementById('softwareEditModal');
    const form = document.getElementById('softwareEditForm');
    const hint = document.getElementById('softwareEditHint');
    const fileInfo = document.getElementById('softwareEditFileInfo');
    const removeFile = document.getElementById('softwareEditRemoveFile');
    initSoftwareCodeEditors(form);
    fillSoftwareForm(form, pkg);
    if (removeFile) removeFile.value = '0';
    if (hint) hint.innerText = softwarePackageLabel(pkg);
    if (fileInfo) fileInfo.innerText = pkg.filename ? `Current file: ${pkg.original_filename || pkg.filename} / SHA256 ${pkg.sha256 || '-'}` : `External URL: ${pkg.external_url || '-'}`;
    if (modal) modal.classList.remove('hidden');
    document.body.classList.add('overflow-hidden');
    setTimeout(() => initSoftwareCodeEditors(form), 80);
}

function closeSoftwareEditModal() {
    destroySoftwareCodeEditors(document.getElementById('softwareEditForm'));
    const modal = document.getElementById('softwareEditModal');
    if (modal) modal.classList.add('hidden');
    document.body.classList.remove('overflow-hidden');
}

function markSoftwareFileForRemoval() {
    const removeFile = document.getElementById('softwareEditRemoveFile');
    const fileInfo = document.getElementById('softwareEditFileInfo');
    if (removeFile) removeFile.value = '1';
    if (fileInfo) fileInfo.innerText = 'Current uploaded file will be removed when you save. Provide an external URL or select a replacement file.';
}

async function submitSoftwareEdit(event) {
    event.preventDefault();
    const form = document.getElementById('softwareEditForm');
    const packageId = form?.elements.package_id?.value;
    if (!form || !packageId) return;
    submitSoftwareForm(form, `/api/infrastructure/software-packages/${encodeURIComponent(packageId)}`, 'PUT', async (data) => {
        softwareSelectedPackageId = data.package?.id || packageId;
        closeSoftwareEditModal();
        await loadSoftwareRegistry();
    });
}

async function deleteSoftwarePackage(id) {
    const pkg = getSoftwarePackage(id);
    if (!pkg || !confirm(`Delete ${softwarePackageLabel(pkg)}? Uploaded file will also be removed.`)) return;
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    const res = await fetch(`/api/infrastructure/software-packages/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: csrfToken ? {'X-CSRF-Token': csrfToken} : {}
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) return alert(data.message || 'Software package delete failed.');
    if (softwareSelectedPackageId === id) softwareSelectedPackageId = null;
    await loadSoftwareRegistry();
}

async function runSoftwareInstall() {
    const packageId = document.getElementById('softwareInstallPackageId')?.value;
    const pkg = getSoftwarePackage(packageId);
    if (!packageId || !pkg) return alert('Select a software package first.');
    const mode = document.getElementById('softwareInstallTargetMode')?.value || 'selected';
    const selectedIds = Array.from(softwareSelectedHostIds);
    const operation = document.getElementById('softwareOperation')?.value || 'install';
    const installScope = document.getElementById('softwareInstallScope')?.value || 'all';
    const userLoginsRaw = document.getElementById('softwareUserLogins')?.value || '';
    const userLogins = userLoginsRaw.split(/[\n,;]+/).map(item => item.trim()).filter(Boolean);
    if (mode === 'selected' && selectedIds.length === 0) return alert('Check at least one node first.');
    if (operation === 'uninstall' && !pkg.uninstall_command) return alert('This package has no uninstall command. Edit the package and add one first.');
    if (operation === 'install' && installScope === 'users') {
        if (!pkg.user_install_command) return alert('This package has no specific-user install recipe. Edit the package and add one first.');
        if (userLogins.length === 0) return alert('Specify at least one user login.');
    }
    if (installScope === 'users' && userLogins.length === 0) return alert('Specify at least one user login.');
    if (!confirm(`Dispatch ${operation} for ${softwarePackageLabel(pkg)}?`)) return;
    const payload = {
        package_id: packageId,
        operation,
        target_mode: mode,
        target_ids: mode === 'selected' ? selectedIds : [],
        group_id: document.getElementById('softwareInstallGroupSelect')?.value || '',
        install_scope: installScope,
        user_logins: userLogins
    };
    const res = await fetch('/api/infrastructure/software/install', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(document.querySelector('meta[name="csrf-token"]')?.content ? {'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content} : {})
        },
        body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) return alert(data.message || 'Software install dispatch failed.');
    alert(`Software install queued for ${data.targets} host(s).`);
    switchView('queue');
}

function toggleDeploymentAiReport() {
    const enabled = document.getElementById('depAiReportToggle')?.checked || false;
    document.getElementById('depAiReportSettings')?.classList.toggle('hidden', !enabled);
    const reportTemplate = document.getElementById('depReportTemplate');
    if (enabled && reportTemplate) reportTemplate.value = '';
}

async function submitDeployment() {
    const btn = document.getElementById('btnDeploy');
    const oldText = btn.innerText;
    btn.disabled = true; btn.innerText = "Dispatching...";

    const action = document.getElementById('depAction').value;
    const targetType = document.getElementById('depType').value;
    const reportTemplateId = document.getElementById('depReportTemplate')?.value || null;
    const aiEnabled = document.getElementById('depAiReportToggle')?.checked || false;
    const aiPrompt = document.getElementById('depAiReportPrompt')?.value?.trim() || '';
    if (aiEnabled && !aiPrompt) {
        btn.disabled = false; btn.innerText = oldText;
        document.getElementById('depAiReportPrompt')?.focus();
        return alert('Describe how AI should format the report.');
    }

    const tplVars = collectVariableInputs('.tpl-var-input');

    const autoConfluence = collectAutoConfluenceSettings();
    const data = {
        title: document.getElementById('depTitle').value || "Manual Action",
        target_type: targetType,
        action,
        template_id: selectedTemplateId,
        report_template_id: reportTemplateId,
        ai_report: {enabled: aiEnabled, prompt: aiPrompt},
        timeout_minutes: parseInt(document.getElementById('depTimeoutMinutes')?.value || '0', 10) || 0,
        variables: tplVars,
        auto_email_toggle: document.getElementById('depAutoEmailToggle')?.checked || false,
        auto_email_sender: document.getElementById('depAutoEmailSender')?.value || '',
        auto_email_recipients: document.getElementById('depAutoEmailRecipients')?.value || '',
        auto_email_use_gpg: document.getElementById('depAutoEmailUseGpg')?.checked !== false,
        auto_confluence_toggle: autoConfluence.enabled,
        auto_confluence_profile: autoConfluence.profile,
        auto_confluence_page_id: autoConfluence.page_id,
        auto_confluence_title: autoConfluence.title,
        auto_confluence_body_format: autoConfluence.body_format,
        auto_confluence_note: autoConfluence.note
    };

    if (targetType === 'hosts') {
        try {
            data.target_ids = JSON.parse(document.getElementById('depTargetHostIds').value);
        } catch(e) { data.target_ids = []; }
        if(data.target_ids.length === 0) { btn.disabled=false; btn.innerText=oldText; return alert("Please select at least one host."); }
    } else {
        data.target_id = document.getElementById('depTargetGroup').value;
    }

    if (action === 'run_script') {
        data.payload = { script: getPayloadValue() };
        const checkedRadio = document.querySelector('input[name="depTemplateType"]:checked');
        if(checkedRadio && checkedRadio.value === 'metric') data.template_type = 'metric';
    }

    try {
        const res = await fetch('/api/infrastructure/tasks/create', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        const resData = await res.json();
        if(res.ok && resData.success) { switchView('queue'); resetWorkspace(); }
        else { alert("Error: " + (resData.message || "Failed to create task")); }
    } catch(e) { alert("Server error."); }
    finally { btn.disabled = false; btn.innerText = oldText; }
}

// --- HOST MODAL TABS ---
function switchHostTab(tab) {
    ['info', 'items', 'history', 'telemetry'].forEach(t => {
        const content = document.getElementById('htab_' + t);
        const btn = document.getElementById('htabBtn_' + t);
        if(content) content.classList.add('hidden');
        if(btn) btn.className = "px-4 py-3 font-bold text-sm text-slate-500 border-b-2 border-transparent hover:text-slate-800 transition-colors flex items-center gap-2 whitespace-nowrap";
    });

    const activeContent = document.getElementById('htab_' + tab);
    const activeBtn = document.getElementById('htabBtn_' + tab);

    if(activeContent) {
        activeContent.classList.remove('hidden');
        if(tab !== 'info') activeContent.classList.add('flex');
    }
    if(activeBtn) {
        activeBtn.className = "px-4 py-3 font-bold text-sm text-indigo-600 border-b-2 border-indigo-600 transition-colors flex items-center gap-2 whitespace-nowrap";
    }

    if(tab === 'items' && currentViewedHostId) loadHostMetrics();
    if(tab === 'telemetry' && currentViewedHostId) loadTelemetry(currentViewedHostId, 1);
}

function switchNodeTab(tab, save = true) {
    if (!['approved', 'review'].includes(tab)) tab = 'approved';
    if (save) {
        localStorage.setItem(infraStateKeys.nodeTab, tab);
        writeInfraState(scopedInfraState('hosts', { nodeTab: tab }));
    }
    const panels = {
        approved: document.getElementById('nodesApprovedPanel'),
        review: document.getElementById('nodesReviewPanel'),
    };
    const buttons = {
        approved: document.getElementById('nodeTab-approved'),
        review: document.getElementById('nodeTab-review'),
    };
    Object.entries(panels).forEach(([key, panel]) => {
        if (!panel) return;
        panel.classList.toggle('hidden', tab !== key);
    });
    Object.values(buttons).forEach(btn => {
        if (!btn) return;
        btn.className = "node-tab-btn inline-flex items-center px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-amber-700";
    });
    const active = buttons[tab] || buttons.approved;
    if (active) active.className = "node-tab-btn inline-flex items-center px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm";
    if (tab === 'review') switchReviewTab(infraUrlParam('reviewTab') || localStorage.getItem(infraStateKeys.reviewTab) || 'pending', false);
    if (tab === 'approved') loadFleetCenter();
}

function switchReviewTab(tab, save = true) {
    if (!['pending', 'duplicates', 'rejected'].includes(tab)) tab = 'pending';
    if (save) {
        localStorage.setItem(infraStateKeys.reviewTab, tab);
        writeInfraState(scopedInfraState('hosts', { nodeTab: 'review', reviewTab: tab }));
    }
    const panels = {
        pending: document.getElementById('nodesPendingPanel'),
        duplicates: document.getElementById('nodesApprovedDuplicatesPanel'),
        rejected: document.getElementById('nodesRejectedPanel'),
    };
    Object.entries(panels).forEach(([key, panel]) => {
        if (panel) panel.classList.toggle('hidden', key !== tab);
    });
    document.querySelectorAll('.review-tab-btn').forEach(btn => {
        btn.className = "review-tab-btn inline-flex items-center px-4 py-2 rounded-xl text-[10px] font-black uppercase";
        btn.classList.remove('is-active');
    });
    const active = document.getElementById('reviewTab-' + tab);
    if (active) active.classList.add('is-active');
    updatePendingApprovalCount();
    updateRejectedSelectionCount();
    updateDuplicateSelectionCount();
}

function reloadKeepingNodeContext(tab = null) {
    localStorage.setItem(infraStateKeys.view, 'hosts');
    localStorage.setItem(infraStateKeys.nodeTab, tab || localStorage.getItem(infraStateKeys.nodeTab) || 'review');
    location.reload();
}

function pendingApprovalSelection() {
    return Array.from(document.querySelectorAll('.pending-approval-cb:checked')).map(cb => cb.value);
}

function updatePendingApprovalCount() {
    const selected = pendingApprovalSelection().length;
    const counter = document.getElementById('pendingApprovalSelectedCount');
    if (counter) counter.innerText = selected;
}

function toggleAllPendingApprovals(source) {
    document.querySelectorAll('.pending-approval-cb').forEach(cb => {
        cb.checked = source.checked;
    });
    updatePendingApprovalCount();
}

function rejectedSelection() {
    return Array.from(document.querySelectorAll('.rejected-host-cb:checked')).map(cb => cb.value);
}

function updateRejectedSelectionCount() {
    const counter = document.getElementById('rejectedSelectedCount');
    if (counter) counter.innerText = rejectedSelection().length;
}

function toggleAllRejectedHosts(source) {
    document.querySelectorAll('.rejected-host-cb').forEach(cb => {
        cb.checked = source.checked;
    });
    updateRejectedSelectionCount();
}

async function approveSelectedRejected() {
    const ids = rejectedSelection();
    if (!ids.length) return alert('Select rejected hosts first.');
    if (!confirm(`Approve ${ids.length} rejected hosts?`)) return;
    for (const id of ids) {
        await fetch('/api/infrastructure/host/' + encodeURIComponent(id) + '/approval', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({status: 'Approved'})
        });
    }
    reloadKeepingNodeContext('review');
}

async function deleteSelectedRejected() {
    const ids = rejectedSelection();
    if (!ids.length) return alert('Select rejected hosts first.');
    if (!confirm(`Delete ${ids.length} rejected hosts permanently?`)) return;
    for (const id of ids) {
        await fetch('/api/infrastructure/host/' + encodeURIComponent(id), { method: 'DELETE' });
    }
    reloadKeepingNodeContext('review');
}

function duplicateSelection() {
    return Array.from(document.querySelectorAll('.duplicate-pair-cb:checked')).map(cb => cb.value);
}

function updateDuplicateSelectionCount() {
    const counter = document.getElementById('duplicateSelectedCount');
    if (counter) counter.innerText = duplicateSelection().length;
}

function toggleAllDuplicatePairs(source) {
    document.querySelectorAll('.duplicate-pair-cb').forEach(cb => {
        cb.checked = source.checked;
    });
    updateDuplicateSelectionCount();
}

async function mergeSelectedDuplicates(preference) {
    const pairs = duplicateSelection();
    if (!pairs.length) return alert('Select duplicate pairs first.');
    const label = preference === 'second' ? 'second' : 'first';
    if (!confirm(`Resolve ${pairs.length} duplicate pairs and keep the ${label} record in each selected row?`)) return;
    for (const pair of pairs) {
        const [first, second] = pair.split('|');
        if (!first || !second) continue;
        const keepId = preference === 'second' ? second : first;
        const removeId = preference === 'second' ? first : second;
        const res = await fetch('/api/infrastructure/host/merge-duplicate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({keep_id: keepId, remove_id: removeId})
        });
        if (!res.ok) {
            alert('One of the duplicate merges failed. Refreshing review center.');
            break;
        }
    }
    reloadKeepingNodeContext('review');
}

async function acceptSelectedDuplicatePairs() {
    const pairs = duplicateSelection();
    if (!pairs.length) return alert('Select duplicate pairs first.');
    if (!confirm(`Keep both records for ${pairs.length} selected duplicate pair(s)? They will remain approved and will no longer be shown as identity duplicates.`)) return;
    for (const pair of pairs) {
        const [first, second] = pair.split('|');
        if (!first || !second) continue;
        const res = await fetch('/api/infrastructure/host/duplicate-exception', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                left_id: first,
                right_id: second,
                reason: 'Accepted as distinct cloned servers'
            })
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            alert(data.message || 'One of the duplicate exceptions failed. Refreshing review center.');
            break;
        }
    }
    reloadKeepingNodeContext('review');
}

async function approveSelectedPending() {
    const hostIds = pendingApprovalSelection();
    if (!hostIds.length) {
        alert('Select at least one pending agent.');
        return;
    }
    if (!confirm(`Approve ${hostIds.length} selected pending agent(s)?`)) return;
    await bulkApprovePending({host_ids: hostIds});
}

async function approveAllPending() {
    if (!confirm('Approve all pending agents?')) return;
    await bulkApprovePending({all_pending: true});
}

async function bulkApprovePending(payload) {
    const res = await fetch('/api/infrastructure/hosts/approval', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({...payload, status: 'Approved'})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
        alert('Approval failed: ' + (data.message || res.statusText));
        return;
    }
    location.reload();
}

async function loadHostMetrics() {
    const tbody = document.getElementById('mItemsBody');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="3" class="p-10 text-center text-slate-400 font-bold text-sm">Loading metrics...</td></tr>';
    try {
        const res = await fetch('/api/infrastructure/host/' + currentViewedHostId + '/metrics');
        const result = await res.json();
        if(result.success && result.data.length > 0) {
            tbody.innerHTML = result.data.map(m => `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-8 py-5 font-black text-slate-700">${escapeHtml(m.item_name)}</td>
                    <td class="px-8 py-5"><span class="bg-purple-50 text-purple-700 font-mono text-sm px-3 py-1 rounded-lg border border-purple-100">${escapeHtml(m.last_value || 'No data')}</span></td>
                    <td class="px-8 py-5 text-right text-xs font-bold text-slate-400">${escapeHtml(m.last_updated)}</td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="3" class="p-16 text-center text-slate-300 font-black italic uppercase tracking-widest text-[10px]">No custom items collected for this host</td></tr>';
        }
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="3" class="p-10 text-center text-rose-400 font-bold text-sm">Failed to load metrics</td></tr>';
    }
}

async function loadTelemetry(hostId, days) {
    document.querySelectorAll('.tel-filter-btn').forEach(btn => {
        btn.classList.remove('bg-white', 'text-indigo-600', 'shadow-sm');
        btn.classList.add('text-slate-500');
    });
    const activeBtn = document.getElementById('telFilter' + days);
    if(activeBtn) {
        activeBtn.classList.remove('text-slate-500');
        activeBtn.classList.add('bg-white', 'text-indigo-600', 'shadow-sm');
    }

    const tLoading = document.getElementById('telemetryLoading');
    const dLoading = document.getElementById('diskLoading');
    const aLoading = document.getElementById('activityLoading');

    if(tLoading) { tLoading.innerText = "Loading metrics..."; tLoading.classList.remove('hidden'); }
    if(dLoading) { dLoading.innerText = "Loading disk metrics..."; dLoading.classList.remove('hidden'); }
    if(aLoading) { aLoading.innerText = "Loading activity timeline..."; aLoading.classList.remove('hidden'); }
    loadIpHistory(hostId, Math.max(days, 30));

    try {
        const res = await fetch(`/api/infrastructure/host/${hostId}/telemetry?days=${days}`);
        const json = await res.json();

        if(json.success && Array.isArray(json.data) && json.data.length > 0) {
            if(tLoading) tLoading.classList.add('hidden');
            if(dLoading) dLoading.classList.add('hidden');
            if(aLoading) aLoading.classList.add('hidden');

            const labels = json.data.map(d => d.time);
            const cpu = json.data.map(d => d.cpu);
            const ram = json.data.map(d => d.ram);
            const disk = json.data.map(d => d.disk);

            if(teleChart) { teleChart.destroy(); teleChart = null; }
            const ctxTele = document.getElementById('telemetryChart');
            if (ctxTele && typeof Chart !== 'undefined') {
                teleChart = new Chart(ctxTele.getContext('2d'), {
                    type: 'line',
                    data: { labels: labels, datasets: [ { label: 'CPU Usage (%)', data: cpu, borderColor: '#4f46e5', backgroundColor: '#4f46e522', fill: true, tension: 0.4 }, { label: 'RAM Usage (%)', data: ram, borderColor: '#10b981', backgroundColor: '#10b98122', fill: true, tension: 0.4 } ] },
                    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { y: { beginAtZero: true, max: 100 } }, plugins: { legend: { position: 'top' } } }
                });
            }

            if(diskChart) { diskChart.destroy(); diskChart = null; }
            const ctxDisk = document.getElementById('diskChart');
            if (ctxDisk && typeof Chart !== 'undefined') {
                diskChart = new Chart(ctxDisk.getContext('2d'), {
                    type: 'line',
                    data: { labels: labels, datasets: [ { label: 'Free Space (GB)', data: disk, borderColor: '#f59e0b', backgroundColor: '#f59e0b22', fill: true, tension: 0.4 } ] },
                    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { y: { beginAtZero: true } }, plugins: { legend: { position: 'top' } } }
                });
            }

            renderActivityChart(json.activity_segments || []);
        } else {
            if(tLoading) { tLoading.innerText = "No telemetry data recorded for this period."; tLoading.classList.remove('hidden'); }
            if(dLoading) { dLoading.innerText = "No disk data recorded for this period."; dLoading.classList.remove('hidden'); }
            if(aLoading) { aLoading.innerText = "No activity data recorded for this period."; aLoading.classList.remove('hidden'); }
            if(teleChart) teleChart.destroy();
            if(diskChart) diskChart.destroy();
            if(activityChart) activityChart.destroy();
            renderActivitySegmentsList([]);
        }
    } catch(e) {
        if(tLoading) { tLoading.innerText = "Failed to load telemetry."; tLoading.classList.remove('hidden'); }
        if(dLoading) { dLoading.innerText = "Failed to load disk telemetry."; dLoading.classList.remove('hidden'); }
        if(aLoading) { aLoading.innerText = "Failed to load activity timeline."; aLoading.classList.remove('hidden'); }
        renderActivitySegmentsList([]);
    }
}

function formatActivityAxis(value) {
    const date = new Date(value);
    if(Number.isNaN(date.getTime())) return '';
    return date.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' });
}

function renderActivitySegmentsList(segments) {
    const list = document.getElementById('activitySegmentsList');
    if(!list) return;
    if(!Array.isArray(segments) || segments.length === 0) {
        list.innerHTML = '<div class="p-4 text-center text-slate-400 font-bold">No activity segments for this period.</div>';
        return;
    }
    list.innerHTML = segments.slice(-24).reverse().map(segment => {
        const online = segment.state === 'online';
        return `
            <div class="flex items-center justify-between gap-4 p-3 border-b border-slate-100 last:border-b-0">
                <div class="min-w-0">
                    <div class="text-xs font-black ${online ? 'text-emerald-700' : 'text-slate-500'} uppercase">${online ? 'Online' : 'Offline'}</div>
                    <div class="text-[11px] font-bold text-slate-500 mt-1">${escapeHtml(segment.start || '-')} - ${escapeHtml(segment.end || '-')}</div>
                </div>
                <div class="text-right shrink-0">
                    <div class="font-mono text-xs font-black text-slate-800">${online ? escapeHtml(segment.ip || '-') : '-'}</div>
                    <div class="text-[10px] font-black text-slate-400 uppercase mt-1">${Number(segment.duration_minutes || 0)} min</div>
                </div>
            </div>
        `;
    }).join('');
}

function renderActivityChart(segments) {
    if(activityChart) { activityChart.destroy(); activityChart = null; }
    const ctxActivity = document.getElementById('activityChart');
    if(!ctxActivity || typeof Chart === 'undefined') return;

    const validSegments = (segments || []).filter(segment => Number.isFinite(Number(segment.start_ms)) && Number.isFinite(Number(segment.end_ms)) && Number(segment.end_ms) > Number(segment.start_ms));
    renderActivitySegmentsList(validSegments);
    if(validSegments.length === 0) return;

    activityChart = new Chart(ctxActivity.getContext('2d'), {
        type: 'bar',
        data: {
            datasets: [{
                label: 'Activity',
                data: validSegments.map(segment => ({
                    x: [Number(segment.start_ms), Number(segment.end_ms)],
                    y: 'Activity',
                    state: segment.state,
                    ip: segment.ip,
                    start: segment.start,
                    end: segment.end,
                    duration: segment.duration_minutes
                })),
                backgroundColor: context => context.raw && context.raw.state === 'online' ? '#10b981' : '#cbd5e1',
                borderColor: context => context.raw && context.raw.state === 'online' ? '#047857' : '#94a3b8',
                borderWidth: 1,
                borderRadius: 8,
                barThickness: 34
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    type: 'linear',
                    ticks: { callback: value => formatActivityAxis(value), maxRotation: 0 },
                    grid: { color: '#e2e8f0' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#334155', font: { weight: '700' } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: context => {
                            const item = context.raw || {};
                            const state = item.state === 'online' ? 'Online' : 'Offline';
                            const ip = item.state === 'online' ? ` | IP: ${item.ip || '-'}` : '';
                            return `${state}${ip} | ${item.start || '-'} - ${item.end || '-'} | ${item.duration || 0} min`;
                        }
                    }
                }
            }
        }
    });
}

async function loadIpHistory(hostId, days = 30) {
    const box = document.getElementById('ipHistoryList');
    if(!box) return;
    box.innerHTML = '<div class="p-6 text-center text-slate-400 font-bold">Loading connection history...</div>';
    try {
        const res = await fetch(`/api/infrastructure/host/${hostId}/ip-history?days=${days}`);
        const json = await res.json();
        const rows = Array.isArray(json.data) ? json.data : [];
        if(!json.success || rows.length === 0) {
            box.innerHTML = '<div class="p-6 text-center text-slate-400 font-bold">No connection IP changes recorded yet.</div>';
            return;
        }
        box.innerHTML = rows.map(row => `
            <div class="p-4 flex items-center justify-between gap-4 hover:bg-slate-50">
                <div>
                    <div class="font-mono text-slate-800 font-black">${escapeHtml(row.ip || '-')}</div>
                    <div class="text-[10px] font-bold text-slate-400 uppercase mt-1">${escapeHtml(row.source || 'agent')}</div>
                </div>
                <div class="text-[10px] font-bold text-slate-400 text-right">${escapeHtml(row.time || '-')}</div>
            </div>
        `).join('');
    } catch(e) {
        box.innerHTML = '<div class="p-6 text-center text-rose-400 font-bold">Failed to load connection history.</div>';
    }
}

// --- QUEUE & HISTORY ---
function restoreQueueState() {
    queueTypeFilter = readInfraState('queueType', infraStateKeys.queueType, 'ALL') || 'ALL';
    queueStatusFilter = readInfraState('queueStatus', infraStateKeys.queueStatus, 'ALL') || 'ALL';
    const searchEl = document.getElementById('queueSearch');
    if (searchEl) searchEl.value = readInfraState('queueSearch', infraStateKeys.queueSearch, '');
    const userEl = document.getElementById('qFilterUser');
    if (userEl) userEl.value = readInfraState('queueUser', infraStateKeys.queueUser, '');
    const contentEl = document.getElementById('queueContent');
    if (contentEl) contentEl.value = readInfraState('queueContent', infraStateKeys.queueContent, '');
    const dateFromEl = document.getElementById('queueDateFrom');
    if (dateFromEl) dateFromEl.value = readInfraState('queueDateFrom', infraStateKeys.queueDateFrom, '');
    const dateToEl = document.getElementById('queueDateTo');
    if (dateToEl) dateToEl.value = readInfraState('queueDateTo', infraStateKeys.queueDateTo, '');
    renderQueueFilterButtons();
}

function persistQueueState() {
    const search = (document.getElementById('queueSearch')?.value || '').trim();
    const user = document.getElementById('qFilterUser')?.value || '';
    const content = (document.getElementById('queueContent')?.value || '').trim();
    const dateFrom = document.getElementById('queueDateFrom')?.value || '';
    const dateTo = document.getElementById('queueDateTo')?.value || '';
    localStorage.setItem(infraStateKeys.queueType, queueTypeFilter || 'ALL');
    localStorage.setItem(infraStateKeys.queueStatus, queueStatusFilter || 'ALL');
    localStorage.setItem(infraStateKeys.queueSearch, search);
    localStorage.setItem(infraStateKeys.queueUser, user);
    localStorage.setItem(infraStateKeys.queueContent, content);
    localStorage.setItem(infraStateKeys.queueDateFrom, dateFrom);
    localStorage.setItem(infraStateKeys.queueDateTo, dateTo);
    writeInfraState(scopedInfraState('queue', {
        queueType: queueTypeFilter === 'ALL' ? null : queueTypeFilter,
        queueStatus: queueStatusFilter === 'ALL' ? null : queueStatusFilter,
        queueSearch: search || null,
        queueUser: user || null,
        queueContent: content || null,
        queueDateFrom: dateFrom || null,
        queueDateTo: dateTo || null,
    }));
}

function renderQueueFilterButtons() {
    document.querySelectorAll('.q-type-btn').forEach(btn => {
        const active = (btn.getAttribute('onclick') || '').includes(`'${queueTypeFilter || 'ALL'}'`);
        btn.classList.toggle('bg-white', active);
        btn.classList.toggle('text-indigo-600', active);
        btn.classList.toggle('shadow-sm', active);
        btn.classList.toggle('text-slate-500', !active);
    });
    document.querySelectorAll('.q-status-btn').forEach(btn => {
        const active = (btn.getAttribute('onclick') || '').includes(`'${queueStatusFilter || 'ALL'}'`);
        btn.classList.toggle('bg-white', active);
        btn.classList.toggle('text-indigo-600', active);
        btn.classList.toggle('shadow-sm', active);
        btn.classList.toggle('text-slate-500', !active);
    });
}

function setQueueTypeFilter(type, btn) {
    queueTypeFilter = type;
    renderQueueFilterButtons();
    persistQueueState();
    loadQueue(1);
}

function setQueueStatusFilter(status, btn) {
    queueStatusFilter = status || 'ALL';
    renderQueueFilterButtons();
    persistQueueState();
    loadQueue(1);
}

async function loadQueue(requestedPage = queuePage) {
    try {
        queuePage = Math.max(1, Number(requestedPage) || 1);
        persistQueueState();
        const params = new URLSearchParams({page: String(queuePage), page_size: '20'});
        const q = (document.getElementById('queueSearch')?.value || '').trim();
        const content = (document.getElementById('queueContent')?.value || '').trim();
        const actor = document.getElementById('qFilterUser')?.value || readInfraState('queueUser', infraStateKeys.queueUser, '');
        const dateFrom = document.getElementById('queueDateFrom')?.value || '';
        const dateTo = document.getElementById('queueDateTo')?.value || '';
        if (q) params.set('q', q);
        if (content) params.set('content', content);
        if (actor) params.set('actor', actor);
        if (dateFrom) params.set('date_from', dateFrom);
        if (dateTo) params.set('date_to', dateTo);
        if (queueTypeFilter !== 'ALL') params.set('source', queueTypeFilter);
        if (queueStatusFilter !== 'ALL') params.set('status', queueStatusFilter);
        const res = await fetch('/api/infrastructure/tasks/all?' + params.toString());
        const data = await res.json();
        if (!data.success) return;
        allQueueJobs = data.jobs;
        queuePagination = data.pagination || {page: queuePage, total: allQueueJobs.length, has_more: false};

        const users = new Set((data.filters?.actors || []).concat(allQueueJobs.map(j => j.created_by)));
        const uSelect = document.getElementById('qFilterUser');
        if(uSelect) {
            const selectedUser = actor;
            uSelect.innerHTML = '<option value="">All Users</option>';
            users.forEach(u => { if(u) uSelect.add(new Option(u, u)); });
            if (!users.has('System')) uSelect.add(new Option('System (Auto)', 'System'));
            uSelect.value = selectedUser;
        }

        renderQueue();
        const t = document.getElementById('statQTotal');
        const p = document.getElementById('statQPending');
        if(t) t.innerText = queuePagination.total ?? allQueueJobs.length;
        if(p) p.innerText = allQueueJobs.filter(j => j.status === 'Pending' || j.status === 'Running' || j.status === 'Scheduled').length;
        const pageInfo = document.getElementById('queuePageInfo');
        if(pageInfo) pageInfo.innerText = `Page ${queuePagination.page || queuePage} · ${queuePagination.total || 0} matching jobs`;
        const prev = document.getElementById('queuePrev');
        const next = document.getElementById('queueNext');
        if(prev) prev.disabled = queuePage <= 1;
        if(next) next.disabled = !queuePagination.has_more;
    } catch(e) { console.error("Error loading queue:", e); }
}

function changeQueuePage(delta) {
    const nextPage = queuePage + Number(delta || 0);
    if (nextPage < 1 || (delta > 0 && !queuePagination.has_more)) return;
    loadQueue(nextPage);
}

function renderQueue() {
    const tbody = document.getElementById('queueBody');
    if(!tbody) return;
    persistQueueState();
    renderQueueFilterButtons();

    tbody.innerHTML = allQueueJobs.map(j => {
        const statusStr = j.status || 'Pending';
        let cls = statusStr === 'Pending' ? 'bg-amber-100 text-amber-700' : (statusStr === 'Success' ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700');
        if (statusStr === 'Scheduled') cls = 'bg-sky-100 text-sky-700';
        if (statusStr === 'Cancelled') cls = 'bg-slate-100 text-slate-500';
        if (j.error > 0 && j.success > 0) cls = 'bg-orange-100 text-orange-700';

        const hasActionColumn = !!window.WinhubIsAdmin || infraPermissions.run_tasks;
        let actionBtn = hasActionColumn ? '<td class="px-10 py-4 text-right"></td>' : '';
        if(j.planned && hasActionColumn) {
            actionBtn = `<td class="px-10 py-4 text-right">
                <div class="flex justify-end gap-2">
                    ${infraPermissions.run_tasks && j.rollout_id ? `<button onclick="event.stopPropagation(); cancelScheduledRollout('${escapeInlineJs(j.rollout_id)}')" class="queue-action-btn p-3 border rounded-2xl transition-colors shadow-sm" title="Cancel scheduled rollout waves"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10 10l4 4m0-4l-4 4M12 22a10 10 0 100-20 10 10 0 000 20z" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                </div>
            </td>`;
        } else if(!j.planned && hasActionColumn) {
            actionBtn = `<td class="px-10 py-4 text-right">
                <div class="flex justify-end gap-2">
                    ${infraPermissions.run_tasks && j.error > 0 ? `<button onclick="event.stopPropagation(); retryFailedJob('${escapeInlineJs(j.job_id)}')" class="queue-action-btn p-3 border rounded-2xl transition-colors shadow-sm" title="Retry failed hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M4 4v6h6M20 20v-6h-6M5 19A9 9 0 0119 5l1 1M19 5A9 9 0 005 19l-1-1" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${infraPermissions.run_tasks && (j.pending + j.running) > 0 && (j.success + j.error) > 0 ? `<button onclick="event.stopPropagation(); finalizeJobReport('${escapeInlineJs(j.job_id)}')" class="queue-action-btn p-3 border rounded-2xl transition-colors shadow-sm" title="Finalize report without active hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M9 12l2 2 4-5M4 20h16M5 4h14v12H5z" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${infraPermissions.run_tasks && (j.pending + j.running) > 0 ? `<button onclick="event.stopPropagation(); cancelPendingJob('${escapeInlineJs(j.job_id)}')" class="queue-action-btn p-3 border rounded-2xl transition-colors shadow-sm" title="Cancel pending/running hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10 10l4 4m0-4l-4 4M12 22a10 10 0 100-20 10 10 0 000 20z" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${window.WinhubIsAdmin ? `<button onclick="event.stopPropagation(); deleteJob('${escapeInlineJs(j.job_id)}')" class="queue-action-btn p-3 border rounded-2xl transition-colors shadow-sm" title="Delete job"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" stroke-width="2.5"/></svg></button>` : ''}
                </div>
            </td>`;
        }

        return `<tr class="queue-job-row cursor-pointer transition-colors" onclick="viewJobDetails('${escapeInlineJs(j.job_id)}')">
                <td class="px-10 py-5 font-black text-slate-800 text-lg">
                    ${escapeHtml(j.title || 'Untitled')}
                    <div class="text-[10px] text-slate-400 uppercase tracking-widest mt-1">By: ${escapeHtml(j.created_by || 'System')}</div>
                    ${j.ai_report?.requested ? `<div class="text-[10px] text-violet-600 uppercase tracking-widest mt-1">AI report: ${escapeHtml(j.ai_report.status || 'Pending')}</div>` : ''}
                </td>
                <td class="px-10 py-5 font-bold text-slate-500">${escapeHtml(j.target_summary || 'N/A')}</td>
                <td class="px-10 py-5 text-center"><span class="px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-wider ${cls}">${escapeHtml(statusStr)} ${j.total > 1 ? `(${j.success}/${j.total})` : ''}</span></td>
                <td class="px-10 py-5 text-xs text-slate-400 font-bold text-right">${escapeHtml(j.created_at)}</td>
                ${actionBtn}
            </tr>`;
    }).join('') || '<tr><td colspan="5" class="p-24 text-center text-slate-300 font-black italic">No tasks match your filters.</td></tr>';
}

// --- TRIGGERS LOGIC ---
function openTriggerModal() {
    ['trgId', 'trgName', 'trgValue'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });

    const trgGroup = document.getElementById('trgGroup'); if(trgGroup) trgGroup.value = 'all';
    const trgMetric = document.getElementById('trgMetric'); if(trgMetric && trgMetric.options.length > 0) trgMetric.selectedIndex = 0;
    const trgOp = document.getElementById('trgOperator'); if(trgOp) trgOp.value = '==';
    const trgAct = document.getElementById('trgAction'); if(trgAct && trgAct.options.length > 0) trgAct.selectedIndex = 0;
    const trgActive = document.getElementById('trgActive'); if(trgActive) trgActive.checked = true;

    const title = document.getElementById('trgModalTitle'); if(title) title.innerText = 'New Trigger';
    openModal('triggerModal');
}

function editTrigger(id, name, target_group_id, metric, op, val, action_id, active) {
    const elId = document.getElementById('trgId'); if(elId) elId.value = id;
    const elName = document.getElementById('trgName'); if(elName) elName.value = name;
    const elGroup = document.getElementById('trgGroup'); if(elGroup) elGroup.value = target_group_id || 'all';

    const metricSelect = document.getElementById('trgMetric');
    if(metricSelect) {
        for(let i=0; i<metricSelect.options.length; i++) {
            if(metricSelect.options[i].value === metric) metricSelect.selectedIndex = i;
        }
    }

    const elOp = document.getElementById('trgOperator'); if(elOp) elOp.value = op;
    const elVal = document.getElementById('trgValue'); if(elVal) elVal.value = val;

    const actionSelect = document.getElementById('trgAction');
    if(actionSelect) {
        for(let i=0; i<actionSelect.options.length; i++) {
            if(actionSelect.options[i].value === action_id) actionSelect.selectedIndex = i;
        }
    }

    const elAct = document.getElementById('trgActive'); if(elAct) elAct.checked = (active === 'True');
    const title = document.getElementById('trgModalTitle'); if(title) title.innerText = 'Edit Trigger';
    openModal('triggerModal');
}

async function saveTrigger() {
    const data = {
        id: document.getElementById('trgId')?.value || null,
        name: document.getElementById('trgName')?.value,
        target_group_id: document.getElementById('trgGroup')?.value,
        metric_name: document.getElementById('trgMetric')?.value,
        operator: document.getElementById('trgOperator')?.value,
        threshold_value: document.getElementById('trgValue')?.value,
        action_template_id: document.getElementById('trgAction')?.value,
        is_active: document.getElementById('trgActive')?.checked
    };

    if(!data.name || !data.metric_name || !data.threshold_value || !data.action_template_id) {
        return alert("Please fill in all trigger details.");
    }

    try {
        const res = await fetch('/api/infrastructure/triggers', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        if(res.ok) window.location.reload();
        else alert("Failed to save trigger");
    } catch(e) { alert("Server error."); }
}

async function deleteTrigger(id) {
    if(confirm("Delete this trigger rule? Auto-remediation for this metric will stop.")) {
        try {
            await fetch('/api/infrastructure/triggers/' + id, { method: 'DELETE' });
            window.location.reload();
        } catch(e) { alert("Server error."); }
    }
}

// --- SCHEDULER LOGIC (VISUAL CRON) ---
function kyivDateTimeParts(offsetMinutes = 0) {
    const parts = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Europe/Kyiv',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).formatToParts(new Date(Date.now() + offsetMinutes * 60000));
    const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
    return {
        date: `${values.year}-${values.month}-${values.day}`,
        time: `${values.hour}:${values.minute}`,
    };
}

function normalizeScheduleTime(value) {
    const match = /^(\d{1,2}):(\d{2})$/.exec(String(value || '').trim());
    if (!match) return null;
    const hour = Number(match[1]);
    const minute = Number(match[2]);
    if (!Number.isInteger(hour) || hour < 0 || hour > 23 || !Number.isInteger(minute) || minute < 0 || minute > 59) return null;
    return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function updateScheduleWheelInput(wheel) {
    if (!wheel) return;
    const hour = wheel.querySelector('.schedule-wheel[data-unit="hour"] .schedule-wheel-option.is-selected')?.dataset.value;
    const minute = wheel.querySelector('.schedule-wheel[data-unit="minute"] .schedule-wheel-option.is-selected')?.dataset.value;
    const input = document.getElementById(wheel.dataset.timeTarget || '');
    if (input && hour !== undefined && minute !== undefined) input.value = `${hour}:${minute}`;
}

function getScheduleWheelRowHeight(column) {
    return column?.querySelector('.schedule-wheel-option')?.getBoundingClientRect().height || 40;
}

function selectScheduleWheelOption(column, rawValue, {scroll = true, updateInput = true} = {}) {
    if (!column) return;
    const max = column.dataset.unit === 'hour' ? 23 : 59;
    const value = Math.max(0, Math.min(max, Number(rawValue) || 0));
    const formatted = String(value).padStart(2, '0');
    const selected = column.querySelector(`.schedule-wheel-option[data-value="${formatted}"]`);
    if (!selected) return;

    column.querySelectorAll('.schedule-wheel-option').forEach(option => {
        const active = option === selected;
        option.classList.toggle('is-selected', active);
        option.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    column.dataset.selectedValue = formatted;
    if (scroll) column.scrollTo({top: value * getScheduleWheelRowHeight(column), behavior: 'auto'});
    if (updateInput) updateScheduleWheelInput(column.closest('.schedule-time-picker'));
}

function populateScheduleWheel(column) {
    if (!column || column.dataset.initialized === 'true') return;
    column.dataset.initialized = 'true';
    const unit = column.dataset.unit;
    const max = unit === 'hour' ? 23 : 59;
    const fragment = document.createDocumentFragment();
    const startSpacer = document.createElement('div');
    startSpacer.className = 'schedule-wheel-spacer';
    startSpacer.setAttribute('aria-hidden', 'true');
    fragment.appendChild(startSpacer);

    for (let value = 0; value <= max; value += 1) {
        const formatted = String(value).padStart(2, '0');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'schedule-wheel-option';
        button.dataset.value = formatted;
        button.setAttribute('role', 'option');
        button.setAttribute('aria-label', `${unit === 'hour' ? 'Hour' : 'Minute'} ${formatted}`);
        button.setAttribute('aria-selected', 'false');
        button.textContent = formatted;
        button.addEventListener('click', () => {
            selectScheduleWheelOption(column, value);
            column.focus();
        });
        fragment.appendChild(button);
    }

    const endSpacer = document.createElement('div');
    endSpacer.className = 'schedule-wheel-spacer';
    endSpacer.setAttribute('aria-hidden', 'true');
    fragment.appendChild(endSpacer);
    column.appendChild(fragment);

    column.addEventListener('scroll', () => {
        clearTimeout(scheduleWheelScrollTimers.get(column));
        scheduleWheelScrollTimers.set(column, setTimeout(() => {
            const value = Math.round(column.scrollTop / getScheduleWheelRowHeight(column));
            selectScheduleWheelOption(column, value, {scroll: true, updateInput: true});
        }, 90));
    }, {passive: true});

    column.addEventListener('keydown', event => {
        const current = Number(column.dataset.selectedValue || 0);
        const maxValue = column.dataset.unit === 'hour' ? 23 : 59;
        let next = current;
        if (event.key === 'ArrowDown') next = Math.min(maxValue, current + 1);
        else if (event.key === 'ArrowUp') next = Math.max(0, current - 1);
        else if (event.key === 'PageDown') next = Math.min(maxValue, current + 5);
        else if (event.key === 'PageUp') next = Math.max(0, current - 5);
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = maxValue;
        else return;
        event.preventDefault();
        selectScheduleWheelOption(column, next);
    });
}

function setScheduleWheelTime(inputId, value) {
    const normalized = normalizeScheduleTime(value) || '00:00';
    const input = document.getElementById(inputId);
    if (input) input.value = normalized;
    const wheel = document.querySelector(`.schedule-time-picker[data-time-target="${inputId}"]`);
    if (!wheel) return;
    const [hour, minute] = normalized.split(':');
    selectScheduleWheelOption(wheel.querySelector('.schedule-wheel[data-unit="hour"]'), hour, {scroll: true, updateInput: false});
    selectScheduleWheelOption(wheel.querySelector('.schedule-wheel[data-unit="minute"]'), minute, {scroll: true, updateInput: false});
    updateScheduleWheelInput(wheel);
}

function syncScheduleTimeWheels() {
    document.querySelectorAll('.schedule-time-picker').forEach(wheel => {
        const input = document.getElementById(wheel.dataset.timeTarget || '');
        setScheduleWheelTime(wheel.dataset.timeTarget, input?.value || '00:00');
    });
}

function initScheduleTimeWheels() {
    document.querySelectorAll('.schedule-wheel').forEach(populateScheduleWheel);
    syncScheduleTimeWheels();
}

function initScheduleModalScroll() {
    const body = document.querySelector('#scheduleModal .schedule-modal-body');
    if (!body || body.dataset.scrollInitialized === 'true') return;
    body.dataset.scrollInitialized = 'true';
    body.addEventListener('keydown', event => {
        const pageStep = Math.max(180, Math.round(body.clientHeight * 0.72));
        if (event.key === 'PageDown') body.scrollBy({top: pageStep, behavior: 'smooth'});
        else if (event.key === 'PageUp') body.scrollBy({top: -pageStep, behavior: 'smooth'});
        else if (event.key === 'Home' && event.ctrlKey) body.scrollTo({top: 0, behavior: 'smooth'});
        else if (event.key === 'End' && event.ctrlKey) body.scrollTo({top: body.scrollHeight, behavior: 'smooth'});
        else return;
        event.preventDefault();
    });
}

function toggleScheduleTargetType() {
    refreshScheduleTargetPicker();
}

function initScheduleTargetPicker() {
    const results = document.getElementById('scheduleTargetResults');
    if (!results || results.dataset.pickerInitialized === 'true') return;
    results.dataset.pickerInitialized = 'true';
    results.addEventListener('click', event => {
        chooseScheduleTarget(event.target.closest('.schedule-target-result'));
    });
}

function activeScheduleTargetSelect() {
    const type = document.getElementById('schTargetType')?.value || 'group';
    return document.getElementById(type === 'host' ? 'schTargetHost' : 'schTargetGroup');
}

function scheduleTargetHostData(option) {
    if (!option) return null;
    return getMultiHostById(option.value) || null;
}

function scheduleTargetOptionMeta(option, type) {
    if (!option) return '';
    if (type === 'host') {
        const host = scheduleTargetHostData(option);
        return [
            host?.hostname || option.dataset.hostname,
            host?.ip || option.dataset.ip,
            host?.os_type || option.dataset.os,
        ].filter(Boolean).join(' · ');
    }
    return option.dataset.details || 'Endpoint group';
}

function refreshScheduleTargetPicker() {
    const type = document.getElementById('schTargetType')?.value || 'group';
    const select = activeScheduleTargetSelect();
    const option = select?.selectedOptions?.[0];
    const label = document.getElementById('scheduleTargetPickerLabel');
    const meta = document.getElementById('scheduleTargetPickerMeta');
    const button = document.getElementById('scheduleTargetPickerButton');
    if (label) label.textContent = option?.textContent?.trim() || `No ${type === 'host' ? 'endpoints' : 'groups'} available`;
    if (meta) meta.textContent = option ? scheduleTargetOptionMeta(option, type) : 'No allowed targets available';
    if (button) button.disabled = !option;
}

function renderScheduleTargetPicker(query = '') {
    const type = document.getElementById('schTargetType')?.value || 'group';
    const select = activeScheduleTargetSelect();
    const results = document.getElementById('scheduleTargetResults');
    const count = document.getElementById('scheduleTargetResultCount');
    if (!results || !select) return;

    const normalizedQuery = String(query || '').trim().toLocaleLowerCase();
    const options = Array.from(select.options).filter(option => {
        const host = type === 'host' ? scheduleTargetHostData(option) : null;
        const searchable = [
            option.textContent,
            option.dataset.hostname,
            option.dataset.ip,
            option.dataset.os,
            option.dataset.details,
            host?.name,
            host?.display_name,
            host?.hostname,
            host?.ip,
            host?.os_type,
            host?.agent_version,
            host?.last_seen,
        ].filter(Boolean).join(' ').toLocaleLowerCase();
        return !normalizedQuery || searchable.includes(normalizedQuery);
    });

    results.innerHTML = options.map(option => {
        const selected = option.value === select.value;
        const meta = scheduleTargetOptionMeta(option, type);
        const host = type === 'host' ? scheduleTargetHostData(option) : null;
        const visibleName = option.textContent.trim();
        const hostname = host?.hostname || option.dataset.hostname || '';
        const hostnameLine = type === 'host' && hostname && hostname !== visibleName
            ? `<span class="block truncate text-[10px] font-mono font-bold text-cyan-200/55 mt-1">HOSTNAME: ${escapeHtml(hostname)}</span>`
            : '';
        const hostStatus = type === 'host' && host ? multiHostStatusBadge(host) : '';
        const hostDetails = type === 'host'
            ? [
                host?.ip || option.dataset.ip || 'No IP',
                host?.os_type || option.dataset.os || 'Unknown OS',
                host?.agent_version ? `Agent ${host.agent_version}` : null,
                host?.last_seen ? `Last seen ${host.last_seen}` : null,
            ].filter(Boolean).join(' / ')
            : meta;
        return `
            <button type="button" class="schedule-target-result ${selected ? 'is-selected' : ''} w-full p-4 border rounded-2xl flex items-center justify-between gap-4 text-left transition-all" data-value="${escapeHtml(option.value)}" aria-pressed="${selected ? 'true' : 'false'}">
                <span class="min-w-0 flex-1">
                    <span class="flex flex-wrap items-center gap-2 text-sm font-black text-slate-100">
                        <span class="truncate">${escapeHtml(visibleName)}</span>${hostStatus}
                    </span>
                    ${hostnameLine}
                    <span class="block truncate text-[10px] font-bold text-slate-400 mt-1">${escapeHtml(hostDetails)}</span>
                </span>
                <span class="shrink-0 w-8 h-8 rounded-xl border ${selected ? 'border-teal-300/60 bg-teal-400/20 text-teal-200' : 'border-slate-700 text-slate-600'} flex items-center justify-center">
                    ${selected ? '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="m5 12 4 4L19 6"></path></svg>' : ''}
                </span>
            </button>`;
    }).join('') || '<div class="min-h-[12rem] flex items-center justify-center text-center text-sm font-bold text-slate-500 p-8">No targets match your search.</div>';
    if (count) count.textContent = `${options.length} ${options.length === 1 ? 'target' : 'targets'}`;
}

function openScheduleTargetPicker() {
    const type = document.getElementById('schTargetType')?.value || 'group';
    const select = activeScheduleTargetSelect();
    if (!select?.options?.length) return alert(`No allowed ${type === 'host' ? 'endpoints' : 'groups'} are available.`);
    const title = document.getElementById('scheduleTargetPickerTitle');
    const subtitle = document.getElementById('scheduleTargetPickerSubtitle');
    const search = document.getElementById('scheduleTargetSearch');
    if (title) title.textContent = type === 'host' ? 'Select endpoint' : 'Select endpoint group';
    if (subtitle) subtitle.textContent = type === 'host' ? 'Search by name, hostname, IP or OS' : 'Search allowed endpoint groups';
    if (search) search.value = '';
    renderScheduleTargetPicker('');
    openModal('scheduleTargetPickerModal');
    setTimeout(() => search?.focus(), 0);
}

function filterScheduleTargetPicker() {
    renderScheduleTargetPicker(document.getElementById('scheduleTargetSearch')?.value || '');
}

function chooseScheduleTarget(button) {
    const select = activeScheduleTargetSelect();
    if (!select || !button?.dataset?.value) return;
    select.value = button.dataset.value;
    select.dispatchEvent(new Event('change', {bubbles: true}));
    refreshScheduleTargetPicker();
    closeScheduleTargetPicker();
}

function closeScheduleTargetPicker() {
    closeModal('scheduleTargetPickerModal');
    document.getElementById('scheduleTargetPickerButton')?.focus();
}

function toggleSchType() {
    const checked = document.querySelector('input[name="schType"]:checked');
    if(!checked) return;
    const type = checked.value;

    const uiOnce = document.getElementById('schUiOnce');
    const uiRec = document.getElementById('schUiRecurring');

    if(uiOnce) uiOnce.classList.toggle('hidden', type !== 'once');
    if(uiRec) uiRec.classList.toggle('hidden', type !== 'recurring');
    setTimeout(syncScheduleTimeWheels, 0);
}

function toggleScheduleDay(inputOrValue, forceState = null) {
    const input = typeof inputOrValue === 'string'
        ? document.querySelector(`.sch-day[value="${inputOrValue}"]`)
        : inputOrValue;
    if (!input) return;
    input.checked = forceState === null ? !input.checked : !!forceState;
}

function handleScheduleDayClick(event) {
    event.preventDefault();
    const input = event.currentTarget?.querySelector('.sch-day');
    if (!input) return;
    input.checked = !input.checked;
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

function buildCronString() {
    const checked = document.querySelector('input[name="schType"]:checked');
    if(!checked) return null;
    const type = checked.value;

    if (type === 'once') {
        const d = document.getElementById('schDate')?.value;
        const t = normalizeScheduleTime(document.getElementById('schTimeOnce')?.value);
        if(!d || !t) return null;
        return "DATE:" + d + " " + t;
    } else {
        const t = normalizeScheduleTime(document.getElementById('schTimeRec')?.value);
        if(!t) return null;
        const [hr, min] = t.split(':');
        const days = Array.from(document.querySelectorAll('.sch-day:checked')).map(cb => Number(cb.value)).sort((a, b) => a - b);
        if(days.length === 0) return null;
        return `${Number(min)} ${Number(hr)} * * ${days.join(',')}`;
    }
}

function parseCronToUI(cronStr) {
    cronStr = String(cronStr || '').trim();
    const elDate = document.getElementById('schDate'); if(elDate) elDate.value = '';
    setScheduleWheelTime('schTimeOnce', '00:00');
    setScheduleWheelTime('schTimeRec', '00:00');
    document.querySelectorAll('.sch-day').forEach(cb => cb.checked = false);

    if (cronStr.startsWith("DATE:")) {
        const rOnce = document.querySelector('input[name="schType"][value="once"]');
        if(rOnce) rOnce.checked = true;
        const [d, t] = cronStr.replace("DATE:", "").trim().split(" ");
        if(elDate) elDate.value = d;
        setScheduleWheelTime('schTimeOnce', t);
    } else {
        const rRec = document.querySelector('input[name="schType"][value="recurring"]');
        if(rRec) rRec.checked = true;
        const parts = cronStr.split(' ');
        if(parts.length >= 5) {
            const min = parts[0].padStart(2, '0');
            const hr = parts[1].padStart(2, '0');
            setScheduleWheelTime('schTimeRec', `${hr}:${min}`);
            if(parts[4] !== '*') {
                const days = parts[4].split(',');
                days.forEach(d => {
                    const cb = document.querySelector(`.sch-day[value="${d}"]`);
                    if(cb) cb.checked = true;
                });
            }
        }
    }
    toggleSchType();
}

function getSelectedScheduleTemplateVars() {
    const option = document.getElementById('schTemplate')?.selectedOptions?.[0];
    if (!option) return [];
    try {
        const vars = JSON.parse(option.dataset.vars || '[]');
        return Array.isArray(vars) ? vars : [];
    } catch(e) {
        return [];
    }
}

function getSelectedScheduleTemplateSchema() {
    const option = document.getElementById('schTemplate')?.selectedOptions?.[0];
    return option ? normalizeVariableSchema(option.dataset.varSchema || '{}') : {};
}

function updateScheduleVariablesUI(values = currentScheduleVariables) {
    currentScheduleVariables = values && typeof values === 'object' ? values : {};
    const schema = getSelectedScheduleTemplateSchema();
    const vars = Array.from(new Set([...getSelectedScheduleTemplateVars(), ...Object.keys(schema)]));
    const area = document.getElementById('scheduleVariablesArea');
    const container = document.getElementById('scheduleVariablesContainer');
    if (!area || !container) return;

    if (!vars.length) {
        area.classList.add('hidden');
        container.innerHTML = '';
        return;
    }

    area.classList.remove('hidden');
    container.innerHTML = vars.map(v => {
        const spec = variableSpecFor(v, schema);
        const field = renderVariableField(v, spec, currentScheduleVariables[v], 'sch-var-input');
        return `
            <div>
                <label class="text-[10px] font-black text-blue-700 uppercase tracking-widest block mb-2">${escapeHtml(spec.label || v)}</label>
                ${field}
            </div>
        `;
    }).join('');
}

function collectScheduleVariables() {
    return collectVariableInputs('.sch-var-input');
}

function openScheduleModal() {
    const elId = document.getElementById('schId'); if(elId) elId.value = '';
    const elName = document.getElementById('schName'); if(elName) elName.value = '';
    const elCat = document.getElementById('schCategory'); if(elCat) elCat.value = 'Scheduled';
    const elAct = document.getElementById('schActive'); if(elAct) elAct.checked = true;
    const elTimeout = document.getElementById('schTimeoutMinutes'); if(elTimeout) elTimeout.value = '';
    const elTemplate = document.getElementById('schTemplate'); if(elTemplate) elTemplate.selectedIndex = 0;
    const elTargetType = document.getElementById('schTargetType'); if(elTargetType) elTargetType.value = 'group';
    const elTargetGroup = document.getElementById('schTargetGroup'); if(elTargetGroup) elTargetGroup.selectedIndex = 0;
    const elTargetHost = document.getElementById('schTargetHost'); if(elTargetHost) elTargetHost.selectedIndex = 0;
    currentScheduleVariables = {};
    document.querySelectorAll('.sch-day').forEach(cb => cb.checked = false);

    const rOnce = document.querySelector('input[name="schType"][value="once"]');
    if(rOnce) rOnce.checked = true;

    const defaultRun = kyivDateTimeParts(60);
    const elDate = document.getElementById('schDate');
    if(elDate) elDate.value = defaultRun.date;
    setScheduleWheelTime('schTimeOnce', defaultRun.time);
    setScheduleWheelTime('schTimeRec', defaultRun.time);
    toggleScheduleTargetType();
    toggleSchType();
    updateScheduleVariablesUI({});

    const title = document.getElementById('schModalTitle'); if(title) title.innerText = 'New Schedule';
    openModal('scheduleModal');
    const modalBody = document.querySelector('#scheduleModal .schedule-modal-body');
    if (modalBody) modalBody.scrollTop = 0;
    setTimeout(syncScheduleTimeWheels, 40);
}

function editSchedule(source, name, cat, cron, type, active) {
    const data = typeof source === 'object' && source?.dataset ? source.dataset : {
        id: source,
        name,
        category: cat,
        cron,
        targetType: type,
        active
    };
    const id = data.id || '';
    name = data.name || '';
    cat = data.category || '';
    cron = data.cron || '';
    type = data.targetType || 'group';
    active = data.active || 'True';

    const elId = document.getElementById('schId'); if(elId) elId.value = id;
    const elName = document.getElementById('schName'); if(elName) elName.value = name;
    const elCat = document.getElementById('schCategory'); if(elCat) elCat.value = cat;
    const elType = document.getElementById('schTargetType'); if(elType) elType.value = type;
    const elAct = document.getElementById('schActive'); if(elAct) elAct.checked = String(active).toLowerCase() === 'true';
    const elTemplate = document.getElementById('schTemplate'); if(elTemplate && data.templateId) elTemplate.value = data.templateId;
    const elTimeout = document.getElementById('schTimeoutMinutes'); if(elTimeout) elTimeout.value = data.timeoutMinutes || '';

    const elHost = document.getElementById('schTargetHost');
    if(elHost) {
        if (type === 'host' && data.targetId) elHost.value = data.targetId;
    }
    const elGroup = document.getElementById('schTargetGroup');
    if(elGroup) {
        if (type === 'group' && data.targetId) elGroup.value = data.targetId;
    }
    toggleScheduleTargetType();

    try { currentScheduleVariables = JSON.parse(data.variables || '{}'); }
    catch(e) { currentScheduleVariables = {}; }
    updateScheduleVariablesUI(currentScheduleVariables);

    parseCronToUI(cron);

    const title = document.getElementById('schModalTitle'); if(title) title.innerText = 'Edit Schedule';
    openModal('scheduleModal');
    const modalBody = document.querySelector('#scheduleModal .schedule-modal-body');
    if (modalBody) modalBody.scrollTop = 0;
    setTimeout(syncScheduleTimeWheels, 40);
}

async function saveSchedule() {
    const cronExpr = buildCronString();
    if (!cronExpr) return alert("Please specify the execution time and date/days completely.");

    const name = document.getElementById('schName')?.value?.trim() || '';
    const category = document.getElementById('schCategory')?.value?.trim() || 'Scheduled';
    const templateId = document.getElementById('schTemplate')?.value || '';
    const targetType = document.getElementById('schTargetType')?.value || '';
    const targetId = targetType === 'host' ? document.getElementById('schTargetHost')?.value : document.getElementById('schTargetGroup')?.value;
    const timeoutMinutes = Number(document.getElementById('schTimeoutMinutes')?.value || 0);
    if (!name) return alert("Job Name is required");
    if (name.length > 150) return alert("Job Name cannot exceed 150 characters");
    if (category.length > 100) return alert("Category cannot exceed 100 characters");
    if (!templateId) return alert("Select a runnable template");
    if (!['host', 'group'].includes(targetType) || !targetId) return alert("Select a valid target");
    if (!Number.isInteger(timeoutMinutes) || timeoutMinutes < 0 || timeoutMinutes > 10080) return alert("Execution time limit must be between 0 and 10080 minutes");

    const data = {
        id: document.getElementById('schId')?.value || null,
        name,
        category,
        template_id: templateId,
        target_type: targetType,
        target_id: targetId,
        cron: cronExpr,
        timeout_minutes: timeoutMinutes,
        variables: collectScheduleVariables(),
        is_active: document.getElementById('schActive')?.checked
    };

    const saveButton = document.getElementById('btnSaveSchedule');
    if (saveButton?.disabled) return;
    if (saveButton) {
        saveButton.disabled = true;
        saveButton.classList.add('opacity-60', 'cursor-not-allowed');
    }
    try {
        const res = await fetch('/api/infrastructure/schedule', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        if(res.ok) window.location.reload();
        else {
            let message = "Save failed";
            try {
                const err = await res.json();
                message = err.message || message;
            } catch(e) {}
            alert(message);
        }
    } catch(e) {
        alert("Server error.");
    } finally {
        if (saveButton) {
            saveButton.disabled = false;
            saveButton.classList.remove('opacity-60', 'cursor-not-allowed');
        }
    }
}

async function deleteSchedule(id) {
    if(confirm("Delete this scheduled task?")) {
        await fetch('/api/infrastructure/schedule/' + id, { method: 'DELETE' });
        window.location.reload();
    }
}

async function runScheduleNow(id) {
    if (!confirm("Run this scheduled task now? The saved schedule will not be changed.")) return;
    try {
        const res = await fetch('/api/infrastructure/schedule/' + encodeURIComponent(id) + '/run-now', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success) {
            return alert(data.message || "Run now failed");
        }
        alert(`Schedule dispatched now for ${data.targets || 0} host(s).`);
        window.location.reload();
    } catch(e) {
        alert("Server error.");
    }
}

// БАЗОВІ ФУНКЦІЇ ВЗАЄМОДІЇ
function openModal(id) {
    const el = document.getElementById(id);
    if(el) el.classList.remove('hidden');
    else console.error("Modal not found: ", id);
}

function filterHosts(status, btn) {
    currentHostStatus = status;
    document.querySelectorAll('.host-filter-btn').forEach(b => {
        b.classList.remove('bg-white', 'text-indigo-600', 'shadow-sm');
        b.classList.add('text-slate-500');
    });
    if(btn) {
        btn.classList.remove('text-slate-500');
        btn.classList.add('bg-white', 'text-indigo-600', 'shadow-sm');
    }
    applyHostFilters();
}

function applyHostFilters() {
    const sEl = document.getElementById('hostSearch');
    const q = sEl ? sEl.value.toLowerCase() : '';
    const gEl = document.getElementById('hostGroupFilter');
    const g = gEl ? gEl.value : 'all';

    document.querySelectorAll('.host-row').forEach(row => {
        const t = row.innerText.toLowerCase();
        const stat = row.dataset.status;
        const approval = row.dataset.approval || 'Approved';
        const groups = (row.dataset.groups || "").split(',');
        const mSearch = t.includes(q);
        const mStat = (currentHostStatus === 'all' || stat === currentHostStatus || (currentHostStatus === 'pending' && approval === 'Pending'));
        const mGroup = (g === 'all') || (g === 'ungrouped' && groups[0] === "") || (groups.includes(g));
        row.style.display = (mSearch && mStat && mGroup) ? '' : 'none';
    });
}

async function viewTaskDetails(taskId) {
    const res = await fetch('/api/infrastructure/task/' + taskId);
    const result = await res.json();
    if(!result.success) return;
    const d = result.data;
    document.getElementById('tTitle').innerText = d.title || 'Task Log';
    document.getElementById('tId').innerText = 'Task ID: ' + d.id;
    document.getElementById('tHost').innerText = d.name || d.hostname || 'Unknown';
    const statusStr = d.status || 'Pending';
    document.getElementById('tStatus').innerHTML = `<span class="uppercase tracking-widest text-[10px] bg-white px-3 py-1 rounded-xl shadow-sm border border-slate-100 font-black ${statusStr === 'Success' ? 'text-emerald-500' : (statusStr === 'Error' ? 'text-rose-500' : 'text-amber-500')}">${escapeHtml(statusStr)}</span>`;
    document.getElementById('tLog').innerText = d.log || "Waiting for agent pulse...";
    openModal('taskModal');
}

function viewJobDetails(jobId) {
    const job = allQueueJobs.find(j => j.job_id === jobId);
    if(!job) return;
    currentViewedJobId = jobId;
    currentJobTasks = job.tasks || [];
    currentJobStatusFilter = 'all';
    document.getElementById('jTitle').innerText = job.title || 'Job Details';
    document.getElementById('jInfo').innerText = `${job.action} • Total targets: ${job.total}`;
    renderJobStatusFilters();
    renderJobTaskRows();
    openModal('jobModal');
}

function normalizeJobTaskStatus(status) {
    const value = (status || 'Pending').toLowerCase();
    if (value === 'success') return 'success';
    if (value === 'error') return 'error';
    if (value === 'cancelled' || value === 'canceled') return 'cancelled';
    if (value === 'scheduled') return 'scheduled';
    if (value === 'pickedup' || value === 'picked_up' || value === 'running') return 'running';
    return 'pending';
}

function jobStatusLabel(status) {
    const normalized = normalizeJobTaskStatus(status);
    if (normalized === 'success') return 'Success';
    if (normalized === 'error') return 'Error';
    if (normalized === 'cancelled') return 'Cancelled';
    if (normalized === 'scheduled') return 'Scheduled';
    if (normalized === 'running') return 'Running';
    return 'Pending';
}

function jobStatusBadgeClass(status) {
    const normalized = normalizeJobTaskStatus(status);
    if (normalized === 'success') return 'bg-emerald-50 text-emerald-700 border-emerald-100';
    if (normalized === 'error') return 'bg-rose-50 text-rose-700 border-rose-100';
    if (normalized === 'cancelled') return 'bg-slate-50 text-slate-500 border-slate-200';
    if (normalized === 'scheduled') return 'bg-sky-50 text-sky-700 border-sky-100';
    if (normalized === 'running') return 'bg-indigo-50 text-indigo-700 border-indigo-100';
    return 'bg-amber-50 text-amber-700 border-amber-100';
}

function renderJobStatusFilters() {
    const wrap = document.getElementById('jobStatusFilters');
    if (!wrap) return;
    const counts = currentJobTasks.reduce((acc, task) => {
        acc[normalizeJobTaskStatus(task.status)] += 1;
        return acc;
    }, { all: currentJobTasks.length, pending: 0, scheduled: 0, running: 0, error: 0, success: 0, cancelled: 0 });

    const filters = [
        ['all', 'All', counts.all],
        ['scheduled', 'Scheduled', counts.scheduled],
        ['pending', 'Pending', counts.pending],
        ['running', 'Running', counts.running],
        ['error', 'Errors', counts.error],
        ['success', 'Success', counts.success],
        ['cancelled', 'Cancelled', counts.cancelled]
    ];

    wrap.innerHTML = filters.map(([key, label, count]) => {
        const active = currentJobStatusFilter === key;
        return `<button onclick="setJobStatusFilter('${key}')" class="job-status-filter px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${active ? 'bg-slate-900 text-white border-slate-900 shadow-sm' : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'}">${label} <span class="${active ? 'text-white/70' : 'text-slate-400'}">${count}</span></button>`;
    }).join('');
}

function setJobStatusFilter(status) {
    currentJobStatusFilter = status || 'all';
    renderJobStatusFilters();
    renderJobTaskRows();
}

function renderJobTaskRows() {
    const body = document.getElementById('jobHostsBody');
    if (!body) return;
    const filteredTasks = currentJobStatusFilter === 'all'
        ? currentJobTasks
        : currentJobTasks.filter(t => normalizeJobTaskStatus(t.status) === currentJobStatusFilter);

    const empty = `<tr><td colspan="3" class="p-16 text-center text-slate-300 font-black uppercase tracking-widest text-xs">No hosts in this status</td></tr>`;
    body.innerHTML = filteredTasks.map(t => {
        const statusStr = t.status || 'Pending';
        const hostCell = t.endpoint_id
            ? `<button onclick="viewHostFromJob('${escapeInlineJs(t.endpoint_id)}')" class="font-black text-slate-800 hover:text-indigo-600 text-left">${escapeHtml(t.name || t.display_name || t.hostname || 'Unknown')}</button>`
            : `<span class="font-black text-slate-700">${escapeHtml(t.name || t.display_name || t.hostname || 'Unknown')}</span>`;
        const logCell = t.task_id
            ? `<button onclick="viewTaskDetails('${escapeInlineJs(t.task_id)}')" class="px-4 py-2 bg-white border border-slate-200 rounded-xl text-xs font-black uppercase text-indigo-600 hover:bg-indigo-50 transition-colors shadow-sm">View Log</button>`
            : `<span class="px-4 py-2 bg-sky-50 border border-sky-100 rounded-xl text-xs font-black uppercase text-sky-600">Planned</span>`;
        return `<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-6 py-4 text-base">${hostCell}</td>
            <td class="px-6 py-4 text-center"><span class="font-black uppercase tracking-widest text-[10px] px-3 py-1 rounded-lg border ${jobStatusBadgeClass(statusStr)}">${jobStatusLabel(statusStr)}</span></td>
            <td class="px-6 py-4 text-right">${logCell}</td>
        </tr>`;
    }).join('') || empty;
}

function viewHostFromJob(endpointId) {
    closeModal('jobModal');
    viewHost(endpointId);
}

async function viewHost(id) {
    currentViewedHostId = id;
    switchHostTab('info');
    document.getElementById('mName').innerText = "Loading...";
    openModal('hostModal');

    try {
        const res = await fetch('/api/infrastructure/host/' + id);
        const result = await res.json();
        if (!result.success) return;
        const d = result.data;
        d.history = (d.history || []).map(h => ({
            ...h,
            id: escapeInlineJs(h.id),
            title: escapeHtml(h.title),
            by: escapeHtml(h.by),
            date: escapeHtml(h.date),
            status: escapeHtml(h.status)
        }));
        currentViewedHostData = d;
        const visibleName = endpointVisibleName(d);

        document.getElementById('mName').innerText = visibleName;
        const hostnameLine = document.getElementById('mHostname');
        if (hostnameLine) {
            hostnameLine.innerText = d.display_name && d.hostname ? `HOSTNAME: ${d.hostname}` : '';
            hostnameLine.classList.toggle('hidden', !(d.display_name && d.hostname));
        }
        if(document.getElementById('confName')) document.getElementById('confName').innerText = visibleName;
        document.getElementById('mId').innerText = 'ID: ' + d.id;
        const hostNameSpec = document.getElementById('mHostNameSpec');
        if (hostNameSpec) hostNameSpec.innerText = d.hostname || "Unknown";
        document.getElementById('mIp').innerText = d.ip || "N/A";
        document.getElementById('mOs').innerText = d.os || "Unknown";
        document.getElementById('mAgentVersion').innerText = d.agent_version || "Unknown";
        const keyEl = document.getElementById('mAgentKeyStatus');
        if (keyEl) keyEl.innerHTML = d.agent_identity_key_enrolled
            ? '<span class="text-emerald-600 font-black uppercase tracking-widest">Enrolled</span>'
            : '<span class="text-violet-600 font-black uppercase tracking-widest">Missing</span>';
        document.getElementById('mSeen').innerText = d.last_seen || "-";
        const identityWarning = d.identity_warning ? `<div class="p-3 bg-rose-50 border border-rose-100 rounded-2xl text-xs font-bold text-rose-700">${escapeHtml(d.identity_warning)}</div>` : '';
        const identityDuplicates = (d.duplicate_matches || []).filter(match => match.strong_match);
        const identityDuplicateWarning = identityDuplicates.length ? `
            <div class="p-3 bg-rose-50 border border-rose-100 rounded-2xl text-xs font-bold text-rose-700">
                <div class="font-black uppercase tracking-widest text-[10px] mb-2">Possible duplicate identity</div>
                ${identityDuplicates.map(match => `
                    <div class="mt-1">
                        <button onclick="viewHost('${escapeInlineJs(match.id)}')" class="font-black underline decoration-rose-300 underline-offset-2 hover:text-rose-900">${escapeHtml(match.hostname || match.id)}</button>
                        <span class="text-rose-500">/ ${escapeHtml(match.agent_version || 'unknown')} / ${(match.reasons || []).map(escapeHtml).join(', ')}</span>
                    </div>
                `).join('')}
            </div>
        ` : '';
        const approval = d.approval_status || 'Approved';
        document.getElementById('mApprovalStatus').innerHTML = approval === 'Approved' ? '<span class="text-emerald-500 font-black uppercase tracking-widest text-[10px]">Approved</span>' : (approval === 'Pending' ? '<span class="text-amber-500 font-black uppercase tracking-widest text-[10px]">Pending</span>' : '<span class="text-rose-500 font-black uppercase tracking-widest text-[10px]">Rejected</span>');
        document.getElementById('mAccessStatus').innerHTML = d.is_blocked ? '<span class="text-rose-500 font-black uppercase tracking-widest text-[10px]">Blocked</span>' : '<span class="text-emerald-500 font-black uppercase tracking-widest text-[10px]">Allowed</span>';

        let iconHtml = '<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>';
        if (d.os_type === "Windows") iconHtml = '<svg class="w-8 h-8 text-blue-500" fill="currentColor" viewBox="0 0 24 24"><path d="M0 3.449L9.75 2.1v9.418H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.67m10.949-8.07H24V24l-13.051-1.754"/></svg>';
        else if (d.os_type === "macOS") iconHtml = '<svg class="w-8 h-8 text-slate-800" fill="currentColor" viewBox="0 0 24 24"><path d="M12 20.8c-1.3 0-3.3-.9-5.1-.9-2.2 0-4.1 1.2-5.1 3.1-1.1 1.9-2.8 6.7-1.1 9.7 1.3 2.1 3.1 4.5 5.5 4.6 2.3.1 3.2-1.3 5.9-1.3s3.4 1.4 5.9 1.3c2.5-.1 4-2.2 5.3-4.3 1.5-2.2 2.1-4.4 2.1-4.5-.1-.1-4.2-1.6-4.3-4.8-.1-2.7 2.2-4 2.3-4.1-1.3-1.9-3.2-2.1-4-2.2-1.8-.2-3.8 1.1-5.1 1.1s-3-1.2-4.8-1.1zM15.4 6.7c1-1.3 1.8-3 1.6-4.7-1.5.1-3.3 1-4.4 2.3-.9 1.1-1.8 2.9-1.6 4.6 1.7.1 3.4-.9 4.4-2.2z"/></svg>';
        else if (d.os_type === "Linux") iconHtml = '<svg class="w-8 h-8 text-amber-500" fill="currentColor" viewBox="0 0 24 24"><path d="M21.1 14.8c-.8 0-1.4.6-1.4 1.4 0 .8.6 1.4 1.4 1.4.8 0 1.4-.6 1.4-1.4 0-.8-.6-1.4-1.4-1.4zm-18.2 0c-.8 0-1.4.6-1.4 1.4 0 .8.6 1.4 1.4 1.4.8 0 1.4-.6 1.4-1.4 0-.8-.6-1.4-1.4-1.4zm10.7-3.6c-1.1-1-2.6-1.5-4-1.4h-.2c-1.4-.1-2.9.4-4 1.4-1.9 1.8-2.6 4.7-2.6 8.3 0 2.2.8 4.2 2.3 5.7 1.2 1.2 2.7 1.8 4.3 1.8s3.1-.6 4.3-1.8c1.5-1.5 2.3-3.5 2.3-5.7.1-3.6-.6-6.5-2.4-8.3zm-5.4 11c-.5 0-.9-.4-.9-.9s.4-.9.9-.9.9.4.9.9-.4.9-.9.9zm3.5 0c-.5 0-.9-.4-.9-.9s.4-.9.9-.9.9.4.9.9-.4.9-.9.9z"/></svg>';
        document.getElementById('mOsIcon').innerHTML = iconHtml;

        document.getElementById('mGroups').innerHTML = d.groups.map(g => `<span class="bg-indigo-50 text-indigo-600 px-3 py-1.5 rounded-xl text-xs font-bold border border-indigo-100 shadow-sm uppercase">${escapeHtml(g.name)}</span>`).join('') || '<span class="text-slate-400 italic text-sm">Ungrouped</span>';
        const networkInfo = Array.isArray(d.network_info) ? d.network_info : [];
        document.getElementById('mNetworkInfo').innerHTML = networkInfo.map(n => `
            <div class="bg-white border border-slate-200 rounded-2xl p-3">
                <div class="font-black text-slate-700">${escapeHtml(n.name || 'Interface')}</div>
                <div class="text-[10px] text-slate-400 font-bold mt-1">${escapeHtml(n.type || 'Unknown')} / ${escapeHtml(n.status || 'Unknown')} / ${escapeHtml(n.mac || 'No MAC')}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-2 break-words">IPv4: ${(n.ipv4 || []).map(escapeHtml).join(', ') || '-'}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-1 break-words">GW: ${(n.gateways || []).map(escapeHtml).join(', ') || '-'}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-1 break-words">DNS: ${(n.dns_servers || []).map(escapeHtml).join(', ') || '-'}</div>
            </div>
        `).join('') || '<span class="text-slate-400 italic text-sm">No network inventory received</span>';
        const hostInfo = d.host_info || {};
        const volumes = Array.isArray(hostInfo.volumes) ? hostInfo.volumes : [];
        const security = hostInfo.security || {};
        const encryption = d.encryption || {};
        const bitlocker = security.bitlocker || {};
        const fmtBool = (v) => v === true ? 'Yes' : (v === false ? 'No' : '-');
        const fmtBytes = (gb) => Number.isFinite(Number(gb)) ? `${gb} GB` : '-';
        const encryptionClass = encryption.level === 'encrypted'
            ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
            : (encryption.level === 'partial' ? 'bg-amber-50 text-amber-700 border-amber-100' : (encryption.level === 'none' ? 'bg-rose-50 text-rose-700 border-rose-100' : 'bg-slate-100 text-slate-500 border-slate-200'));
        document.getElementById('mHostInfo').innerHTML = `
            <div class="bg-white border border-slate-200 rounded-2xl p-3 space-y-2">
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">FQDN</span><span class="text-slate-700 font-mono text-right break-all">${escapeHtml(hostInfo.fqdn || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Domain</span><span class="text-slate-700 text-right">${escapeHtml(hostInfo.domain_name || hostInfo.user_domain_name || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Domain Joined</span><span class="text-slate-700">${fmtBool(hostInfo.likely_domain_joined)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">CPU / RAM</span><span class="text-slate-700">${hostInfo.processor_count || '-'} cores / ${hostInfo.total_memory_mb ? Math.round(hostInfo.total_memory_mb / 1024) + ' GB' : '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Timezone</span><span class="text-slate-700 text-right">${escapeHtml(hostInfo.timezone || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Boot UTC</span><span class="text-slate-700 font-mono text-[10px] text-right">${escapeHtml(hostInfo.boot_time_utc || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">First Seen</span><span class="text-slate-700 font-mono text-[10px] text-right">${escapeHtml(d.first_seen || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Last Enrollment</span><span class="text-slate-700 font-mono text-[10px] text-right">${escapeHtml(d.last_enrollment_at || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Enroll IP</span><span class="text-slate-700 font-mono text-[10px] text-right">${escapeHtml(d.last_enrollment_ip || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Attempts</span><span class="text-slate-700 font-black">${d.enrollment_attempts || 0}</span></div>
            </div>
            ${identityWarning}
            ${identityDuplicateWarning}
            ${volumes.length ? volumes.map(v => `
                <div class="bg-white border border-slate-200 rounded-2xl p-3">
                    <div class="font-black text-slate-700">${escapeHtml(v.name || 'Volume')} ${v.label ? '/ ' + escapeHtml(v.label) : ''}</div>
                    <div class="text-[10px] text-slate-400 font-bold mt-1">${escapeHtml(v.type || '-')} / ${escapeHtml(v.format || '-')} / ${v.ready ? 'Ready' : 'Not ready'}</div>
                    <div class="font-mono text-[10px] text-slate-600 mt-2">Free: ${fmtBytes(v.free_gb)} / Total: ${fmtBytes(v.total_gb)}</div>
                </div>
            `).join('') : ''}
        `;
        document.getElementById('mSecurityInfo').innerHTML = `
            <div class="bg-white border border-slate-200 rounded-2xl p-3 space-y-2">
                <div class="flex justify-between gap-3 items-center"><span class="text-slate-400 font-bold">Encryption</span><span class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${encryptionClass}">${escapeHtml(encryption.status || 'Unknown')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Methods</span><span class="text-slate-700 text-right">${(encryption.methods || []).map(escapeHtml).join(', ') || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Pending Reboot</span><span class="${security.pending_reboot ? 'text-amber-600' : 'text-emerald-600'} font-black">${fmtBool(security.pending_reboot)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Domain</span><span class="text-slate-700">${escapeHtml(security.firewall_domain || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Private</span><span class="text-slate-700">${escapeHtml(security.firewall_private || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Public</span><span class="text-slate-700">${escapeHtml(security.firewall_public || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Defender</span><span class="text-slate-700">${escapeHtml(security.defender_service_state || '-')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">VeraCrypt</span><span class="${security.veracrypt_detected ? 'text-emerald-600' : 'text-slate-500'} font-black">${fmtBool(security.veracrypt_detected)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">TrueCrypt</span><span class="${security.truecrypt_detected ? 'text-emerald-600' : 'text-slate-500'} font-black">${fmtBool(security.truecrypt_detected)}</span></div>
                <div class="pt-2 border-t border-slate-100 grid grid-cols-2 gap-2 text-[10px]">
                    <div><span class="text-slate-400 font-bold block">BitLocker Status</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.status || 'unknown')}</span></div>
                    <div><span class="text-slate-400 font-bold block">Encrypted</span><span class="text-slate-700 font-black">${Number.isFinite(Number(bitlocker.encrypted_percentage)) && Number(bitlocker.encrypted_percentage) >= 0 ? Number(bitlocker.encrypted_percentage) + '%' : '-'}</span></div>
                    <div><span class="text-slate-400 font-bold block">Protection</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.protection_status || 'unknown')}</span></div>
                    <div><span class="text-slate-400 font-bold block">Conversion</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.conversion_status || 'unknown')}</span></div>
                </div>
                <div class="pt-2 border-t border-slate-100"><span class="text-slate-400 font-bold block mb-1">BitLocker</span><span class="font-mono text-[10px] text-slate-600 whitespace-pre-wrap break-words">${escapeHtml(security.bitlocker_summary || '-')}</span></div>
            </div>
        `;

        if (document.getElementById('btnBlockHost')) document.getElementById('btnBlockHost').innerText = d.is_blocked ? "Unblock Host" : "Block Host";
        if (document.getElementById('btnApproveHost')) document.getElementById('btnApproveHost').classList.toggle('hidden', approval === 'Approved');
        if (document.getElementById('btnRejectHost')) document.getElementById('btnRejectHost').classList.toggle('hidden', approval === 'Rejected');
        const allowReenrollBtn = document.getElementById('btnAllowReenroll');
        if (allowReenrollBtn) {
            allowReenrollBtn.classList.toggle('hidden', approval !== 'Approved' || d.agent_identity_key_enrolled);
        }
        const recoveryEl = document.getElementById('mReenrollRecovery');
        if (recoveryEl) {
            recoveryEl.classList.toggle('hidden', !d.reenroll_allowed_until);
            recoveryEl.innerText = d.reenroll_allowed_until ? `Re-enroll allowed until ${d.reenroll_allowed_until}` : '';
        }

        document.getElementById('mHistory').innerHTML = d.history.map(h => `<div class="p-4 bg-white border border-slate-200 rounded-2xl flex justify-between items-center cursor-pointer hover:border-indigo-300 hover:shadow-md transition-all shadow-sm" onclick="viewTaskDetails('${h.id}')"><div><p class="font-black text-slate-800 text-sm">${h.title}</p><p class="text-[10px] text-slate-400 uppercase tracking-widest mt-1">By ${h.by} • ${h.date}</p></div><span class="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest ${h.status === 'Success' ? 'bg-emerald-100 text-emerald-700' : (h.status === 'Error' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700')}">${h.status}</span></div>`).join('') || '<p class="text-slate-400 italic text-sm">No task history</p>';
    } catch(e) { console.error("Error loading host data", e); }
}

function updateVisibleHostLabels(hostId, name, hostname, displayName = '') {
    const safeName = name || hostname || hostId || 'Unknown';
    document.querySelectorAll(`button[onclick="viewHost('${hostId}')"]`).forEach(button => {
        button.innerText = safeName;
        const existingLine = button.nextElementSibling?.classList?.contains('display-hostname-line')
            ? button.nextElementSibling
            : null;
        if (displayName && hostname) {
            if (existingLine) {
                existingLine.innerText = `HOSTNAME: ${hostname}`;
            } else {
                const line = document.createElement('div');
                line.className = 'display-hostname-line text-[10px] font-mono text-slate-400 mt-1';
                line.innerText = `HOSTNAME: ${hostname}`;
                button.insertAdjacentElement('afterend', line);
            }
        } else if (existingLine) {
            existingLine.remove();
        }
    });
    if (currentViewedHostData && currentViewedHostData.id === hostId) {
        currentViewedHostData.name = safeName;
        currentViewedHostData.display_name = displayName || '';
        currentViewedHostData.hostname = hostname || currentViewedHostData.hostname;
    }
    const fleetHost = (fleetCenterData.hosts || []).find(host => String(host.id) === String(hostId));
    if (fleetHost) {
        fleetHost.name = safeName;
        fleetHost.display_name = displayName || '';
        fleetHost.hostname = hostname || fleetHost.hostname;
        if (displayName && hostname && String(displayName).trim().toUpperCase() !== String(hostname).trim().toUpperCase()) {
            fleetHost.possible_duplicate = false;
            fleetHost.duplicate_matches = [];
            fleetHost.identity_warning = null;
            if (fleetHost.health && Array.isArray(fleetHost.health.reasons)) {
                fleetHost.health.reasons = fleetHost.health.reasons.filter(reason => reason !== 'identity_warning');
            }
        }
        renderFleetCenter();
    }
    const availableHost = availableHostsData.find(host => String(host.id) === String(hostId));
    if (availableHost) {
        availableHost.name = safeName;
        availableHost.display_name = displayName || '';
        availableHost.hostname = hostname || availableHost.hostname;
    }
}

async function editCurrentHostDisplayName() {
    if (!currentViewedHostId || !currentViewedHostData) return;
    const currentAlias = currentViewedHostData.display_name || '';
    const hostname = currentViewedHostData.hostname || currentViewedHostData.id || '';
    const nextName = prompt(`Display Name for ${hostname}\\nLeave empty to show hostname.`, currentAlias);
    if (nextName === null) return;
    const res = await fetch('/api/infrastructure/host/' + encodeURIComponent(currentViewedHostId), {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({display_name: nextName})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
        alert(data.message || 'Failed to update Display Name.');
        return;
    }
    updateVisibleHostLabels(currentViewedHostId, data.name, data.hostname, data.display_name);
    const visibleName = data.name || data.hostname || currentViewedHostId;
    document.getElementById('mName').innerText = visibleName;
    const hostnameLine = document.getElementById('mHostname');
    if (hostnameLine) {
        hostnameLine.innerText = data.display_name && data.hostname ? `HOSTNAME: ${data.hostname}` : '';
        hostnameLine.classList.toggle('hidden', !(data.display_name && data.hostname));
    }
    if (document.getElementById('confName')) document.getElementById('confName').innerText = visibleName;
}

async function toggleBlockHost() { await fetch('/api/infrastructure/host/' + currentViewedHostId + '/block', { method: 'POST' }); closeModal('hostModal'); location.reload(); }
async function allowCurrentHostReenroll() {
    if (!currentViewedHostId) return;
    if (!confirm('Allow this approved host to re-enroll once during the next 30 minutes? The agent will receive a new token and can enroll its identity key.')) return;
    const res = await fetch('/api/infrastructure/host/' + encodeURIComponent(currentViewedHostId) + '/allow-reenroll', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({minutes: 30})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
        alert(data.message || 'Failed to allow re-enroll.');
        return;
    }
    await viewHost(currentViewedHostId);
}
async function setHostApprovalQuick(hostId, status) {
    await fetch('/api/infrastructure/host/' + hostId + '/approval', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status})
    });
    reloadKeepingNodeContext(status === 'Approved' ? 'approved' : 'review');
}
async function deleteHostQuick(hostId) {
    if (!confirm('Delete this rejected host permanently?')) return;
    const res = await fetch('/api/infrastructure/host/' + hostId, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
        alert(data.message || 'Failed to delete host.');
        return;
    }
    reloadKeepingNodeContext('review');
}
async function mergeEndpointDuplicate(keepId, removeId) {
    if (!confirm('Merge these duplicate endpoint records? The kept record will remain active, and groups, history, telemetry and tasks from the removed record will be moved into it.')) return;
    const res = await fetch('/api/infrastructure/host/merge-duplicate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({keep_id: keepId, remove_id: removeId})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
        alert(data.message || 'Failed to merge duplicate endpoint.');
        return;
    }
    reloadKeepingNodeContext('review');
}
async function acceptEndpointDuplicatePair(leftId, rightId) {
    if (!confirm('Keep both endpoint records? Use this for real cloned servers that must stay as separate nodes. This pair will no longer be shown as an identity duplicate.')) return;
    const res = await fetch('/api/infrastructure/host/duplicate-exception', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            left_id: leftId,
            right_id: rightId,
            reason: 'Accepted as distinct cloned servers'
        })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
        alert(data.message || 'Failed to accept duplicate pair.');
        return;
    }
    reloadKeepingNodeContext('review');
}
async function setHostApproval(status) {
    await fetch('/api/infrastructure/host/' + currentViewedHostId + '/approval', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status})
    });
    closeModal('hostModal');
    reloadKeepingNodeContext(status === 'Approved' ? 'approved' : 'review');
}
async function submitCreateGroup() { await fetch('/api/infrastructure/group', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: document.getElementById('cgName').value, description: document.getElementById('cgDesc').value}) }); location.reload(); }
async function deleteJob(id) { if(confirm("Permanently delete this job and all its logs?")) { await fetch('/api/infrastructure/job/' + id, { method: 'DELETE' }); loadQueue(); } }

async function retryFailedJob(id) {
    if(!confirm("Retry failed hosts from this job?")) return;
    const res = await fetch('/api/infrastructure/job/' + encodeURIComponent(id) + '/retry-failed', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if(!res.ok || !data.success) return alert(data.message || 'Retry failed.');
    loadQueue();
}

async function cancelPendingJob(id) {
    if(!confirm("Cancel all hosts that are still pending or running in this job? Already started local scripts cannot be killed remotely, but WinHUB will close their tasks as Cancelled.")) return;
    const res = await fetch('/api/infrastructure/job/' + encodeURIComponent(id) + '/cancel-pending', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if(!res.ok || !data.success) return alert(data.message || 'Cancel failed.');
    loadQueue();
}

async function cancelScheduledRollout(id) {
    if(!confirm("Cancel this scheduled agent update rollout? Future waves will not be created. Already created jobs are not changed.")) return;
    const res = await fetch('/api/infrastructure/agent-rollout/' + encodeURIComponent(id) + '/cancel', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if(!res.ok || !data.success) return alert(data.message || 'Cancel scheduled rollout failed.');
    loadQueue();
}

async function finalizeJobReport(id) {
    if(!confirm("Finalize this job now? Pending/running hosts will be excluded and the report will include only successful and failed results.")) return;
    const res = await fetch('/api/infrastructure/job/' + encodeURIComponent(id) + '/finalize-report', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if(!res.ok || !data.success) return alert(data.message || 'Finalize failed.');
    alert(`Report finalized. Included: ${data.included}, excluded pending/running: ${data.cancelled}.`);
    closeModal('jobModal');
    switchView('reports');
    loadQueue();
}

async function openGroupFullView(id) {
    currentViewedGroupId = id;
    currentGroupNonMembers = [];
    const res = await fetch('/api/infrastructure/group/' + encodeURIComponent(id));
    const data = await res.json();
    if(!data.success) return;

    document.getElementById('gdPageName').innerText = data.data.name;
    currentGroupNonMembers = data.data.non_members || [];
    const groupCapabilities = data.data.capabilities || {};
    const manageGroupMembers = !!groupCapabilities.manage_groups;
    [
        ['gdBlockGroupBtn', !!groupCapabilities.manage_hosts],
        ['gdUnblockGroupBtn', !!groupCapabilities.manage_hosts],
        ['gdDeleteGroupBtn', !!groupCapabilities.delete_groups],
        ['gdAddHostsBtn', manageGroupMembers],
        ['gdMemberActionsHeader', manageGroupMembers],
    ].forEach(([elementId, visible]) => {
        const element = document.getElementById(elementId);
        if (element) element.classList.toggle('hidden', !visible);
    });

    document.getElementById('groupHostsBody').innerHTML = data.data.members.map(m => `
        <tr class="hover:bg-slate-50/80 transition-colors">
            <td class="px-10 py-5 font-black text-slate-700 text-lg cursor-pointer" onclick="viewHost('${escapeInlineJs(m.id)}')">
                ${escapeHtml(endpointVisibleName(m))}
                ${endpointHostnameLine(m)}
            </td>
            <td class="px-10 py-5">
                <div class="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1">${escapeHtml(m.os_type)}</div>
                <div class="text-sm font-bold text-slate-600">${escapeHtml(m.ip)}</div>
            </td>
            ${manageGroupMembers ? `<td class="px-10 py-5 text-right"><button onclick="removeHostFromGroup('${escapeInlineJs(m.id)}')" class="px-4 py-2 bg-white text-rose-500 border border-slate-200 hover:bg-rose-50 rounded-xl text-xs font-black uppercase transition-all shadow-sm">Remove</button></td>` : ''}
        </tr>`).join('') || '<tr><td colspan="3" class="p-16 text-center text-slate-300 font-black uppercase tracking-widest text-sm">No hosts in this group</td></tr>';

    switchView('group-detail');
}

function filterGroupHosts() {
    const q = document.getElementById('groupInnerSearch').value.toLowerCase();
    const rows = document.getElementById('groupHostsBody').getElementsByTagName('tr');
    for (let r of rows) {
        if(r.cells.length === 1) continue;
        r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
    }
}

async function blockGroup(action) { if(confirm(`Are you sure you want to ${action} all hosts in this group?`)) { await fetch(`/api/infrastructure/group/${currentViewedGroupId}/block`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action}) }); openGroupFullView(currentViewedGroupId); } }

async function openAddHostsToGroupModal() {
    if (!currentViewedGroupId) return;
    const searchEl = document.getElementById('addHostSearch');
    if(searchEl) searchEl.value = '';
    const list = document.getElementById('availableHostsList');
    if (list) list.innerHTML = '<div class="p-10 text-center text-slate-400 font-bold">Loading available hosts...</div>';
    openModal('groupAddHostModal');
    try {
        const res = await fetch('/api/infrastructure/group/' + encodeURIComponent(currentViewedGroupId) + '?include_non_members=1');
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || 'Failed to load available hosts');
        currentGroupNonMembers = data.data.non_members || [];
    } catch (e) {
        currentGroupNonMembers = [];
        if (list) list.innerHTML = '<div class="p-10 text-center text-rose-400 font-bold">Failed to load available hosts.</div>';
        return;
    }
    renderAddHostList('');
}

function renderAddHostList(q) {
    const list = document.getElementById('availableHostsList');
    if(!list) return;
    const filtered = currentGroupNonMembers.filter(m => `${m.name || ''} ${m.display_name || ''} ${m.hostname || ''}`.toLowerCase().includes(q));
    list.innerHTML = filtered.map(m => `
        <label class="group-add-host-row flex items-center gap-4 p-4 border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors group">
            <input type="checkbox" value="${escapeHtml(m.id)}" class="add-host-cb w-5 h-5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" onchange="document.getElementById('selCount').innerText = document.querySelectorAll('.add-host-cb:checked').length">
            <span class="min-w-0">
                <span class="font-black text-slate-700 text-sm group-hover:text-indigo-600 transition-colors">${escapeHtml(endpointVisibleName(m))}</span>
                ${endpointHostnameLine(m)}
            </span>
        </label>`).join('') || '<div class="p-10 text-center text-slate-400 font-bold">No available hosts found</div>';

    const countEl = document.getElementById('selCount');
    if(countEl) countEl.innerText = "0";
}

function filterAddHostList() {
    const el = document.getElementById('addHostSearch');
    if(el) renderAddHostList(el.value.toLowerCase());
}

async function submitAddHostsToGroup() {
    const cbs = document.querySelectorAll('.add-host-cb:checked');
    if(cbs.length === 0) return;
    for(let cb of cbs) await fetch(`/api/infrastructure/group/${currentViewedGroupId}/members`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action: 'add', agent_id: cb.value}) });
    openGroupFullView(currentViewedGroupId);
    closeModal('groupAddHostModal');
}

async function removeHostFromGroup(id) { if(confirm("Remove host from group?")) { await fetch(`/api/infrastructure/group/${currentViewedGroupId}/members`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action: 'remove', agent_id: id}) }); openGroupFullView(currentViewedGroupId); } }
async function deleteCurrentGroup() { if(confirm("Permanently delete group?")) { await fetch('/api/infrastructure/group/' + currentViewedGroupId, { method: 'DELETE' }); location.reload(); } }
async function cleanupTasks(d) { await fetch('/api/infrastructure/tasks/cleanup', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({days: d}) }); loadQueue(); }
function confirmDeleteHostFromTable(id, n) { currentViewedHostId = id; const el = document.getElementById('confName'); if(el) el.innerText = n; openModal('confirmModal'); }
function confirmDeleteHost() { const elName = document.getElementById('mName'); const elConf = document.getElementById('confName'); if(elName && elConf) elConf.innerText = elName.innerText; openModal('confirmModal'); }
if(document.getElementById('finalDelBtn')) document.getElementById('finalDelBtn').onclick = async () => { await fetch('/api/infrastructure/host/' + currentViewedHostId, { method: 'DELETE' }); location.reload(); };
