// --- БЕЗПЕЧНА ІНІЦІАЛІЗАЦІЯ ---
let socket;
try {
    if (typeof io !== 'undefined') {
        socket = io();
        socket.on('connect', () => { console.log('Connected to WebSockets successfully'); });
        socket.on('log_update', (msg) => {
            const tLogElement = document.getElementById('tLog');
            const taskModal = document.getElementById('taskModal');
            if (tLogElement && taskModal && !taskModal.classList.contains('hidden')) {
                if (tLogElement.innerText === "Loading..." || tLogElement.innerText === "Waiting for agent pulse...") { tLogElement.innerText = ""; }
                tLogElement.innerText += msg.data + "\n";
                tLogElement.scrollTop = tLogElement.scrollHeight;
            }
        });
    }
} catch (e) {
    console.warn("SocketIO не завантажено.");
}

let allQueueJobs = [];
let allReports = [];
let smtpProfiles = [];
let scheduledReports = [];
let currentJobTasks = [];
let currentViewedJobId = null;
let currentJobStatusFilter = 'all';
let currentViewedHostId = null;
let currentViewedGroupId = null;
let currentGroupNonMembers = [];
let currentReportId = null;

let selectedTemplateId = null;
let editingTemplateId = null;
let currentTemplateVariables = [];
let teleChart = null;
let diskChart = null;
let activityChart = null;
let currentHostStatus = 'all';
let queueTypeFilter = 'ALL';
const infraPermissions = window.WinhubPermissions || {};
let payloadEditor = null;
const infraStateKeys = {
    view: 'infra_vfinal_view',
    nodeTab: 'infra_nodes_active_tab',
    categories: 'infra_open_categories',
    template: 'infra_selected_template'
};
let workspaceTab = 'builder';
let guideLanguage = localStorage.getItem('infra_workspace_guide_lang') || 'en';
let multiHostSelectedIds = new Set();
let pendingTemplateImport = [];

function getPayloadValue() {
    if (payloadEditor) return payloadEditor.getValue();
    return document.getElementById('depPayload')?.value || '';
}

function setPayloadValue(value) {
    const nextValue = value || '';
    if (payloadEditor) {
        payloadEditor.setValue(nextValue);
    }
    const textarea = document.getElementById('depPayload');
    if (textarea) textarea.value = nextValue;
}

function syncPayloadTextarea() {
    const textarea = document.getElementById('depPayload');
    if (textarea && payloadEditor) textarea.value = payloadEditor.getValue();
}

function setEditorMode(mode) {
    if (!payloadEditor) return;
    payloadEditor.setOption('mode', mode || 'powershell');
}

function refreshPayloadEditor() {
    if (payloadEditor) {
        setTimeout(() => {
            payloadEditor.refresh();
            payloadEditor.setOption('lineNumbers', true);
        }, 40);
    }
}

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
    const textarea = document.getElementById('depPayload');
    if (!textarea || payloadEditor || typeof CodeMirror === 'undefined') return;

    payloadEditor = CodeMirror.fromTextArea(textarea, {
        mode: 'powershell',
        theme: 'material-darker',
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

    payloadEditor.on('change', () => {
        syncPayloadTextarea();
        updateVariablesUI();
    });
}

function switchWorkspaceTab(tab) {
    workspaceTab = tab || 'builder';
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
                    smtpProfiles.map(p => `<option value="${p.email}">${p.email}</option>`).join('');
                if (currentVal) selDep.value = currentVal;
            }

            // Наповнюємо дропдаун в модалці Reports
            const selRep = document.getElementById('reportSenderEmail');
            if (selRep) {
                const currentVal = selRep.value;
                selRep.innerHTML = '<option value="">-- Select Sender Profile --</option>' +
                    smtpProfiles.map(p => `<option value="${p.email}">${p.email}</option>`).join('');
                if (currentVal) selRep.value = currentVal;
            }
        }
    } catch (e) { console.error("Error fetching SMTP", e); }
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
    while ((match = regex.exec(scriptText)) !== null) {
        vars.add(match[1]);
    }

    const varArea = document.getElementById('templateVariablesArea');
    const varContainer = document.getElementById('variablesContainer');
    if(!varArea || !varContainer) return;

    if (vars.size > 0) {
        varArea.classList.remove('hidden');

        const currentValues = {};
        document.querySelectorAll('.tpl-var-input').forEach(inp => {
            currentValues[inp.dataset.var] = inp.value;
        });

        varContainer.innerHTML = Array.from(vars).map(v => `
            <div>
                <label class="text-[10px] font-black text-indigo-400 uppercase tracking-widest block mb-2 ml-2">${v}</label>
                <input type="text" data-var="${v}" value="${currentValues[v] || ''}" class="tpl-var-input w-full p-4 bg-white border border-indigo-100 rounded-2xl text-sm font-bold shadow-sm outline-none focus:ring-2 focus:ring-indigo-500" placeholder="Enter value for ${v}...">
            </div>
        `).join('');
    } else {
        varArea.classList.add('hidden');
        varContainer.innerHTML = '';
    }
}


// --- REPORTS (BUFFER) & SMTP LOGIC ---
async function loadReports() {
    try {
        const res = await fetch('/api/infrastructure/reports/all');
        const data = await res.json();
        if (data.success) {
            allReports = data.data;
            renderReports();
        }
    } catch(e) { console.error("Error loading reports", e); }
}

function renderReports() {
    const container = document.getElementById('reportsList');
    if(!container) return;

    if(!allReports || allReports.length === 0) {
        container.innerHTML = `<div class="col-span-full py-20 text-center"><p class="text-slate-400 font-bold uppercase tracking-widest text-sm mb-2">No Reports Found</p><p class="text-slate-400 text-xs">Completed multi-host tasks will appear here.</p></div>`;
        return;
    }

    container.innerHTML = allReports.map(r => {
        let statusCls = r.status === 'Waiting Review' ? 'bg-amber-100 text-amber-700 border-amber-200' : (r.status.startsWith('Sent') ? 'bg-indigo-100 text-indigo-700 border-indigo-200' : 'bg-slate-100 text-slate-500 border-slate-200');
        let dotColor = r.error > 0 ? 'bg-rose-500' : (r.success > 0 ? 'bg-emerald-500' : 'bg-slate-300');

        return `
        <div class="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm hover:shadow-lg hover:border-indigo-300 transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between cursor-pointer gap-4" onclick="viewReport('${r.id}')">
            <div class="flex items-center gap-4 w-full sm:w-auto">
                <div class="w-1.5 h-12 rounded-full ${dotColor} shrink-0 shadow-sm"></div>
                <div class="min-w-0">
                    <h3 class="text-sm font-black text-slate-800 tracking-tight truncate">${r.title}</h3>
                    <div class="flex gap-2 items-center mt-1">
                        <span class="text-[10px] text-slate-400 font-bold uppercase tracking-widest">${r.created_at}</span>
                        <span class="text-slate-300">•</span>
                        <span class="text-[10px] text-slate-500 font-bold">Total: ${r.total} | <span class="text-emerald-500">Succ: ${r.success}</span> | <span class="text-rose-500">Err: ${r.error}</span></span>
                    </div>
                </div>
            </div>
            <div class="shrink-0">
                <span class="px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border shadow-sm ${statusCls}">${r.status}</span>
            </div>
        </div>`;
    }).join('');
}

function viewReport(id) {
    const r = allReports.find(x => x.id === id);
    if(!r) return;
    currentReportId = id;
    window.currentReportId = id;

    document.getElementById('vrTitle').innerText = r.title;

    let statusCls = r.status === 'Waiting Review' ? 'bg-amber-100 text-amber-700 border-amber-200' : (r.status.startsWith('Sent') ? 'bg-indigo-100 text-indigo-700 border-indigo-200' : 'bg-slate-100 text-slate-500 border-slate-200');
    const stEl = document.getElementById('vrStatus');
    if(stEl) {
        stEl.innerText = r.status;
        stEl.className = `px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest border shadow-sm ${statusCls}`;
    }

    const bodyEl = document.getElementById('vrBody');
    if(bodyEl) bodyEl.value = r.report_data || "";

    const saveBtn = document.getElementById('btnSaveReportText');
    if(saveBtn) {
        saveBtn.innerText = "Save Changes";
        saveBtn.className = "px-6 py-3 bg-emerald-50 text-emerald-600 border border-emerald-200 hover:bg-emerald-100 rounded-2xl text-xs font-black uppercase transition-all shadow-sm";
    }

    openModal('reportViewModal');
}

async function saveReportChanges() {
    const bodyEl = document.getElementById('vrBody');
    if(!bodyEl) return;
    const newText = bodyEl.value;

    const btn = document.getElementById('btnSaveReportText');
    if(btn) btn.innerText = "Saving...";

    try {
        await fetch(`/api/infrastructure/reports/${currentReportId}/action`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'save', report_data: newText})
        });

        const r = allReports.find(x => x.id === currentReportId);
        if(r) r.report_data = newText;

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
    } catch(e) { console.error("Error saving report", e); }
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
                <p class="font-black text-slate-800 text-sm">${p.email}</p>
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">${p.host} : ${p.port}</p>
            </div>
            <button onclick="deleteSmtpProfile('${p.email}')" class="p-2 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors">
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

    if(!email || !host || !password) return alert("Fill all fields (Email, Host, App Password).");

    try {
        await fetch('/api/infrastructure/smtp', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, host, port, password})
        });
        document.getElementById('smtpEmail').value = '';
        document.getElementById('smtpHost').value = '';
        document.getElementById('smtpPass').value = '';

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
        <div class="flex justify-between items-center bg-slate-50 p-4 rounded-xl border border-slate-100">
            <div>
                <p class="font-black text-slate-800 text-sm">${s.name}</p>
                <p class="text-[10px] font-mono text-indigo-600 mt-1">${s.placeholder}</p>
            </div>
            <button onclick="deleteTemplateSecret('${s.name}')" class="p-2 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </button>
        </div>
    `).join('') || '<p class="text-center text-slate-400 text-sm font-bold p-6">No template secrets configured.</p>';
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
                    <span class="font-bold text-slate-700 text-sm">${cat}</span>
                    ${!isDefault
                        ? `<button onclick="deleteCategoryUI('${cat}')" class="text-rose-400 hover:text-rose-600 hover:bg-rose-50 p-2 rounded-xl transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>`
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
        const saved = localStorage.getItem(infraStateKeys.view) || defaultView;
        switchView(document.getElementById('view-' + saved) ? saved : defaultView, false);
        renderCategoryListUI();
        restoreOpenCategories();
        updateInfraNavArrows();
        document.getElementById('infraNavScroller')?.addEventListener('scroll', updateInfraNavArrows);
        window.addEventListener('resize', updateInfraNavArrows);

        fetchSmtpProfilesGlobally(); // ГЛОБАЛЬНЕ ЗАВАНТАЖЕННЯ ПОШТ
        initAvailableHostsData();

        const hostSearchEl = document.getElementById('hostSearch');
        if(hostSearchEl) hostSearchEl.addEventListener('input', applyHostFilters);

        initPayloadEditor();
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

    } catch(e) {
        console.error("Initialization error:", e);
    }
});

function switchView(view, save=true) {
    if(save) localStorage.setItem(infraStateKeys.view, view);
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
    if(view === 'deploy') refreshPayloadEditor();
    if(view === 'hosts') switchNodeTab(localStorage.getItem(infraStateKeys.nodeTab) || 'approved', false);
    if(view === 'software') loadSoftwareRegistry();
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
        const text = `${h.name || ''} ${h.ip || ''} ${h.os_type || ''} ${h.agent_version || ''}`.toLowerCase();
        return text.includes(q);
    });

    list.innerHTML = filtered.map(h => {
        const hostId = String(h.id);
        const safeId = escapeHtml(hostId);
        const isChecked = multiHostSelectedIds.has(hostId) ? 'checked' : '';
        const blockedBadge = h.is_blocked ? '<span class="ml-2 px-2 py-0.5 rounded bg-rose-50 text-rose-600 border border-rose-100 text-[9px] font-black uppercase">Blocked</span>' : '';
        const approval = h.approval_status || 'Approved';
        const approvalBadge = approval !== 'Approved' ? `<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-600 border border-amber-100 text-[9px] font-black uppercase">${approval}</span>` : '';
        const versionBadge = h.agent_outdated ? '<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-100 text-[9px] font-black uppercase">Outdated</span>' : '';
        const statusBadge = multiHostStatusBadge(h);
        const disabled = approval !== 'Approved' || h.is_blocked ? 'disabled' : '';
        return `
        <label class="flex items-center gap-4 p-4 border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors group ${disabled ? 'opacity-60' : ''}">
            <input type="checkbox" value="${safeId}" ${isChecked} ${disabled} class="multi-host-cb w-5 h-5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" onchange="toggleMultiHostSelection(this.value, this.checked)">
            <span class="min-w-0">
                <span class="flex flex-wrap items-center gap-2 font-black text-slate-700 text-sm group-hover:text-indigo-600 transition-colors">${escapeHtml(h.name || hostId)} ${statusBadge}${blockedBadge}${approvalBadge}${versionBadge}</span>
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
        .sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)));

    container.innerHTML = selectedHosts.map(h => `
        <div class="flex items-start justify-between gap-3 p-3 bg-white border border-slate-200 rounded-2xl shadow-sm">
            <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2 font-black text-slate-800 text-sm">${escapeHtml(h.name || h.id)} ${multiHostStatusBadge(h)}</div>
                <div class="text-[10px] text-slate-400 font-bold mt-1 truncate">${escapeHtml(h.ip || 'No IP')} / Agent ${escapeHtml(h.agent_version || 'unknown')} / Last seen ${escapeHtml(h.last_seen || '-')}</div>
            </div>
            <button onclick="removeMultiHostSelection('${escapeHtml(String(h.id))}')" class="shrink-0 p-2 bg-slate-50 hover:bg-rose-50 text-slate-400 hover:text-rose-600 rounded-xl border border-slate-100 hover:border-rose-100 transition-colors" title="Remove endpoint">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" stroke-width="2.5" stroke-linecap="round"/></svg>
            </button>
        </div>
    `).join('') || '<div class="h-full min-h-[180px] flex items-center justify-center text-center text-slate-400 text-sm font-bold p-8">No endpoints selected yet.</div>';
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
function resetWorkspace(clearPersistedState = true) {
    editingTemplateId = null; selectedTemplateId = null; currentTemplateVariables = [];
    if (clearPersistedState) localStorage.removeItem(infraStateKeys.template);

    ['depTitle', 'depCategory', 'depReportTemplate'].forEach(id => {
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
        saveTemplateBtn.title = '';
    }

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
    if (isAdmin && canEditTemplate) {
        editingTemplateId = el.dataset.id;
        const saveTemplateBtn = document.getElementById('btnSaveTemplate');
        if(saveTemplateBtn) {
            saveTemplateBtn.disabled = false;
            saveTemplateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            saveTemplateBtn.title = '';
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
    }, 50);

    updateVariablesUI();
    toggleActionView();
}

function restoreWorkspaceState() {
    const templateId = localStorage.getItem(infraStateKeys.template);
    if (!templateId) {
        if (document.getElementById('btnNewScript')) resetWorkspace(false);
        return;
    }

    const card = Array.from(document.querySelectorAll('.template-card')).find(item => item.dataset.id === templateId);
    if (!card) {
        localStorage.removeItem(infraStateKeys.template);
        if (document.getElementById('btnNewScript')) resetWorkspace(false);
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
    syncPayloadTextarea();

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
            payload.classList.remove('text-emerald-400', 'bg-[#0f172a]', 'border-slate-800');
            payload.classList.add('text-sky-700', 'bg-sky-50', 'border-sky-200');
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
            payload.classList.remove('text-sky-700', 'bg-sky-50', 'border-sky-200');
            payload.classList.add('text-emerald-400', 'bg-[#0f172a]', 'border-slate-800');
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
            payload.classList.remove('text-sky-700', 'bg-sky-50', 'border-sky-200');
            payload.classList.add('text-emerald-400', 'bg-[#0f172a]', 'border-slate-800');
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
    const isScriptMode = actionEl.value === 'run_script';

    const payArea = document.getElementById('payloadArea');
    const tplArea = document.getElementById('templateInfoArea');

    if (isAdmin) {
        if(payArea) payArea.classList.toggle('hidden', !isScriptMode);
        if(tplArea) tplArea.classList.toggle('hidden', isScriptMode);
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
            return payload;
        } catch(e) {
            alert('Agent update template payload must be valid JSON.');
            throw e;
        }
    }
    return {
        script: getPayloadValue(),
        __report_template_id: document.getElementById('depReportTemplate')?.value || '',
        __auto_email_toggle: document.getElementById('depAutoEmailToggle')?.checked || false,
        __auto_email_sender: document.getElementById('depAutoEmailSender')?.value || '',
        __auto_email_recipients: document.getElementById('depAutoEmailRecipients')?.value || '',
        __auto_email_use_gpg: document.getElementById('depAutoEmailUseGpg')?.checked !== false,
        __template_policy: policy
    };
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
    body.innerHTML = pendingTemplateImport.map((tpl, index) => `
        <label class="flex items-start gap-3 p-4 bg-white border border-slate-200 rounded-2xl shadow-sm hover:border-indigo-200 transition-colors cursor-pointer">
            <input type="checkbox" class="template-import-cb mt-1 w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" value="${index}" checked onchange="updateTemplateImportSelection()">
            <span class="min-w-0 flex-1">
                <span class="block font-black text-slate-800 text-sm truncate">${escapeHtml(tpl.name || 'Untitled')}</span>
                <span class="block text-[10px] font-black text-slate-400 uppercase tracking-widest mt-1">${escapeHtml(tpl.category || 'Imported')} / ${escapeHtml(tpl.type || 'action')} / ${escapeHtml(tpl.action_type || tpl.action || 'run_script')}</span>
            </span>
            <span class="px-2 py-1 rounded-lg bg-slate-100 text-slate-500 text-[9px] font-black uppercase">${tpl.is_approved ? 'Shared' : 'Draft'}</span>
        </label>
    `).join('');
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

async function deleteTemplate(id) {
    if (!id) return;
    if (!confirm("Delete this template? Scheduled jobs using it will be removed.")) return;

    try {
        const res = await fetch('/api/infrastructure/templates/' + encodeURIComponent(id), {
            method: 'DELETE'
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.success === false) {
            return alert(data.message || 'Failed to delete template.');
        }

        if (selectedTemplateId === id || editingTemplateId === id) {
            selectedTemplateId = null;
            editingTemplateId = null;
        }
        window.location.reload();
    } catch(e) {
        alert("Error deleting template.");
    }
}

let fleetCenterData = { hosts: [], packages: [] };
let fleetSelectedHostIds = new Set();
let fleetSortState = { key: 'hostname', direction: 'asc' };
let softwareRegistryData = { packages: [] };
let softwareSelectedHostIds = new Set();
let softwareSelectedPackageId = null;
let softwareActiveTab = 'library';
let softwareInfoLanguage = localStorage.getItem('software_info_lang') || 'en';
let softwareOpenGroups = new Set(JSON.parse(localStorage.getItem('software_open_groups') || '[]'));
let softwareCodeEditors = new Map();

async function loadFleetCenter() {
    const body = document.getElementById('fleetHostsBody');
    if (!body) return;
    try {
        const res = await fetch('/api/infrastructure/fleet');
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || 'Fleet load failed');
        fleetCenterData = data;
        const liveHostIds = new Set((fleetCenterData.hosts || []).map(host => host.id));
        fleetSelectedHostIds = new Set(Array.from(fleetSelectedHostIds).filter(id => liveHostIds.has(id)));
        renderFleetCenter();
    } catch(e) {
        body.innerHTML = '<tr><td colspan="8" class="p-12 text-center text-rose-400 font-black">Failed to load fleet data.</td></tr>';
    }
}

function updateFleetSelectedCount() {
    const countEl = document.getElementById('fleetSelectedCount');
    if (countEl) countEl.innerText = fleetSelectedHostIds.size;
}

function toggleFleetHostSelection(id, checked) {
    if (checked) fleetSelectedHostIds.add(id);
    else fleetSelectedHostIds.delete(id);
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
    return String(host[key] || '').toLowerCase();
}

window.setFleetSort = function setFleetSort(key) {
    if (fleetSortState.key === key) {
        fleetSortState.direction = fleetSortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
        fleetSortState = { key, direction: 'desc' };
        if (key === 'hostname') fleetSortState.direction = 'asc';
    }
    renderFleetCenter();
};

window.setFleetStatusFilter = function setFleetStatusFilter(status) {
    const select = document.getElementById('fleetStatusFilter');
    if (select) select.value = status || 'all';
    document.querySelectorAll('.fleet-status-tab').forEach(btn => {
        const active = btn.dataset.fleetStatus === (status || 'all');
        btn.className = `fleet-status-tab px-4 py-2 rounded-xl text-[10px] font-black uppercase border transition-all ${active ? 'bg-[#0f3d8a] text-white border-[#75a7f7] shadow-sm' : 'bg-white text-slate-700 border-slate-200 hover:bg-blue-50 hover:text-[#0f3d8a]'}`;
    });
    renderFleetCenter();
};

function renderFleetCenter() {
    const body = document.getElementById('fleetHostsBody');
    const packagesBox = document.getElementById('agentPackageList');
    const packageSelect = document.getElementById('fleetPackageSelect');
    if (!body) return;

    const search = (document.getElementById('fleetSearch')?.value || '').trim().toLowerCase();
    const statusFilter = document.getElementById('fleetStatusFilter')?.value || 'all';
    const groupFilters = Array.from(document.querySelectorAll('#fleetGroupFilters input[type="checkbox"]:checked')).map(cb => String(cb.value));
    const hosts = (fleetCenterData.hosts || []).filter(host => {
        const health = host.health || {};
        const encryption = host.encryption || {};
        const groupText = (host.groups || []).map(group => group.name).join(' ');
        const duplicateText = host.possible_duplicate ? 'duplicate identity approved duplicate' : '';
        const keyText = host.agent_identity_key_enrolled ? 'signed key enrolled identity key ok' : 'missing key unsigned no key';
        const haystack = [host.hostname, host.ip, host.os, host.agent_version, host.identity_fingerprint, duplicateText, keyText, groupText, health.status, encryption.status, ...(encryption.methods || []), ...(health.reasons || [])].join(' ').toLowerCase();
        const matchSearch = !search || haystack.includes(search);
        const hostGroupIds = (host.groups || []).map(group => String(group.id));
        const wantsUngrouped = groupFilters.includes('ungrouped');
        const selectedGroupIds = groupFilters.filter(value => value !== 'ungrouped');
        const matchGroup = groupFilters.length === 0
            || (wantsUngrouped && hostGroupIds.length === 0 && selectedGroupIds.length === 0)
            || (selectedGroupIds.length > 0 && selectedGroupIds.every(groupId => hostGroupIds.includes(groupId)) && !wantsUngrouped);
        let matchStatus = true;
        if (statusFilter === 'outdated') matchStatus = !!health.outdated;
        else if (statusFilter === 'current') matchStatus = !health.outdated;
        else if (statusFilter === 'warning') matchStatus = ['Warning', 'Critical'].includes(health.status);
        else if (statusFilter === 'unsigned') matchStatus = !host.agent_identity_key_enrolled;
        return matchSearch && matchGroup && matchStatus;
    }).sort((a, b) => {
        const av = fleetSortValue(a, fleetSortState.key);
        const bv = fleetSortValue(b, fleetSortState.key);
        const result = typeof av === 'number' && typeof bv === 'number'
            ? av - bv
            : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
        return fleetSortState.direction === 'asc' ? result : -result;
    });

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
        const encryptionTitle = (encryption.methods || []).join(', ') || 'No encryption method detected';
        const groups = (host.groups || []).map(group => `<span class="px-2 py-1 rounded-lg bg-slate-100 text-slate-500 border border-slate-200 text-[9px] font-black uppercase">${escapeHtml(group.name)}</span>`).join('');
        const keyClass = host.agent_identity_key_enrolled ? 'text-emerald-700 bg-emerald-50 border-emerald-100' : 'text-violet-700 bg-violet-50 border-violet-100';
        const keyLabel = host.agent_identity_key_enrolled ? 'Key OK' : 'No key';
        const healthReasons = (health.reasons || []).map(escapeHtml).join(', ') || 'current version, signed key, approved, unblocked';
        const checked = fleetSelectedHostIds.has(host.id) ? 'checked' : '';
        const duplicateMatches = (host.duplicate_matches || []).filter(match => match.strong_match);
        const duplicateSummary = duplicateMatches.map(match => `${match.hostname || match.id} / ${match.agent_version || 'unknown'} / ${(match.reasons || []).join(', ')}`).join(' | ');
        const duplicateBadge = host.possible_duplicate
            ? `<div class="mt-2 inline-flex px-2.5 py-1 rounded-lg bg-rose-50 text-rose-700 border border-rose-100 text-[9px] font-black uppercase" title="${escapeHtml(duplicateSummary || 'Same stable identity as another approved node')}">Duplicate identity</div>`
            : '';
        return `<tr class="${host.possible_duplicate ? 'bg-rose-50/35' : ''}">
            <td class="px-6 py-4">
                <input type="checkbox" value="${escapeHtml(host.id)}" ${checked} onchange="toggleFleetHostSelection('${escapeHtml(host.id)}', this.checked)" class="fleet-host-cb w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500">
            </td>
            <td class="px-6 py-4">
                <button onclick="viewHost('${escapeHtml(host.id)}')" class="font-black text-slate-800 hover:text-indigo-600 text-left">${escapeHtml(host.hostname)}</button>
                <div class="text-[10px] font-bold text-slate-400 uppercase mt-1">${escapeHtml(host.os || 'Windows')}</div>
                ${duplicateBadge}
            </td>
            <td class="px-6 py-4"><span class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${versionClass}">${escapeHtml(host.agent_version || 'unknown')}</span></td>
            <td class="px-6 py-4">
                <span title="${healthReasons}" class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${healthClass}">${health.score || 0}% ${escapeHtml(health.status || 'Unknown')}</span>
                <span class="ml-1 inline-flex whitespace-nowrap px-2 py-1 rounded-lg border text-[9px] font-black uppercase ${keyClass}" title="Agent request signing key exchange">${keyLabel}</span>
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
    }).join('') || '<tr><td colspan="9" class="p-12 text-center text-slate-500 font-black">No fleet hosts match filters.</td></tr>';
    updateFleetSelectedCount();

    if (packagesBox) {
        packagesBox.innerHTML = (fleetCenterData.packages || []).map(pkg => `
            <div class="p-4 rounded-2xl border border-slate-200 bg-slate-50">
                <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0">
                        <div class="font-black text-slate-800 text-sm truncate">${escapeHtml(pkg.version)}</div>
                        <div class="text-[10px] font-bold text-slate-400 uppercase mt-1">${Math.round((pkg.size || 0) / 1024 / 1024 * 10) / 10} MB</div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button onclick="navigator.clipboard.writeText('${escapeHtml(pkg.sha256)}')" class="px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-[9px] font-black uppercase text-slate-500 hover:text-indigo-600">SHA</button>
                        ${window.WinhubIsAdmin ? `<button onclick="deleteAgentPackage('${escapeHtml(pkg.id)}', '${escapeHtml(pkg.version)}')" class="px-3 py-1.5 rounded-xl bg-white border border-rose-100 text-[9px] font-black uppercase text-rose-500 hover:bg-rose-50">Delete</button>` : ''}
                    </div>
                </div>
                <div class="mt-2 text-[10px] font-mono text-slate-500 break-all">${escapeHtml(pkg.sha256 || '')}</div>
            </div>
        `).join('') || '<div class="p-4 rounded-xl bg-slate-50 text-xs font-bold text-slate-400">No packages uploaded yet.</div>';
    }
    if (packageSelect) {
        packageSelect.innerHTML = (fleetCenterData.packages || []).map(pkg =>
            `<option value="${escapeHtml(pkg.id)}">${escapeHtml(pkg.version)} (${escapeHtml(pkg.original_filename || 'package')})</option>`
        ).join('') || '<option value="">No packages available</option>';
    }
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
    alert(`Rollout queued for ${data.targets} hosts in ${data.waves} wave(s).`);
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
            theme: 'material-darker',
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
            return `<div onclick="selectSoftwarePackage('${escapeHtml(pkg.id)}')" class="group grid grid-cols-12 gap-3 items-center px-4 py-3 border-t border-slate-200 ${active ? 'bg-indigo-50/70' : 'bg-white hover:bg-slate-50'} transition-all cursor-pointer">
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

async function submitDeployment() {
    const btn = document.getElementById('btnDeploy');
    const oldText = btn.innerText;
    btn.disabled = true; btn.innerText = "Dispatching...";

    const action = document.getElementById('depAction').value;
    const targetType = document.getElementById('depType').value;
    const reportTemplateId = document.getElementById('depReportTemplate')?.value || null;

    const tplVars = {};
    document.querySelectorAll('.tpl-var-input').forEach(inp => {
        tplVars[inp.dataset.var] = inp.value;
    });

    const data = {
        title: document.getElementById('depTitle').value || "Manual Action",
        target_type: targetType,
        action,
        template_id: selectedTemplateId,
        report_template_id: reportTemplateId,
        variables: tplVars,
        auto_email_toggle: document.getElementById('depAutoEmailToggle')?.checked || false,
        auto_email_sender: document.getElementById('depAutoEmailSender')?.value || '',
        auto_email_recipients: document.getElementById('depAutoEmailRecipients')?.value || '',
        auto_email_use_gpg: document.getElementById('depAutoEmailUseGpg')?.checked !== false
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
    if (save) localStorage.setItem(infraStateKeys.nodeTab, tab);
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
        btn.className = "node-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-amber-700";
    });
    const active = buttons[tab] || buttons.approved;
    if (active) active.className = "node-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm";
    if (tab === 'review') switchReviewTab(localStorage.getItem('winhub_infra_review_tab') || 'pending', false);
    if (tab === 'approved') loadFleetCenter();
}

function switchReviewTab(tab, save = true) {
    if (!['pending', 'duplicates', 'rejected'].includes(tab)) tab = 'pending';
    if (save) localStorage.setItem('winhub_infra_review_tab', tab);
    const panels = {
        pending: document.getElementById('nodesPendingPanel'),
        duplicates: document.getElementById('nodesApprovedDuplicatesPanel'),
        rejected: document.getElementById('nodesRejectedPanel'),
    };
    Object.entries(panels).forEach(([key, panel]) => {
        if (panel) panel.classList.toggle('hidden', key !== tab);
    });
    document.querySelectorAll('.review-tab-btn').forEach(btn => {
        btn.className = "review-tab-btn px-4 py-2 rounded-xl text-[10px] font-black uppercase text-slate-700 hover:text-rose-700";
    });
    const active = document.getElementById('reviewTab-' + tab);
    if (active) active.className = "review-tab-btn px-4 py-2 rounded-xl text-[10px] font-black uppercase bg-slate-900 text-white shadow-sm";
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
                    <td class="px-8 py-5 font-black text-slate-700">${m.item_name}</td>
                    <td class="px-8 py-5"><span class="bg-purple-50 text-purple-700 font-mono text-sm px-3 py-1 rounded-lg border border-purple-100">${m.last_value || 'No data'}</span></td>
                    <td class="px-8 py-5 text-right text-xs font-bold text-slate-400">${m.last_updated}</td>
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

            renderActivityChart(json.data);
        } else {
            if(tLoading) { tLoading.innerText = "No telemetry data recorded for this period."; tLoading.classList.remove('hidden'); }
            if(dLoading) { dLoading.innerText = "No disk data recorded for this period."; dLoading.classList.remove('hidden'); }
            if(aLoading) { aLoading.innerText = "No activity data recorded for this period."; aLoading.classList.remove('hidden'); }
            if(teleChart) teleChart.destroy();
            if(diskChart) diskChart.destroy();
            if(activityChart) activityChart.destroy();
        }
    } catch(e) {
        if(tLoading) { tLoading.innerText = "Failed to load telemetry."; tLoading.classList.remove('hidden'); }
        if(dLoading) { dLoading.innerText = "Failed to load disk telemetry."; dLoading.classList.remove('hidden'); }
        if(aLoading) { aLoading.innerText = "Failed to load activity timeline."; aLoading.classList.remove('hidden'); }
    }
}

function buildActivityPoints(records) {
    const points = [];
    const sorted = (records || [])
        .map(row => ({...row, date: row.timestamp ? new Date(row.timestamp) : null}))
        .filter(row => row.date && !Number.isNaN(row.date.getTime()))
        .sort((a, b) => a.date - b.date);
    if(sorted.length === 0) return points;

    const medianGapMs = (() => {
        const gaps = [];
        for(let i = 1; i < sorted.length; i++) {
            const gap = sorted[i].date - sorted[i - 1].date;
            if(gap > 0) gaps.push(gap);
        }
        if(!gaps.length) return 120000;
        gaps.sort((a, b) => a - b);
        return gaps[Math.floor(gaps.length / 2)];
    })();
    const offlineGapMs = Math.max(5 * 60 * 1000, medianGapMs * 3);

    points.push({x: sorted[0].time, y: 1});
    for(let i = 1; i < sorted.length; i++) {
        const previous = sorted[i - 1];
        const current = sorted[i];
        const gap = current.date - previous.date;
        if(gap > offlineGapMs) {
            points.push({x: previous.time, y: 1});
            points.push({x: previous.time + ' +gap', y: 0});
            points.push({x: current.time, y: 0});
        }
        points.push({x: current.time, y: 1});
    }
    return points;
}

function renderActivityChart(records) {
    if(activityChart) { activityChart.destroy(); activityChart = null; }
    const ctxActivity = document.getElementById('activityChart');
    if(!ctxActivity || typeof Chart === 'undefined') return;

    const points = buildActivityPoints(records);
    activityChart = new Chart(ctxActivity.getContext('2d'), {
        type: 'line',
        data: {
            labels: points.map(point => point.x),
            datasets: [{
                label: 'Agent Activity',
                data: points.map(point => point.y),
                borderColor: '#059669',
                backgroundColor: '#10b98122',
                fill: true,
                stepped: true,
                tension: 0,
                pointRadius: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 0,
                    max: 1,
                    ticks: {
                        stepSize: 1,
                        callback: value => value === 1 ? 'Online' : 'Offline'
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: context => context.raw === 1 ? 'Online' : 'Offline'
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
function setQueueTypeFilter(type, btn) {
    queueTypeFilter = type;
    document.querySelectorAll('.q-type-btn').forEach(b => {
        b.classList.remove('bg-white', 'text-indigo-600', 'shadow-sm');
        b.classList.add('text-slate-500');
    });
    if(btn) {
        btn.classList.remove('text-slate-500');
        btn.classList.add('bg-white', 'text-indigo-600', 'shadow-sm');
    }
    renderQueue();
}

async function loadQueue() {
    try {
        const res = await fetch('/api/infrastructure/tasks/all');
        const data = await res.json();
        if (!data.success) return;
        allQueueJobs = data.jobs;

        const users = new Set(allQueueJobs.map(j => j.created_by));
        const uSelect = document.getElementById('qFilterUser');
        if(uSelect && uSelect.options.length <= 1) {
            users.forEach(u => { if(u) uSelect.add(new Option(u, u)); });
            uSelect.add(new Option('System (Auto)', 'System'));
        }

        renderQueue();
        const t = document.getElementById('statQTotal');
        const p = document.getElementById('statQPending');
        if(t) t.innerText = allQueueJobs.length;
        if(p) p.innerText = allQueueJobs.filter(j => j.status === 'Pending' || j.status === 'Running').length;
    } catch(e) { console.error("Error loading queue:", e); }
}

function renderQueue() {
    const tbody = document.getElementById('queueBody');
    if(!tbody) return;

    const searchEl = document.getElementById('queueSearch');
    const q = (searchEl ? searchEl.value : '').toLowerCase();

    const uFilterEl = document.getElementById('qFilterUser');
    const uFilter = uFilterEl ? uFilterEl.value : '';

    const filtered = allQueueJobs.filter(j => {
        const titleLower = (j.title || '').toLowerCase();
        const matchSearch = titleLower.includes(q) || (j.target_summary || '').toLowerCase().includes(q) || (j.status || '').toLowerCase().includes(q);

        let matchUser = true;
        if(uFilter !== '') {
            if(uFilter === 'System') matchUser = !j.created_by || j.created_by === 'System';
            else matchUser = j.created_by === uFilter;
        }

        let matchType = true;
        if(queueTypeFilter === 'Auto') matchType = titleLower.startsWith('[auto] ');
        else if(queueTypeFilter === 'Auto-Fix') matchType = titleLower.startsWith('[auto-fix]');
        else if(queueTypeFilter === 'Manual') matchType = !titleLower.startsWith('[auto]') && !titleLower.startsWith('[auto-fix]');

        return matchSearch && matchUser && matchType;
    });

    tbody.innerHTML = filtered.map(j => {
        const statusStr = j.status || 'Pending';
        let cls = statusStr === 'Pending' ? 'bg-amber-100 text-amber-700' : (statusStr === 'Success' ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700');
        if (statusStr === 'Cancelled') cls = 'bg-slate-100 text-slate-500';
        if (j.error > 0 && j.success > 0) cls = 'bg-orange-100 text-orange-700';

        let actionBtn = '';
        if(infraPermissions.cleanup_tasks || infraPermissions.run_tasks) {
            actionBtn = `<td class="px-10 py-4 text-right">
                <div class="flex justify-end gap-2">
                    ${infraPermissions.run_tasks && j.error > 0 ? `<button onclick="event.stopPropagation(); retryFailedJob('${j.job_id}')" class="p-3 bg-white border border-slate-200 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-2xl transition-colors shadow-sm" title="Retry failed hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M4 4v6h6M20 20v-6h-6M5 19A9 9 0 0119 5l1 1M19 5A9 9 0 005 19l-1-1" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${infraPermissions.run_tasks && j.pending > 0 && (j.success + j.error) > 0 ? `<button onclick="event.stopPropagation(); finalizeJobReport('${j.job_id}')" class="p-3 bg-white border border-slate-200 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-2xl transition-colors shadow-sm" title="Finalize report without pending hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M9 12l2 2 4-5M4 20h16M5 4h14v12H5z" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${infraPermissions.run_tasks && j.pending > 0 ? `<button onclick="event.stopPropagation(); cancelPendingJob('${j.job_id}')" class="p-3 bg-white border border-slate-200 text-slate-400 hover:text-amber-600 hover:bg-amber-50 rounded-2xl transition-colors shadow-sm" title="Cancel pending hosts"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10 10l4 4m0-4l-4 4M12 22a10 10 0 100-20 10 10 0 000 20z" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg></button>` : ''}
                    ${infraPermissions.cleanup_tasks ? `<button onclick="event.stopPropagation(); deleteJob('${j.job_id}')" class="p-3 bg-white border border-slate-200 text-slate-400 hover:text-rose-500 hover:bg-rose-50 rounded-2xl transition-colors shadow-sm" title="Delete job"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" stroke-width="2.5"/></svg></button>` : ''}
                </div>
            </td>`;
        }

        return `<tr class="hover:bg-slate-50/80 cursor-pointer transition-colors" onclick="viewJobDetails('${j.job_id}')">
                <td class="px-10 py-5 font-black text-slate-800 text-lg">
                    ${j.title || 'Untitled'}
                    <div class="text-[10px] text-slate-400 uppercase tracking-widest mt-1">By: ${j.created_by || 'System'}</div>
                </td>
                <td class="px-10 py-5 font-bold text-slate-500">${j.target_summary || 'N/A'}</td>
                <td class="px-10 py-5 text-center"><span class="px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-wider ${cls}">${statusStr} ${j.total > 1 ? `(${j.success}/${j.total})` : ''}</span></td>
                <td class="px-10 py-5 text-xs text-slate-400 font-bold text-right">${j.created_at}</td>
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
function toggleSchType() {
    const checked = document.querySelector('input[name="schType"]:checked');
    if(!checked) return;
    const type = checked.value;

    const uiOnce = document.getElementById('schUiOnce');
    const uiRec = document.getElementById('schUiRecurring');

    if(uiOnce) uiOnce.classList.toggle('hidden', type !== 'once');
    if(uiRec) uiRec.classList.toggle('hidden', type !== 'recurring');
}

function buildCronString() {
    const checked = document.querySelector('input[name="schType"]:checked');
    if(!checked) return null;
    const type = checked.value;

    if (type === 'once') {
        const d = document.getElementById('schDate')?.value;
        const t = document.getElementById('schTimeOnce')?.value;
        if(!d || !t) return null;
        return "DATE:" + d + " " + t;
    } else {
        const t = document.getElementById('schTimeRec')?.value;
        if(!t) return null;
        const [hr, min] = t.split(':');
        const days = Array.from(document.querySelectorAll('.sch-day:checked')).map(cb => cb.value);
        if(days.length === 0) return null;
        return `${parseInt(min)} ${parseInt(hr)} * * ${days.join(',')}`;
    }
}

function parseCronToUI(cronStr) {
    const elDate = document.getElementById('schDate'); if(elDate) elDate.value = '';
    const elTimeOnce = document.getElementById('schTimeOnce'); if(elTimeOnce) elTimeOnce.value = '';
    const elTimeRec = document.getElementById('schTimeRec'); if(elTimeRec) elTimeRec.value = '';
    document.querySelectorAll('.sch-day').forEach(cb => cb.checked = false);

    if (cronStr.startsWith("DATE:")) {
        const rOnce = document.querySelector('input[name="schType"][value="once"]');
        if(rOnce) rOnce.checked = true;
        const [d, t] = cronStr.replace("DATE:", "").trim().split(" ");
        if(elDate) elDate.value = d;
        if(elTimeOnce) elTimeOnce.value = t;
    } else {
        const rRec = document.querySelector('input[name="schType"][value="recurring"]');
        if(rRec) rRec.checked = true;
        const parts = cronStr.split(' ');
        if(parts.length >= 5) {
            const min = parts[0].padStart(2, '0');
            const hr = parts[1].padStart(2, '0');
            if(elTimeRec) elTimeRec.value = `${hr}:${min}`;
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

function openScheduleModal() {
    const elId = document.getElementById('schId'); if(elId) elId.value = '';
    const elName = document.getElementById('schName'); if(elName) elName.value = '';
    const elCat = document.getElementById('schCategory'); if(elCat) elCat.value = 'Scheduled';
    const elAct = document.getElementById('schActive'); if(elAct) elAct.checked = true;

    const rOnce = document.querySelector('input[name="schType"][value="once"]');
    if(rOnce) rOnce.checked = true;

    const elDate = document.getElementById('schDate');
    if(elDate) {
        const now = new Date();
        elDate.value = now.toISOString().split('T')[0];
    }
    toggleSchType();

    const title = document.getElementById('schModalTitle'); if(title) title.innerText = 'New Schedule';
    openModal('scheduleModal');
}

function editSchedule(id, name, cat, cron, type, active) {
    const elId = document.getElementById('schId'); if(elId) elId.value = id;
    const elName = document.getElementById('schName'); if(elName) elName.value = name;
    const elCat = document.getElementById('schCategory'); if(elCat) elCat.value = cat;
    const elType = document.getElementById('schTargetType'); if(elType) elType.value = type;
    const elAct = document.getElementById('schActive'); if(elAct) elAct.checked = (active === 'True');

    const elHost = document.getElementById('schTargetHost'); if(elHost) elHost.classList.toggle('hidden', type !== 'host');
    const elGroup = document.getElementById('schTargetGroup'); if(elGroup) elGroup.classList.toggle('hidden', type !== 'group');

    parseCronToUI(cron);

    const title = document.getElementById('schModalTitle'); if(title) title.innerText = 'Edit Schedule';
    openModal('scheduleModal');
}

async function saveSchedule() {
    const cronExpr = buildCronString();
    if (!cronExpr) return alert("Please specify the execution time and date/days completely.");

    const data = {
        id: document.getElementById('schId')?.value || null,
        name: document.getElementById('schName')?.value,
        category: document.getElementById('schCategory')?.value || 'Scheduled',
        template_id: document.getElementById('schTemplate')?.value,
        target_type: document.getElementById('schTargetType')?.value,
        target_id: document.getElementById('schTargetType')?.value === 'host' ? document.getElementById('schTargetHost')?.value : document.getElementById('schTargetGroup')?.value,
        cron: cronExpr,
        is_active: document.getElementById('schActive')?.checked
    };
    if(!data.name) return alert("Job Name is required");

    try {
        const res = await fetch('/api/infrastructure/schedule', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        if(res.ok) window.location.reload();
        else alert("Save failed");
    } catch(e) { alert("Server error."); }
}

async function deleteSchedule(id) {
    if(confirm("Delete this scheduled task?")) {
        await fetch('/api/infrastructure/schedule/' + id, { method: 'DELETE' });
        window.location.reload();
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
    document.getElementById('tHost').innerText = d.hostname || 'Unknown';
    const statusStr = d.status || 'Pending';
    document.getElementById('tStatus').innerHTML = `<span class="uppercase tracking-widest text-[10px] bg-white px-3 py-1 rounded-xl shadow-sm border border-slate-100 font-black ${statusStr === 'Success' ? 'text-emerald-500' : (statusStr === 'Error' ? 'text-rose-500' : 'text-amber-500')}">${statusStr}</span>`;
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
    if (value === 'pickedup' || value === 'picked_up' || value === 'running') return 'running';
    return 'pending';
}

function jobStatusLabel(status) {
    const normalized = normalizeJobTaskStatus(status);
    if (normalized === 'success') return 'Success';
    if (normalized === 'error') return 'Error';
    if (normalized === 'cancelled') return 'Cancelled';
    if (normalized === 'running') return 'Running';
    return 'Pending';
}

function jobStatusBadgeClass(status) {
    const normalized = normalizeJobTaskStatus(status);
    if (normalized === 'success') return 'bg-emerald-50 text-emerald-700 border-emerald-100';
    if (normalized === 'error') return 'bg-rose-50 text-rose-700 border-rose-100';
    if (normalized === 'cancelled') return 'bg-slate-50 text-slate-500 border-slate-200';
    if (normalized === 'running') return 'bg-indigo-50 text-indigo-700 border-indigo-100';
    return 'bg-amber-50 text-amber-700 border-amber-100';
}

function renderJobStatusFilters() {
    const wrap = document.getElementById('jobStatusFilters');
    if (!wrap) return;
    const counts = currentJobTasks.reduce((acc, task) => {
        acc[normalizeJobTaskStatus(task.status)] += 1;
        return acc;
    }, { all: currentJobTasks.length, pending: 0, running: 0, error: 0, success: 0, cancelled: 0 });

    const filters = [
        ['all', 'All', counts.all],
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
            ? `<button onclick="viewHostFromJob('${escapeHtml(t.endpoint_id)}')" class="font-black text-slate-800 hover:text-indigo-600 text-left">${escapeHtml(t.hostname || 'Unknown')}</button>`
            : `<span class="font-black text-slate-700">${escapeHtml(t.hostname || 'Unknown')}</span>`;
        return `<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-6 py-4 text-base">${hostCell}</td>
            <td class="px-6 py-4 text-center"><span class="font-black uppercase tracking-widest text-[10px] px-3 py-1 rounded-lg border ${jobStatusBadgeClass(statusStr)}">${jobStatusLabel(statusStr)}</span></td>
            <td class="px-6 py-4 text-right"><button onclick="viewTaskDetails('${t.task_id}')" class="px-4 py-2 bg-white border border-slate-200 rounded-xl text-xs font-black uppercase text-indigo-600 hover:bg-indigo-50 transition-colors shadow-sm">View Log</button></td>
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

        document.getElementById('mName').innerText = d.hostname || "Unknown";
        if(document.getElementById('confName')) document.getElementById('confName').innerText = d.hostname || "Unknown";
        document.getElementById('mId').innerText = 'ID: ' + d.id;
        document.getElementById('mIp').innerText = d.ip || "N/A";
        document.getElementById('mOs').innerText = d.os || "Unknown";
        document.getElementById('mAgentVersion').innerText = d.agent_version || "Unknown";
        const keyEl = document.getElementById('mAgentKeyStatus');
        if (keyEl) keyEl.innerHTML = d.agent_identity_key_enrolled
            ? '<span class="text-emerald-600 font-black uppercase tracking-widest">Enrolled</span>'
            : '<span class="text-violet-600 font-black uppercase tracking-widest">Missing</span>';
        document.getElementById('mSeen').innerText = d.last_seen || "-";
        const identityWarning = d.identity_warning ? `<div class="p-3 bg-rose-50 border border-rose-100 rounded-2xl text-xs font-bold text-rose-700">${d.identity_warning}</div>` : '';
        const identityDuplicates = (d.duplicate_matches || []).filter(match => match.strong_match);
        const identityDuplicateWarning = identityDuplicates.length ? `
            <div class="p-3 bg-rose-50 border border-rose-100 rounded-2xl text-xs font-bold text-rose-700">
                <div class="font-black uppercase tracking-widest text-[10px] mb-2">Possible duplicate identity</div>
                ${identityDuplicates.map(match => `
                    <div class="mt-1">
                        <button onclick="viewHost('${escapeHtml(match.id)}')" class="font-black underline decoration-rose-300 underline-offset-2 hover:text-rose-900">${escapeHtml(match.hostname || match.id)}</button>
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

        document.getElementById('mGroups').innerHTML = d.groups.map(g => `<span class="bg-indigo-50 text-indigo-600 px-3 py-1.5 rounded-xl text-xs font-bold border border-indigo-100 shadow-sm uppercase">${g.name}</span>`).join('') || '<span class="text-slate-400 italic text-sm">Ungrouped</span>';
        const networkInfo = Array.isArray(d.network_info) ? d.network_info : [];
        document.getElementById('mNetworkInfo').innerHTML = networkInfo.map(n => `
            <div class="bg-white border border-slate-200 rounded-2xl p-3">
                <div class="font-black text-slate-700">${n.name || 'Interface'}</div>
                <div class="text-[10px] text-slate-400 font-bold mt-1">${n.type || 'Unknown'} / ${n.status || 'Unknown'} / ${n.mac || 'No MAC'}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-2 break-words">IPv4: ${(n.ipv4 || []).join(', ') || '-'}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-1 break-words">GW: ${(n.gateways || []).join(', ') || '-'}</div>
                <div class="font-mono text-[10px] text-slate-600 mt-1 break-words">DNS: ${(n.dns_servers || []).join(', ') || '-'}</div>
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
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">FQDN</span><span class="text-slate-700 font-mono text-right break-all">${hostInfo.fqdn || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Domain</span><span class="text-slate-700 text-right">${hostInfo.domain_name || hostInfo.user_domain_name || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Domain Joined</span><span class="text-slate-700">${fmtBool(hostInfo.likely_domain_joined)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">CPU / RAM</span><span class="text-slate-700">${hostInfo.processor_count || '-'} cores / ${hostInfo.total_memory_mb ? Math.round(hostInfo.total_memory_mb / 1024) + ' GB' : '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Timezone</span><span class="text-slate-700 text-right">${hostInfo.timezone || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Boot UTC</span><span class="text-slate-700 font-mono text-[10px] text-right">${hostInfo.boot_time_utc || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">First Seen</span><span class="text-slate-700 font-mono text-[10px] text-right">${d.first_seen || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Last Enrollment</span><span class="text-slate-700 font-mono text-[10px] text-right">${d.last_enrollment_at || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Enroll IP</span><span class="text-slate-700 font-mono text-[10px] text-right">${d.last_enrollment_ip || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Attempts</span><span class="text-slate-700 font-black">${d.enrollment_attempts || 0}</span></div>
            </div>
            ${identityWarning}
            ${identityDuplicateWarning}
            ${volumes.length ? volumes.map(v => `
                <div class="bg-white border border-slate-200 rounded-2xl p-3">
                    <div class="font-black text-slate-700">${v.name || 'Volume'} ${v.label ? '/ ' + v.label : ''}</div>
                    <div class="text-[10px] text-slate-400 font-bold mt-1">${v.type || '-'} / ${v.format || '-'} / ${v.ready ? 'Ready' : 'Not ready'}</div>
                    <div class="font-mono text-[10px] text-slate-600 mt-2">Free: ${fmtBytes(v.free_gb)} / Total: ${fmtBytes(v.total_gb)}</div>
                </div>
            `).join('') : ''}
        `;
        document.getElementById('mSecurityInfo').innerHTML = `
            <div class="bg-white border border-slate-200 rounded-2xl p-3 space-y-2">
                <div class="flex justify-between gap-3 items-center"><span class="text-slate-400 font-bold">Encryption</span><span class="px-3 py-1 rounded-xl border text-[10px] font-black uppercase ${encryptionClass}">${escapeHtml(encryption.status || 'Unknown')}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Methods</span><span class="text-slate-700 text-right">${(encryption.methods || []).map(escapeHtml).join(', ') || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Pending Reboot</span><span class="${security.pending_reboot ? 'text-amber-600' : 'text-emerald-600'} font-black">${fmtBool(security.pending_reboot)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Domain</span><span class="text-slate-700">${security.firewall_domain || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Private</span><span class="text-slate-700">${security.firewall_private || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Public</span><span class="text-slate-700">${security.firewall_public || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Defender</span><span class="text-slate-700">${security.defender_service_state || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">VeraCrypt</span><span class="${security.veracrypt_detected ? 'text-emerald-600' : 'text-slate-500'} font-black">${fmtBool(security.veracrypt_detected)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">TrueCrypt</span><span class="${security.truecrypt_detected ? 'text-emerald-600' : 'text-slate-500'} font-black">${fmtBool(security.truecrypt_detected)}</span></div>
                <div class="pt-2 border-t border-slate-100 grid grid-cols-2 gap-2 text-[10px]">
                    <div><span class="text-slate-400 font-bold block">BitLocker Status</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.status || 'unknown')}</span></div>
                    <div><span class="text-slate-400 font-bold block">Encrypted</span><span class="text-slate-700 font-black">${Number.isFinite(Number(bitlocker.encrypted_percentage)) && Number(bitlocker.encrypted_percentage) >= 0 ? Number(bitlocker.encrypted_percentage) + '%' : '-'}</span></div>
                    <div><span class="text-slate-400 font-bold block">Protection</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.protection_status || 'unknown')}</span></div>
                    <div><span class="text-slate-400 font-bold block">Conversion</span><span class="text-slate-700 font-black uppercase">${escapeHtml(bitlocker.conversion_status || 'unknown')}</span></div>
                </div>
                <div class="pt-2 border-t border-slate-100"><span class="text-slate-400 font-bold block mb-1">BitLocker</span><span class="font-mono text-[10px] text-slate-600 whitespace-pre-wrap break-words">${security.bitlocker_summary || '-'}</span></div>
            </div>
        `;

        if (document.getElementById('btnBlockHost')) document.getElementById('btnBlockHost').innerText = d.is_blocked ? "Unblock Host" : "Block Host";
        if (document.getElementById('btnApproveHost')) document.getElementById('btnApproveHost').classList.toggle('hidden', approval === 'Approved');
        if (document.getElementById('btnRejectHost')) document.getElementById('btnRejectHost').classList.toggle('hidden', approval === 'Rejected');

        document.getElementById('mHistory').innerHTML = d.history.map(h => `<div class="p-4 bg-white border border-slate-200 rounded-2xl flex justify-between items-center cursor-pointer hover:border-indigo-300 hover:shadow-md transition-all shadow-sm" onclick="viewTaskDetails('${h.id}')"><div><p class="font-black text-slate-800 text-sm">${h.title}</p><p class="text-[10px] text-slate-400 uppercase tracking-widest mt-1">By ${h.by} • ${h.date}</p></div><span class="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest ${h.status === 'Success' ? 'bg-emerald-100 text-emerald-700' : (h.status === 'Error' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700')}">${h.status}</span></div>`).join('') || '<p class="text-slate-400 italic text-sm">No task history</p>';
    } catch(e) { console.error("Error loading host data", e); }
}

async function toggleBlockHost() { await fetch('/api/infrastructure/host/' + currentViewedHostId + '/block', { method: 'POST' }); closeModal('hostModal'); location.reload(); }
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
    if(!confirm("Cancel all hosts that are still pending in this job?")) return;
    const res = await fetch('/api/infrastructure/job/' + encodeURIComponent(id) + '/cancel-pending', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if(!res.ok || !data.success) return alert(data.message || 'Cancel failed.');
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
    const res = await fetch('/api/infrastructure/group/' + id);
    const data = await res.json();
    if(!data.success) return;

    document.getElementById('gdPageName').innerText = data.data.name;
    currentGroupNonMembers = data.data.non_members;

    document.getElementById('groupHostsBody').innerHTML = data.data.members.map(m => `
        <tr class="hover:bg-slate-50/80 transition-colors">
            <td class="px-10 py-5 font-black text-slate-700 text-lg cursor-pointer" onclick="viewHost('${m.id}')">${m.hostname}</td>
            <td class="px-10 py-5">
                <div class="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-1">${m.os_type}</div>
                <div class="text-sm font-bold text-slate-600">${m.ip}</div>
            </td>
            ${infraPermissions.manage_groups ? `<td class="px-10 py-5 text-right"><button onclick="removeHostFromGroup('${m.id}')" class="px-4 py-2 bg-white text-rose-500 border border-slate-200 hover:bg-rose-50 rounded-xl text-xs font-black uppercase transition-all shadow-sm">Remove</button></td>` : ''}
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

function openAddHostsToGroupModal() {
    const searchEl = document.getElementById('addHostSearch');
    if(searchEl) searchEl.value = '';
    renderAddHostList('');
    openModal('groupAddHostModal');
}

function renderAddHostList(q) {
    const list = document.getElementById('availableHostsList');
    if(!list) return;
    const filtered = currentGroupNonMembers.filter(m => m.hostname.toLowerCase().includes(q));
    list.innerHTML = filtered.map(m => `
        <label class="flex items-center gap-4 p-4 border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors group">
            <input type="checkbox" value="${m.id}" class="add-host-cb w-5 h-5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" onchange="document.getElementById('selCount').innerText = document.querySelectorAll('.add-host-cb:checked').length">
            <span class="font-black text-slate-700 text-sm group-hover:text-indigo-600 transition-colors">${m.hostname}</span>
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
