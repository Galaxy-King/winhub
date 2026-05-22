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
let currentJobTasks = [];
let currentViewedHostId = null;
let currentViewedGroupId = null;
let currentGroupNonMembers = [];
let currentReportId = null;

let selectedTemplateId = null;
let editingTemplateId = null;
let teleChart = null; 
let diskChart = null;
let currentHostStatus = 'all';
let queueTypeFilter = 'ALL';
const infraPermissions = window.WinhubPermissions || {};
let payloadEditor = null;

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
        <div class="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md hover:border-indigo-300 transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between cursor-pointer gap-4" onclick="viewReport('${r.id}')">
            <div class="flex items-center gap-4 w-full sm:w-auto">
                <div class="w-1.5 h-10 rounded-full ${dotColor} shrink-0"></div>
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
        
        const defaultView = ['hosts', 'groups', 'queue', 'reports', 'deploy', 'scheduler', 'triggers']
            .find(v => document.getElementById('view-' + v)) || 'hosts';
        const saved = localStorage.getItem('infra_vfinal_view') || defaultView;
        switchView(document.getElementById('view-' + saved) ? saved : defaultView, false);
        renderCategoryListUI(); 
        updateInfraNavArrows();
        document.getElementById('infraNavScroller')?.addEventListener('scroll', updateInfraNavArrows);
        window.addEventListener('resize', updateInfraNavArrows);
        
        fetchSmtpProfilesGlobally(); // ГЛОБАЛЬНЕ ЗАВАНТАЖЕННЯ ПОШТ
        initAvailableHostsData();
        
        if (document.getElementById('btnNewScript')) resetWorkspace();
        
        const hostSearchEl = document.getElementById('hostSearch');
        if(hostSearchEl) hostSearchEl.addEventListener('input', applyHostFilters);
        
        initPayloadEditor();
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
    if(save) localStorage.setItem('infra_vfinal_view', view);
    ['hosts', 'groups', 'group-detail', 'queue', 'deploy', 'scheduler', 'triggers', 'reports'].forEach(v => {
        const el = document.getElementById('view-' + v);
        const nav = document.getElementById('nav-' + v);
        if (el) el.classList.add('hidden');
        if (nav && nav.id !== 'nav-deploy') {
            nav.classList.remove('active', 'bg-white', 'text-indigo-600', 'shadow-sm', 'border-slate-200/50');
            nav.classList.add('text-slate-500', 'border-transparent');
        }
    });
    
    const target = document.getElementById('view-' + view);
    if (!target) return;
    const navBtn = document.getElementById('nav-' + (view === 'group-detail' ? 'groups' : view));
    target.classList.remove('hidden');
    if (navBtn && navBtn.id !== 'nav-deploy') {
        navBtn.classList.add('active', 'bg-white', 'text-indigo-600', 'shadow-sm', 'border-slate-200/50'); 
        navBtn.classList.remove('text-slate-500', 'border-transparent');
    }
    if(view === 'queue') loadQueue();
    if(view === 'reports') loadReports();
    if(view === 'deploy') refreshPayloadEditor();
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
    renderMultiHostList('');
    const searchEl = document.getElementById('multiHostSearch');
    if(searchEl) searchEl.value = '';
    openModal('selectMultipleHostsModal');
}

function renderMultiHostList(query) {
    const list = document.getElementById('multiHostListContainer');
    if(!list) return;

    const q = query.toLowerCase();
    const currentSelectedStr = document.getElementById('depTargetHostIds')?.value || "[]";
    let selectedIds = [];
    try { selectedIds = JSON.parse(currentSelectedStr); } catch(e){}

    const filtered = availableHostsData.filter(h => {
        const text = `${h.name || ''} ${h.ip || ''} ${h.os_type || ''} ${h.agent_version || ''}`.toLowerCase();
        return text.includes(q);
    });
    
    list.innerHTML = filtered.map(h => {
        const isChecked = selectedIds.includes(h.id) ? 'checked' : '';
        const blockedBadge = h.is_blocked ? '<span class="ml-2 px-2 py-0.5 rounded bg-rose-50 text-rose-600 border border-rose-100 text-[9px] font-black uppercase">Blocked</span>' : '';
        const approval = h.approval_status || 'Approved';
        const approvalBadge = approval !== 'Approved' ? `<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-600 border border-amber-100 text-[9px] font-black uppercase">${approval}</span>` : '';
        const versionBadge = h.agent_outdated ? '<span class="ml-2 px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-100 text-[9px] font-black uppercase">Outdated</span>' : '';
        const disabled = approval !== 'Approved' || h.is_blocked ? 'disabled' : '';
        return `
        <label class="flex items-center gap-4 p-4 border-b border-slate-100 hover:bg-slate-50 cursor-pointer transition-colors group ${disabled ? 'opacity-60' : ''}">
            <input type="checkbox" value="${h.id}" ${isChecked} ${disabled} class="multi-host-cb w-5 h-5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500" onchange="updateMultiHostCount()">
            <span class="min-w-0">
                <span class="font-black text-slate-700 text-sm group-hover:text-indigo-600 transition-colors">${h.name}${blockedBadge}${approvalBadge}${versionBadge}</span>
                <span class="block text-[10px] text-slate-400 font-bold mt-1">${h.ip || 'No IP'} / ${h.os_type || 'Unknown OS'} / Agent ${h.agent_version || 'unknown'}</span>
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
    checkboxes.forEach(cb => cb.checked = !allChecked);
    updateMultiHostCount();
}

function updateMultiHostCount() {
    const count = document.querySelectorAll('.multi-host-cb:checked').length;
    const label = document.getElementById('multiHostSelCount');
    if(label) label.innerText = count;
}

function confirmMultiHostSelection() {
    const cbs = document.querySelectorAll('.multi-host-cb:checked');
    const selectedIds = Array.from(cbs).map(cb => cb.value);
    
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
function resetWorkspace() {
    editingTemplateId = null; selectedTemplateId = null;
    
    ['depTitle', 'depCategory', 'depReportTemplate'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.value = '';
    });
    setPayloadValue('');
    
    const builderTitle = document.getElementById('builderTitle');
    if(builderTitle) builderTitle.innerText = "Deployment Builder";
    
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
    resetWorkspace();
    el.classList.add('active');
    
    const isAdmin = checkIsAdmin();
    selectedTemplateId = el.dataset.id;
    
    const titleEl = document.getElementById('depTitle');
    if(titleEl) titleEl.value = el.dataset.name;
    const catEl = document.getElementById('depCategory');
    if(catEl) catEl.value = el.dataset.category || 'General';

    const tType = el.dataset.type || 'action';

    try {
        const payload = JSON.parse(el.dataset.payload);
        setPayloadValue(payload.script || el.dataset.payload);
    } catch(e) { setPayloadValue(el.dataset.payload); }

    const actEl = document.getElementById('depAction');
    if(actEl) actEl.value = el.dataset.action || 'run_script';

    if (isAdmin) {
        editingTemplateId = el.dataset.id;
        
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
        if(tType === 'report') return alert("You cannot deploy a report format. Please select an Action or Item.");
        const lblSel = document.getElementById('selectedTemplateLabel');
        if(lblSel) lblSel.innerText = "Ready to deploy: " + el.dataset.name;
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
    if (action === 'agent_update') {
        try {
            return JSON.parse(getPayloadValue() || '{}');
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
        __auto_email_use_gpg: document.getElementById('depAutoEmailUseGpg')?.checked !== false
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

function switchNodeTab(tab) {
    const approved = document.getElementById('nodesApprovedPanel');
    const pending = document.getElementById('nodesPendingPanel');
    const approvedBtn = document.getElementById('nodeTab-approved');
    const pendingBtn = document.getElementById('nodeTab-pending');
    if (approved) approved.classList.toggle('hidden', tab !== 'approved');
    if (pending) pending.classList.toggle('hidden', tab !== 'pending');
    [approvedBtn, pendingBtn].forEach(btn => {
        if (!btn) return;
        btn.className = "node-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase text-slate-500 hover:text-amber-700";
    });
    const active = tab === 'pending' ? pendingBtn : approvedBtn;
    if (active) active.className = "node-tab-btn px-5 py-2.5 rounded-xl text-xs font-black uppercase bg-slate-900 text-white shadow-sm";
    if (tab === 'pending') updatePendingApprovalCount();
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
    
    if(tLoading) { tLoading.innerText = "Loading metrics..."; tLoading.classList.remove('hidden'); }
    if(dLoading) { dLoading.innerText = "Loading disk metrics..."; dLoading.classList.remove('hidden'); }

    try {
        const res = await fetch(`/api/infrastructure/host/${hostId}/telemetry?days=${days}`);
        const json = await res.json();
        
        if(json.success && Array.isArray(json.data) && json.data.length > 0) {
            if(tLoading) tLoading.classList.add('hidden');
            if(dLoading) dLoading.classList.add('hidden');
            
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
        } else {
            if(tLoading) { tLoading.innerText = "No telemetry data recorded for this period."; tLoading.classList.remove('hidden'); }
            if(dLoading) { dLoading.innerText = "No disk data recorded for this period."; dLoading.classList.remove('hidden'); }
            if(teleChart) teleChart.destroy();
            if(diskChart) diskChart.destroy();
        }
    } catch(e) {
        if(tLoading) { tLoading.innerText = "Failed to load telemetry."; tLoading.classList.remove('hidden'); }
        if(dLoading) { dLoading.innerText = "Failed to load disk telemetry."; dLoading.classList.remove('hidden'); }
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
        if (j.error > 0 && j.success > 0) cls = 'bg-orange-100 text-orange-700';
        
        let actionBtn = '';
        if(infraPermissions.cleanup_tasks) {
            actionBtn = `<td class="px-10 py-4 text-right"><button onclick="event.stopPropagation(); deleteJob('${j.job_id}')" class="p-3 bg-white border border-slate-200 text-slate-400 hover:text-rose-500 hover:bg-rose-50 rounded-2xl transition-colors shadow-sm"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" stroke-width="2.5"/></svg></button></td>`;
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
    currentJobTasks = job.tasks;
    document.getElementById('jTitle').innerText = job.title || 'Job Details';
    document.getElementById('jInfo').innerText = `${job.action} • Total targets: ${job.total}`;
    document.getElementById('jobHostsBody').innerHTML = currentJobTasks.map(t => {
        const statusStr = t.status || 'Pending';
        return `<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-6 py-4 font-black text-slate-700 text-lg">${t.hostname || 'Unknown'}</td>
            <td class="px-6 py-4 text-center"><span class="font-black uppercase tracking-widest text-[10px] bg-slate-100 px-3 py-1 rounded-lg ${statusStr === 'Success' ? 'text-emerald-500' : (statusStr === 'Error' ? 'text-rose-500' : 'text-amber-500')}">${statusStr}</span></td>
            <td class="px-6 py-4 text-right"><button onclick="viewTaskDetails('${t.task_id}')" class="px-4 py-2 bg-white border border-slate-200 rounded-xl text-xs font-black uppercase text-indigo-600 hover:bg-indigo-50 transition-colors shadow-sm">View Log</button></td>
        </tr>`;
    }).join('');
    openModal('jobModal');
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
        document.getElementById('mSeen').innerText = d.last_seen || "-";
        const identityWarning = d.identity_warning ? `<div class="p-3 bg-rose-50 border border-rose-100 rounded-2xl text-xs font-bold text-rose-700">${d.identity_warning}</div>` : '';
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
        const fmtBool = (v) => v === true ? 'Yes' : (v === false ? 'No' : '-');
        const fmtBytes = (gb) => Number.isFinite(Number(gb)) ? `${gb} GB` : '-';
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
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Pending Reboot</span><span class="${security.pending_reboot ? 'text-amber-600' : 'text-emerald-600'} font-black">${fmtBool(security.pending_reboot)}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Domain</span><span class="text-slate-700">${security.firewall_domain || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Private</span><span class="text-slate-700">${security.firewall_private || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Firewall Public</span><span class="text-slate-700">${security.firewall_public || '-'}</span></div>
                <div class="flex justify-between gap-3"><span class="text-slate-400 font-bold">Defender</span><span class="text-slate-700">${security.defender_service_state || '-'}</span></div>
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
    location.reload();
}
async function setHostApproval(status) {
    await fetch('/api/infrastructure/host/' + currentViewedHostId + '/approval', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status})
    });
    closeModal('hostModal');
    location.reload();
}
async function submitCreateGroup() { await fetch('/api/infrastructure/group', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: document.getElementById('cgName').value, description: document.getElementById('cgDesc').value}) }); location.reload(); }
async function deleteJob(id) { if(confirm("Permanently delete this job and all its logs?")) { await fetch('/api/infrastructure/job/' + id, { method: 'DELETE' }); loadQueue(); } }

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
