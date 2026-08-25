// Mobile-first task launcher. It intentionally reuses template metadata already
// rendered by Workspace and the existing authenticated template-run endpoint.

const quickLaunchState = {
    step: 1,
    templateId: null,
    templateName: '',
    targetType: 'hosts',
    hostIds: new Set(),
    variables: [],
    variableSchema: {},
    submitting: false,
};

const quickLaunchStorageKeys = {
    recent: 'winhub_quick_launch_recent_templates',
    favorites: 'winhub_quick_launch_favorite_templates',
};

function quickLaunchStoredList(key) {
    try {
        const parsed = JSON.parse(localStorage.getItem(key) || '[]');
        return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch (error) {
        return [];
    }
}

function quickLaunchTemplateCards() {
    return Array.from(document.querySelectorAll('.template-card')).filter(card => (
        card.dataset.type !== 'report' && card.dataset.canRun !== 'false'
    ));
}

function quickLaunchTemplateCard(templateId) {
    return quickLaunchTemplateCards().find(card => String(card.dataset.id) === String(templateId));
}

function quickLaunchTemplateTypeLabel(card) {
    if (card?.dataset.type === 'metric') return 'Metric';
    if (card?.dataset.action === 'agent_update') return 'Agent update';
    return 'Action';
}

function quickLaunchParseArray(value) {
    try {
        const parsed = JSON.parse(value || '[]');
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        return [];
    }
}

function quickLaunchParseObject(value) {
    try {
        const parsed = JSON.parse(value || '{}');
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (error) {
        return {};
    }
}

function quickLaunchSetError(message = '') {
    const error = document.getElementById('quickLaunchError');
    if (error) error.textContent = message;
}

function quickLaunchFavoriteIds() {
    return new Set(quickLaunchStoredList(quickLaunchStorageKeys.favorites));
}

function toggleQuickLaunchFavorite(templateId) {
    const favorites = quickLaunchFavoriteIds();
    const id = String(templateId);
    if (favorites.has(id)) favorites.delete(id);
    else favorites.add(id);
    localStorage.setItem(quickLaunchStorageKeys.favorites, JSON.stringify(Array.from(favorites)));
    renderQuickLaunchTemplates(document.getElementById('quickLaunchTemplateSearch')?.value || '');
}

function renderQuickLaunchTemplates(query = '') {
    const list = document.getElementById('quickLaunchTemplateList');
    if (!list) return;

    const normalizedQuery = String(query).trim().toLowerCase();
    const favorites = quickLaunchFavoriteIds();
    const recent = quickLaunchStoredList(quickLaunchStorageKeys.recent);
    const recentRank = new Map(recent.map((id, index) => [id, index]));
    const cards = quickLaunchTemplateCards()
        .filter(card => `${card.dataset.name || ''} ${card.dataset.category || ''} ${card.dataset.type || ''}`.toLowerCase().includes(normalizedQuery))
        .sort((left, right) => {
            const leftId = String(left.dataset.id);
            const rightId = String(right.dataset.id);
            const favoriteDelta = Number(favorites.has(rightId)) - Number(favorites.has(leftId));
            if (favoriteDelta) return favoriteDelta;
            const leftRecent = recentRank.has(leftId) ? recentRank.get(leftId) : Number.MAX_SAFE_INTEGER;
            const rightRecent = recentRank.has(rightId) ? recentRank.get(rightId) : Number.MAX_SAFE_INTEGER;
            if (leftRecent !== rightRecent) return leftRecent - rightRecent;
            return String(left.dataset.name || '').localeCompare(String(right.dataset.name || ''));
        });

    list.innerHTML = cards.map(card => {
        const id = String(card.dataset.id);
        const isFavorite = favorites.has(id);
        const isRecent = recentRank.has(id);
        const isSelected = String(quickLaunchState.templateId) === id;
        return `
            <div class="quick-launch-template-wrap${isSelected ? ' is-selected' : ''}" data-quick-template-wrap="${escapeHtml(id)}">
                <button type="button" class="quick-launch-template-row" data-quick-template="${escapeHtml(id)}">
                    <span class="block truncate text-sm font-black text-white">${escapeHtml(card.dataset.name || 'Untitled template')}</span>
                    <span class="mt-1 flex flex-wrap items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                        <span>${escapeHtml(card.dataset.category || 'General')}</span>
                        <span class="text-cyan-300">${escapeHtml(quickLaunchTemplateTypeLabel(card))}</span>
                        ${isRecent ? '<span class="text-emerald-300">Recent</span>' : ''}
                    </span>
                </button>
                <button type="button" class="quick-launch-favorite${isFavorite ? ' is-favorite' : ''}" data-quick-favorite="${escapeHtml(id)}" aria-label="${isFavorite ? 'Remove from favorites' : 'Add to favorites'}">★</button>
            </div>`;
    }).join('') || '<div class="quick-launch-empty">No runnable templates match this search.</div>';

    list.querySelectorAll('[data-quick-template]').forEach(button => {
        button.addEventListener('click', () => selectQuickLaunchTemplate(button.dataset.quickTemplate));
    });
    list.querySelectorAll('[data-quick-favorite]').forEach(button => {
        button.addEventListener('click', () => toggleQuickLaunchFavorite(button.dataset.quickFavorite));
    });
}

function quickLaunchAvailableHosts() {
    const hosts = Array.isArray(window.WinhubHosts) ? window.WinhubHosts : [];
    return hosts.filter(host => (host.approval_status || 'Approved') === 'Approved' && !host.is_blocked);
}

function renderQuickLaunchHosts(query = '') {
    const list = document.getElementById('quickLaunchHostList');
    if (!list) return;
    const normalizedQuery = String(query).trim().toLowerCase();
    const hosts = quickLaunchAvailableHosts()
        .filter(host => `${host.name || ''} ${host.display_name || ''} ${host.hostname || ''} ${host.ip || ''} ${host.os_type || ''}`.toLowerCase().includes(normalizedQuery))
        .sort((left, right) => Number(!!right.is_online) - Number(!!left.is_online) || String(endpointVisibleName(left)).localeCompare(String(endpointVisibleName(right))));

    list.innerHTML = hosts.map(host => {
        const id = String(host.id);
        const selected = quickLaunchState.hostIds.has(id);
        return `
            <button type="button" class="quick-launch-host-row${selected ? ' is-selected' : ''}" data-quick-host="${escapeHtml(id)}" aria-pressed="${selected ? 'true' : 'false'}">
                <span class="quick-launch-check" aria-hidden="true">✓</span>
                <span class="min-w-0 flex-1">
                    <span class="block truncate text-sm font-black text-white">${escapeHtml(endpointVisibleName(host))}</span>
                    <span class="mt-1 flex items-center gap-2 text-[10px] font-bold text-slate-400">
                        <span class="quick-launch-online-dot${host.is_online ? ' is-online' : ''}"></span>
                        <span>${host.is_online ? 'Online' : 'Offline'}</span>
                        <span class="truncate">${escapeHtml(host.ip || host.hostname || 'No IP')}</span>
                    </span>
                </span>
            </button>`;
    }).join('') || '<div class="quick-launch-empty">No allowed endpoints match this search.</div>';

    list.querySelectorAll('[data-quick-host]').forEach(button => {
        button.addEventListener('click', () => toggleQuickLaunchHost(button.dataset.quickHost));
    });
    updateQuickLaunchControls();
}

function toggleQuickLaunchHost(hostId) {
    const id = String(hostId);
    if (quickLaunchState.hostIds.has(id)) quickLaunchState.hostIds.delete(id);
    else quickLaunchState.hostIds.add(id);
    renderQuickLaunchHosts(document.getElementById('quickLaunchHostSearch')?.value || '');
}

function selectQuickLaunchTemplate(templateId) {
    const card = quickLaunchTemplateCard(templateId);
    if (!card) {
        quickLaunchSetError('This template is no longer available.');
        return;
    }
    quickLaunchState.templateId = String(card.dataset.id);
    quickLaunchState.templateName = card.dataset.name || 'Template task';
    quickLaunchState.variables = quickLaunchParseArray(card.dataset.vars);
    quickLaunchState.variableSchema = quickLaunchParseObject(card.dataset.varSchema);
    quickLaunchSetError();
    showQuickLaunchStep(2);
}

function setQuickLaunchTargetType(targetType) {
    quickLaunchState.targetType = targetType === 'group' ? 'group' : 'hosts';
    document.getElementById('quickLaunchHostsPanel')?.classList.toggle('hidden', quickLaunchState.targetType !== 'hosts');
    document.getElementById('quickLaunchGroupPanel')?.classList.toggle('hidden', quickLaunchState.targetType !== 'group');
    document.getElementById('quickLaunchTargetHostsButton')?.classList.toggle('is-active', quickLaunchState.targetType === 'hosts');
    document.getElementById('quickLaunchTargetGroupButton')?.classList.toggle('is-active', quickLaunchState.targetType === 'group');
    localStorage.setItem('winhub_quick_launch_target_type', quickLaunchState.targetType);
    quickLaunchSetError();
    updateQuickLaunchControls();
}

function quickLaunchTargetSummary() {
    if (quickLaunchState.targetType === 'group') {
        const select = document.getElementById('quickLaunchGroup');
        return select?.selectedOptions?.[0]?.textContent?.trim() || 'No group selected';
    }
    const count = quickLaunchState.hostIds.size;
    if (count === 1) {
        const id = Array.from(quickLaunchState.hostIds)[0];
        const host = quickLaunchAvailableHosts().find(item => String(item.id) === id);
        return host ? endpointVisibleName(host) : '1 endpoint';
    }
    return `${count} endpoints`;
}

function renderQuickLaunchReview() {
    const summary = document.getElementById('quickLaunchSummary');
    if (summary) {
        summary.innerHTML = `
            <p class="text-[10px] font-black text-cyan-300 uppercase tracking-widest">Ready to run</p>
            <p class="mt-2 text-base font-black text-white">${escapeHtml(quickLaunchState.templateName)}</p>
            <p class="mt-1 text-xs font-bold text-slate-400">Target: ${escapeHtml(quickLaunchTargetSummary())}</p>`;
    }

    const title = document.getElementById('quickLaunchTaskTitle');
    if (title && !title.value.trim()) title.value = quickLaunchState.templateName;

    const block = document.getElementById('quickLaunchVariablesBlock');
    const container = document.getElementById('quickLaunchVariables');
    if (!block || !container) return;
    block.classList.toggle('hidden', quickLaunchState.variables.length === 0);
    container.innerHTML = quickLaunchState.variables.map(name => {
        const spec = variableSpecFor(name, quickLaunchState.variableSchema);
        return `
            <div>
                <label class="block mb-2 text-[10px] font-black text-slate-400 uppercase tracking-widest">${escapeHtml(spec.label || name)}</label>
                ${renderVariableField(name, spec, spec.default ?? '', 'quick-launch-var-input')}
                ${spec.help ? `<p class="mt-1 text-[10px] font-bold text-slate-500">${escapeHtml(spec.help)}</p>` : ''}
            </div>`;
    }).join('');
}

function quickLaunchStepTitle(step) {
    if (step === 2) return 'Choose targets';
    if (step === 3) return 'Review and run';
    return 'Choose a template';
}

function showQuickLaunchStep(step) {
    quickLaunchState.step = Math.max(1, Math.min(3, Number(step) || 1));
    document.querySelectorAll('[data-quick-step]').forEach(section => {
        section.classList.toggle('hidden', Number(section.dataset.quickStep) !== quickLaunchState.step);
    });
    document.querySelectorAll('[data-quick-progress]').forEach(progress => {
        progress.classList.toggle('is-active', Number(progress.dataset.quickProgress) <= quickLaunchState.step);
    });
    const eyebrow = document.getElementById('quickLaunchEyebrow');
    const title = document.getElementById('quickLaunchTitle');
    if (eyebrow) eyebrow.textContent = `Step ${quickLaunchState.step} of 3`;
    if (title) title.textContent = quickLaunchStepTitle(quickLaunchState.step);
    if (quickLaunchState.step === 2) renderQuickLaunchHosts(document.getElementById('quickLaunchHostSearch')?.value || '');
    if (quickLaunchState.step === 3) renderQuickLaunchReview();
    quickLaunchSetError();
    updateQuickLaunchControls();
    document.querySelector('#quickLaunchModal .quick-launch-body')?.scrollTo({top: 0});
}

function updateQuickLaunchControls() {
    const back = document.getElementById('quickLaunchBack');
    const next = document.getElementById('quickLaunchNext');
    const run = document.getElementById('quickLaunchRun');
    const count = document.getElementById('quickLaunchHostCount');
    if (count) count.textContent = String(quickLaunchState.hostIds.size);
    if (back) back.classList.toggle('invisible', quickLaunchState.step === 1);
    if (next) {
        next.classList.toggle('hidden', quickLaunchState.step === 3);
        next.disabled = quickLaunchState.step === 1 ? !quickLaunchState.templateId : !quickLaunchTargetsValid();
    }
    if (run) {
        run.classList.toggle('hidden', quickLaunchState.step !== 3);
        run.disabled = quickLaunchState.submitting;
        if (!quickLaunchState.submitting) run.textContent = `Run on ${quickLaunchTargetSummary()}`;
    }
}

function quickLaunchTargetsValid() {
    if (quickLaunchState.targetType === 'group') return !!document.getElementById('quickLaunchGroup')?.value;
    return quickLaunchState.hostIds.size > 0;
}

function quickLaunchNext() {
    if (quickLaunchState.step === 1) {
        if (!quickLaunchState.templateId) quickLaunchSetError('Choose a template first.');
        else showQuickLaunchStep(2);
        return;
    }
    if (quickLaunchState.step === 2) {
        if (!quickLaunchTargetsValid()) {
            quickLaunchSetError(quickLaunchState.targetType === 'group' ? 'Choose an endpoint group.' : 'Select at least one endpoint.');
            return;
        }
        showQuickLaunchStep(3);
    }
}

function quickLaunchBack() {
    if (quickLaunchState.step > 1) showQuickLaunchStep(quickLaunchState.step - 1);
}

function resetQuickLaunch() {
    quickLaunchState.step = 1;
    quickLaunchState.templateId = null;
    quickLaunchState.templateName = '';
    quickLaunchState.hostIds.clear();
    quickLaunchState.variables = [];
    quickLaunchState.variableSchema = {};
    quickLaunchState.submitting = false;
    const templateSearch = document.getElementById('quickLaunchTemplateSearch');
    const hostSearch = document.getElementById('quickLaunchHostSearch');
    const group = document.getElementById('quickLaunchGroup');
    const taskTitle = document.getElementById('quickLaunchTaskTitle');
    if (templateSearch) templateSearch.value = '';
    if (hostSearch) hostSearch.value = '';
    if (group) group.value = '';
    if (taskTitle) taskTitle.value = '';
    const savedTargetType = localStorage.getItem('winhub_quick_launch_target_type');
    setQuickLaunchTargetType(savedTargetType === 'group' ? 'group' : 'hosts');
    renderQuickLaunchTemplates();
    showQuickLaunchStep(1);
}

function openQuickLaunch(templateId = null) {
    const modal = document.getElementById('quickLaunchModal');
    if (!modal) return;
    resetQuickLaunch();
    modal.classList.remove('hidden');
    document.body.classList.add('overflow-hidden');
    if (templateId) selectQuickLaunchTemplate(templateId);
    else setTimeout(() => document.getElementById('quickLaunchTemplateSearch')?.focus(), 80);
}

function closeQuickLaunch() {
    document.getElementById('quickLaunchModal')?.classList.add('hidden');
    document.body.classList.remove('overflow-hidden');
    quickLaunchSetError();
}

function quickLaunchRememberTemplate(templateId) {
    const id = String(templateId);
    const recent = quickLaunchStoredList(quickLaunchStorageKeys.recent).filter(item => item !== id);
    recent.unshift(id);
    localStorage.setItem(quickLaunchStorageKeys.recent, JSON.stringify(recent.slice(0, 8)));
}

function quickLaunchNotify(message) {
    document.querySelector('.quick-launch-toast')?.remove();
    const toast = document.createElement('div');
    toast.className = 'quick-launch-toast';
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

async function submitQuickLaunch() {
    if (quickLaunchState.submitting || !quickLaunchState.templateId || !quickLaunchTargetsValid()) return;
    const run = document.getElementById('quickLaunchRun');
    const variables = collectVariableInputs('.quick-launch-var-input');
    const title = document.getElementById('quickLaunchTaskTitle')?.value?.trim() || quickLaunchState.templateName;
    const groupId = document.getElementById('quickLaunchGroup')?.value || '';
    const payload = {
        title,
        target_type: quickLaunchState.targetType,
        variables,
        ...(quickLaunchState.targetType === 'group'
            ? {target_id: groupId}
            : {target_ids: Array.from(quickLaunchState.hostIds)}),
    };

    quickLaunchState.submitting = true;
    if (run) {
        run.disabled = true;
        run.textContent = 'Launching...';
    }
    quickLaunchSetError();

    try {
        const response = await fetch(`/api/infrastructure/templates/${encodeURIComponent(quickLaunchState.templateId)}/run`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success) {
            const missing = Array.isArray(data.missing_variables) && data.missing_variables.length
                ? `: ${data.missing_variables.join(', ')}`
                : '';
            throw new Error(`${data.message || 'Task launch failed'}${missing}`);
        }
        const createdTasks = Number(data.created_tasks || 0);
        quickLaunchRememberTemplate(quickLaunchState.templateId);
        closeQuickLaunch();
        const successTarget = createdTasks > 0
            ? `${createdTasks} endpoint${createdTasks === 1 ? '' : 's'}`
            : quickLaunchTargetSummary();
        quickLaunchNotify(`Task queued for ${successTarget}.`);
        if (infraPermissions.view_queue && document.getElementById('view-queue')) switchView('queue');
    } catch (error) {
        quickLaunchSetError(error?.message || 'Server connection failed.');
    } finally {
        quickLaunchState.submitting = false;
        updateQuickLaunchControls();
    }
}

document.getElementById('quickLaunchTemplateSearch')?.addEventListener('input', event => {
    renderQuickLaunchTemplates(event.target.value);
});
document.getElementById('quickLaunchHostSearch')?.addEventListener('input', event => {
    renderQuickLaunchHosts(event.target.value);
});
document.getElementById('quickLaunchGroup')?.addEventListener('change', () => {
    quickLaunchSetError();
    updateQuickLaunchControls();
});
document.getElementById('quickLaunchModal')?.addEventListener('click', event => {
    if (event.target.id === 'quickLaunchModal') closeQuickLaunch();
});
document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !document.getElementById('quickLaunchModal')?.classList.contains('hidden')) closeQuickLaunch();
});
