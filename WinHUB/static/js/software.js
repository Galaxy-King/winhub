/* Software uses DOM text nodes for all catalogue, group and host supplied text. */
const swState = {packages: [], hosts: [], sets: new Set(), packagesSelected: new Set(), hostsSelected: new Set(), settings: {}, panel: 'library', polling: false, pages: {}, canViewQueue: false, groups: [], groupsSelected: new Set(), targetDraft: null, targetFocus: null};
const swLabels = {Queued: 'Queued', Active: 'Running', Success: 'Success', Error: 'Error',
    Pending: 'Waiting for agent', PickedUp: 'Received by agent', SoftwareQueued: 'Waiting for capacity', Active: 'Preparing delivery', Skipped: 'Skipped', RebootRequired: 'Reboot required', Cancelled: 'Cancelled',
    Running: 'Running', Paused: 'Paused', Cancelling: 'Finishing active operations'};

function swElement(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.className = cls;
    return node;
}

function swNotice(message, error=false) {
    const node = document.getElementById('swNotice');
    if (!node) return;
    node.textContent = message;
    node.className = `p-4 rounded-xl whitespace-pre-wrap ${error ? 'bg-rose-50 text-rose-900' : 'bg-indigo-50 text-indigo-900'}`;
}

async function swRequest(url, options={}) {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
    const res = await fetch(url, {...options, headers: {...(csrf ? {'X-CSRF-Token': csrf} : {}), ...options.headers}});
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) throw new Error(data.message || `Server error (${res.status}).`);
    return data;
}

async function loadSoftwareRegistry() {
    if (!document.getElementById('softwarePackageList')) return;
    try {
        const data = await swRequest('/api/infrastructure/software-packages');
        swState.packages = data.packages || [];
        swState.installers = data.installers || [];
        swState.isAdmin = !!data.is_admin;
        swRenderInstallers();
        const installerSelect = document.getElementById('swInstallerSelect');
        if (installerSelect) {
            const selected = installerSelect.value;
            installerSelect.replaceChildren(new Option('Script only / retain existing installer', ''));
            swState.installers.filter(p => p.prepared).forEach(p => installerSelect.add(new Option(`${p.name} · ${p.version}`, p.id)));
            installerSelect.value = selected;
        }
        swState.hosts = data.hosts || [];
        swState.settings = data.settings || {};
        swState.canViewQueue = !!data.can_view_queue;
        const packageForm = document.getElementById('swPackageForm');
        ['install_template_id', 'update_template_id', 'uninstall_template_id'].forEach(name => {
            const field = packageForm?.elements[name];
            if (!field) return;
            const selected = field.value;
            field.replaceChildren(new Option('Use the script in this application card', ''));
            (data.templates || []).forEach(template => field.add(new Option(`${template.category || 'Workspace'} / ${template.name}`, template.id)));
            field.value = selected;
        });
        swState.groups = data.groups || [];
        const groupIds = new Set(swState.groups.map(group => group.id));
        swState.groupsSelected = new Set([...swState.groupsSelected].filter(id => groupIds.has(id)));
        const known = new Set(swState.packages.map(p => p.id));
        swState.packagesSelected = new Set([...swState.packagesSelected].filter(id => known.has(id)));
        const availableSets = new Set(swState.packages.flatMap(p => p.sets || []));
        swState.sets = new Set([...swState.sets].filter(name => availableSets.has(name)));
        const hostIds = new Set(swState.hosts.map(h => h.id));
        swState.hostsSelected = new Set([...swState.hostsSelected].filter(id => hostIds.has(id)));
        const parallel = document.getElementById('swParallelism');
        if (parallel) {
            parallel.max = swState.settings.max_hosts || 2;
            parallel.value = Math.min(Number(parallel.value || 2), Number(parallel.max));
        }
        const settingsForm = document.getElementById('swSettingsForm');
        if (settingsForm) Object.entries(swState.settings).forEach(([key, value]) => {
            if (settingsForm.elements[key]) settingsForm.elements[key].value = value;
        });
        renderSoftwareRegistry();
        renderSoftwareTargets();
    } catch (error) { swNotice(error.message, true); }
}

function switchSoftwareTab(panel) {
    if (swState.targetDraft) swCloseTargets();
    swState.panel = panel;
    document.querySelectorAll('[data-sw-panel]').forEach(button => {
        if (button.dataset.swPanel === panel) button.setAttribute('aria-current', 'page');
        else button.removeAttribute('aria-current');
    });
    ['library', 'editor', 'settings', 'progress', 'installers'].forEach(name => {
        document.getElementById(`swPanel-${name}`)?.classList.toggle('hidden', panel !== name);
    });
    if (panel === 'progress') swLoadDeployments();
}

function swChosenPackages() {
    // Preserve the canonical order returned by the server, including name tie-breaks.
    return swState.packages.filter(p => swState.packagesSelected.has(p.id) || (p.sets || []).some(s => swState.sets.has(s)));
}

function swChosenHosts(hostIds=swState.hostsSelected, groupIds=swState.groupsSelected) {
    return swState.hosts.filter(h => hostIds.has(h.id) || (h.groups || []).some(id => groupIds.has(id)));
}

function renderSoftwareRegistry() {
    const sets = document.getElementById('swSets');
    const list = document.getElementById('softwarePackageList');
    if (!sets || !list) return;
    sets.replaceChildren();
    [...new Set(swState.packages.flatMap(p => p.sets || []))].sort().forEach(name => {
        const label = swElement('label', undefined, 'sw-set');
        const check = swElement('input'); check.type = 'checkbox'; check.checked = swState.sets.has(name);
        check.addEventListener('change', () => {
            if (check.checked) swState.sets.add(name); else swState.sets.delete(name);
            renderSoftwareRegistry();
        });
        label.append(check, swElement('span', name)); sets.append(label);
    });
    const q = (document.getElementById('swSearch')?.value || '').toLocaleLowerCase();
    const chosen = new Set(swChosenPackages().map(p => p.id));
    list.replaceChildren();
    swState.packages.filter(p => `${p.name} ${p.version} ${(p.sets || []).join(' ')}`.toLocaleLowerCase().includes(q))
        .sort((a,b) => a.name.localeCompare(b.name)).forEach(p => {
            const row = swElement('div', undefined, `sw-card ${chosen.has(p.id) ? 'sw-selected' : ''}`);
            const label = swElement('label', undefined, 'flex gap-3 items-start flex-1 min-w-0');
            const check = swElement('input'); check.type = 'checkbox'; check.checked = chosen.has(p.id);
            const fromSet = (p.sets || []).some(s => swState.sets.has(s));
            check.disabled = fromSet;
            if (fromSet) check.title = 'Included through a software set. Deselect that set to exclude this application.';
            check.addEventListener('change', () => {
                if (check.checked) swState.packagesSelected.add(p.id); else swState.packagesSelected.delete(p.id);
                renderSoftwareRegistry();
            });
            const details = swElement('span', undefined, 'min-w-0');
            details.append(swElement('strong', `${p.name} · ${p.version}`, 'block'),
                swElement('span', (p.sets || []).join(' · '), 'block text-xs text-slate-500'),
                swElement('span', `${p.approved ? 'Approved' : 'Approval required'} · ${p.prepared ? `${(p.size / 1048576).toFixed(1)} MiB cached in WinHUB` : p.preparation === 'Preparing' ? 'Downloading from OMV…' : p.preparation === 'Queued' ? 'Preparation queued' : p.preparation === 'Error' ? 'Preparation failed' : p.external_url ? 'Preparation required' : 'Script only'}`, 'block text-xs mt-1'));
            label.append(check, details); row.append(label);
            if (window.WinhubCanManageSoftware) {
                const edit = swElement('button', 'Edit', 'sw-button'); edit.type = 'button';
                edit.addEventListener('click', () => swEditPackage(p)); row.append(edit);
                if (swState.isAdmin && !p.approved) {
                    const approve = swElement('button', 'Review and approve', 'sw-button'); approve.type = 'button';
                    approve.addEventListener('click', () => swApprove(p)); row.append(approve);
                }
                if (!p.prepared && p.preparation_error) details.append(swElement('span', `Download error: ${p.preparation_error} Next: open Installers to test the link, or Edit to replace the installer.`, 'block text-xs mt-2'));
                details.append(swElement('span', p.approved ? 'Recipes approved. Choose targets to deploy.' : 'Next: save recipes, then ask a superadmin to Review and approve.', 'block text-xs mt-2'));
                const remove = swElement('button', 'Delete', 'sw-button text-rose-700'); remove.type = 'button';
                remove.addEventListener('click', () => swDeletePackage(p)); row.append(remove);
            }
            list.append(row);
        });
    if (!list.childElementCount) list.append(swElement('p', 'No applications found. Add an application or change your search.', 'text-slate-500 p-4'));
    swUpdatePreview();
}

function renderSoftwareTargets() {
    const endpoints = document.getElementById('swEndpointsCount');
    const groups = document.getElementById('swGroupsCount');
    const summary = document.getElementById('swTargetsSummary');
    if (endpoints) endpoints.textContent = `${swState.hostsSelected.size} individually selected`;
    if (groups) groups.textContent = `${swState.groupsSelected.size} groups selected`;
    if (summary) {
        const hosts = swChosenHosts();
        const names = hosts.slice(0, 3).map(h => h.name).join(', ');
        summary.textContent = hosts.length ? `${hosts.length} unique endpoints: ${names}${hosts.length > 3 ? ` and ${hosts.length - 3} more` : ''}` : 'No targets selected. Choose endpoints or groups.';
    }
    swUpdatePreview();
}

function swOpenTargets(mode) {
    const modal = document.getElementById('swTargetModal');
    if (!modal || !['endpoints', 'groups'].includes(mode)) return;
    swState.targetFocus = document.activeElement;
    swState.targetDraft = {mode, hosts: new Set(swState.hostsSelected), groups: new Set(swState.groupsSelected)};
    document.getElementById('swTargetTitle').textContent = mode === 'groups' ? 'Select endpoint groups' : 'Select endpoints';
    document.getElementById('swTargetDescription').textContent = mode === 'groups'
        ? 'Choose one or more groups. Their endpoints are combined with individual selections without duplicates.'
        : 'Choose individual endpoints. Group selections are retained separately.';
    document.getElementById('swTargetListTitle').textContent = mode === 'groups' ? 'Available groups' : 'Available endpoints';
    const search = document.getElementById('swTargetPickerSearch');
    search.value = ''; search.placeholder = mode === 'groups' ? 'Search groups' : 'Search name or IP address';
    modal.classList.remove('hidden');
    document.body.classList.add('sw-target-modal-open');
    swRenderTargetPicker();
    search.focus();
}

function swCloseTargets() {
    document.getElementById('swTargetModal')?.classList.add('hidden');
    document.body.classList.remove('sw-target-modal-open');
    swState.targetDraft = null;
    swState.targetFocus?.focus();
    swState.targetFocus = null;
}

function swConfirmTargets() {
    const draft = swState.targetDraft;
    if (!draft) return;
    const hosts = new Set(swState.hosts.map(h => h.id)), groups = new Set(swState.groups.map(g => g.id));
    swState.hostsSelected = new Set([...draft.hosts].filter(id => hosts.has(id)));
    swState.groupsSelected = new Set([...draft.groups].filter(id => groups.has(id)));
    swCloseTargets();
    renderSoftwareTargets();
}

function swPickerItems() {
    const draft = swState.targetDraft;
    if (!draft) return [];
    const query = (document.getElementById('swTargetPickerSearch')?.value || '').trim().toLocaleLowerCase();
    return (draft.mode === 'groups' ? swState.groups : swState.hosts)
        .filter(item => `${item.name} ${item.id} ${item.ip || ''} ${item.os_type || ''}`.toLocaleLowerCase().includes(query));
}

function swRenderTargetPicker() {
    const draft = swState.targetDraft;
    if (!draft) return;
    const selected = draft.mode === 'groups' ? draft.groups : draft.hosts;
    const all = draft.mode === 'groups' ? swState.groups : swState.hosts;
    const list = document.getElementById('swTargetPickerList');
    const chosen = document.getElementById('swTargetPickerSelected');
    list.replaceChildren(); chosen.replaceChildren();
    for (const item of swPickerItems()) {
        const row = swElement('label', undefined, `sw-picker-row ${selected.has(item.id) ? 'sw-picker-row-selected' : ''}`);
        const check = swElement('input'); check.type = 'checkbox'; check.checked = selected.has(item.id);
        check.addEventListener('change', () => {
            if (check.checked) selected.add(item.id); else selected.delete(item.id);
            // Keep the focused checkbox in place while updating the selected pane.
            row.classList.toggle('sw-picker-row-selected', check.checked);
            swRenderPickerSelection();
        });
        const text = swElement('span', undefined, 'sw-picker-row-text');
        text.append(swElement('strong', item.name || item.id));
        const description = draft.mode === 'groups' ? `${swState.hosts.filter(h => (h.groups || []).includes(item.id)).length} eligible endpoints` : `${item.online ? '● Online' : '○ Offline'} · ${item.ip || 'No IP'} · ${item.os_type || 'Unknown OS'}`;
        text.append(swElement('span', description, 'sw-muted'));
        row.append(check, text); list.append(row);
    }
    if (!list.childElementCount) list.append(swElement('p', 'No matching targets.', 'sw-muted sw-picker-empty'));
    swRenderPickerSelection();
}

function swRenderPickerSelection() {
    const draft = swState.targetDraft;
    if (!draft) return;
    const selected = draft.mode === 'groups' ? draft.groups : draft.hosts;
    const all = draft.mode === 'groups' ? swState.groups : swState.hosts;
    const chosen = document.getElementById('swTargetPickerSelected');
    chosen.replaceChildren();
    for (const item of all.filter(item => selected.has(item.id))) {
        const row = swElement('div', undefined, 'sw-picker-row');
        const remove = swElement('button', 'Remove', 'sw-button'); remove.type = 'button';
        remove.setAttribute('aria-label', `Remove ${item.name || item.id}`);
        remove.addEventListener('click', () => { selected.delete(item.id); swRenderTargetPicker(); });
        row.append(swElement('strong', item.name || item.id), remove); chosen.append(row);
    }
    if (!chosen.childElementCount) chosen.append(swElement('p', 'Nothing selected yet.', 'sw-muted sw-picker-empty'));
    document.getElementById('swTargetDraftCount').textContent = selected.size;
    const effective = swChosenHosts(draft.hosts, draft.groups);
    document.getElementById('swTargetDraftSummary').textContent = `${selected.size} ${draft.mode === 'groups' ? 'groups' : 'individual endpoints'} selected · ${effective.length} unique endpoints in total. Changes apply only after confirmation.`;
}

function swSelectVisibleTargets() {
    const draft = swState.targetDraft;
    if (!draft) return;
    const selected = draft.mode === 'groups' ? draft.groups : draft.hosts;
    swPickerItems().forEach(item => selected.add(item.id));
    swRenderTargetPicker();
}

function swClearDraftTargets() {
    const draft = swState.targetDraft;
    if (!draft) return;
    (draft.mode === 'groups' ? draft.groups : draft.hosts).clear();
    swRenderTargetPicker();
}

document.addEventListener('keydown', event => {
    if (!swState.targetDraft) return;
    if (event.key === 'Escape') { event.preventDefault(); swCloseTargets(); return; }
    if (event.key !== 'Tab') return;
    const nodes = [...document.querySelectorAll('#swTargetModal button, #swTargetModal input')].filter(n => !n.disabled && n.getClientRects().length);
    const first = nodes[0], last = nodes[nodes.length - 1];
    if (!document.getElementById('swTargetModal')?.contains(document.activeElement)) {
        event.preventDefault(); (event.shiftKey ? last : first)?.focus();
    }
    else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
});

function swUpdatePreview() {
    const node = document.getElementById('swPreview');
    if (!node) return;
    const packages = swChosenPackages(), hosts = swChosenHosts();
    node.textContent = `${packages.length} applications · ${hosts.length} unique endpoints · ${packages.length * hosts.length} operations\n` +
        `Order: ${packages.map(p => p.name + ' ' + p.version).join(' → ') || 'nothing selected'}\n` +
        `Global limit: ${swState.settings.max_hosts || 2} endpoints, ${swState.settings.max_downloads || 2} downloads, ${swState.settings.bandwidth_mib || 10} MiB/s.\n` +
        (hosts.some(h => (h.os_type || '').toLowerCase() !== 'windows') ? 'Warning: non-Windows endpoints are selected. Remove them or change the selected groups.' : '');
}

async function runSoftwareInstall() {
    const packages = swChosenPackages(), hosts = swChosenHosts();
    if (!packages.length || !hosts.length) return swNotice('Select applications and target endpoints or groups.', true);
    if (hosts.some(h => (h.os_type || '').toLowerCase() !== 'windows')) return swNotice('These recipes support Windows. Remove other operating systems from your targets.', true);
    if (packages.some(p => !p.approved)) return swNotice('A superadmin must approve every selected recipe before deployment.', true);
    const operation = document.getElementById('swOperation').value;
    const verbs = {install: 'Install', update: 'Update', uninstall: 'Uninstall', detect: 'Detect status'};
    const summary = `${verbs[operation]}:\n${packages.map(p => `${p.name} ${p.version}`).join('\n')}\n\nTarget endpoints:\n${hosts.map(h => h.name).join(', ')}\n\nLaunch reason:`;
    const launchReason = await askTaskLaunchReason(summary);
    if (launchReason === null) return;
    const button = document.getElementById('softwareRunButton'); button.disabled = true;
    try {
        const data = await swRequest('/api/infrastructure/software/deployments', {method: 'POST',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify({operation,
                package_ids: [...swState.packagesSelected], sets: [...swState.sets],
                target_ids: [...swState.hostsSelected], group_ids: [...swState.groupsSelected],
                expected_target_ids: hosts.map(h => h.id), expected_packages: packages.map(p => ({id:p.id, revision:p.revision})),
                parallelism: Number(document.getElementById('swParallelism').value), launch_reason: launchReason})});
        swNotice(`Deployment created: ${data.packages} applications on ${data.targets} endpoints. The queue starts automatically.`);
        switchSoftwareTab('progress');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; }
}

function newSoftwarePackage() {
    const form = document.getElementById('swPackageForm'); if (!form) return;
    form.reset(); form.elements.package_id.value = '';
    document.getElementById('swLinkTestResult').textContent = 'Uses the saved storage settings. Tests access from the WinHUB server.';
    document.getElementById('swEditorTitle').textContent = 'Add application';
    document.getElementById('swPreparedInfo').textContent = '';
    switchSoftwareTab('editor');
}

function swEditPackage(pkg) {
    newSoftwarePackage();
    const form = document.getElementById('swPackageForm');
    Object.entries(pkg).forEach(([key,value]) => {
        const field = form.elements[key];
        if (field?.tagName === 'SELECT' && key.endsWith('_template_id') && value && ![...field.options].some(o => o.value === value)) {
            field.add(new Option('Unavailable or unapproved Workspace template', value));
        }
        if (key === 'update_requires_installer' && field) { field.value = value ? '1' : '0'; return; }
        if (field && field.type !== 'file' && field.type !== 'checkbox') field.value = key === 'sets' ? value.join(', ') : value ?? '';
    });
    form.elements.package_id.value = pkg.id;
    // Expected hash is only for a newly supplied file, never accidentally reuse an old version's hash.
    form.elements.sha256.value = '';
    document.getElementById('swEditorTitle').textContent = `Edit: ${pkg.name}`;
    document.getElementById('swPreparedInfo').textContent = pkg.preparation_error ? `Download failed: ${pkg.preparation_error} Use Installers to test and prepare a replacement, then select it above.` : pkg.prepared ? `Prepared: ${pkg.version}, SHA-256 ${pkg.sha256}. The existing copy is retained unless a new file or preparation is requested.` : 'Package not prepared yet.';
}

async function swSavePackage(event) {
    event.preventDefault();
    const form = event.currentTarget, id = form.elements.package_id.value;
    const button = document.getElementById('swSaveButton'); button.disabled = true; button.textContent = 'Preparing…';
    try {
        await swRequest('/api/infrastructure/software-packages' + (id ? '/' + encodeURIComponent(id) : ''),
            {method: id ? 'PUT' : 'POST', body: new FormData(form)});
        await loadSoftwareRegistry(); switchSoftwareTab('library');
        swNotice('Application saved. OMV preparation runs in the background; wait until the package is cached in WinHUB. Use Review and approve on the application card (superadmin only).');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; button.textContent = 'Save and prepare package'; }
}

async function swDeletePackage(pkg) {
    if (!confirm(`Remove “${pkg.name}” from the catalogue? Deployment history and files used by existing deployments will be retained.`)) return;
    try {
        await swRequest('/api/infrastructure/software-packages/' + encodeURIComponent(pkg.id), {method: 'DELETE'});
        await loadSoftwareRegistry();
    } catch (error) { swNotice(error.message, true); }
}

async function swSaveSettings(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]'); button.disabled = true;
    try {
        await swRequest('/api/infrastructure/software/settings', {method: 'PUT', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(Object.fromEntries(new FormData(form)))});
        await loadSoftwareRegistry(); swNotice('Settings saved. New limits apply to subsequent operations.');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; }
}

async function swLoadDeployments() {
    if (swState.polling || swState.panel !== 'progress') return;
    const view = document.getElementById('view-software');
    if (!view || view.classList.contains('hidden')) return;
    swState.polling = true;
    try {
        const params = new URLSearchParams(Object.entries(swState.pages).map(([id,page]) => ['page_' + id, String(page)]));
        const data = await swRequest('/api/infrastructure/software/deployments?' + params.toString());
        const list = document.getElementById('swDeployments');
        const expanded = new Set([...list.querySelectorAll('details[open]')].map(n => n.dataset.deployment));
        list.replaceChildren();
        for (const deployment of data.deployments) {
            const card = swElement('div', undefined, 'border border-slate-200 rounded-xl p-4 space-y-3');
            card.append(swElement('strong', `${swLabels[deployment.status] || deployment.status} · ${new Date(deployment.created_at).toLocaleString('uk-UA')}`));
            const done = deployment.completed;
            const progress = swElement('progress'); progress.max = deployment.total || 1; progress.value = done;
            progress.setAttribute('aria-label', 'Completed operations'); progress.className = 'w-full';
            card.append(progress, swElement('p', `${done} / ${deployment.total} operations completed`, 'text-sm text-slate-500'));
            if (['Running','Paused'].includes(deployment.status)) {
                const controls = swElement('div', undefined, 'flex gap-2');
                [['pause','Pause'],['resume','Resume'],['cancel','Cancel pending']].forEach(([action,label]) => {
                    if (action === 'pause' && deployment.status === 'Paused' || action === 'resume' && deployment.status !== 'Paused') return;
                    const button = swElement('button', label, 'sw-button'); button.type = 'button';
                    button.addEventListener('click', async () => {
                        if (action === 'cancel' && !confirm('Cancel all pending operations in this deployment? Installers already running will finish.')) return;
                        button.disabled = true;
                        try { await swRequest(`/api/infrastructure/software/deployments/${encodeURIComponent(deployment.id)}`,
                            {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action})});
                            swState.polling = false; await swLoadDeployments();
                        } catch (error) { swNotice(error.message, true); }
                        finally { button.disabled = false; }
                    }); controls.append(button);
                }); card.append(controls);
            }
            const detail = swElement('details'); detail.dataset.deployment = deployment.id; detail.open = expanded.has(deployment.id);
            detail.append(swElement('summary', 'Endpoints and applications', 'cursor-pointer font-bold'));
            if (deployment.page || deployment.has_more) {
                const pager = swElement('div', undefined, 'flex items-center gap-2 py-2');
                pager.append(swElement('span', `Page ${deployment.page + 1}`, 'text-sm'));
                [['Previous', -1], ['Next', 1]].forEach(([label, delta]) => {
                    const button = swElement('button', label, 'sw-button'); button.type = 'button';
                    button.disabled = delta < 0 ? !deployment.page : !deployment.has_more;
                    button.addEventListener('click', async () => {
                        swState.pages[deployment.id] = deployment.page + delta;
                        await swLoadDeployments();
                    }); pager.append(button);
                }); detail.append(pager);
            }
            deployment.steps.forEach(step => {
                const host = swState.hosts.find(h => h.id === step.host);
                const row = swElement('div', undefined, 'text-sm py-2 border-b border-slate-100');
                row.append(swElement('span', `${host?.name || step.host} · ${step.name}: ${swLabels[step.status] || step.status}${step.message ? ' — ' + step.message : ''}`));
                if (step.resolve_allowed) {
                    const resolve = swElement('button', 'Resolve manually', 'sw-button ml-2'); resolve.type = 'button';
                    resolve.addEventListener('click', async () => {
                        if (!confirm('Check the endpoint first: the installer and all child processes must have stopped. Confirm that execution has stopped?')) return;
                        const reason = await askTaskLaunchReason('Reason for manual resolution after checking the endpoint:');
                        if (reason === null) return;
                        try {
                            await swRequest(`/api/infrastructure/software/deployments/${encodeURIComponent(deployment.id)}`,
                                {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'resolve', step_id:step.id, execution_stopped:true, launch_reason:reason})});
                            await swLoadDeployments();
                        } catch(error) { swNotice(error.message, true); }
                    }); row.append(resolve);
                }
                if (step.task_id && swState.canViewQueue) {
                    const log = swElement('button', 'View log', 'sw-button ml-2'); log.type = 'button';
                    log.addEventListener('click', () => {
                        if (typeof viewTaskDetails === 'function') viewTaskDetails(step.task_id);
                        else switchView('queue');
                    }); row.append(log);
                }
                detail.append(row);
            });
            card.append(detail); list.append(card);
        }
        if (!list.childElementCount) list.append(swElement('p', 'No deployments yet. Select applications and endpoints in the Install tab.'));
    } catch (error) { swNotice(error.message, true); }
    finally { swState.polling = false; }
}

setInterval(() => { if (swState.panel === 'progress') swLoadDeployments(); }, 5000);

setInterval(() => { if ([...swState.packages, ...(swState.installers || [])].some(p => ['Queued', 'Preparing'].includes(p.preparation)) && !swState.targetDraft && ['library', 'installers'].includes(swState.panel) && !document.getElementById('view-software')?.classList.contains('hidden')) loadSoftwareRegistry(); }, 5000);

async function swTestLink(button) {
    const input = document.getElementById('swInstallerForm').elements.external_url;
    const result = document.getElementById('swLinkTestResult');
    const url = input.value.trim();
    if (!url) { result.textContent = 'Enter an OMV download link first.'; input.focus(); return; }
    button.disabled = true;
    result.textContent = 'Testing access from the WinHUB server…';
    try {
        const data = await swRequest('/api/infrastructure/software/test-link', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})
        });
        result.textContent = input.value.trim() === url ? data.message : 'The link changed. Test the new link again.';
    } catch (error) { result.textContent = input.value.trim() === url ? error.message : 'The link changed. Test the new link again.'; }
    finally { button.disabled = false; }
}

function swRenderInstallers() {
    const list = document.getElementById('swInstallerList');
    if (!list) return;
    list.replaceChildren();
    for (const p of swState.installers || []) {
        const card = swElement('div', undefined, 'sw-panel space-y-2');
        card.append(swElement('strong', `${p.name} · ${p.version}`), swElement('p',
            p.prepared ? `Ready · ${(p.size / 1048576).toFixed(1)} MiB · SHA-256 ${p.sha256}` :
            p.preparation === 'Error' ? `Download failed: ${p.preparation_error || 'Check storage settings and test the link.'}` : `Preparing: ${p.preparation || 'Queued'}`));
        const retry = swElement('button', 'Test this link', 'sw-button'); retry.type = 'button';
        retry.addEventListener('click', () => {
            const form = document.getElementById('swInstallerForm');
            ['name', 'version', 'package_type', 'external_url'].forEach(key => { form.elements[key].value = p[key] || ''; });
            document.getElementById('swInstallerForm').elements.external_url.value = p.external_url || '';
            swTestLink(retry);
        });
        card.append(retry); list.append(card);
    }
}
async function swSaveInstaller(event) {
    event.preventDefault();
    const button = event.currentTarget.querySelector('[type="submit"]'); button.disabled = true;
    try {
        await swRequest('/api/infrastructure/software/installers', {method: 'POST', body: new FormData(event.currentTarget)});
        await loadSoftwareRegistry(); swNotice('Installer queued. Wait for Ready before selecting it in an application.');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; }
}
async function swApprove(p) {
    const review = [p.install_command, p.update_command, p.uninstall_command].join('\n\n');
    if (!confirm(`Approve ${p.name} ${p.version}?\nInstaller SHA-256: ${p.sha256 || 'Script only'}\n\n${review}\n\nAlso review detection and Workspace templates in Edit before approving.`)) return;
    try {
        await swRequest(`/api/infrastructure/software/${encodeURIComponent(p.id)}/approve`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({revision: p.revision})});
        await loadSoftwareRegistry(); swNotice('Application recipes approved.');
    } catch (error) { swNotice(error.message, true); }
}
