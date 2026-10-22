/* Software uses DOM text nodes for all catalogue, group and host supplied text. */
const swState = {packages: [], hosts: [], sets: new Set(), packagesSelected: new Set(), hostsSelected: new Set(), settings: {}, panel: 'library', polling: false, pages: {}, canViewQueue: false};
const swLabels = {Queued: 'Очікує', Active: 'Виконується', Success: 'Успішно', Error: 'Помилка',
    Skipped: 'Пропущено', RebootRequired: 'Потрібне перезавантаження', Cancelled: 'Скасовано',
    Running: 'Триває', Paused: 'Призупинено', Cancelling: 'Завершуються поточні операції'};

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
    if (!res.ok || !data.success) throw new Error(data.message || `Помилка сервера (${res.status}).`);
    return data;
}

async function loadSoftwareRegistry() {
    if (!document.getElementById('softwarePackageList')) return;
    try {
        const data = await swRequest('/api/infrastructure/software-packages');
        swState.packages = data.packages || [];
        swState.hosts = data.hosts || [];
        swState.settings = data.settings || {};
        swState.canViewQueue = !!data.can_view_queue;
        const packageForm = document.getElementById('swPackageForm');
        ['install_template_id', 'update_template_id', 'uninstall_template_id'].forEach(name => {
            const field = packageForm?.elements[name];
            if (!field) return;
            const selected = field.value;
            field.replaceChildren(new Option('Власний скрипт у цій картці', ''));
            (data.templates || []).forEach(template => field.add(new Option(`${template.category || 'Workspace'} / ${template.name}`, template.id)));
            field.value = selected;
        });
        const selectedGroups = new Set([...document.querySelectorAll('.sw-group:checked')].map(n => n.value));
        const groupList = document.getElementById('swHostGroups');
        if (groupList) {
            groupList.replaceChildren();
            (data.groups || []).forEach(group => {
                const label = swElement('label', undefined, 'flex items-center gap-2');
                const check = swElement('input'); check.type = 'checkbox'; check.className = 'sw-group';
                check.value = group.id; check.checked = selectedGroups.has(group.id);
                check.addEventListener('change', renderSoftwareTargets);
                label.append(check, swElement('span', group.name)); groupList.append(label);
            });
        }
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
    swState.panel = panel;
    ['library', 'editor', 'settings', 'progress'].forEach(name => {
        document.getElementById(`swPanel-${name}`)?.classList.toggle('hidden', panel !== name);
    });
    if (panel === 'progress') swLoadDeployments();
}

function swChosenPackages() {
    // Preserve the canonical order returned by the server, including name tie-breaks.
    return swState.packages.filter(p => swState.packagesSelected.has(p.id) || (p.sets || []).some(s => swState.sets.has(s)));
}

function swChosenHosts() {
    const groups = new Set([...document.querySelectorAll('.sw-group:checked')].map(n => n.value));
    return swState.hosts.filter(h => swState.hostsSelected.has(h.id) || (h.groups || []).some(id => groups.has(id)));
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
            if (fromSet) check.title = 'Програма вибрана через набір. Зніміть вибір набору, щоб виключити її.';
            check.addEventListener('change', () => {
                if (check.checked) swState.packagesSelected.add(p.id); else swState.packagesSelected.delete(p.id);
                renderSoftwareRegistry();
            });
            const details = swElement('span', undefined, 'min-w-0');
            details.append(swElement('strong', `${p.name} · ${p.version}`, 'block'),
                swElement('span', (p.sets || []).join(' · '), 'block text-xs text-slate-500'),
                swElement('span', `${p.approved ? 'Погоджено' : 'Потрібне погодження'} · ${p.prepared ? `${(p.size / 1048576).toFixed(1)} MiB у WinHUB` : p.preparation === 'Preparing' ? 'Завантажується з OMV…' : p.preparation === 'Queued' ? 'У черзі підготовки' : p.preparation === 'Error' ? 'Помилка підготовки' : p.external_url ? 'Потрібна підготовка файла' : 'Без файла'}`, 'block text-xs mt-1'));
            label.append(check, details); row.append(label);
            if (window.WinhubCanManageSoftware) {
                const edit = swElement('button', 'Змінити', 'sw-button'); edit.type = 'button';
                edit.addEventListener('click', () => swEditPackage(p)); row.append(edit);
                const remove = swElement('button', 'Видалити', 'sw-button text-rose-700'); remove.type = 'button';
                remove.addEventListener('click', () => swDeletePackage(p)); row.append(remove);
            }
            list.append(row);
        });
    if (!list.childElementCount) list.append(swElement('p', 'Програм не знайдено. Додайте програму або змініть пошук.', 'text-slate-500 p-4'));
    swUpdatePreview();
}

function renderSoftwareTargets() {
    const list = document.getElementById('softwareTargetsList');
    if (!list) return;
    const q = (document.getElementById('swHostSearch')?.value || '').toLocaleLowerCase();
    const selectedGroups = new Set([...document.querySelectorAll('.sw-group:checked')].map(n => n.value));
    list.replaceChildren();
    swState.hosts.filter(h => `${h.name} ${h.id}`.toLocaleLowerCase().includes(q)).forEach(h => {
        const label = swElement('label', undefined, 'flex items-center gap-3 p-2 rounded-lg bg-slate-50');
        const fromGroup = (h.groups || []).some(id => selectedGroups.has(id));
        const check = swElement('input'); check.type = 'checkbox'; check.checked = swState.hostsSelected.has(h.id) || fromGroup;
        check.disabled = fromGroup;
        if (fromGroup) check.title = 'Хост вибраний через групу.';
        check.addEventListener('change', () => {
            if (check.checked) swState.hostsSelected.add(h.id); else swState.hostsSelected.delete(h.id);
            swUpdatePreview();
        });
        label.append(check, swElement('span', `${h.name} · ${h.os_type || 'невідома ОС'}`)); list.append(label);
    });
    swUpdatePreview();
}

function swUpdatePreview() {
    const node = document.getElementById('swPreview');
    if (!node) return;
    const packages = swChosenPackages(), hosts = swChosenHosts();
    node.textContent = `${packages.length} програм · ${hosts.length} унікальних хостів · ${packages.length * hosts.length} операцій\n` +
        `Порядок: ${packages.map(p => p.name + ' ' + p.version).join(' → ') || 'нічого не вибрано'}\n` +
        `Глобальний ліміт: ${swState.settings.max_hosts || 2} хостів, ${swState.settings.max_downloads || 2} завантажень, ${swState.settings.bandwidth_mib || 10} MiB/с.\n` +
        (hosts.some(h => (h.os_type || '').toLowerCase() !== 'windows') ? '⚠ У виборі є не-Windows хости: виключіть їх або змініть групи.' : '');
}

async function runSoftwareInstall() {
    const packages = swChosenPackages(), hosts = swChosenHosts();
    if (!packages.length || !hosts.length) return swNotice('Виберіть програми та цільові хости або групи.', true);
    if (hosts.some(h => (h.os_type || '').toLowerCase() !== 'windows')) return swNotice('Ці рецепти підтримують Windows. Виключіть інші ОС із цілей.', true);
    if (packages.some(p => !p.approved)) return swNotice('Спочатку superadmin має погодити всі вибрані рецепти.', true);
    const operation = document.getElementById('swOperation').value;
    const verbs = {install: 'Встановити', update: 'Оновити', uninstall: 'Видалити', detect: 'Перевірити стан'};
    const summary = `${verbs[operation]}:\n${packages.map(p => `${p.name} ${p.version}`).join('\n')}\n\nНа хостах:\n${hosts.map(h => h.name).join(', ')}\n\nПричина запуску:`;
    const launchReason = await askTaskLaunchReason(summary);
    if (launchReason === null) return;
    const button = document.getElementById('softwareRunButton'); button.disabled = true;
    try {
        const data = await swRequest('/api/infrastructure/software/deployments', {method: 'POST',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify({operation,
                package_ids: [...swState.packagesSelected], sets: [...swState.sets],
                target_ids: [...swState.hostsSelected], group_ids: [...document.querySelectorAll('.sw-group:checked')].map(n => n.value),
                expected_target_ids: hosts.map(h => h.id), expected_packages: packages.map(p => ({id:p.id, revision:p.revision})),
                parallelism: Number(document.getElementById('swParallelism').value), launch_reason: launchReason})});
        swNotice(`Розгортання створено: ${data.packages} програм на ${data.targets} хостах. Черга запускається автоматично.`);
        switchSoftwareTab('progress');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; }
}

function newSoftwarePackage() {
    const form = document.getElementById('swPackageForm'); if (!form) return;
    form.reset(); form.elements.package_id.value = '';
    document.getElementById('swEditorTitle').textContent = 'Додати програму';
    document.getElementById('swPreparedInfo').textContent = '';
    switchSoftwareTab('editor');
}

function swEditPackage(pkg) {
    newSoftwarePackage();
    const form = document.getElementById('swPackageForm');
    Object.entries(pkg).forEach(([key,value]) => {
        const field = form.elements[key];
        if (field?.tagName === 'SELECT' && key.endsWith('_template_id') && value && ![...field.options].some(o => o.value === value)) {
            field.add(new Option('Недоступний або непогоджений шаблон Workspace', value));
        }
        if (field && field.type !== 'file' && field.type !== 'checkbox') field.value = key === 'sets' ? value.join(', ') : value ?? '';
    });
    form.elements.package_id.value = pkg.id;
    // Expected hash is only for a newly supplied file, never accidentally reuse an old version's hash.
    form.elements.sha256.value = '';
    document.getElementById('swEditorTitle').textContent = `Змінити: ${pkg.name}`;
    document.getElementById('swPreparedInfo').textContent = pkg.prepared ? `Підготовлено: ${pkg.version}, SHA-256 ${pkg.sha256}. Без нового файла чи повторної підготовки копія зберігається.` : 'Файл ще не підготовлено.';
}

async function swSavePackage(event) {
    event.preventDefault();
    const form = event.currentTarget, id = form.elements.package_id.value;
    const button = document.getElementById('swSaveButton'); button.disabled = true; button.textContent = 'Підготовка…';
    try {
        await swRequest('/api/infrastructure/software-packages' + (id ? '/' + encodeURIComponent(id) : ''),
            {method: id ? 'PUT' : 'POST', body: new FormData(form)});
        await loadSoftwareRegistry(); switchSoftwareTab('library');
        swNotice('Програму збережено. Пакет OMV готується у фоні; дочекайтеся статусу «MiB у WinHUB». Без погодження superadmin запуск недоступний.');
    } catch (error) { swNotice(error.message, true); }
    finally { button.disabled = false; button.textContent = 'Зберегти та підготувати пакет'; }
}

async function swDeletePackage(pkg) {
    if (!confirm(`Прибрати «${pkg.name}» з каталогу? Історія й файли поточних розгортань збережуться.`)) return;
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
        await loadSoftwareRegistry(); swNotice('Налаштування збережено. Нові ліміти застосовуються до наступних операцій.');
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
            progress.setAttribute('aria-label', 'Завершені операції'); progress.className = 'w-full';
            card.append(progress, swElement('p', `${done} / ${deployment.total} операцій завершено`, 'text-sm text-slate-500'));
            if (['Running','Paused'].includes(deployment.status)) {
                const controls = swElement('div', undefined, 'flex gap-2');
                [['pause','Призупинити'],['resume','Продовжити'],['cancel','Скасувати наступні']].forEach(([action,label]) => {
                    if (action === 'pause' && deployment.status === 'Paused' || action === 'resume' && deployment.status !== 'Paused') return;
                    const button = swElement('button', label, 'sw-button'); button.type = 'button';
                    button.addEventListener('click', async () => {
                        if (action === 'cancel' && !confirm('Скасувати всі операції цього запуску, що ще очікують? Поточні інсталятори завершаться.')) return;
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
            detail.append(swElement('summary', 'Хости та програми', 'cursor-pointer font-bold'));
            if (deployment.page || deployment.has_more) {
                const pager = swElement('div', undefined, 'flex items-center gap-2 py-2');
                pager.append(swElement('span', `Сторінка ${deployment.page + 1}`, 'text-sm'));
                [['Попередня', -1], ['Наступна', 1]].forEach(([label, delta]) => {
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
                    const resolve = swElement('button', 'Завершити вручну', 'sw-button ml-2'); resolve.type = 'button';
                    resolve.addEventListener('click', async () => {
                        if (!confirm('Спочатку перевірте хост: інсталятор і його дочірні процеси повинні бути завершені. Підтверджуєте, що виконання зупинено?')) return;
                        const reason = await askTaskLaunchReason('Причина ручного завершення після перевірки хоста:');
                        if (reason === null) return;
                        try {
                            await swRequest(`/api/infrastructure/software/deployments/${encodeURIComponent(deployment.id)}`,
                                {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'resolve', step_id:step.id, execution_stopped:true, launch_reason:reason})});
                            await swLoadDeployments();
                        } catch(error) { swNotice(error.message, true); }
                    }); row.append(resolve);
                }
                if (step.task_id && swState.canViewQueue) {
                    const log = swElement('button', 'Журнал', 'sw-button ml-2'); log.type = 'button';
                    log.addEventListener('click', () => {
                        if (typeof viewTaskDetails === 'function') viewTaskDetails(step.task_id);
                        else switchView('queue');
                    }); row.append(log);
                }
                detail.append(row);
            });
            card.append(detail); list.append(card);
        }
        if (!list.childElementCount) list.append(swElement('p', 'Розгортань ще немає. Виберіть програми й хости у вкладці «Встановлення».'));
    } catch (error) { swNotice(error.message, true); }
    finally { swState.polling = false; }
}

setInterval(() => { if (swState.panel === 'progress') swLoadDeployments(); }, 5000);

setInterval(() => { if (swState.packages.some(p => ['Queued', 'Preparing'].includes(p.preparation)) && swState.panel === 'library' && !document.getElementById('view-software')?.classList.contains('hidden')) loadSoftwareRegistry(); }, 5000);
