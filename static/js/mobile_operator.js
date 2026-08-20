(() => {
    'use strict';

    const permissions = window.WinhubMobilePermissions || {};
    const state = {
        activeTab: '',
        jobs: [],
        reports: [],
        launchOptions: null,
        jobFilter: 'all',
        launchStep: 1,
        selectedTemplateId: '',
        targetType: 'hosts',
        selectedHostIds: new Set(),
        selectedGroupId: '',
        launching: false,
        taskLoading: false,
        reportLoading: false,
        pollTimer: null,
        toastTimer: null,
    };
    const storageKeys = {
        mode: 'winhub_ui_mode',
        tab: 'winhub_mobile_tab',
        favorites: 'winhub_mobile_favorite_templates',
        recent: 'winhub_mobile_recent_templates',
    };

    const byId = id => document.getElementById(id);
    const all = selector => Array.from(document.querySelectorAll(selector));

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>'"]/g, character => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
        }[character]));
    }

    function storedList(key) {
        try {
            const parsed = JSON.parse(localStorage.getItem(key) || '[]');
            return Array.isArray(parsed) ? parsed.map(String) : [];
        } catch (_) {
            return [];
        }
    }

    async function apiJson(url, options = {}) {
        const response = await fetch(url, options);
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.success === false) {
            const error = new Error(data.message || `Request failed (${response.status})`);
            error.status = response.status;
            error.data = data;
            throw error;
        }
        return data;
    }

    function showToast(message, kind = 'success') {
        const toast = byId('moToast');
        if (!toast) return;
        clearTimeout(state.toastTimer);
        toast.textContent = message;
        toast.dataset.kind = kind;
        toast.hidden = false;
        state.toastTimer = setTimeout(() => { toast.hidden = true; }, 4500);
    }

    function availableTabs() {
        return all('[data-mobile-tab]').map(button => button.dataset.mobileTab);
    }

    function defaultTab() {
        if (permissions.view_queue) return 'tasks';
        if (permissions.run_tasks) return 'launch';
        return 'reports';
    }

    function switchTab(tab) {
        const tabs = availableTabs();
        const next = tabs.includes(tab) ? tab : defaultTab();
        state.activeTab = next;
        localStorage.setItem(storageKeys.tab, next);
        all('[data-mobile-tab]').forEach(button => {
            const active = button.dataset.mobileTab === next;
            button.classList.toggle('is-active', active);
            button.setAttribute('aria-current', active ? 'page' : 'false');
        });
        all('[data-mobile-view]').forEach(view => {
            view.hidden = view.dataset.mobileView !== next;
        });
        window.scrollTo({top: 0, behavior: 'auto'});
        if (next === 'tasks') loadTasks();
        if (next === 'reports') loadReports();
        if (next === 'launch') loadLaunchOptions();
        schedulePolling();
    }

    function schedulePolling() {
        clearTimeout(state.pollTimer);
        if (document.hidden || state.activeTab !== 'tasks' || !permissions.view_queue) return;
        state.pollTimer = setTimeout(async () => {
            await loadTasks(true);
            schedulePolling();
        }, 15000);
    }

    function normalizeStatus(status) {
        const value = String(status || 'Pending').trim().toLowerCase();
        if (value === 'success') return 'success';
        if (value === 'error' || value === 'failed') return 'error';
        if (value === 'cancelled' || value === 'canceled') return 'cancelled';
        if (value === 'scheduled') return 'scheduled';
        if (value === 'running' || value === 'pickedup' || value === 'picked_up') return 'running';
        return 'pending';
    }

    function statusLabel(status) {
        const normalized = normalizeStatus(status);
        return ({
            success: 'Виконано', error: 'Помилка', cancelled: 'Скасовано',
            scheduled: 'Заплановано', running: 'Виконується', pending: 'Очікує',
        })[normalized];
    }

    function statusClass(status) {
        const normalized = normalizeStatus(status);
        if (normalized === 'success') return 'success';
        if (normalized === 'error') return 'error';
        if (['pending', 'running', 'scheduled'].includes(normalized)) return 'active';
        return 'neutral';
    }

    function jobMatchesFilter(job) {
        const normalized = normalizeStatus(job.status);
        if (state.jobFilter === 'active') return ['pending', 'running', 'scheduled'].includes(normalized);
        if (state.jobFilter === 'error') return normalized === 'error' || Number(job.error || 0) > 0;
        if (state.jobFilter === 'success') return normalized === 'success';
        return true;
    }

    function renderTaskStats() {
        const jobs = state.jobs || [];
        const active = jobs.filter(job => ['pending', 'running', 'scheduled'].includes(normalizeStatus(job.status))).length;
        const errors = jobs.filter(job => normalizeStatus(job.status) === 'error' || Number(job.error || 0) > 0).length;
        if (byId('moTaskTotal')) byId('moTaskTotal').textContent = String(jobs.length);
        if (byId('moTaskActive')) byId('moTaskActive').textContent = String(active);
        if (byId('moTaskErrors')) byId('moTaskErrors').textContent = String(errors);
    }

    function renderTasks() {
        const container = byId('moTasksList');
        if (!container) return;
        renderTaskStats();
        const query = String(byId('moTaskSearch')?.value || '').trim().toLowerCase();
        const jobs = (state.jobs || []).filter(job => {
            const haystack = `${job.title || ''} ${job.target_summary || ''} ${job.created_by || ''} ${job.status || ''}`.toLowerCase();
            return jobMatchesFilter(job) && haystack.includes(query);
        });
        if (!jobs.length) {
            container.innerHTML = '<div class="mo-empty">Немає задач, що відповідають фільтру.</div>';
            return;
        }
        container.innerHTML = jobs.map(job => {
            const total = Math.max(0, Number(job.total || 0));
            const completed = Math.min(total, Number(job.success || 0) + Number(job.error || 0) + Number(job.cancelled || 0));
            const progress = total ? Math.round((completed / total) * 100) : 0;
            const label = statusLabel(job.status);
            const css = statusClass(job.status);
            return `
                <button type="button" class="mo-job-card" data-job-id="${escapeHtml(job.job_id)}">
                    <span class="mo-card-top">
                        <span class="mo-card-title">
                            <strong>${escapeHtml(job.title || 'Без назви')}</strong>
                            <small>${escapeHtml(job.target_summary || 'Ціль не вказана')}</small>
                        </span>
                        <span class="mo-status mo-status-${css}">${escapeHtml(label)}</span>
                    </span>
                    <progress class="mo-progress" max="100" value="${progress}" aria-label="Виконано ${progress}%"></progress>
                    <span class="mo-card-footer">
                        <span>${escapeHtml(job.created_at || '')}</span>
                        <strong>${completed}/${total || 0} · помилок ${Number(job.error || 0)}</strong>
                    </span>
                </button>`;
        }).join('');
        container.querySelectorAll('[data-job-id]').forEach(button => {
            button.addEventListener('click', () => openJob(button.dataset.jobId));
        });
    }

    async function loadTasks(silent = false) {
        if (!permissions.view_queue || state.taskLoading) return;
        const container = byId('moTasksList');
        state.taskLoading = true;
        if (!silent && container && !state.jobs.length) {
            container.innerHTML = '<div class="mo-loading-card"><span class="mo-spinner"></span> Завантаження задач…</div>';
        }
        try {
            const data = await apiJson('/api/infrastructure/tasks/all');
            state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
            renderTasks();
        } catch (error) {
            if (container && !silent) container.innerHTML = `<div class="mo-error-card">${escapeHtml(error.message || 'Не вдалося завантажити задачі.')}</div>`;
        } finally {
            state.taskLoading = false;
            schedulePolling();
        }
    }

    function openOverlay(id) {
        const overlay = byId(id);
        if (!overlay) return;
        overlay.hidden = false;
        document.body.classList.add('mo-modal-open');
        overlay.querySelector('button, [href], input, select, textarea')?.focus();
    }

    function closeOverlay(id) {
        const overlay = byId(id);
        if (overlay) overlay.hidden = true;
        if (!all('.mo-overlay').some(item => !item.hidden)) document.body.classList.remove('mo-modal-open');
    }

    function openJob(jobId) {
        const job = state.jobs.find(item => String(item.job_id) === String(jobId));
        if (!job) return;
        byId('moJobTitle').textContent = job.title || 'Задача';
        byId('moJobMeta').textContent = `${job.action || 'operation'} · ${job.created_at || ''}`;
        const stats = byId('moJobStats');
        if (stats) {
            stats.innerHTML = `
                <div><span>Усього</span><strong>${Number(job.total || 0)}</strong></div>
                <div><span>Успішно</span><strong>${Number(job.success || 0)}</strong></div>
                <div><span>Помилки</span><strong>${Number(job.error || 0)}</strong></div>`;
        }
        const hosts = byId('moJobHosts');
        const tasks = Array.isArray(job.tasks) ? job.tasks : [];
        if (!tasks.length) {
            hosts.innerHTML = '<div class="mo-empty">Деталі цілей ще недоступні.</div>';
        } else {
            hosts.innerHTML = tasks.map(task => {
                const taskId = task.task_id ? String(task.task_id) : '';
                return `
                    <article class="mo-result-row">
                        <span class="mo-result-host">
                            <strong>${escapeHtml(task.name || task.display_name || task.hostname || 'Невідомий хост')}</strong>
                            <small>${escapeHtml(statusLabel(task.status))}</small>
                        </span>
                        ${taskId ? `<button type="button" class="mo-result-action" data-task-id="${escapeHtml(taskId)}">Лог</button>` : '<span class="mo-status mo-status-neutral">План</span>'}
                    </article>`;
            }).join('');
            hosts.querySelectorAll('[data-task-id]').forEach(button => {
                button.addEventListener('click', () => openTaskLog(button.dataset.taskId));
            });
        }
        openOverlay('moJobModal');
    }

    async function openTaskLog(taskId) {
        byId('moLogTitle').textContent = 'Лог задачі';
        byId('moLogMeta').textContent = `Task ID: ${taskId}`;
        byId('moLogBody').textContent = 'Завантаження…';
        openOverlay('moLogModal');
        try {
            const result = await apiJson(`/api/infrastructure/task/${encodeURIComponent(taskId)}`);
            const task = result.data || {};
            byId('moLogTitle').textContent = task.title || 'Лог задачі';
            byId('moLogMeta').textContent = `${task.name || task.hostname || 'Хост'} · ${statusLabel(task.status)}`;
            byId('moLogBody').textContent = task.log || 'Задача очікує відповіді агента.';
        } catch (error) {
            byId('moLogBody').textContent = error.message || 'Не вдалося завантажити лог.';
        }
    }

    function renderReports() {
        const container = byId('moReportsList');
        if (!container) return;
        const query = String(byId('moReportSearch')?.value || '').trim().toLowerCase();
        const reports = (state.reports || []).filter(report => `${report.title || ''} ${report.status || ''}`.toLowerCase().includes(query));
        if (!reports.length) {
            container.innerHTML = '<div class="mo-empty">Звітів за цим запитом немає.</div>';
            return;
        }
        container.innerHTML = reports.map(report => {
            const css = Number(report.error || 0) > 0 ? 'error' : (String(report.status || '').toLowerCase().includes('waiting') ? 'active' : 'success');
            return `
                <button type="button" class="mo-report-card" data-report-id="${escapeHtml(report.id)}">
                    <span class="mo-card-top">
                        <span class="mo-card-title"><strong>${escapeHtml(report.title || 'Звіт')}</strong><small>${escapeHtml(report.created_at || '')}</small></span>
                        <span class="mo-status mo-status-${css}">${escapeHtml(report.status || 'Готово')}</span>
                    </span>
                    <span class="mo-report-counts">
                        <span>Усього ${Number(report.total || 0)}</span>
                        <span class="is-success">Успішно ${Number(report.success || 0)}</span>
                        <span class="is-error">Помилки ${Number(report.error || 0)}</span>
                    </span>
                </button>`;
        }).join('');
        container.querySelectorAll('[data-report-id]').forEach(button => {
            button.addEventListener('click', () => openReport(button.dataset.reportId));
        });
    }

    async function loadReports(force = false) {
        if (!permissions.view_reports || state.reportLoading) return;
        if (state.reports.length && !force) {
            renderReports();
            return;
        }
        const container = byId('moReportsList');
        state.reportLoading = true;
        if (container) container.innerHTML = '<div class="mo-loading-card"><span class="mo-spinner"></span> Завантаження звітів…</div>';
        try {
            const data = await apiJson('/api/infrastructure/reports/all');
            state.reports = Array.isArray(data.data) ? data.data : [];
            renderReports();
        } catch (error) {
            if (container) container.innerHTML = `<div class="mo-error-card">${escapeHtml(error.message || 'Не вдалося завантажити звіти.')}</div>`;
        } finally {
            state.reportLoading = false;
        }
    }

    function readableReportBody(value) {
        const source = String(value || '');
        if (!/<[a-z][\s\S]*>/i.test(source)) return source;
        try {
            const documentFragment = new DOMParser().parseFromString(source, 'text/html');
            documentFragment.querySelectorAll('script, style, noscript').forEach(node => node.remove());
            documentFragment.querySelectorAll('br').forEach(node => node.replaceWith('\n'));
            documentFragment.querySelectorAll('p, div, h1, h2, h3, h4, li, tr').forEach(node => node.append('\n'));
            return String(documentFragment.body.textContent || source).replace(/\n[ \t]+/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
        } catch (_) {
            return source;
        }
    }

    async function openReport(reportId) {
        const summary = state.reports.find(item => String(item.id) === String(reportId));
        byId('moReportTitle').textContent = summary?.title || 'Звіт';
        byId('moReportMeta').textContent = summary ? `${summary.created_at || ''} · ${summary.status || ''}` : '';
        byId('moReportBody').textContent = 'Завантаження…';
        openOverlay('moReportModal');
        try {
            const result = await apiJson(`/api/infrastructure/reports/${encodeURIComponent(reportId)}`);
            const report = result.data || {};
            byId('moReportTitle').textContent = report.title || summary?.title || 'Звіт';
            byId('moReportMeta').textContent = `${report.created_at || summary?.created_at || ''} · ${report.status || summary?.status || ''}`;
            byId('moReportBody').textContent = readableReportBody(report.report_data || 'Звіт порожній.');
        } catch (error) {
            byId('moReportBody').textContent = error.message || 'Не вдалося завантажити звіт.';
        }
    }

    function selectedTemplate() {
        return state.launchOptions?.templates?.find(template => String(template.id) === String(state.selectedTemplateId)) || null;
    }

    function favoriteIds() {
        return new Set(storedList(storageKeys.favorites));
    }

    function toggleFavorite(templateId) {
        const favorites = favoriteIds();
        const id = String(templateId);
        if (favorites.has(id)) favorites.delete(id);
        else favorites.add(id);
        localStorage.setItem(storageKeys.favorites, JSON.stringify(Array.from(favorites)));
        renderTemplates();
    }

    function rememberTemplate(templateId) {
        const id = String(templateId);
        const recent = storedList(storageKeys.recent).filter(item => item !== id);
        recent.unshift(id);
        localStorage.setItem(storageKeys.recent, JSON.stringify(recent.slice(0, 8)));
    }

    function renderTemplates() {
        const container = byId('moTemplateList');
        if (!container || !state.launchOptions) return;
        const query = String(byId('moTemplateSearch')?.value || '').trim().toLowerCase();
        const favorites = favoriteIds();
        const recent = storedList(storageKeys.recent);
        const recentRank = new Map(recent.map((id, index) => [id, index]));
        const templates = (state.launchOptions.templates || []).filter(template => (
            `${template.name || ''} ${template.category || ''} ${template.action_type || ''}`.toLowerCase().includes(query)
        )).sort((left, right) => {
            const leftId = String(left.id);
            const rightId = String(right.id);
            const favoriteDelta = Number(favorites.has(rightId)) - Number(favorites.has(leftId));
            if (favoriteDelta) return favoriteDelta;
            const leftRank = recentRank.has(leftId) ? recentRank.get(leftId) : Number.MAX_SAFE_INTEGER;
            const rightRank = recentRank.has(rightId) ? recentRank.get(rightId) : Number.MAX_SAFE_INTEGER;
            if (leftRank !== rightRank) return leftRank - rightRank;
            return String(left.name || '').localeCompare(String(right.name || ''));
        });
        if (!templates.length) {
            container.innerHTML = '<div class="mo-empty">Доступних шаблонів не знайдено.</div>';
            return;
        }
        container.innerHTML = templates.map(template => {
            const id = String(template.id);
            const selected = id === String(state.selectedTemplateId);
            const favorite = favorites.has(id);
            const risk = template.risk_level === 'high' ? ' · підвищений ризик' : '';
            return `
                <div class="mo-template-row${selected ? ' is-selected' : ''}">
                    <button type="button" class="mo-template-select" data-template-id="${escapeHtml(id)}">
                        <strong>${escapeHtml(template.name || 'Шаблон')}</strong>
                        <span>${escapeHtml(template.category || 'General')} · ${escapeHtml(template.type || 'action')}${escapeHtml(risk)}</span>
                    </button>
                    <button type="button" class="mo-favorite${favorite ? ' is-active' : ''}" data-favorite-id="${escapeHtml(id)}" aria-label="${favorite ? 'Прибрати з обраних' : 'Додати в обрані'}">★</button>
                </div>`;
        }).join('');
        container.querySelectorAll('[data-template-id]').forEach(button => {
            button.addEventListener('click', () => {
                state.selectedTemplateId = button.dataset.templateId;
                const template = selectedTemplate();
                if (template && !byId('moTaskTitle').value.trim()) byId('moTaskTitle').value = template.name || '';
                setLaunchError('');
                renderTemplates();
                updateLaunchActions();
            });
        });
        container.querySelectorAll('[data-favorite-id]').forEach(button => {
            button.addEventListener('click', () => toggleFavorite(button.dataset.favoriteId));
        });
    }

    function renderHosts() {
        const container = byId('moHostList');
        if (!container || !state.launchOptions) return;
        const query = String(byId('moHostSearch')?.value || '').trim().toLowerCase();
        const hosts = (state.launchOptions.hosts || []).filter(host => (
            `${host.name || ''} ${host.hostname || ''} ${host.ip || ''} ${host.os_type || ''}`.toLowerCase().includes(query)
        )).sort((left, right) => Number(!!right.is_online) - Number(!!left.is_online) || String(left.name || '').localeCompare(String(right.name || '')));
        if (!hosts.length) {
            container.innerHTML = '<div class="mo-empty">Дозволених хостів не знайдено.</div>';
            return;
        }
        container.innerHTML = hosts.map(host => {
            const id = String(host.id);
            const selected = state.selectedHostIds.has(id);
            return `
                <button type="button" class="mo-host-row${selected ? ' is-selected' : ''}" data-host-id="${escapeHtml(id)}" aria-pressed="${selected ? 'true' : 'false'}">
                    <span class="mo-host-check" aria-hidden="true">✓</span>
                    <span class="mo-online-dot${host.is_online ? ' is-online' : ''}"></span>
                    <span class="mo-host-copy">
                        <strong>${escapeHtml(host.name || host.hostname || id)}</strong>
                        <small>${host.is_online ? 'Online' : 'Offline'} · ${escapeHtml(host.ip || host.hostname || host.os_type || '')}</small>
                    </span>
                </button>`;
        }).join('');
        container.querySelectorAll('[data-host-id]').forEach(button => {
            button.addEventListener('click', () => {
                const id = String(button.dataset.hostId);
                if (state.selectedHostIds.has(id)) state.selectedHostIds.delete(id);
                else state.selectedHostIds.add(id);
                renderHosts();
                updateLaunchActions();
            });
        });
        byId('moSelectedHostCount').textContent = String(state.selectedHostIds.size);
    }

    function renderGroups() {
        const select = byId('moGroupSelect');
        if (!select || !state.launchOptions) return;
        const current = state.selectedGroupId;
        select.innerHTML = '<option value="">Оберіть групу…</option>' + (state.launchOptions.groups || []).map(group => (
            `<option value="${escapeHtml(group.id)}">${escapeHtml(group.name || 'Група')} (${Number(group.hosts_count || 0)})</option>`
        )).join('');
        select.value = current;
    }

    async function loadLaunchOptions(force = false) {
        if (!permissions.run_tasks) return;
        if (state.launchOptions && !force) {
            renderTemplates();
            renderHosts();
            renderGroups();
            return;
        }
        try {
            const data = await apiJson('/api/infrastructure/task-launch/options');
            state.launchOptions = {
                templates: Array.isArray(data.templates) ? data.templates : [],
                hosts: Array.isArray(data.hosts) ? data.hosts : [],
                groups: Array.isArray(data.groups) ? data.groups : [],
            };
            renderTemplates();
            renderHosts();
            renderGroups();
        } catch (error) {
            const container = byId('moTemplateList');
            if (container) container.innerHTML = `<div class="mo-error-card">${escapeHtml(error.message || 'Не вдалося завантажити дані запуску.')}</div>`;
        }
    }

    function setTargetType(type) {
        state.targetType = type === 'group' ? 'group' : 'hosts';
        if (byId('moHostsPanel')) byId('moHostsPanel').hidden = state.targetType !== 'hosts';
        if (byId('moGroupPanel')) byId('moGroupPanel').hidden = state.targetType !== 'group';
        byId('moTargetHosts')?.classList.toggle('is-active', state.targetType === 'hosts');
        byId('moTargetGroup')?.classList.toggle('is-active', state.targetType === 'group');
        setLaunchError('');
        updateLaunchActions();
    }

    function targetCount() {
        if (state.targetType === 'hosts') return state.selectedHostIds.size;
        const group = state.launchOptions?.groups?.find(item => String(item.id) === String(state.selectedGroupId));
        return Number(group?.hosts_count || 0);
    }

    function targetSummary() {
        if (state.targetType === 'group') {
            const group = state.launchOptions?.groups?.find(item => String(item.id) === String(state.selectedGroupId));
            return group ? `${group.name} · ${Number(group.hosts_count || 0)} хостів` : 'Групу не обрано';
        }
        const count = state.selectedHostIds.size;
        if (count === 1) {
            const id = Array.from(state.selectedHostIds)[0];
            const host = state.launchOptions?.hosts?.find(item => String(item.id) === id);
            return host?.name || '1 хост';
        }
        return `${count} хостів`;
    }

    function variableSpec(template, name) {
        const source = template?.variable_schema?.[name];
        let spec = {};
        if (Array.isArray(source)) spec = {type: 'select', options: source};
        else if (source && typeof source === 'object') spec = {...source};
        else if (typeof source === 'string') spec = {type: 'text', label: source};
        if (!spec.type) spec.type = /folders|paths|list|users|ids/i.test(name) ? 'textarea' : 'text';
        if (!spec.label) spec.label = name;
        if (!spec.options && spec.choices) spec.options = spec.choices;
        if (typeof spec.options === 'string') spec.options = spec.options.split(/\r?\n|,/).map(item => item.trim()).filter(Boolean);
        return spec;
    }

    function renderVariables() {
        const container = byId('moVariables');
        const template = selectedTemplate();
        if (!container || !template) return;
        const variables = Array.isArray(template.variables) ? template.variables : [];
        if (!variables.length) {
            container.innerHTML = '';
            return;
        }
        container.innerHTML = variables.map(name => {
            const spec = variableSpec(template, name);
            const type = String(spec.type || 'text').toLowerCase();
            const value = spec.default ?? '';
            let field = '';
            if (type === 'select') {
                const options = Array.isArray(spec.options) ? spec.options : [];
                field = `<select data-mobile-var="${escapeHtml(name)}">${options.map(option => {
                    const optionValue = typeof option === 'object' ? (option.value ?? option.label ?? '') : option;
                    const optionLabel = typeof option === 'object' ? (option.label ?? option.value ?? '') : option;
                    return `<option value="${escapeHtml(optionValue)}"${String(optionValue) === String(value) ? ' selected' : ''}>${escapeHtml(optionLabel)}</option>`;
                }).join('')}</select>`;
            } else if (type === 'textarea') {
                field = `<textarea data-mobile-var="${escapeHtml(name)}" placeholder="${escapeHtml(spec.placeholder || '')}">${escapeHtml(value)}</textarea>`;
            } else if (type === 'checkbox' || type === 'boolean') {
                const checked = value === true || value === 1 || String(value).toLowerCase() === 'true';
                field = `<label class="mo-checkbox-field"><input type="checkbox" data-mobile-var="${escapeHtml(name)}"${checked ? ' checked' : ''}><span>${escapeHtml(spec.checkbox_label || spec.label || name)}</span></label>`;
            } else {
                const sensitive = /password|passwd|secret|token|credential/i.test(name);
                const inputType = sensitive ? 'password' : (type === 'number' ? 'number' : 'text');
                const constraints = type === 'number'
                    ? `${spec.min !== undefined ? ` min="${escapeHtml(spec.min)}"` : ''}${spec.max !== undefined ? ` max="${escapeHtml(spec.max)}"` : ''}${spec.step !== undefined ? ` step="${escapeHtml(spec.step)}"` : ''}`
                    : '';
                field = `<input type="${inputType}" data-mobile-var="${escapeHtml(name)}" value="${escapeHtml(value)}" placeholder="${escapeHtml(spec.placeholder || '')}"${constraints}>`;
            }
            return `<div class="mo-variable-field"><span>${escapeHtml(spec.label || name)}</span>${field}${spec.help ? `<small>${escapeHtml(spec.help)}</small>` : ''}</div>`;
        }).join('');
    }

    function collectVariables() {
        const variables = {};
        all('[data-mobile-var]').forEach(input => {
            const name = input.dataset.mobileVar;
            if (!name) return;
            variables[name] = input.type === 'checkbox' ? (input.checked ? 'true' : 'false') : input.value;
        });
        return variables;
    }

    function renderReview() {
        const template = selectedTemplate();
        if (!template) return;
        byId('moLaunchSummary').innerHTML = `
            <strong>${escapeHtml(template.name || 'Шаблон')}</strong>
            <span>Ціль: ${escapeHtml(targetSummary())}</span>
            <span>Тип: ${escapeHtml(template.action_type || template.type || 'operation')}</span>`;
        if (!byId('moTaskTitle').value.trim()) byId('moTaskTitle').value = template.name || '';
        renderVariables();
        const count = targetCount();
        const risky = template.risk_level === 'high' || count >= 10;
        byId('moRiskConfirmation').hidden = !risky;
        byId('moRiskCheckbox').checked = false;
        byId('moRiskText').textContent = template.risk_level === 'high'
            ? `Ця операція має підвищений ризик і буде запущена на ${count} хостах.`
            : `Операція буде запущена одразу на ${count} хостах.`;
    }

    function setLaunchStep(step) {
        state.launchStep = Math.max(1, Math.min(3, Number(step) || 1));
        all('[data-launch-step]').forEach(section => { section.hidden = Number(section.dataset.launchStep) !== state.launchStep; });
        all('[data-launch-progress]').forEach(progress => { progress.classList.toggle('is-active', Number(progress.dataset.launchProgress) <= state.launchStep); });
        if (state.launchStep === 2) renderHosts();
        if (state.launchStep === 3) renderReview();
        setLaunchError('');
        updateLaunchActions();
        window.scrollTo({top: 0, behavior: 'smooth'});
    }

    function setLaunchError(message) {
        const alert = byId('moLaunchError');
        if (!alert) return;
        alert.textContent = message || '';
        alert.hidden = !message;
    }

    function launchTargetsValid() {
        return state.targetType === 'group' ? !!state.selectedGroupId : state.selectedHostIds.size > 0;
    }

    function updateLaunchActions() {
        const back = byId('moLaunchBack');
        const next = byId('moLaunchNext');
        const run = byId('moLaunchRun');
        if (!back || !next || !run) return;
        back.hidden = state.launchStep === 1;
        next.hidden = state.launchStep === 3;
        run.hidden = state.launchStep !== 3;
        if (state.launchStep === 1) next.disabled = !state.selectedTemplateId;
        if (state.launchStep === 2) next.disabled = !launchTargetsValid();
        if (state.launchStep === 3) {
            const confirmationRequired = !byId('moRiskConfirmation').hidden;
            run.disabled = state.launching || (confirmationRequired && !byId('moRiskCheckbox').checked);
            run.textContent = state.launching ? 'Запуск…' : `Запустити · ${targetCount()}`;
        }
    }

    function resetLaunch() {
        state.launchStep = 1;
        state.selectedTemplateId = '';
        state.targetType = 'hosts';
        state.selectedHostIds.clear();
        state.selectedGroupId = '';
        state.launching = false;
        if (byId('moTemplateSearch')) byId('moTemplateSearch').value = '';
        if (byId('moHostSearch')) byId('moHostSearch').value = '';
        if (byId('moTaskTitle')) byId('moTaskTitle').value = '';
        if (byId('moGroupSelect')) byId('moGroupSelect').value = '';
        setTargetType('hosts');
        renderTemplates();
        renderHosts();
        setLaunchStep(1);
    }

    function launchNext() {
        if (state.launchStep === 1) {
            if (!selectedTemplate()) return setLaunchError('Оберіть шаблон.');
            setLaunchStep(2);
            return;
        }
        if (state.launchStep === 2) {
            if (!launchTargetsValid()) return setLaunchError(state.targetType === 'group' ? 'Оберіть групу.' : 'Оберіть хоча б один хост.');
            setLaunchStep(3);
        }
    }

    async function submitLaunch() {
        const template = selectedTemplate();
        if (!template || !launchTargetsValid() || state.launching) return;
        const title = String(byId('moTaskTitle').value || '').trim() || template.name || 'Mobile task';
        if (title.length > 150) return setLaunchError('Назва задачі не може бути довшою за 150 символів.');
        const confirmationRequired = !byId('moRiskConfirmation').hidden;
        if (confirmationRequired && !byId('moRiskCheckbox').checked) return setLaunchError('Підтвердьте запуск операції.');
        const payload = {
            title,
            target_type: state.targetType,
            variables: collectVariables(),
            ...(state.targetType === 'group'
                ? {target_id: state.selectedGroupId}
                : {target_ids: Array.from(state.selectedHostIds)}),
        };
        state.launching = true;
        updateLaunchActions();
        setLaunchError('');
        try {
            const result = await apiJson(`/api/infrastructure/templates/${encodeURIComponent(template.id)}/run`, {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
            });
            rememberTemplate(template.id);
            const created = Number(result.created_tasks || targetCount());
            const jobId = result.job_id;
            resetLaunch();
            showToast(`Задачу створено для ${created} хостів.`);
            if (permissions.view_queue) {
                switchTab('tasks');
                while (state.taskLoading) {
                    await new Promise(resolve => setTimeout(resolve, 50));
                }
                await loadTasks(true);
                if (jobId && state.jobs.some(job => String(job.job_id) === String(jobId))) openJob(jobId);
            }
        } catch (error) {
            const missing = Array.isArray(error.data?.missing_variables) ? `: ${error.data.missing_variables.join(', ')}` : '';
            setLaunchError(`${error.message || 'Не вдалося запустити задачу'}${missing}`);
        } finally {
            state.launching = false;
            updateLaunchActions();
        }
    }

    function bindEvents() {
        all('[data-mobile-tab]').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.mobileTab)));
        byId('moRefreshTasks')?.addEventListener('click', () => loadTasks());
        byId('moTaskSearch')?.addEventListener('input', renderTasks);
        all('[data-job-filter]').forEach(button => button.addEventListener('click', () => {
            state.jobFilter = button.dataset.jobFilter || 'all';
            all('[data-job-filter]').forEach(item => item.classList.toggle('is-active', item === button));
            renderTasks();
        }));
        byId('moRefreshReports')?.addEventListener('click', () => loadReports(true));
        byId('moReportSearch')?.addEventListener('input', renderReports);
        byId('moTemplateSearch')?.addEventListener('input', renderTemplates);
        byId('moHostSearch')?.addEventListener('input', renderHosts);
        byId('moTargetHosts')?.addEventListener('click', () => setTargetType('hosts'));
        byId('moTargetGroup')?.addEventListener('click', () => setTargetType('group'));
        byId('moGroupSelect')?.addEventListener('change', event => {
            state.selectedGroupId = event.target.value || '';
            updateLaunchActions();
        });
        byId('moResetLaunch')?.addEventListener('click', resetLaunch);
        byId('moLaunchBack')?.addEventListener('click', () => setLaunchStep(state.launchStep - 1));
        byId('moLaunchNext')?.addEventListener('click', launchNext);
        byId('moLaunchRun')?.addEventListener('click', submitLaunch);
        byId('moRiskCheckbox')?.addEventListener('change', updateLaunchActions);
        all('[data-close-overlay]').forEach(button => button.addEventListener('click', () => closeOverlay(button.dataset.closeOverlay)));
        all('.mo-overlay').forEach(overlay => overlay.addEventListener('click', event => {
            if (event.target === overlay) closeOverlay(overlay.id);
        }));
        document.addEventListener('keydown', event => {
            if (event.key !== 'Escape') return;
            const visible = all('.mo-overlay').filter(item => !item.hidden).pop();
            if (visible) closeOverlay(visible.id);
            else if (!byId('moMoreMenu')?.hidden) closeMenu();
        });
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && state.activeTab === 'tasks') loadTasks(true);
            schedulePolling();
        });
    }

    function closeMenu() {
        const menu = byId('moMoreMenu');
        const button = byId('moMoreButton');
        if (menu) menu.hidden = true;
        if (button) button.setAttribute('aria-expanded', 'false');
    }

    function bindMenu() {
        const button = byId('moMoreButton');
        const menu = byId('moMoreMenu');
        button?.addEventListener('click', event => {
            event.stopPropagation();
            menu.hidden = !menu.hidden;
            button.setAttribute('aria-expanded', menu.hidden ? 'false' : 'true');
        });
        document.addEventListener('click', event => {
            if (menu && !menu.hidden && !menu.contains(event.target) && event.target !== button) closeMenu();
        });
        byId('moDesktopLink')?.addEventListener('click', () => localStorage.setItem(storageKeys.mode, 'desktop'));
    }

    function init() {
        localStorage.setItem(storageKeys.mode, 'mobile');
        bindEvents();
        bindMenu();
        if (permissions.run_tasks) resetLaunch();
        const savedTab = localStorage.getItem(storageKeys.tab);
        switchTab(availableTabs().includes(savedTab) ? savedTab : defaultTab());
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once: true});
    else init();
})();
