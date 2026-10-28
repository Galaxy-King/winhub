/* Calendar rules are data. All user/agent strings are rendered as text nodes. */
const schedulerState = {tab:'schedules', language:'en', page:1, hasMore:false, preview:0, timer:null, loading:false};
const schedulerLabels = {NeverRun:'Never run',WaitingForAgent:'Waiting for agent',DeliveryExpired:'Delivery expired',
    ScriptFailed:'Script failed',VerificationFailed:'Verification failed',DispatchFailed:'Dispatch failed',
    ExecutionFailed:'Execution failed',ResultUnknown:'Result unknown',PartialFailure:'Partial failure',
    ResolvedManually:'Resolved manually',Claimed:'Preparing dispatch'};

function schedulerText(tag, text, cls='') {const n=document.createElement(tag);if(text!==undefined)n.textContent=text;n.className=cls;return n;}
function schedulerTone(status) {
    if(status==='Success') return 'success';
    if(['Running','Claimed'].includes(status)) return 'active';
    if(['Warning','Queued','WaitingForAgent','DeliveryExpired','ResultUnknown','Missed'].includes(status)) return 'warning';
    if(['ScriptFailed','VerificationFailed','ExecutionFailed','DispatchFailed','PartialFailure','Error'].includes(status)) return 'error';
    const legacy=/Completed: (\d+)\/(\d+) success, (\d+) failed/.exec(status||'');
    if(legacy) return Number(legacy[3]) ? 'error' : legacy[1]===legacy[2] ? 'success' : 'warning';
    if(/required|error|invalid|expired|missing|no target/i.test(status||'')) return 'error';
    if(/dispatched|timed out/i.test(status||'')) return 'warning';
    return 'neutral';
}
function schedulerBadge(status) {
    const n=schedulerText('span',schedulerLabels[status]||status||'Never run','scheduler-status');
    n.dataset.tone=schedulerTone(status);return n;
}
function schedulerDate(value, zone) {return value ? new Date(value).toLocaleString('en-GB',{timeZone:zone||undefined,timeZoneName:'short'}) : '—';}
async function schedulerRequest(url, options={}) {
    const response=await fetch(url,{...options,headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content||'',...options.headers}});
    const data=await response.json();if(!response.ok||!data.success) throw Error(data.message||'Scheduler request failed');return data;
}
function schedulerTab(tab) {
    schedulerState.tab=['schedules','history','guide'].includes(tab)?tab:'schedules';
    sessionStorage.setItem('winhub.scheduler.tab',schedulerState.tab);
    for(const name of ['schedules','history','guide']) {
        document.getElementById('scheduler-'+name)?.toggleAttribute('hidden',name!==schedulerState.tab);
        const button=document.querySelector(`[data-scheduler-tab="${name}"]`);
        if(button) {if(name===schedulerState.tab)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');}
    }
    if(schedulerState.tab==='history') schedulerHistory();
}
function schedulerLanguage(language) {
    schedulerState.language=language==='uk'?'uk':'en';sessionStorage.setItem('winhub.scheduler.language',schedulerState.language);
    for(const name of ['en','uk']) document.getElementById('scheduler-guide-'+name)?.toggleAttribute('hidden',name!==schedulerState.language);
    document.querySelectorAll('[data-scheduler-language]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.schedulerLanguage===schedulerState.language)));
}
function schedulerRecurrenceFields() {
    const kind=document.getElementById('schRuleKind')?.value;if(!kind)return;
    document.querySelectorAll('#scheduleRecurrence [data-rule]').forEach(n=>n.hidden=!n.dataset.rule.split(' ').includes(kind));
    const mode=document.getElementById('schRuleMonthMode').value;
    document.getElementById('schRuleMonthDayWrap').hidden=kind!=='monthly'||mode!=='day';
    document.getElementById('schRuleOrdinalWrap').hidden=kind!=='monthly'||mode!=='weekday';
    document.getElementById('schRuleWeekdayWrap').hidden=kind!=='monthly'||mode!=='weekday';
    document.getElementById('schRuleUnitLabel').textContent=({daily:'day(s)',weekly:'week(s)',monthly:'month(s)'})[kind]||'period(s)';
}
function schedulerCollectRecurrence() {
    const value=id=>document.getElementById(id).value;
    const kind=value('schRuleKind'), time=value('schRuleTime');
    if(kind!=='cron'&&(!value('schRuleDate')||!/^([01]\d|2[0-3]):[0-5]\d$/.test(time))) throw Error('Enter a start date and 24-hour HH:MM time');
    const recurrence={kind,timezone:value('schRuleTimezone').trim(),start:value('schRuleDate')+'T'+time,every:Number(value('schRuleEvery')),
        weekdays:[...document.querySelectorAll('.sch-rule-day:checked')].map(n=>Number(n.value)),mode:value('schRuleMonthMode'),
        day:Number(value('schRuleMonthDay')),ordinal:Number(value('schRuleOrdinal')),weekday:Number(value('schRuleWeekday')),
        unit:value('schRuleUnit'),cron:value('schRuleCron').trim()};
    if(value('schRuleEndDate')) {
        if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(value('schRuleEndTime'))) throw Error('Use HH:MM for end time');
        recurrence.end=value('schRuleEndDate')+'T'+value('schRuleEndTime');
    }
    return recurrence;
}
function schedulerCollectSettings() {
    const codes=id=>{const text=document.getElementById(id).value.trim();if(!text)return [];return text.split(',').map(v=>{if(!/^-?\d+$/.test(v.trim()))throw Error('Exit codes must be comma-separated integers');return Number(v.trim());});};
    return {recurrence:schedulerCollectRecurrence(),execution_policy:{
        delivery_seconds:Number(document.getElementById('schDeliveryMinutes').value)*60,
        execution_seconds:Number(document.getElementById('schTimeoutMinutes').value||30)*60,
        overlap:document.getElementById('schOverlap').value,missed:document.getElementById('schMissed').value,
        retries:Number(document.getElementById('schRetries').value),retry_delay_seconds:Number(document.getElementById('schRetryMinutes').value)*60,
        success_codes:codes('schSuccessCodes'),warning_codes:codes('schWarningCodes'),verification_codes:codes('schVerificationCodes')}};
}
function schedulerResetForm(data={}) {
    const date=kyivDateTimeParts(60);
    let rule={kind:'once',timezone:'Europe/Kyiv',start:date.date+'T'+date.time,every:1};
    let policy={delivery_seconds:3600,execution_seconds:1800,overlap:'skip',missed:'run_once',retries:0,retry_delay_seconds:300,success_codes:[0],warning_codes:[],verification_codes:[21]};
    try {if(data.recurrence&&data.recurrence!=='null')rule=JSON.parse(data.recurrence);else if(data.cron)rule=data.cron.startsWith('DATE:')?{...rule,start:data.cron.slice(5).trim().replace(' ','T')}:{kind:'cron',timezone:'Europe/Kyiv',cron:data.cron};
        if(data.executionPolicy&&data.executionPolicy!=='null')policy={...policy,...JSON.parse(data.executionPolicy)};
        else if(data.timeoutMinutes)policy.execution_seconds=Number(data.timeoutMinutes)*60;
    } catch (_) {}
    const values={schRuleKind:rule.kind,schRuleTimezone:rule.timezone,schRuleDate:(rule.start||'').slice(0,10),schRuleTime:(rule.start||'').slice(11,16)||'03:00',
        schRuleEvery:rule.every||1,schRuleMonthMode:rule.mode||'day',schRuleMonthDay:rule.day||1,schRuleOrdinal:rule.ordinal||1,
        schRuleWeekday:rule.weekday||0,schRuleUnit:rule.unit||'hours',schRuleCron:rule.cron||'',schRuleEndDate:(rule.end||'').slice(0,10),schRuleEndTime:(rule.end||'').slice(11,16)||'23:59',
        schDeliveryMinutes:policy.delivery_seconds/60,schTimeoutMinutes:policy.execution_seconds/60,schOverlap:policy.overlap,schMissed:policy.missed,
        schRetries:policy.retries,schRetryMinutes:policy.retry_delay_seconds/60,schSuccessCodes:policy.success_codes.join(','),schWarningCodes:policy.warning_codes.join(','),schVerificationCodes:policy.verification_codes.join(',')};
    Object.entries(values).forEach(([id,value])=>{const n=document.getElementById(id);if(n)n.value=value;});
    document.querySelectorAll('.sch-rule-day').forEach(n=>n.checked=(rule.weekdays||[]).includes(Number(n.value)));
    schedulerRecurrenceFields();schedulerPreviewSoon();
}
function schedulerPreviewSoon() {clearTimeout(schedulerState.timer);schedulerState.timer=setTimeout(schedulerPreview,350);}
async function schedulerPreview() {
    const output=document.getElementById('schRulePreview');if(!output)return;
    const ticket=++schedulerState.preview;
    try {
        const recurrence=schedulerCollectRecurrence();output.textContent='Calculating…';
        const data=await schedulerRequest('/api/infrastructure/schedule/preview',{method:'POST',body:JSON.stringify({recurrence})});
        if(ticket!==schedulerState.preview)return;
        output.replaceChildren(...data.dates.map(date=>schedulerText('div',schedulerDate(date,recurrence.timezone))));
        if(!data.dates.length)output.textContent='No future executions. Check start/end dates.';
    } catch(error) {if(ticket===schedulerState.preview)output.textContent=error.message;}
}
async function schedulerSummary() {
    const data=await schedulerRequest('/api/infrastructure/schedule/summary');
    for(const schedule of data.schedules) {
        const row=[...document.querySelectorAll('[data-schedule-row]')].find(n=>n.dataset.scheduleRow===schedule.id);if(!row)continue;
        row.querySelector('[data-schedule-status]')?.replaceChildren(schedulerBadge(schedule.status));
        if(row.querySelector('[data-schedule-last]'))row.querySelector('[data-schedule-last]').textContent=schedulerDate(schedule.last_run);
        if(row.querySelector('[data-schedule-next]'))row.querySelector('[data-schedule-next]').textContent=schedulerDate(schedule.next_run);
    }
}
async function schedulerHistory(page=schedulerState.page) {
    const list=document.getElementById('schedulerHistoryList');if(!list)return;
    const params=new URLSearchParams({page:String(page)});
    for(const [id,key] of [['schedulerHistorySearch','q'],['schedulerHistoryStatus','status'],['schedulerHistorySource','source'],['schedulerHistoryCategory','category'],['schedulerHistoryHost','host'],['schedulerHistoryFrom','from'],['schedulerHistoryTo','to']]) {
        const value=document.getElementById(id)?.value.trim();if(value)params.set(key,value);
    }
    try {
        const data=await schedulerRequest('/api/infrastructure/schedule/history?'+params);
        schedulerState.page=data.page;schedulerState.hasMore=data.has_more;
        const open=new Set([...document.querySelectorAll('#schedulerHistoryList details[open]')].map(n=>n.dataset.run));
        list.replaceChildren();
        for(const run of data.runs) {
            const card=schedulerText('article',undefined,'scheduler-run');
            const header=schedulerText('div',undefined,'scheduler-run-header');header.append(schedulerText('strong',run.name),schedulerBadge(run.status));card.append(header);
            card.append(schedulerText('p',run.category+' · '+run.source,'scheduler-hint'));
            const facts=schedulerText('div',undefined,'scheduler-run-facts');
            for(const [label,value] of [['Planned',run.scheduled_at],['Dispatched / recorded',run.created_at],['Finished',run.finished_at]])facts.append(schedulerText('span',label+': '+schedulerDate(value)));
            card.append(facts,schedulerText('p',run.message,'scheduler-hint'));
            const detail=schedulerText('details');detail.dataset.run=run.id;detail.open=open.has(run.id);detail.append(schedulerText('summary','Host results · '+run.tasks.length+(run.tasks_truncated?' shown (first 100)':'')));
            for(const task of run.tasks) {
                const row=schedulerText('div',undefined,'scheduler-host-result');row.append(schedulerText('strong',task.name||task.host),document.createTextNode(' '),schedulerBadge(task.status));
                row.append(schedulerText('p',`Exit code: ${task.exit_code??'Not reported'} · Delivery retries: ${task.retries} · Duration: ${task.duration_seconds??'—'} s`,'scheduler-hint'));
                row.append(schedulerText('p',`Agent received: ${schedulerDate(task.received_at)} · Finished: ${schedulerDate(task.finished_at)}`,'scheduler-hint'));
                if(window.WinhubPermissions?.view_queue) {const log=schedulerText('button','View log','scheduler-action');log.type='button';log.onclick=()=>viewTaskDetails(task.id);row.append(log);}
                detail.append(row);
            }
            if(!run.tasks.length)detail.append(schedulerText('p','No visible host tasks were dispatched. See the run status.','scheduler-hint'));
            card.append(detail);
            if(run.resolve_allowed) {
                const button=schedulerText('button','Resolve manually','scheduler-action');button.type='button';button.onclick=async()=>{
                    if(!confirm('Confirm on the endpoint that the script and all child processes have stopped. Resolution does not stop processes. Continue?'))return;
                    const reason=await askTaskLaunchReason('Reason for resolving this unknown run:');if(reason===null)return;
                    try {await schedulerRequest(`/api/infrastructure/schedule/history/${encodeURIComponent(run.id)}/resolve`,{method:'POST',body:JSON.stringify({launch_reason:reason,execution_stopped:true})});await schedulerRefresh();}catch(error){alert(error.message);}
                };card.append(button);
            }
            list.append(card);
        }
        if(!data.runs.length)list.append(schedulerText('p','No runs match these filters. Historical tasks created before this upgrade remain in Execution Queue.','scheduler-hint'));
        document.getElementById('schedulerHistoryPage').textContent=`Page ${data.page} · ${data.total} runs`;
        document.getElementById('schedulerHistoryPrev').disabled=data.page<=1;document.getElementById('schedulerHistoryNext').disabled=!data.has_more;
    } catch(error) {list.replaceChildren(schedulerText('p',error.message,'scheduler-hint'));}
}
async function schedulerRefresh() {await Promise.all([schedulerSummary(),schedulerState.tab==='history'?schedulerHistory():Promise.resolve()]);}
function schedulerHistoryPage(delta) {schedulerHistory(Math.max(1,schedulerState.page+delta));}
document.addEventListener('DOMContentLoaded',()=>{
    if(!document.getElementById('view-scheduler'))return;
    schedulerTab(sessionStorage.getItem('winhub.scheduler.tab')||'schedules');
    schedulerLanguage(sessionStorage.getItem('winhub.scheduler.language')||'en');
    document.querySelectorAll('#schedulerHistoryStatus option').forEach(option=>{if(option.value)option.textContent=schedulerLabels[option.value]||option.value;});
    document.querySelectorAll('[data-schedule-status]').forEach(n=>n.replaceChildren(schedulerBadge(n.textContent.trim())));
    document.querySelectorAll('[data-schedule-recurrence]').forEach(n=>{try {const rule=JSON.parse(n.dataset.scheduleRecurrence);if(!rule)return;const every=rule.every||1;const days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];let label=({once:'Once',daily:`Every ${every} day(s)`,weekly:`Every ${every} week(s) · ${(rule.weekdays||[]).map(d=>days[d]).join(', ')}`,monthly:`Every ${every} month(s) · ${rule.mode==='last_day'?'last day':rule.mode==='weekday'?`${rule.ordinal===-1?'Last':rule.ordinal} ${days[rule.weekday]}`:'day '+rule.day}`,interval:`Every ${every} ${rule.unit}`,cron:rule.cron})[rule.kind];n.textContent=label+' · '+rule.timezone+(rule.start?' · '+rule.start.replace('T',' '):'');} catch(_) {}});
    setInterval(()=>{if(!document.hidden&&!document.getElementById('view-scheduler').classList.contains('hidden'))schedulerRefresh().catch(()=>{});},10000);
});
