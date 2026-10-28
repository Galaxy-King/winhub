/* History tools never turn archive contents into executable code or HTML. */
const queueHistoryState={range:null,rangeAt:0,request:null,preview:null,busy:false};
const queueHistoryElement=id=>document.getElementById(id);
function queueHistoryDate(value){return value?new Date(value).toLocaleString('en-GB',{timeZone:'Europe/Kyiv',timeZoneName:'short'}):'—';}
function queueHistoryLocalDay(value){return value?new Intl.DateTimeFormat('en-CA',{timeZone:'Europe/Kyiv',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date(value)):'';}
function queueHistoryMessage(text,error=false){const el=queueHistoryElement('queueHistoryMessage');el.textContent=text;el.dataset.error=String(error);}
async function queueHistoryApi(url,body){const response=await fetch(url,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content||''},...(body?{body:JSON.stringify(body)}:{})});const data=await response.json();if(!response.ok||!data.success)throw Error(data.message||'History request failed');return data;}
async function queueHistoryRange(force=false){
    if(!force&&Date.now()-queueHistoryState.rangeAt<30000)return queueHistoryState.range;
    if(queueHistoryState.request)return queueHistoryState.request;
    queueHistoryState.request=(async()=>{
        const data=await queueHistoryApi('/api/infrastructure/tasks/history-range');queueHistoryState.range=data;queueHistoryState.rangeAt=Date.now();
        const text=data.tasks?`Available task history: ${queueHistoryDate(data.oldest)} — ${queueHistoryDate(data.newest)} · ${data.tasks} task records`:'No stored task history is available.';
        for(const id of ['queueHistoryRange','queueHistoryAvailable']){const el=queueHistoryElement(id);if(el)el.textContent=text;}
        return data;
    })();
    try{return await queueHistoryState.request;}catch(error){const el=queueHistoryElement('queueHistoryRange');if(el)el.textContent='History period unavailable. Refresh to retry.';throw error;}finally{queueHistoryState.request=null;}
}
async function queueHistoryOpen(mode){
    if(queueHistoryState.busy)return;
    const dialog=queueHistoryElement('queueHistoryDialog');if(!dialog.open)dialog.showModal();
    queueHistoryElement('queueHistoryTitle').textContent=mode==='cleanup'?'Clean task history':'Export task history';
    queueHistoryElement('queueHistoryExportFields').hidden=mode==='cleanup';
    if(queueHistoryElement('queueHistoryCleanupFields'))queueHistoryElement('queueHistoryCleanupFields').hidden=mode!=='cleanup';
    queueHistoryMessage('');queueHistoryInvalidatePreview();
    try{const range=await queueHistoryRange(true);if(mode==='export'){
        queueHistoryElement('queueExportFrom').value=queueHistoryElement('queueDateFrom')?.value||queueHistoryLocalDay(range.oldest);
        queueHistoryElement('queueExportTo').value=queueHistoryElement('queueDateTo')?.value||queueHistoryLocalDay(range.newest);
    }}catch(error){queueHistoryMessage(error.message,true);}
}
function queueHistoryClose(){if(!queueHistoryState.busy)queueHistoryElement('queueHistoryDialog').close();}
async function queueHistoryExportBeforeCleanup(){
    try{const cutoff=queueHistoryState.preview?.cutoff||new Date(Date.now()-queueHistoryDays()*86400000).toISOString();
        await queueHistoryOpen('export');
        queueHistoryElement('queueExportFrom').value=queueHistoryLocalDay(queueHistoryState.range?.oldest);
        queueHistoryElement('queueExportTo').value=queueHistoryLocalDay(cutoff);
    }catch(error){queueHistoryMessage(error.message,true);}
}
function queueHistoryInvalidatePreview(){queueHistoryState.preview=null;if(queueHistoryElement('queueCleanupConfirm'))queueHistoryElement('queueCleanupConfirm').disabled=true;if(queueHistoryElement('queueCleanupPreviewText'))queueHistoryElement('queueCleanupPreviewText').textContent='';}
function queueHistoryDays(){const value=queueHistoryElement('queueCleanupDays').value;if(!/^\d+$/.test(value)||Number(value)<1||Number(value)>3650)throw Error('Enter whole days between 1 and 3650');return Number(value);}
async function queueHistoryBusy(button,work){if(queueHistoryState.busy)return;queueHistoryState.busy=true;button.disabled=true;button.setAttribute('aria-busy','true');try{await work();}catch(error){queueHistoryMessage(error.message,true);}finally{queueHistoryState.busy=false;button.disabled=false;button.removeAttribute('aria-busy');}}
async function queueHistoryPreview(button){await queueHistoryBusy(button,async()=>{
    queueHistoryInvalidatePreview();queueHistoryMessage('Checking eligible records…');
    const data=await queueHistoryApi('/api/infrastructure/tasks/cleanup',{days:queueHistoryDays(),preview:true});queueHistoryState.preview=data;
    queueHistoryElement('queueCleanupPreviewText').textContent=`${data.eligible} eligible task records. Created and completed before ${queueHistoryDate(data.cutoff)}. Active and unresolved jobs are excluded.`;
    queueHistoryElement('queueCleanupConfirm').disabled=!data.eligible;queueHistoryMessage(data.eligible?'Export the required date range before deleting.':'There are no eligible records to delete.');
});}
async function queueHistoryClean(button){
    const preview=queueHistoryState.preview;if(!preview||preview.days!==queueHistoryDays()){queueHistoryInvalidatePreview();return;}
    if(!confirm(`Permanently delete ${preview.eligible} eligible task records older than ${preview.days} days? This cannot be undone.`))return;
    await queueHistoryBusy(button,async()=>{
        let deleted=0,data;
        do{data=await queueHistoryApi('/api/infrastructure/tasks/cleanup',{days:preview.days,cutoff:preview.cutoff});deleted+=data.deleted;queueHistoryMessage(`Deleted ${deleted} task records. ${data.remaining} eligible records remain…`);}while(data.has_more&&data.deleted>0);
        queueHistoryState.preview=null;queueHistoryElement('queueCleanupPreviewText').textContent='';
        await queueHistoryRange(true);await loadQueue(1);queueHistoryMessage(`Deleted ${deleted} task records.${data.remaining?' Some records are busy; preview again later.':''}`);
    });button.disabled=!queueHistoryState.preview;
}
async function queueHistoryExport(button){await queueHistoryBusy(button,async()=>{
    const date_from=queueHistoryElement('queueExportFrom').value,date_to=queueHistoryElement('queueExportTo').value;
    if(!date_from||!date_to||date_from>date_to)throw Error('Choose a valid start and end date');
    queueHistoryMessage('Preparing ZIP archive…');
    const response=await fetch('/api/infrastructure/tasks/export',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content||''},body:JSON.stringify({date_from,date_to})});
    if(!response.ok){const data=await response.json();throw Error(data.message||'Export failed');}
    const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`winhub-tasks-${date_from}-to-${date_to}.zip`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
    queueHistoryMessage('Archive download started. Check that the ZIP was saved and opens correctly before cleaning history.');
});}
document.addEventListener('DOMContentLoaded',()=>{
    queueHistoryElement('queueCleanupDays')?.addEventListener('input',queueHistoryInvalidatePreview);
    queueHistoryElement('queueHistoryDialog')?.addEventListener('cancel',event=>{if(queueHistoryState.busy)event.preventDefault();});
});
