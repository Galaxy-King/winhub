const taskRerunState={url:null,data:null,fields:[],busy:false,ticket:0};
const taskRerunElement=id=>document.getElementById(id);
function taskRerunMessage(text,error=false){const element=taskRerunElement('taskRerunMessage');element.textContent=text;element.dataset.error=String(error);}
function taskRerunClose(){if(!taskRerunState.busy){taskRerunState.ticket++;taskRerunElement('taskRerunDialog').close();taskRerunState.fields=[];taskRerunElement('taskRerunFields').replaceChildren();}}
async function taskRerunOpen(kind,id){
    if(taskRerunState.busy)return;
    const ticket=++taskRerunState.ticket;taskRerunState.data=null;taskRerunState.fields=[];
    taskRerunElement('taskRerunFields').replaceChildren();taskRerunElement('taskRerunContent').hidden=true;
    taskRerunElement('taskRerunTitle').textContent='Re-run task';taskRerunElement('taskRerunReason').value='';
    const dialog=taskRerunElement('taskRerunDialog');if(!dialog.open)dialog.showModal();taskRerunMessage('Loading original targets and template parameters…');
    const url=`/api/infrastructure/${kind==='task'?'task':'job'}/${encodeURIComponent(id)}/rerun`;
    try{
        const response=await fetch(url),data=await response.json();if(ticket!==taskRerunState.ticket)return;
        if(!response.ok||!data.success)throw Error(data.message||'This task cannot be re-run');
        taskRerunState.url=url;taskRerunState.data=data;taskRerunElement('taskRerunTitle').textContent='Re-run · '+data.template.name;
        taskRerunElement('taskRerunTargets').textContent=`${data.targets.length} host(s)${data.group_name?' · Original group: '+data.group_name:''}: `+data.targets.map(target=>target.name).join(', ');
        const notices=[];if(!data.saved_parameters)notices.push('Saved input values are not available for this task. Review defaults and fill in the required parameters.');
        if(data.template_changed)notices.push('The template changed since this task. Its current version and current fields will be used.');
        if(data.original_code_edited)notices.push('The original code was edited after selecting the template. Re-run uses the current template code.');
        taskRerunElement('taskRerunNotice').textContent=notices.join(' ');
        taskRerunElement('taskRerunTimeout').value=data.timeout_minutes||0;
        for(const field of data.fields){
            const wrap=document.createElement('div'),label=document.createElement(['checkbox','boolean'].includes(field.spec.type)?'div':'label');label.className='task-rerun-label';label.append(document.createTextNode(field.spec.label||field.name));
            let input,keep;
            if(field.secret){
                input=document.createElement('input');input.type='password';input.autocomplete='new-password';input.value='';label.append(input);
                if(field.has_saved){const row=document.createElement('label');keep=document.createElement('input');keep.type='checkbox';keep.checked=true;keep.dataset.secretKeep=field.name;
                    row.append(keep,document.createTextNode('Reuse saved value'));wrap.append(row);input.disabled=true;keep.onchange=()=>input.disabled=keep.checked;
                }else input.placeholder='Enter value';
            }else{
                const holder=document.createElement('div');holder.innerHTML=renderVariableField(field.name,field.spec,field.value,'task-rerun-input');
                input=holder.querySelector('input,select,textarea');label.append(holder);
            }
            wrap.prepend(label);if(field.spec.help||field.spec.description){const hint=document.createElement('p');hint.className='task-rerun-hint';hint.textContent=field.spec.help||field.spec.description;wrap.append(hint);}
            taskRerunElement('taskRerunFields').append(wrap);taskRerunState.fields.push({field,input,keep});
        }
        if(!data.fields.length){const text=document.createElement('p');text.textContent='This template has no parameters.';taskRerunElement('taskRerunFields').append(text);}
        taskRerunElement('taskRerunContent').hidden=false;taskRerunMessage('Review the parameters. Hosts are fixed to the original selection.');
    }catch(error){if(ticket===taskRerunState.ticket)taskRerunMessage(error.message,true);}
}
async function taskRerunSubmit(){
    if(taskRerunState.busy||!taskRerunState.data)return;
    const reason=taskRerunElement('taskRerunReason').value.trim();if(!reason){taskRerunElement('taskRerunReason').focus();return;}
    const variables=Object.create(null),keep_secrets=[];for(const {field,input,keep} of taskRerunState.fields){if(keep?.checked)keep_secrets.push(field.name);else variables[field.name]=input.type==='checkbox'?(input.checked?'true':'false'):input.value;}
    const button=taskRerunElement('taskRerunSubmitButton');taskRerunState.busy=true;button.disabled=true;button.setAttribute('aria-busy','true');taskRerunMessage('Submitting a new task…');
    try{
        const response=await fetch(taskRerunState.url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content||''},
            body:JSON.stringify({variables,keep_secrets,template_hash:taskRerunState.data.template.hash,timeout_minutes:Number(taskRerunElement('taskRerunTimeout').value),launch_reason:reason})});
        const data=await response.json();if(!response.ok||!data.success)throw Error(data.message||'Re-run failed');
        taskRerunState.busy=false;taskRerunClose();if(window.closeModal){closeModal('taskModal');closeModal('jobModal');}if(window.showDeploymentReceipt)showDeploymentReceipt();if(window.loadQueue)await loadQueue();
    }catch(error){taskRerunMessage(error.message,true);}finally{taskRerunState.busy=false;button.disabled=false;button.removeAttribute('aria-busy');}
}
document.addEventListener('DOMContentLoaded',()=>taskRerunElement('taskRerunDialog')?.addEventListener('cancel',event=>{if(taskRerunState.busy)event.preventDefault();else taskRerunClose();}));
