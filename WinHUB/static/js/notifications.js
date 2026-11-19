/* Shared desktop/mobile inbox. Text nodes only; never render notification HTML. */
(() => {
    'use strict';
    const $ = id => document.getElementById(id), drawer = $('notificationDrawer');
    if (!drawer) return;
    let items = [], preferences = {}, seen = new Set(), initialized = false, busy = false, timer;
    const selectedTemplate=new URLSearchParams(location.search).get('notification_template');
    if(selectedTemplate && typeof window.loadTemplate==='function'){const card=[...document.querySelectorAll('.template-card')].find(el=>el.dataset.id===selectedTemplate);if(card)window.loadTemplate(card);}
    const categories = ['approvals','tasks','software','scheduler','reports','fleet','newsletter','system'];
    async function api(path, method = 'GET', body) {
        const response = await fetch('/api/notifications' + path, {method, cache:'no-store', headers:{'Content-Type':'application/json', 'X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content || ''}, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
        if (!response.ok) {
            const error = await response.json().catch(()=>({}));
            throw new Error(response.status === 440 || response.status === 401 ? 'Session expired. Sign in again.' : response.status === 429 ? 'Too many requests. Wait a minute and try again.' : error.message || 'Unable to complete this action. Refresh and try again.');
        }
        return response.json();
    }
    function node(tag, text, cls) {const el=document.createElement(tag);if(text)el.textContent=text;if(cls)el.className=cls;return el;}
    function card(item, toast=false) {
        const el=node('article',null,'wn-card'+(!item.read?' wn-unread':''));el.dataset.severity=item.resolved?'success':item.severity;
        el.append(node('span',item.category+' · '+(item.resolved?'Resolved':item.severity)+(!item.read?' · New':''),'wn-tag'),node('h3',item.title));
        const time=node('time',new Date(item.created_at).toLocaleString());time.dateTime=item.created_at;el.append(time);
        const footer=node('footer'), link=node('a','Open details');link.href=item.url;
        link.addEventListener('click',()=>{api('/read','POST',{ids:[item.id]}).catch(()=>{});});footer.append(link);
        const dismiss=node('button',toast?'Dismiss':'Clear');dismiss.type='button';dismiss.onclick=async()=>{if(toast){el.remove();return;}try{await api('/clear','POST',{ids:[item.id]});await refresh();}catch(e){message(e.message);}};footer.append(dismiss);el.append(footer);
        return el;
    }
    function message(text){$('notificationMessage').textContent=text;}
    function render(){const filter=$('notificationFilter').value;const selected=items.filter(x=>filter==='all'||filter==='unread'&&!x.read||x.category===filter&&!(filter==='approvals'&&x.resolved));$('notificationList').replaceChildren(...selected.map(x=>card(x)));if(!selected.length)$('notificationList').append(node('p','You’re all caught up.','wn-hint'));}
    function populateSettings(){
        $('notificationToasts').checked=preferences.toasts!==false;$('notificationErrors').checked=!!preferences.errors_only;
        $('notificationCategories').querySelectorAll('input').forEach(el=>{el.checked=(preferences.push_categories||[]).includes(el.value);});
        $('notificationQuietStart').value=preferences.quiet_start??'';$('notificationQuietEnd').value=preferences.quiet_end??'';
    }
    async function refresh(){
        if(busy)return;busy=true;$('notificationRefresh').classList.add('wn-spin');
        try{const data=await api('');items=data.items;preferences=data.settings;const badge=$('notificationCount');badge.hidden=!data.unread;badge.textContent=data.unread>99?'99+':data.unread;$('notificationBell').setAttribute('aria-label',`Notifications: ${data.unread} unread`);
            if(navigator.setAppBadge){(data.unread?navigator.setAppBadge(data.unread):navigator.clearAppBadge()).catch(()=>{});}
            if(initialized&&preferences.toasts!==false&&!document.hidden&&!drawer.open){items.filter(x=>!seen.has(x.id)&&!x.read).slice(0,3).forEach(x=>{const el=card(x,true);$('notificationToastsArea').append(el);setTimeout(()=>el.remove(),12000);});while($('notificationToastsArea').children.length>3)$('notificationToastsArea').firstChild.remove();}
            seen=new Set(items.map(x=>x.id));initialized=true;render();if(!drawer.open)populateSettings();message(`${data.unread} unread · ${items.length} notifications`);
        }catch(e){message(e.message);}finally{busy=false;$('notificationRefresh').classList.remove('wn-spin');}
    }
    async function devices(){
        for(const [path,id] of [['/push/devices','notificationDevices'],['/sessions','notificationSessions']]){
            try{const data=await api(path);$(id).replaceChildren();for(const d of data.devices){const row=node('div',null,'wn-device');row.append(node('span',d.name+(d.current?' · This device':'')));const button=node('button','Revoke');button.type='button';button.onclick=async()=>{try{await api(path+'/'+d.id,'DELETE');await devices();}catch(e){message(e.message);}};row.append(button);$(id).append(row);}if(!data.devices.length)$(id).append(node('p','No active devices.','wn-hint'));}catch(e){message(e.message);}
        }
    }
    $('notificationBell').onclick=async()=>{drawer.showModal();await refresh();populateSettings();await devices();};$('notificationClose').onclick=()=>drawer.close();
    $('notificationFilter').onchange=render;$('notificationRefresh').onclick=refresh;
    for(const [id,path,body] of [['notificationReadAll','/read',{}],['notificationClearRead','/clear',{read_only:true}],['notificationClearAll','/clear',{}]]){$(id).onclick=async()=>{if(id==='notificationClearAll'&&!confirm('Clear your notification history? Tasks, approvals and audit history will remain.'))return;try{await api(path,'POST',body);await refresh();}catch(e){message(e.message);}};}
    for(const category of categories){const label=node('label'),input=node('input');input.type='checkbox';input.value=category;label.append(input,document.createTextNode(category));$('notificationCategories').append(label);}
    for(const id of ['notificationQuietStart','notificationQuietEnd']){$(id).append(new Option('Off',''));for(let h=0;h<24;h++)$(id).append(new Option(String(h).padStart(2,'0')+':00',h));}
    $('notificationSave').onclick=async()=>{try{const result=await api('/preferences','PUT',{toasts:$('notificationToasts').checked,errors_only:$('notificationErrors').checked,push_categories:[...$('notificationCategories').querySelectorAll('input:checked')].map(x=>x.value),quiet_start:$('notificationQuietStart').value===''?null:Number($('notificationQuietStart').value),quiet_end:$('notificationQuietEnd').value===''?null:Number($('notificationQuietEnd').value)});preferences=result.settings;message('Preferences saved.');}catch(e){message(e.message);}};
    $('notificationEnable').onclick=async()=>{
        const button=$('notificationEnable');button.disabled=true;
        try{
            if(!window.isSecureContext||!('serviceWorker'in navigator)||!('PushManager'in window))throw new Error('Push is unavailable. Use trusted HTTPS; on iPhone/iPad open WinHUB from the Home Screen.');
            // Permission request is directly tied to the user’s click.
            if(await Notification.requestPermission()!=='granted')throw new Error('Notifications are blocked. Allow them in browser/device settings.');
            const reg=await navigator.serviceWorker.register('/winhub-sw.js',{scope:'/'});await navigator.serviceWorker.ready;
            const key=await api('/push/key','POST',{});const raw=atob(key.public_key.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-key.public_key.length%4)%4));
            let sub=await reg.pushManager.getSubscription();const keyBytes=Uint8Array.from(raw,c=>c.charCodeAt(0));if(sub?.options.applicationServerKey && !Array.from(new Uint8Array(sub.options.applicationServerKey)).every((v,i)=>v===keyBytes[i])){await sub.unsubscribe();sub=null;}if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:Uint8Array.from(raw,c=>c.charCodeAt(0))});
            await api('/push/devices','POST',{subscription:sub.toJSON(),name:(navigator.userAgentData?.platform || navigator.platform || 'Browser')+' · '+(/Edg/.test(navigator.userAgent)?'Edge':/Firefox/.test(navigator.userAgent)?'Firefox':/Chrome/.test(navigator.userAgent)?'Chrome':'Safari / browser')});message('Push enabled on this device.');await devices();
        }catch(e){message(e.message);}finally{button.disabled=false;}
    };
    $('notificationTest').onclick=async()=>{
        const button=$('notificationTest'), result=$('notificationTestResult');
        button.disabled=true;button.textContent='Sending…';result.textContent='Contacting the push provider…';
        try {
            if(!window.isSecureContext || !('serviceWorker' in navigator) || !('Notification' in window) || Notification.permission!=='granted')throw new Error('Allow notifications and enable push on this device first.');
            const reg=await navigator.serviceWorker.getRegistration('/');
            const sub=await reg?.pushManager?.getSubscription();
            if(!sub)throw new Error('No browser subscription. Enable push on this device first.');
            await api('/push/bind','POST',{endpoint:sub.endpoint});
            const response=await api('/push/test','POST',{});result.textContent=response.message;
        }catch(e){result.textContent=e.message;}finally{button.disabled=false;button.textContent='Send test push';}
    };
    function schedule(){clearTimeout(timer);timer=setTimeout(async()=>{if(!document.hidden)await refresh();schedule();},30000);}
    if(window.isSecureContext && 'serviceWorker' in navigator) navigator.serviceWorker.register('/winhub-sw.js',{scope:'/'}).then(async()=>{const reg=await navigator.serviceWorker.ready;const sub=await reg.pushManager?.getSubscription();if(sub)await api('/push/bind','POST',{endpoint:sub.endpoint});}).catch(()=>{});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});refresh();schedule();
})();
