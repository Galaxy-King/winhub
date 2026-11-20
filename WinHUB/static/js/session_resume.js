/* Recheck the existing session from a same-origin document after an external launch. */
(() => {
    const next=new URLSearchParams(location.search).get('next');
    let preferred='';try{preferred=localStorage.getItem('winhub_ui_mode')||'';}catch(_){}
    const mobile=preferred==='mobile'||(preferred!=='desktop' && typeof matchMedia==='function' && matchMedia('(max-width: 767px)').matches);
    const fallback=mobile?'/mobile':'/dashboard';
    const safe=next==='/mobile'||/^\/notifications\/[a-f0-9-]{36}$/.test(next||'')?next:fallback;
    const guard='winhub_session_resume';
    // A stale cookie or concurrent tab must never create a navigation loop.
    if(location.pathname==='/login'){
        try{if(Date.now()-Number(sessionStorage.getItem(guard)||0)<30000)return;}catch(_){}
    }
    fetch('/api/notifications/session-check',{credentials:'same-origin',cache:'no-store',redirect:'error'})
        .then(async response=>{
            if(response.ok && (await response.json()).success){
                try{sessionStorage.setItem(guard,String(Date.now()));}catch(_){}
                location.replace(safe);return;
            }
            if(location.pathname==='/push-open')location.replace('/login?next='+encodeURIComponent(safe));
        }).catch(()=>{
            const status=document.getElementById('openingStatus');
            if(status){status.textContent='Unable to check your session. ';const link=document.createElement('a');link.href=safe;link.textContent='Open WinHUB';status.append(link);}
        });
})();
