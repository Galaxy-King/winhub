/* Recheck the existing session from a same-origin document after an external launch. */
(() => {
    const next=new URLSearchParams(location.search).get('next');
    const safe=next==='/mobile'||/^\/notifications\/[a-f0-9-]{36}$/.test(next||'')?next:'/mobile';
    fetch('/api/notifications/session-check',{credentials:'same-origin',cache:'no-store',redirect:'error'})
        .then(async response=>{
            if(response.ok && (await response.json()).success){location.replace(safe);return;}
            if(location.pathname==='/push-open')location.replace('/login?next='+encodeURIComponent(safe));
        }).catch(()=>{
            const status=document.getElementById('openingStatus');
            if(status){status.textContent='Unable to check your session. ';const link=document.createElement('a');link.href=safe;link.textContent='Open WinHUB';status.append(link);}
        });
})();
