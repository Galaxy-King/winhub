'use strict';
// Deliberately no fetch handler or authenticated/offline response cache.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('push', event => {
    let data={};try{data=event.data.json();}catch(_){}
    const id=/^[a-f0-9-]{36}$/.test(data.id||'')?data.id:'';
    event.waitUntil(self.registration.showNotification('WinHUB', {
        body:data.test===true?'Test push received. WinHUB can reach this browser.':'You have a new notification. Open WinHUB to review.',
        tag:data.test===true?'winhub-test-'+Date.now():id||'winhub', icon:'/static/pwa-192.png', badge:'/static/pwa-192.png',
        data:{url:id?'/notifications/'+id:'/mobile'}
    }));
});
self.addEventListener('notificationclick', event => {
    event.notification.close();
    const path=event.notification.data?.url||'/mobile';
    const safe=/^\/notifications\/[a-f0-9-]{36}$/.test(path)?path:'/mobile';
    event.waitUntil((async()=>{
        const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});
        for(const client of windows){
            if(new URL(client.url).origin!==self.location.origin)continue;
            try{const opened=await client.navigate('/push-open?next='+encodeURIComponent(safe));
                if(opened){await opened.focus();return;}
            }catch(_){}
        }
        await self.clients.openWindow('/push-open?next='+encodeURIComponent(safe));
    })());
});
