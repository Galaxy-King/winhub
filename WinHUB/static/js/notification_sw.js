'use strict';
// Deliberately no fetch handler or authenticated/offline response cache.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('push', event => {
    let data={};try{data=event.data.json();}catch(_){}
    const id=/^[a-f0-9-]{36}$/.test(data.id||'')?data.id:'';
    event.waitUntil(self.registration.showNotification('WinHUB', {
        body:'You have a new notification. Open WinHUB to review.',
        tag:id||'winhub', icon:'/static/pwa-192.png', badge:'/static/pwa-192.png',
        data:{url:id?'/notifications/'+id:'/mobile'}
    }));
});
self.addEventListener('notificationclick', event => {
    event.notification.close();
    const path=event.notification.data?.url||'/mobile';
    const safe=/^\/notifications\/[a-f0-9-]{36}$/.test(path)?path:'/mobile';
    event.waitUntil(self.clients.openWindow(safe));
});
