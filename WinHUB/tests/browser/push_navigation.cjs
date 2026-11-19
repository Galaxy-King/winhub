const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../../static/js/notification_sw.js'),'utf8');
async function check(existing,url){
 const handlers={},opened=[],navigated=[];let focused=0,waiting;
 const client={url:'https://winhub.test/mobile',navigate:async target=>{navigated.push(target);return {focus:async()=>focused++};}};
 const self={location:{origin:'https://winhub.test'},addEventListener:(name,fn)=>handlers[name]=fn,
 clients:{matchAll:async()=>existing?[client]:[],openWindow:async target=>opened.push(target)}};
 vm.runInNewContext(source,{self,URL});
 handlers.notificationclick({notification:{close(){},data:{url}},waitUntil:p=>waiting=p});await waiting;
 if(existing){assert.equal(opened.length,0);assert.equal(focused,1);assert.equal(navigated.length,1);}
 else assert.equal(opened.length,1);
 const target=new URL((existing?navigated:opened)[0],'https://winhub.test');
 assert.equal(target.pathname,'/push-open');
 assert.equal(target.searchParams.get('next'),url.startsWith('/notifications/')?url:'/mobile');
}
(async()=>{await check(true,'/notifications/12345678-1234-1234-1234-123456789abc');await check(false,'/mobile');await check(false,'https://evil.test');console.log('Push navigation tests OK');})().catch(e=>{console.error(e);process.exitCode=1;});
