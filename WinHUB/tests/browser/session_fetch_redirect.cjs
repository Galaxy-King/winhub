const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
async function check(template,pathname,requestPath,status,expected){
 const text=fs.readFileSync(path.join(__dirname,'../../templates',template),'utf8');
 const start=text.indexOf('window.fetch = async');
 const end=text.indexOf('return response;',start)+'return response;'.length;
 const wrapper=text.slice(start,end)+'\n};';
 let navigations=0;
 const location={pathname,origin:'https://winhub.test',set href(value){navigations++;}};
 const window={location}, context={window,URL,Headers,document:{querySelector:()=>null},
 safeMethods:new Set(['GET','HEAD','OPTIONS']),originalFetch:async()=>({status}),
 isAuthFlowUrl:url=>url.pathname.startsWith('/api/auth/')||['/login','/logout'].includes(url.pathname)};
 vm.runInNewContext(wrapper,context);
 await window.fetch(requestPath);
 assert.equal(navigations,expected,`${template} ${pathname} ${requestPath} ${status}`);
}
(async()=>{
 for(const template of ['base.html','mobile_base.html'])for(const status of [401,440]){
  await check(template,'/login','/api/notifications/session-check',status,0);
  await check(template,'/login','/api/notifications',status,0);
  await check(template,'/push-open','/api/notifications/session-check',status,0);
  await check(template,'/mobile','/api/notifications',status,1);
  await check(template,'/mobile','https://other.test/api',status,0);
 }
 console.log('Desktop/mobile session fetch redirect tests OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
