const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.WINHUB_PLAYWRIGHT_MODULE||'playwright');
async function main(){
 const html=fs.readFileSync(process.argv[2]),root=path.resolve(process.argv[3],'static');
 const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://fixture');if(url.pathname==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}const file=path.resolve(root,url.pathname.replace(/^\/static\//,''));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}res.setHeader('Content-Type',file.endsWith('.css')?'text/css':'application/javascript');res.end(fs.readFileSync(file));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.WINHUB_PLAYWRIGHT_CHANNEL?{channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL}:{})});
  for(const width of [1440,390]){
   const page=await browser.newPage({viewport:{width,height:900}}),errors=[];
   let items=[{id:'a',category:'approvals',severity:'warning',title:'Host awaiting approval <img src=x onerror=alert(1)>',created_at:new Date().toISOString(),read:false,url:'/notifications/a'},{id:'b',category:'tasks',severity:'success',title:'Task completed: 2/2 successful',created_at:new Date().toISOString(),read:false,url:'/notifications/b'}];
   const settings={toasts:true,push_categories:['tasks'],errors_only:false,quiet_start:null,quiet_end:null};
   page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
   await page.route('**/api/notifications**',async route=>{const url=new URL(route.request().url()),method=route.request().method();if(url.pathname.endsWith('/read'))items.forEach(x=>x.read=true);if(url.pathname.endsWith('/clear'))items=items.filter(x=>!x.read);if(url.pathname.endsWith('/preferences')&&method==='PUT')Object.assign(settings,route.request().postDataJSON());return route.fulfill({json:{items,unread:items.filter(x=>!x.read).length,settings,devices:[]}});});
   await page.goto(`http://127.0.0.1:${server.address().port}/`);
   await page.getByRole('button',{name:'Notifications: 2 unread',exact:true}).click();
   await page.locator('#notificationDrawer').waitFor({state:'visible'});
   assert.equal(await page.locator('#notificationList .wn-card').count(),2);
   assert.equal(await page.locator('#notificationList img').count(),0);
   await page.locator('#notificationFilter').selectOption('approvals');assert.equal(await page.locator('#notificationList .wn-card').count(),1);
   await page.locator('#notificationFilter').selectOption('all');
   const box=await page.locator('#notificationDrawer').boundingBox();assert(box.x>=0&&box.x+box.width<=width+1);
   assert(await page.locator('#notificationDrawer').evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   if(process.env.WINHUB_UI_SCREENSHOT_DIR){fs.mkdirSync(process.env.WINHUB_UI_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.WINHUB_UI_SCREENSHOT_DIR,`notifications-${width}.png`)});}
   await page.getByRole('button',{name:'Mark all read',exact:true}).click();await page.waitForFunction(()=>document.getElementById('notificationCount').hidden);
   await page.getByRole('button',{name:'Clear read',exact:true}).click();await page.getByText('You’re all caught up.').waitFor();
   await page.locator('summary').click();await page.locator('#notificationToasts').uncheck();await page.getByRole('button',{name:'Save preferences',exact:true}).click();await page.getByText('Preferences saved.').waitFor();assert.equal(settings.toasts,false);
   await page.getByRole('button',{name:'Send test push',exact:true}).click();
   await page.locator('#notificationTestResult').filter({hasText:'Allow notifications and enable push on this device first.'}).waitFor();
   assert.equal(await page.locator('#notificationTest').isEnabled(),true);
   await page.getByRole('button',{name:'Close notifications',exact:true}).click();assert(await page.locator('#notificationDrawer').isHidden());assert.deepEqual(errors,[]);await page.close();
  }
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
