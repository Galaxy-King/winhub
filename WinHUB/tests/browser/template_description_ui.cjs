const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.WINHUB_PLAYWRIGHT_MODULE||'playwright');
async function main(){
 const html=fs.readFileSync(process.argv[2]),root=path.resolve(process.argv[3],'static');
 const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://fixture');if(url.pathname==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}const file=path.resolve(root,url.pathname.replace(/^\/static\//,''));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}res.setHeader('Content-Type',file.endsWith('.css')?'text/css':'application/javascript');res.end(fs.readFileSync(file));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.WINHUB_PLAYWRIGHT_CHANNEL?{channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL}:{})});
  const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[];let text='Purpose\nHow to use\n<img src=x onerror=alert(1)>',canEdit=true,patches=0,created;
  page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.dismiss());
  await page.route('**/api/**',async route=>{
   if(route.request().url().endsWith('/description')){if(route.request().method()==='PATCH'){text=route.request().postDataJSON().description;patches++;}return route.fulfill({json:{success:true,description:text,can_edit:canEdit}});}
   if(route.request().url().endsWith('/templates')&&route.request().method()==='POST'){created=route.request().postDataJSON();return route.fulfill({status:400,json:{success:false,message:'Fixture prevents navigation'}});}
   return route.fulfill({json:{success:true}});
  });
  const select=async()=>page.evaluate(()=>loadTemplate(document.querySelector('.template-card')));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);await select();
  await page.getByRole('button',{name:'Open template description and usage guide'}).click();await page.locator('#templateCodeEditorModal').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>payloadEditor.getValue()),text);assert.equal(await page.locator('#templateCodeEditorModal img').count(),0);
  assert.equal(await page.evaluate(()=>payloadEditor.getOption('readOnly')),false);
  await page.evaluate(()=>payloadEditor.setValue('What this does\nUsage: fill the fields, select a host and run.'));
  await page.getByRole('button',{name:'Save description',exact:true}).click();await page.locator('#templateCodeEditorModal').waitFor({state:'hidden'});assert.equal(patches,1);
  assert.equal(await page.locator('#depPayload').inputValue(),'echo fixture');assert.match(await page.locator('#descriptionEditorSummary').innerText(),/What this does/);
  canEdit=false;await page.reload();await select();await page.getByRole('button',{name:'Open template description and usage guide'}).click();await page.locator('#templateCodeEditorModal').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>payloadEditor.getOption('readOnly')),true);assert(await page.locator('#btnApplyTemplateCodeEditor').isHidden());
  await page.getByRole('button',{name:'Close code editor',exact:true}).click();await page.getByRole('button',{name:'Open template description and usage guide'}).click();assert.equal(await page.evaluate(()=>payloadEditor.getOption('readOnly')),true);
  await page.getByRole('button',{name:'Close code editor',exact:true}).click();
  await page.evaluate(()=>resetWorkspace());await page.getByRole('button',{name:'Open template description and usage guide'}).click();await page.locator('#templateCodeEditorModal').waitFor({state:'visible'});
  await page.evaluate(()=>payloadEditor.setValue('New template instructions'));await page.getByRole('button',{name:'Apply changes',exact:true}).click();assert.equal(patches,1);
  await page.locator('#depTitle').fill('New template');await page.evaluate(()=>setPayloadValue('echo new'));await page.evaluate(()=>saveAsTemplate());assert.equal(created.description,'New template instructions');
  assert.deepEqual(errors,[]);
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
