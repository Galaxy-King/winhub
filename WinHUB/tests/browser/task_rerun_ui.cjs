const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.WINHUB_PLAYWRIGHT_MODULE||'playwright');
async function main(){
    const html=fs.readFileSync(process.argv[2]),root=path.resolve(process.argv[3],'static');
    const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://fixture');if(url.pathname==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}const file=path.resolve(root,url.pathname.replace(/^\/static\//,''));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}res.setHeader('Content-Type',file.endsWith('.css')?'text/css':'application/javascript');res.end(fs.readFileSync(file));});
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
    try{
        browser=await chromium.launch({headless:true,...(process.env.WINHUB_PLAYWRIGHT_CHANNEL?{channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL}:{})});
        const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];let submitted,legacy=false;
        page.on('pageerror',error=>errors.push(error.message));
        await page.route('**/api/**',async route=>{
            if(route.request().url().endsWith('/rerun')){
                if(route.request().method()==='POST'){submitted=route.request().postDataJSON();return route.fulfill({json:{success:true,job_id:'new-job'}});}
                return route.fulfill({json:{success:true,template:{id:'template-1',name:'Maintenance',hash:'current-hash'},saved_parameters:!legacy,template_changed:legacy,timeout_minutes:15,
                    targets:[{id:'host-1',name:'<img src=x onerror=alert(1)>'},{id:'host-2',name:'SECOND'}],group_name:'Original group',
                    fields:[{name:'Folder',spec:{type:'text',label:'Folder'},value:'C:\\Archive'},
                        {name:'Enabled',spec:{type:'checkbox',label:'Enabled'},value:'true'},
                        {name:'Mode',spec:{type:'select',options:['Safe','Full'],label:'Mode'},value:'Full'},
                        {name:'Password',spec:{type:'password',label:'Password'},secret:true,has_saved:!legacy,value:''}]
                }});
            }
            return route.fulfill({json:{success:true,jobs:[],pagination:{page:1,total:0,has_more:false},filters:{actors:[]}}});
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/`);await page.getByRole('button',{name:'Re-run original job'}).click();
        await page.locator('#taskRerunContent').waitFor({state:'visible'});
        assert.equal(await page.locator('#taskRerunTargets img').count(),0);
        assert.equal(await page.locator('#taskRerunFields [data-var=Folder]').inputValue(),'C:\\Archive');
        assert(await page.locator('#taskRerunFields [data-var=Enabled]').isChecked());
        assert.equal(await page.locator('#taskRerunFields [data-var=Mode]').inputValue(),'Full');
        assert.equal(await page.locator('#taskRerunFields input[type=password]').inputValue(),'');
        assert(await page.locator('#taskRerunFields input[type=password]').isDisabled());
        const output=process.env.WINHUB_RERUN_UI_OUTPUT_DIR;if(output){fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,'rerun-desktop.png'),fullPage:true});}
        await page.locator('#taskRerunFields [data-var=Folder]').fill('C:\\Updated');await page.locator('#taskRerunReason').fill('Repeat after correcting folder');
        await page.getByRole('button',{name:'Run again on original targets'}).click();await page.waitForFunction(()=>!document.getElementById('taskRerunDialog').open);
        assert.equal(submitted.variables.Folder,'C:\\Updated');assert.deepEqual(submitted.keep_secrets,['Password']);assert.equal(submitted.template_hash,'current-hash');assert(!('target_ids' in submitted));assert(!('payload' in submitted));
        legacy=true;await page.getByRole('button',{name:'Re-run original job'}).click();await page.locator('#taskRerunContent').waitFor({state:'visible'});
        assert.match(await page.locator('#taskRerunNotice').innerText(),/Saved input values are not available/);assert.match(await page.locator('#taskRerunNotice').innerText(),/template changed/);
        await page.setViewportSize({width:390,height:844});const box=await page.locator('#taskRerunDialog').boundingBox();assert(box.x>=0&&box.x+box.width<=391);if(output)await page.screenshot({path:path.join(output,'rerun-mobile.png'),fullPage:true});
        await page.getByRole('button',{name:'Close re-run',exact:true}).click();assert.deepEqual(errors,[]);
    }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
