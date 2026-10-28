const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.WINHUB_PLAYWRIGHT_MODULE||'playwright');
async function main(){
    const html=fs.readFileSync(process.argv[2]),root=path.resolve(process.argv[3],'static');
    const server=http.createServer((req,res)=>{
        const url=new URL(req.url,'http://fixture');if(url.pathname==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}
        const file=path.resolve(root,url.pathname.replace(/^\/static\//,''));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}
        res.setHeader('Content-Type',file.endsWith('.css')?'text/css':'application/javascript');res.end(fs.readFileSync(file));
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
    try{
        browser=await chromium.launch({headless:true,...(process.env.WINHUB_PLAYWRIGHT_CHANNEL?{channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL}:{})});
        const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];let cleanup=0,exportBody;
        page.on('pageerror',error=>errors.push(error.message));
        await page.route('**/api/**',async route=>{
            const url=new URL(route.request().url());
            if(url.pathname.endsWith('/history-range'))return route.fulfill({json:{success:true,oldest:'2026-08-01T00:00:00Z',newest:'2026-10-28T08:00:00Z',tasks:120}});
            if(url.pathname.endsWith('/tasks/all')){await new Promise(resolve=>setTimeout(resolve,200));return route.fulfill({json:{success:true,jobs:[],pagination:{page:1,total:0,has_more:false},filters:{actors:[]}}});}
            if(url.pathname.endsWith('/cleanup')){const body=route.request().postDataJSON();if(body.preview)return route.fulfill({json:{success:true,days:body.days,eligible:3,cutoff:'2026-09-13T08:00:00Z'}});cleanup++;return route.fulfill({json:{success:true,deleted:3,remaining:0,has_more:false}});}
            if(url.pathname.endsWith('/export')){exportBody=route.request().postDataJSON();return route.fulfill({contentType:'application/zip',body:Buffer.from('fixture zip')});}
            return route.fulfill({json:{success:true}});
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/`);await page.evaluate(()=>queueHistoryRange(true));
        assert.match(await page.locator('#queueHistoryRange').innerText(),/120 task records/);
        assert.equal(await page.locator('#statQTotal').count(),0);
        assert.equal(await page.locator('.q-status-btn').filter({hasText:/^Scheduled$/}).count(),0);
        const box=await page.getByRole('button',{name:'Refresh queue',exact:true}).boundingBox();assert.equal(box.width,box.height);assert(box.x>1200);
        const output=process.env.WINHUB_QUEUE_UI_OUTPUT_DIR;if(output){fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,'queue-desktop.png'),fullPage:true});}
        await page.getByRole('button',{name:'Refresh queue',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.queue-refresh').disabled);
        await page.getByRole('button',{name:'Export tasks',exact:true}).click();await page.locator('#queueExportFrom').fill('2026-08-01');await page.locator('#queueExportTo').fill('2026-09-01');
        const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download ZIP archive'}).click();assert.equal((await download).suggestedFilename(),'winhub-tasks-2026-08-01-to-2026-09-01.zip');
        assert.deepEqual(exportBody,{date_from:'2026-08-01',date_to:'2026-09-01'});
        await page.getByRole('button',{name:'Close history tools'}).click();await page.getByRole('button',{name:'Clean History',exact:true}).click();
        await page.locator('#queueCleanupDays').fill('45');await page.getByRole('button',{name:'Preview cleanup'}).click();await page.waitForFunction(()=>!document.getElementById('queueCleanupConfirm').disabled);assert.equal(cleanup,0);
        assert.match(await page.locator('#queueCleanupPreviewText').innerText(),/3 eligible task records/);
        if(output)await page.screenshot({path:path.join(output,'queue-cleanup.png'),fullPage:true});
        await page.locator('#queueCleanupDays').fill('46');assert(await page.locator('#queueCleanupConfirm').isDisabled());
        await page.locator('#queueCleanupDays').fill('45');await page.getByRole('button',{name:'Preview cleanup'}).click();await page.waitForFunction(()=>!document.getElementById('queueCleanupConfirm').disabled);
        page.once('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:'Delete eligible records'}).click();await page.waitForFunction(()=>document.getElementById('queueHistoryMessage').textContent==='Deleted 3 task records.');assert.equal(cleanup,1);
        await page.setViewportSize({width:390,height:844});const modal=await page.locator('#queueHistoryDialog').boundingBox();assert(modal.x>=0&&modal.x+modal.width<=391);
        if(output)await page.screenshot({path:path.join(output,'queue-mobile.png'),fullPage:true});
        await page.getByRole('button',{name:'Close history tools'}).click();
        const select=await page.locator('#qFilterUser').boundingBox();assert(select.x+select.width<=391);
        assert.deepEqual(errors,[]);
    }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
