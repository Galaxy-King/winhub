const fs=require('node:fs'), path=require('node:path'), http=require('node:http'), assert=require('node:assert/strict');
const {chromium}=require(process.env.WINHUB_PLAYWRIGHT_MODULE||'playwright');
async function main(){
    const html=fs.readFileSync(process.argv[2]), root=path.resolve(process.argv[3],'static');
    const server=http.createServer((req,res)=>{
        const url=new URL(req.url,'http://fixture');
        if(url.pathname==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}
        const file=path.resolve(root,url.pathname.replace(/^\/static\//,''));
        if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}
        res.setHeader('Content-Type',file.endsWith('.css')?'text/css':'application/javascript');res.end(fs.readFileSync(file));
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
    try{
        browser=await chromium.launch({headless:true,...(process.env.WINHUB_PLAYWRIGHT_CHANNEL?{channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL}:{})});
        const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
        page.on('pageerror',e=>errors.push(e.message));let saved;
        await page.route('**/api/**',async route=>{
            const url=new URL(route.request().url());
            if(url.pathname.endsWith('/preview'))return route.fulfill({json:{success:true,dates:['2030-01-06T03:00:00Z','2030-01-20T03:00:00Z','2030-02-03T03:00:00Z','2030-02-17T03:00:00Z','2030-03-03T03:00:00Z']}});
            if(url.pathname.endsWith('/summary'))return route.fulfill({json:{success:true,schedules:[{id:'s1',status:'VerificationFailed',last_run:'2030-01-01T03:00:00Z',next_run:'2030-01-06T03:00:00Z'}]}});
            if(url.pathname.endsWith('/history'))return route.fulfill({json:{success:true,page:1,total:1,has_more:false,runs:[{id:'r1',name:'Backup <img src=x onerror=alert(1)>',category:'Backups',source:'scheduler',status:'VerificationFailed',message:'Archive check failed',scheduled_at:'2030-01-01T03:00:00Z',created_at:'2030-01-01T03:00:10Z',finished_at:'2030-01-01T03:02:00Z',tasks:[{id:'task1',name:'WIN-PILOT',status:'VerificationFailed',exit_code:21,retries:0,duration_seconds:100,received_at:'2030-01-01T03:00:20Z',finished_at:'2030-01-01T03:02:00Z'}]}]}});
            if(url.pathname==='/api/infrastructure/schedule'){saved=route.request().postDataJSON();return route.fulfill({json:{success:false,message:'Fixture save captured; no host was contacted'}});}
            return route.fulfill({json:{success:true}});
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.getByRole('button',{name:'New Schedule',exact:true}).click();
        await page.locator('#schName').fill('Fortnightly backup');await page.locator('#schLaunchReason').fill('Pilot scheduled backup');
        await page.locator('#schRuleKind').selectOption('weekly');await page.locator('#schRuleEvery').fill('2');
        await page.locator('#schRuleTimezone').fill('UTC');await page.locator('#schRuleDate').fill('2030-01-01');await page.locator('#schRuleTime').fill('03:00');
        await page.locator('.sch-rule-day[value="6"]').check();
        await page.locator('#schWarningCodes').fill('10');
        await page.locator('#schRulePreview').getByText('06/01/2030',{exact:false}).waitFor();
        assert.equal(await page.locator('#schUiOnce').isVisible(),false,'Legacy controls must not compete with calendar form');
        await page.locator('#schRuleKind').selectOption('monthly');await page.locator('#schRuleMonthMode').selectOption('weekday');
        assert.equal(await page.locator('#schRuleOrdinal').isVisible(),true);
        assert.equal(await page.locator('#schRuleMonthDay').isVisible(),false);
        await page.locator('#schRuleKind').selectOption('weekly');
        const output=process.env.WINHUB_SCHEDULER_UI_ARTIFACT_DIR;if(output){fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,'scheduler-form-desktop.png'),fullPage:true});}
        await page.setViewportSize({width:390,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Form must fit mobile viewport');
        const box=await page.locator('#scheduleModal .schedule-modal-shell').boundingBox();assert(box.y>=0&&box.y+box.height<=845,'Dialog must fit viewport');
        if(output)await page.screenshot({path:path.join(output,'scheduler-form-mobile.png'),fullPage:true});
        page.on('dialog',d=>d.dismiss());await page.locator('#btnSaveSchedule').click();
        await page.waitForFunction(()=>document.getElementById('btnSaveSchedule').disabled===false);
        assert.equal(saved.recurrence.kind,'weekly');assert.equal(saved.recurrence.every,2);assert.deepEqual(saved.recurrence.weekdays,[6]);
        assert.equal(saved.execution_policy.execution_seconds,1800);assert.deepEqual(saved.execution_policy.warning_codes,[10]);
        await page.evaluate(()=>closeModal('scheduleModal'));await page.setViewportSize({width:1440,height:1000});
        await page.getByRole('button',{name:'Run history',exact:true}).click();
        await page.locator('#schedulerHistoryList summary').click();
        await page.getByText('Exit code: 21',{exact:false}).waitFor();
        assert.equal(await page.locator('#schedulerHistoryList img').count(),0,'Agent/host text must not become markup');
        assert.equal(await page.locator('#schedulerHistoryList .scheduler-status').first().getAttribute('data-tone'),'error');
        if(output)await page.screenshot({path:path.join(output,'scheduler-history.png'),fullPage:true});
        await page.getByRole('button',{name:'Guide',exact:true}).click();
        await page.getByRole('button',{name:'Українська',exact:true}).click();
        assert.equal(await page.locator('#scheduler-guide-uk').isVisible(),true);assert.equal(await page.locator('#scheduler-guide-en').isVisible(),false);
        await page.reload();await page.locator('#scheduler-guide-uk').waitFor({state:'visible'});
        await page.getByRole('button',{name:'English',exact:true}).click();assert.equal(await page.locator('#scheduler-guide-en').isVisible(),true);
        assert.deepEqual(errors,[]);console.log('PASS: fortnightly form, monthly controls, preview, policy payload, mobile bounds, scoped history rendering, colored failures, bilingual guide and reload state');
    }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
