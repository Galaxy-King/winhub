/* Fixture-only browser test. This server never executes Software tasks. */
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.WINHUB_PLAYWRIGHT_MODULE || 'playwright');

async function main() {
    const html = fs.readFileSync(process.argv[2]);
    const staticRoot = path.resolve(process.argv[3], 'static');
    const server = http.createServer((req,res) => {
        const url = new URL(req.url, 'http://fixture');
        if (url.pathname === '/') { res.setHeader('Content-Type','text/html; charset=utf-8'); return res.end(html); }
        if (!url.pathname.startsWith('/static/')) { res.writeHead(404); return res.end(); }
        const file = path.resolve(staticRoot, decodeURIComponent(url.pathname.slice(8)));
        if (!file.startsWith(staticRoot + path.sep) || !fs.existsSync(file)) { res.writeHead(404); return res.end(); }
        res.setHeader('Content-Type', file.endsWith('.css') ? 'text/css' : 'application/javascript');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    try {
        browser = await chromium.launch({headless:true, ...(process.env.WINHUB_PLAYWRIGHT_CHANNEL ? {channel:process.env.WINHUB_PLAYWRIGHT_CHANNEL} : {})});
        const page = await browser.newPage({viewport:{width:1440,height:1000}});
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const hosts = Array.from({length:320}, (_,i) => ({id:`h${i+1}`,name:`ENDPOINT-${String(i+1).padStart(3,'0')}`,os_type:'Windows',
            groups:i===0?['g1']:i===1?['g1','g2']:i===2?['g2']:[]}));
        const groups = [{id:'g1',name:'Office A'},{id:'g2',name:'Office B'},{id:'g3',name:'Lab <img src=x onerror=alert(1)>'}];
        const packages = ['7-Zip','WireGuard'].map((name,i)=>({id:`p${i}`,name,version:'1.0',sets:['Standard'],approved:true,prepared:true,size:1048576,revision:`r${i}`}));
        let payload;
        await page.route('**/api/**', async route => {
            const url = new URL(route.request().url());
            if (url.pathname === '/api/infrastructure/software-packages') return route.fulfill({json:{success:true,packages,hosts,groups,templates:[],settings:{max_hosts:2,max_downloads:2,bandwidth_mib:10}}});
            if (route.request().method()==='POST') {
                payload = route.request().postDataJSON();
                return route.fulfill({json:{success:true,targets:3,packages:2,tasks:6}});
            }
            return route.fulfill({json:{success:true,deployments:[]}});
        });
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.getByText('7-Zip · 1.0',{exact:true}).waitFor();
        const initialHeight = await page.locator('#swPanel-library').evaluate(n=>n.getBoundingClientRect().height);
        assert.equal(await page.locator('#swTargetPickerList label').count(),0,'Endpoint list must not expand inline');
        await page.locator('#swSets label').filter({hasText:'Standard'}).locator('input').check();

        async function open(mode) { await page.getByRole('button',{name:mode==='groups'?'Select groups':'Select endpoints'}).click(); }
        async function check(name) { await page.locator('#swTargetPickerList label').filter({hasText:name}).locator('input').check(); }
        const modal = page.locator('#swTargetModal');
        await open('endpoints'); await check('ENDPOINT-001');
        assert.match(await page.locator('#swTargetsSummary').innerText(),/No targets/,'Draft must not change confirmed targets');
        await modal.getByRole('button',{name:'Cancel',exact:true}).click();
        assert.match(await page.locator('#swTargetsSummary').innerText(),/No targets/);
        await open('endpoints'); await check('ENDPOINT-001');
        await modal.getByRole('button',{name:'Use selected',exact:true}).click();
        assert.match(await page.locator('#swTargetsSummary').innerText(),/^1 unique/);
        await open('groups'); await check('Office A'); await check('Office B');
        await modal.getByRole('button',{name:'Use selected',exact:true}).click();
        assert.match(await page.locator('#swTargetsSummary').innerText(),/^3 unique/,'Overlapping groups and individual endpoints must be deduplicated');
        await open('groups'); await modal.getByRole('button',{name:'Clear',exact:true}).click(); await page.keyboard.press('Escape');
        assert.match(await page.locator('#swGroupsCount').innerText(),/^2 groups/,'Escape must discard draft edits');
        assert.equal(await page.evaluate(()=>document.activeElement.id),'swChooseGroups');
        await open('groups');
        await page.locator('#swTargetPickerList label').filter({hasText:'Office A'}).locator('input').uncheck();
        await modal.click({position:{x:4,y:4}});
        assert.match(await page.locator('#swGroupsCount').innerText(),/^2 groups/,'Backdrop dismissal must discard draft edits');
        await open('groups');
        await modal.getByRole('button',{name:'Close target selection',exact:true}).focus();
        await page.keyboard.press('Shift+Tab');
        assert.equal(await page.evaluate(()=>document.activeElement.textContent),'Use selected','Focus must stay inside the modal');
        assert.equal(await modal.locator('img').count(),0,'Untrusted group names must remain text');
        await modal.getByRole('button',{name:'Close target selection',exact:true}).click();
        await open('endpoints');
        await page.locator('#swTargetPickerSearch').fill('ENDPOINT-00');
        await modal.getByRole('button',{name:'Select visible',exact:true}).click();
        assert.equal(await page.locator('#swTargetDraftCount').innerText(),'9');
        await modal.getByRole('button',{name:'Cancel',exact:true}).click();
        assert(Math.abs(await page.locator('#swPanel-library').evaluate(n=>n.getBoundingClientRect().height)-initialHeight)<100,'Target selection must not expand the page into an inline endpoint list');

        // Use actual computed styles with base.html, not a light-theme approximation.
        const colours = await page.locator('.sw-card').first().evaluate(n=>({text:getComputedStyle(n).color,bg:getComputedStyle(n).backgroundColor}));
        function luminance(css) {
            const rgb=css.match(/[\d.]+/g).slice(0,3).map(x=>{const v=Number(x)/255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;});
            return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;
        }
        const ratio=(Math.max(luminance(colours.text),luminance(colours.bg))+.05)/(Math.min(luminance(colours.text),luminance(colours.bg))+.05);
        assert(ratio>=4.5,`Card contrast ${ratio} is below 4.5:1`);
        assert(!/[А-Яа-яІіЇїЄєҐґ]/.test(await page.locator('#view-software').innerText()),'Interface must be English');
        const output = process.env.WINHUB_SOFTWARE_UI_ARTIFACT_DIR;
        if (output) { fs.mkdirSync(output,{recursive:true}); await page.screenshot({path:path.join(output,'desktop.png'),fullPage:true}); }
        await open('endpoints');
        if (output) await page.screenshot({path:path.join(output,'endpoints.png'),fullPage:true});
        await page.setViewportSize({width:390,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Modal must fit mobile width');
        const bounds = await modal.locator('.sw-modal-card').boundingBox();
        assert(bounds.y>=0 && bounds.y+bounds.height<=844,'Modal must fit mobile height');
        if (output) await page.screenshot({path:path.join(output,'mobile.png'),fullPage:true});
        await page.keyboard.press('Escape');
        await page.setViewportSize({width:1440,height:1000});
        await page.getByRole('button', {name:'Installers · Add / Test link', exact:true}).click();
        await page.getByRole('button', {name:'Test download link', exact:true}).click();
        assert((await page.locator('#swLinkTestResult').innerText()).includes('Enter an OMV download link first.'));
        await page.getByRole('button', {name:'Install', exact:true}).click();
        await page.getByRole('button',{name:'Review and deploy',exact:true}).click();
        await page.getByText('Deployment created:',{exact:false}).waitFor();
        assert.deepEqual(payload.target_ids,['h1']);
        assert.deepEqual(payload.group_ids,['g1','g2']);
        assert.equal(payload.expected_target_ids.length,3);
        assert.equal(payload.package_ids.length,0); // Both applications came from the Standard set.
        assert.deepEqual(payload.sets,['Standard']);
        assert.deepEqual(errors,[],'Browser must have no JavaScript errors');
        console.log(`PASS: modal confirmation/cancel/Escape, group union, search, scoped select-visible, English UI, dark-theme contrast ${ratio.toFixed(2)}:1, mobile bounds, deployment payload`);
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
