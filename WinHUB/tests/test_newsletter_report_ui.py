"""Viewport and scrolling regression checks using an optional headless browser."""
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BROWSER = os.environ.get("WINHUB_BROWSER_EXE") or shutil.which("chromium") or shutil.which("google-chrome")
if not BROWSER and os.name == "nt":
    candidate = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe"
    if candidate.is_file():
        BROWSER = str(candidate)


@unittest.skipUnless(BROWSER, "Requires Chromium/Chrome or WINHUB_BROWSER_EXE")
class NewsletterReportBrowserTests(unittest.TestCase):
    def test_large_campaign_stays_in_viewport_and_can_scroll_and_change_pages(self):
        source = (ROOT / "modules/Newsletter/templates/newsletter_index.html").read_text(encoding="utf-8")
        styles = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", source, re.S))
        base = (ROOT / "templates/base.html").read_text(encoding="utf-8")
        styles += "\n" + "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", base, re.S))
        styles = re.sub(r"\{[{%].*?[%}]\}", "", styles)
        modal = source[source.index('<div id="campaignReportModal"'):source.index('<!-- Modal: Newsletter Guide -->')]
        script = source[source.index("    function campaignStatusClass("):source.index("    async function loadCampaigns(")]
        script += source[source.index("    function campaignReportCard("):source.index("    async function campaignAction(")]
        script += source[source.index("    async function retryCampaign("):source.index("    // --- Permission-controlled management functions ---")]
        test_script = r"""
let campaignReportState = {id:null,status:'',page:1,pages:1};
let campaignReportLoading=false;
let campaignReportRequest=0;
let campaignReportAutoRefresh=false;
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
let retryDialog = {id:null,groups:[],selected:new Set(),pages:{},submitting:false};
let retryDialogRequest=0;
const loadCampaigns = async()=>{};
const requests = [];
const manyReports = location.hash === '#many-reports';
window.fetch = async (url, options={}) => {
    if(url.endsWith('/retry')) {
        if(options.method==='POST'){
            requests.push({retry:JSON.parse(options.body).delivery_ids});
            return {ok:true,json:async()=>({success:true,retry_count:120})};
        }
        return {ok:true,json:async()=>({success:true,groups:[
            {id:'missing_key',label:'Missing public key',count:120,recipients:Array.from({length:120},(_,i)=>({id:'missing-'+i,recipient:`missing-${i}@example.org`,status:'Failed',error:'Missing public key <img src=x onerror=alert(1)>'}))},
            {id:'recipient_address',label:'Recipient address rejected',count:3880,recipients:Array.from({length:3880},(_,i)=>({id:'address-'+i,recipient:`address-${i}@example.org`,status:'Failed',error:'550 5.1.1 Recipient address rejected'}))}
        ]})};
    }
    const query = new URL(url, 'https://fixture.invalid').searchParams;
    const page = Number(query.get('page') || 1);
    requests.push({page,status:query.get('status') || '',summaryOnly:query.get('summary_only')==='1'});
    const payload = {success:true,
        campaign:{id:'fixture',subject:'Large campaign ' + 'x'.repeat(2000),source:'inbound',sender:'relay@example.org',created_at:'2026-11-25T10:00:00Z',status:'Sending',total_count:4000,sent_count:3900,failed_count:100,skipped_count:0},
        pagination:{page,pages:40,total:4000},delivery_counts:{Sent:3900,Failed:100},
        result_report:{status:'Completed',recipients:Array.from({length:manyReports ? 4000 : 2},(_,i)=>({recipient:`report-${i}@example.org`,status:'Sent'}))},
        deliveries:Array.from({length:100},(_,i)=>({recipient:`user-${(page-1)*100+i}@example.org`,status:'Failed',attempts:1,error:'LongErrorWithoutSpaces'.repeat(100),updated_at:'2026-11-25T10:00:00Z'}))
    };
    if(query.get('summary_only')==='1'){
        payload.campaign.sent_count=3910;
        payload.delivery_counts.Sent=3910;
        delete payload.deliveries;
        delete payload.pagination;
        payload.result_report={status:'Pending'};
    }
    return {ok:true,json:async()=>payload};
};
window.addEventListener('load', async()=>{
    const errors=[];
    const assert=(condition,message)=>{if(!condition)errors.push(message);};
    try {
        await openCampaignReport('fixture');
        const modal=document.getElementById('campaignReportModal');
        const panel=modal.firstElementChild;
        const table=modal.querySelector('table').parentElement;
        const inside=element=>{
            const r=element.getBoundingClientRect();
            return r.left>=-1 && r.top>=-1 && r.right<=innerWidth+1 && r.bottom<=innerHeight+1;
        };
        assert(inside(panel),'Panel exceeds viewport');
        assert(inside(document.getElementById('campaignReportNext')),'Next is outside viewport');
        assert(inside(modal.querySelector('[onclick="closeCampaignReport()"]')),'Close is outside viewport');
        assert(table.clientHeight>30,'Delivery table has no visible height');
        assert(table.scrollHeight>table.clientHeight,'Table does not have its own vertical scrolling');
        table.scrollTop=table.scrollHeight;
        assert(table.scrollTop>0,'Cannot scroll deliveries');
        const scrollBefore=table.scrollTop;
        const rowsBefore=document.getElementById('campaignReportRows').innerHTML;
        await loadCampaignReport(true);
        assert(requests.at(-1).summaryOnly,'Auto-refresh requested full delivery rows');
        assert(document.getElementById('campaignReportSummary').textContent.includes('3910'),'Live sent count did not update');
        assert(document.getElementById('campaignReportRows').innerHTML===rowsBefore,'Summary refresh replaced delivery rows');
        assert(table.scrollTop===scrollBefore,'Summary refresh changed delivery scroll position');
        assert(campaignReportAutoRefresh,'Active campaign stopped progress refresh');
        if(table.scrollWidth>table.clientWidth){table.scrollLeft=table.scrollWidth;assert(table.scrollLeft>0,'Cannot scroll columns');}
        assert(document.documentElement.scrollWidth<=innerWidth+1,'Report overflows the page horizontally');
        changeCampaignReportPage(1);
        await new Promise(resolve=>setTimeout(resolve,0));
        assert(requests.at(-1).page===2,'Next does not request page 2');
        assert(table.scrollTop===0,'Next page does not reset delivery scrolling');
        assert(document.getElementById('campaignReportRows').textContent.includes('user-100@example.org'),'Next page rows were not rendered');
        setCampaignReportFilter('Failed');
        await new Promise(resolve=>setTimeout(resolve,0));
        assert(requests.at(-1).status==='Failed' && requests.at(-1).page===1,'Filter does not reset pagination');
        closeCampaignReport();
        assert(getComputedStyle(modal).display==='none','Close does not hide the report');
        assert(!campaignReportAutoRefresh,'Closed report continues progress polling');
        await retryCampaign('fixture');
        const retryModal=document.getElementById('campaignRetryModal');
        assert(inside(retryModal.firstElementChild),'Retry dialog exceeds viewport');
        assert(inside(document.getElementById('retryConfirm')),'Retry confirmation is outside viewport');
        assert(document.getElementById('retryGroups').textContent.includes('Missing public key · 120'),'Retry category count is missing');
        assert(retryDialog.selected.size===0 && document.getElementById('retryConfirm').disabled,'Retry selected recipients by default');
        assert(document.querySelectorAll('.retry-recipient-cb').length===100,'Retry eagerly rendered all 4000 recipients');
        assert(!document.querySelector('#retryGroups img'),'Retry error text created HTML');
        const groupCheckbox=document.querySelector('.retry-group-cb[data-category="missing_key"]');
        groupCheckbox.click();
        assert(retryDialog.selected.size===120,'Group checkbox did not select recipients on all pages');
        document.querySelector('details[data-category="missing_key"]').open=true;
        document.querySelector('.retry-recipient-cb[data-delivery-id="missing-0"]').click();
        assert(retryDialog.selected.size===119 && groupCheckbox.indeterminate,'Individual deselection did not update the group');
        changeRetryPage('missing_key',1);
        assert(document.querySelector('.retry-recipient-cb[data-delivery-id="missing-50"]').checked,'Selection was lost across pages');
        const search=document.getElementById('retrySearch');
        search.value='address-0@';search.dispatchEvent(new Event('input'));
        assert(retryDialog.selected.size===119,'Search changed the selection');
        document.querySelector('.retry-recipient-cb[data-delivery-id="address-0"]').click();
        assert(retryDialog.selected.size===120,'Individual selection from another category failed');
        await confirmSelectedRetry();
        const submitted=requests.find(item=>item.retry)?.retry || [];
        assert(submitted.length===120 && submitted.includes('address-0') && !submitted.includes('missing-0'),'Retry submitted the wrong recipient selection');
        assert(getComputedStyle(retryModal).display==='none','Successful retry did not close the dialog');
    } catch(error){errors.push(error.stack || String(error));}
    const result=document.createElement('pre');
    result.id='browser-test-result';
    result.textContent=JSON.stringify({errors,width:innerWidth,height:innerHeight});
    document.body.append(result);
});
"""
        fixture = ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                   '<style>' + (ROOT / "static/css/tailwind.local.css").read_text(encoding="utf-8") + styles + '</style></head><body>'
                   + modal + '<script>' + script + test_script + '</script></body></html>')
        for width, height, fragment in ((1440, 900, ''), (1024, 600, ''), (480, 740, ''), (1024, 600, '#many-reports')):
            with self.subTest(width=width, height=height, many_reports=bool(fragment)), tempfile.TemporaryDirectory(prefix="winhub-report-ui-") as directory:
                document = Path(directory) / "report.html"
                document.write_text(fixture, encoding="utf-8")
                result = subprocess.run([BROWSER, '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
                                         '--disable-extensions', '--force-device-scale-factor=1', '--no-default-browser-check',
                                         '--user-data-dir=' + str(Path(directory) / 'profile'), f'--window-size={width},{height}',
                                         '--virtual-time-budget=1000', '--dump-dom', document.as_uri() + fragment],
                                        capture_output=True, text=True, encoding="utf-8", timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                match = re.search(r'<pre id="browser-test-result">(.*?)</pre>', result.stdout, re.S)
                self.assertIsNotNone(match, 'Browser did not finish report checks: ' + result.stderr[-1000:])
                metrics = json.loads(html.unescape(match[1]))
                self.assertEqual(metrics['errors'], [], json.dumps(metrics))
