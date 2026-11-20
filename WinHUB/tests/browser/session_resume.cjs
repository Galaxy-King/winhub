const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const code=fs.readFileSync(path.join(__dirname,'../../static/js/session_resume.js'),'utf8');
async function run(pathname,status,stored){
 const redirects=[],storage=new Map(stored?[['winhub_session_resume',String(Date.now())]]:[]);let calls=0;
 vm.runInNewContext(code,{URLSearchParams,Date,Number,String,location:{pathname,search:'?next=/mobile',replace:x=>redirects.push(x)},
 sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},document:{getElementById:()=>null},
 fetch:async()=>{calls++;return {ok:status===200,json:async()=>({success:true})};}});
 await new Promise(r=>setImmediate(r));return {redirects,calls};
}
(async()=>{
 assert.deepEqual((await run('/login',440,false)).redirects,[]);
 assert.deepEqual((await run('/login',200,false)).redirects,['/mobile']);
 assert.equal((await run('/login',200,true)).calls,0);
 assert.deepEqual((await run('/push-open',440,false)).redirects,['/login?next=%2Fmobile']);
 console.log('Session resume tests OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
