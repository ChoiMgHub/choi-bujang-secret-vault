import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createVerificationHandler,measureVerificationCase,validVerificationReport } from '../src/verification-api.mjs';
import { createOperationsRuleHandler,executeRuleFixture } from '../src/operations-rule-api.mjs';
import { VERIFICATION_CASES,caseById } from '../src/verification-catalog.mjs';
import { sessionDeviceId } from '../src/device-approval.mjs';
import { ACCESS_COOKIE } from '../src/browser-session.mjs';

const commit='a'.repeat(40),rid='30000000-0000-4000-8000-000000000001';
const identity={kind:'student',userId:'10000000-0000-4000-8000-000000000001',sessionId:'20000000-0000-4000-8000-000000000001'};
const config={step:11,publicAppUrl:'https://fixture.vercel.app/',identityProvider:{issuer:'https://fixture.supabase.co/auth/v1'},originalApiUrl:'https://fixture.supabase.co/rest/v1/vault_notes'};
const origin=new URL(config.publicAppUrl).origin;
const reply=()=>({code:0,headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(body){this.body=body;return this;}});
async function call(handler,{method='GET',url='/api/operations-check',body,headers={}}={}) {
  const response=reply();
  await handler({method,url,body,headers:{origin,'x-requested-with':'vault-ui','content-type':'application/json',cookie:`${ACCESS_COOKIE}=a.b.c`,...headers}},response);
  return response;
}
const empty=()=>({schema:'aleph.verification.record.v1',runId:null,startedAt:null,commit,account:'A',fixtureNotesReady:true,rows:[]});
function fixture() {
  const state={report:empty(),status:'approved',verified:true,dbCalls:[],fetchCalls:[],logs:[]};
  const db={rpc(name,args){state.dbCalls.push({name,args});return {abortSignal:async()=>{
    if(name==='aleph_step11_device_status')return {data:{schema:'aleph.device-status.v1',deviceId:sessionDeviceId(identity),status:state.status}};
    if(args.p_user_id!==identity.userId||args.p_session_id!==identity.sessionId)return {error:{message:'private actor error'}};
    if(args.p_mode==='start')state.report={...empty(),runId:rid,startedAt:'2026-11-10T03:00:00+00:00'};
    else if(args.p_run_id&&args.p_run_id!==state.report.runId)return {error:{message:'private run error'}};
    if(args.p_mode==='append'&&!state.report.rows.some(v=>v.caseId===args.p_item.caseId))state.report.rows.push(args.p_item);
    return {data:structuredClone(state.report)};
  }};}};
  const fetchImpl=async(url,init)=>{state.fetchCalls.push({url:String(url),init});
    return new Response(JSON.stringify({id:'10000000-0000-4000-8000-000000000001',title:'virtual title',body:'VIRTUAL_BODY_ONLY'}),
      {status:200,headers:{'content-type':'application/json','x-vercel-id':'sfo1::fixture-proof'}});};
  const options={deploymentConfig:config,env:{VERCEL_GIT_COMMIT_SHA:commit},fetchImpl,
    runtimeFactory:()=>({db,verifyLogin:async token=>state.verified&&token==='Bearer a.b.c'?identity:null}),log:v=>state.logs.push(JSON.parse(v))};
  return {state,options,handler:createVerificationHandler(options)};
}
test('verification only measures real server-selected requests and stores/returns the same redacted observation',async()=>{
  const f=fixture();assert.equal((await call(f.handler)).body.report.runId,null);
  const start=await call(f.handler,{method:'POST',body:{action:'start'}});assert.equal(start.code,200);
  const result=await call(f.handler,{method:'POST',body:{action:'check',runId:rid,caseId:'own_note'},headers:{'x-user-id':'other','x-role':'admin'}});
  assert.equal(result.code,200);const row=result.body.report.rows[0];
  assert.equal(row.state,'passed');assert.equal(row.actualStatus,200);assert.equal(row.requestId,'sfo1::fixture-proof');
  assert.ok(Number.isFinite(Date.parse(row.checkedAt)));assert.equal(validVerificationReport(result.body.report,commit),true);
  const stored=f.state.dbCalls.find(v=>v.name==='aleph_step12_verification'&&v.args.p_mode==='append').args;
  assert.deepEqual(stored.p_item,row);assert.equal(stored.p_user_id,identity.userId);
  assert.doesNotMatch(JSON.stringify(result.body)+JSON.stringify(f.state.logs),/VIRTUAL_BODY_ONLY|a\.b\.c|session_id|actor_id/u);
  await call(f.handler,{method:'POST',body:{action:'check',runId:rid,caseId:'own_note'}});
  assert.equal(f.state.fetchCalls.length,1);
});
test('verification rejects client-submitted results, URLs, other runs, unknown/manual cases and unapproved sessions',async()=>{
  const f=fixture();
  for(const body of [{action:'start',passed:41},{action:'check',runId:rid,caseId:'own_note',actualStatus:200},
    {action:'check',runId:[rid],caseId:'own_note'},
    {action:'check',runId:rid,caseId:'own_note',url:'https://other.example'},
    {action:'check',runId:rid,caseId:'official_41'},{action:'check',runId:rid,caseId:'manual_revocation'}]) {
    assert.equal((await call(f.handler,{method:'POST',body})).code,400);
  }
  assert.equal((await call(f.handler,{method:'POST',body:{action:'check',runId:rid,caseId:'own_note'}})).code,503);
  assert.equal((await call(f.handler,{url:'/api/operations-check?passed=41'})).code,400);
  assert.equal((await call(f.handler,{url:'/api/operations-check?feature=operations-check'})).code,200);
  assert.equal((await call(f.handler,{headers:{cookie:undefined}})).code,401);
  for(const status of ['pending','revoked','expired']) {f.state.status=status;assert.equal((await call(f.handler)).code,403);}
  assert.equal(f.state.fetchCalls.length,0);
});
test('unexpected DB rows, fabricated passes and data-bearing fields are rejected rather than returned or logged',async()=>{
  const f=fixture();await call(f.handler,{method:'POST',body:{action:'start'}});
  const row={...caseById('own_note'),state:'passed',actualStatus:500,actualResult:'NOTE_SHAPE_MATCHED',requestId:'sfo1::fixture-proof',checkedAt:new Date().toISOString()};
  const keys=['caseId','source','method','path','expectedStatus','expectedResult','state','actualStatus','actualResult','requestId','checkedAt'];
  f.state.report.rows=[Object.fromEntries(keys.map(k=>[k,row[k]]))];
  const result=await call(f.handler);assert.equal(result.code,503);assert.deepEqual(result.body,{error:'VERIFICATION_UNAVAILABLE'});
  f.state.report={...empty(),title:'VIRTUAL_BODY_ONLY'};
  assert.equal((await call(f.handler)).code,503);
  assert.doesNotMatch(JSON.stringify(f.state.logs),/VIRTUAL_BODY_ONLY/u);
});
test('measurement never invents response IDs or successes for failures, absent fixtures and unsupported accounts',async()=>{
  const context={account:'A',fixtureNotesReady:true,authorization:'Bearer a.b.c',commit};
  const item=caseById('own_note');
  const noTrace=async()=>new Response(JSON.stringify({id:'10000000-0000-4000-8000-000000000001',title:'virtual',body:'VIRTUAL_BODY_ONLY'}),{status:200,headers:{'content-type':'application/json'}});
  const noId=await measureVerificationCase(item,context,{deploymentConfig:config,fetchImpl:noTrace});
  assert.equal(noId.state,'failed');assert.equal(noId.requestId,null);
  const broken=await measureVerificationCase(item,context,{deploymentConfig:config,fetchImpl:async()=>{throw Error('VIRTUAL_PRIVATE_DIAGNOSTIC');}});
  assert.equal(broken.state,'error');assert.equal(broken.actualStatus,null);
  const bad=await measureVerificationCase(item,context,{deploymentConfig:config,fetchImpl:async()=>new Response('VIRTUAL_PRIVATE_DIAGNOSTIC',{status:500,headers:{'x-vercel-id':'sfo1::bad'}})});
  assert.equal(bad.state,'failed');assert.equal(bad.actualResult,'UNEXPECTED_RESPONSE');
  assert.doesNotMatch(JSON.stringify([broken,bad,noId]),/VIRTUAL_PRIVATE_DIAGNOSTIC|VIRTUAL_BODY_ONLY/u);
  const never=async()=>assert.fail('not applicable rows must not send a request');
  assert.equal((await measureVerificationCase(item,{...context,fixtureNotesReady:false},{fetchImpl:never})).state,'not_applicable');
  assert.equal((await measureVerificationCase(caseById('backup_snapshot'),context,{fetchImpl:never})).state,'not_applicable');
});
test('direct DB check uses only the fixed original source and public application key, never a student token',async()=>{
  const context={account:'B',fixtureNotesReady:true,authorization:'Bearer a.b.c',commit};
  const row=await measureVerificationCase(caseById('direct_database'),context,{deploymentConfig:config,fetchImpl:async(url,init)=>{
    assert.equal(String(url),'https://fixture.supabase.co/rest/v1/vault_notes?select=id&limit=1');
    assert.equal(init.headers.authorization,undefined);assert.ok(init.headers.apikey);assert.equal(init.redirect,'error');
    return new Response(JSON.stringify({code:'42501',details:null,hint:null,message:'denied'}),{status:401,headers:{'content-type':'application/json','sb-request-id':rid}});
  }});
  assert.equal(row.state,'passed');assert.equal(row.actualResult,'42501');
  const denied=await measureVerificationCase(caseById('direct_database'),context,{deploymentConfig:{...config,originalApiUrl:'https://other.example/rest/v1/vault_notes'},fetchImpl:async()=>assert.fail('external source must never be requested')});
  assert.equal(denied.state,'error');
});
test('rule API executes only fixed student fixtures with real current rules and labels them separately from live engine events',async()=>{
  const f=fixture();const handler=createOperationsRuleHandler(f.options);
  for(const item of VERIFICATION_CASES.filter(v=>v.source==='student_fixture_api')) {
    const r=await call(handler,{method:'POST',url:'/api/operations-rule?feature=operations-rule',body:{caseId:item.caseId}});
    assert.equal(r.code,200);assert.equal(r.body.source,'student_fixture_api');
    assert.equal(r.body.result.outcome,item.expectedResult);assert.equal(r.headers['X-Request-ID'],r.body.requestId);
    assert.doesNotMatch(JSON.stringify(r.body),/a\.b\.c|session_id|subjectId|identity/u);
  }
  for(const body of [{caseId:'detect_121',events:[]},{caseId:'official_41'},{caseId:'decider_allow',deviceRegistered:true}])
    assert.equal((await call(handler,{method:'POST',url:'/api/operations-rule',body})).code,400);
  await assert.rejects(executeRuleFixture('unknown',rid));
});

const uiSource=await readFile(new URL('../public/verification-ui.js',import.meta.url),'utf8');
const settle=async()=>{await new Promise(resolve=>setImmediate(resolve));};
function viewFixture() {
  const controls=new Map(),events={},calls=[];let observer;
  const element=()=>({hidden:true,disabled:false,textContent:'',children:[],append(v){this.children.push(v);},replaceChildren(...v){this.children=v;},addEventListener(name,fn){this.events??={};this.events[name]=fn;}});
  for(const id of ['memo-panel','verification-run','verification-read','verification-status','verification-reference','verification-rows','verification-record','verification-details'])controls.set(`#${id}`,element());
  const navigator={onLine:true};
  vm.runInNewContext(uiSource,{document:{querySelector:id=>controls.get(id),createElement:element},navigator,
    window:{addEventListener:(name,fn)=>{events[name]=fn;}},MutationObserver:class{constructor(fn){observer=fn;}observe(){}},
    fetch:(url,init)=>new Promise(resolve=>calls.push({url,init,resolve})),AbortController,JSON,Object,Error});
  return {controls,events,calls,navigator,change:()=>observer(),element};
}
test('verification UI keeps all missing rows unexecuted and clears late results on logout and offline',async()=>{
  const f=viewFixture();assert.equal(f.calls.length,0);
  f.controls.get('#memo-panel').hidden=false;f.change();
  f.calls[0].resolve({ok:true,json:async()=>({schema:'aleph.verification.view.v1',catalog:VERIFICATION_CASES,report:empty()})});await settle();
  assert.equal(f.controls.get('#verification-rows').children.length,24);
  assert.match(f.controls.get('#verification-status').textContent,/미실행 24/u);
  f.controls.get('#verification-read').events.click();assert.equal(f.calls.length,2);
  f.controls.get('#memo-panel').hidden=true;f.change();
  f.calls[1].resolve({ok:true,json:async()=>({schema:'aleph.verification.view.v1',catalog:VERIFICATION_CASES,report:empty()})});await settle();
  assert.equal(f.controls.get('#verification-record').textContent,'');assert.equal(f.controls.get('#verification-rows').children.length,0);
  f.events.offline();assert.equal(f.controls.get('#verification-record').textContent,'');
  assert.doesNotMatch(uiSource,/localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML/u);
});
test('verification UI stops at the first measured mismatch and leaves later requests unexecuted',async()=>{
  const f=viewFixture();f.controls.get('#memo-panel').hidden=false;f.change();
  const catalog=[caseById('own_note'),caseById('foreign_note'),caseById('manual_revocation')];
  const response=report=>({ok:true,json:async()=>({schema:'aleph.verification.view.v1',catalog,report})});
  f.calls[0].resolve(response(empty()));await settle();
  f.controls.get('#verification-run').events.click();
  assert.equal(JSON.parse(f.calls[1].init.body).action,'start');
  const run={...empty(),runId:rid,startedAt:new Date().toISOString()};
  f.calls[1].resolve(response(run));await settle();
  assert.equal(JSON.parse(f.calls[2].init.body).caseId,'own_note');
  const item=caseById('own_note');
  f.calls[2].resolve(response({...run,rows:[{caseId:item.caseId,source:item.source,method:item.method,path:item.path,
    expectedStatus:item.expectedStatus,expectedResult:item.expectedResult,state:'failed',actualStatus:500,
    actualResult:'UNEXPECTED_RESPONSE',requestId:'sfo1::fixture-response',checkedAt:new Date().toISOString()}]}));
  await settle();
  assert.equal(f.calls.length,3);assert.match(f.controls.get('#verification-status').textContent,/첫 불일치에서 중단/u);
  assert.equal(f.controls.get('#verification-rows').children[1].children[3].textContent,'미실행');
  assert.equal(f.controls.get('#verification-run').disabled,false);
});
