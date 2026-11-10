import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createOperationsHandler, validOperationsRecord } from '../src/operations-api.mjs';
import { sessionDeviceId } from '../src/device-approval.mjs';
import { ACCESS_COOKIE } from '../src/browser-session.mjs';

const commit = 'a'.repeat(40);
const config = {step:11,publicAppUrl:'https://fixture.example/'};
const identity = {kind:'student',userId:'10000000-0000-4000-8000-000000000001',sessionId:'20000000-0000-4000-8000-000000000001'};
function record() {
  return {schema:'aleph.operations.record.v1',requestId:'30000000-0000-4000-8000-000000000001',
    checkedAt:'2026-11-10T03:00:00+00:00',commit,scope:'current_login_session',
    policy:{ruleIds:['device_registered','step_up_required','resource_zone'],decisionTests:'not_executed'},
    detection:{state:'not_executed',events:null,proposals:null},
    revocation:{scope:'student_session_registry',sessionStatus:'approved',events:0,lastRevokedAt:null,engineExecution:'not_executed'},
    recovery:{state:'not_available_for_this_account',version:null,backedUpAt:null,backupVerified:null,liveMatchesBackup:null,restoreEvents:null,lastRestoredAt:null},
    officialTests:{total:41,state:'not_executed',passed:null}};
}
function fixture() {
  const state = {status:'approved',verified:true,data:record(),error:null,calls:[],logs:[]};
  const db = {rpc(name,args) {
    state.calls.push({name,args});
    return {abortSignal:async()=>name==='aleph_step11_device_status'
      ? {data:{schema:'aleph.device-status.v1',deviceId:sessionDeviceId(identity),status:state.status}}
      : {data:state.data,error:state.error}};
  }};
  const handler=createOperationsHandler({deploymentConfig:config,env:{VERCEL_GIT_COMMIT_SHA:commit},
    runtimeFactory:()=>({db,verifyLogin:async token=>state.verified && token==='Bearer a.b.c' ? identity : null}),
    log:value=>state.logs.push(JSON.parse(value))});
  return {state,handler};
}
const reply=()=>({code:0,headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(body){this.body=body;return this;}});
async function call(handler,options={}) {
  const response=reply();
  await handler({method:options.method||'GET',url:options.url||'/api/operations',body:options.body,
    headers:{origin:'https://fixture.example','x-requested-with':'vault-ui',cookie:`${ACCESS_COOKIE}=a.b.c`,...options.headers}},response);
  return response;
}

test('operations returns/logs the same scoped DB record and derives identity only from verified login',async()=>{
  const f=fixture();
  const r=await call(f.handler,{headers:{'x-user-id':'another','x-role':'admin','x-device-approved':'true'}});
  assert.equal(r.code,200);assert.deepEqual(r.body,f.state.data);assert.deepEqual(f.state.logs,[r.body]);
  assert.equal(r.headers['X-Request-ID'],r.body.requestId);assert.match(r.headers['Cache-Control'],/no-store/u);
  const args=f.state.calls.find(c=>c.name==='aleph_step12_operations_snapshot').args;
  assert.equal(args.p_user_id,identity.userId);assert.equal(args.p_session_id,identity.sessionId);
  assert.equal(args.p_commit,commit);
  assert.equal(r.body.detection.events,null);assert.equal(r.body.officialTests.passed,null);
  assert.doesNotMatch(JSON.stringify(r.body),/a\.b\.c|session_id|actor_id|title|content|owner_id/u);
});
test('operations rejects anonymous/forged/unapproved/revoked sessions before requesting a snapshot',async()=>{
  const f=fixture();
  assert.equal((await call(f.handler,{headers:{cookie:undefined}})).code,401);
  f.state.verified=false;assert.equal((await call(f.handler)).code,401);f.state.verified=true;
  for(const status of ['unrequested','pending','revoked','expired']) {
    f.state.status=status;const r=await call(f.handler);assert.equal(r.code,403);assert.equal(r.body.error,'DEVICE_APPROVAL_REQUIRED');
  }
  f.state.status='invalid';assert.equal((await call(f.handler)).code,503);
  assert.ok(f.state.calls.every(c=>c.name==='aleph_step11_device_status'));assert.equal(f.state.logs.length,0);
});
test('operations cannot select a different account, source, result or path through request fields',async()=>{
  const f=fixture();
  for(const method of ['POST','PUT','DELETE'])assert.equal((await call(f.handler,{method,body:{passed:41}})).code,405);
  for(const url of ['/api/operations?userId=other','/api/operations?passed=41','/api/operations/approve'])
    assert.equal((await call(f.handler,{url})).code,400);
  assert.equal((await call(f.handler,{headers:{origin:'https://other.example'}})).code,403);
  assert.equal(f.state.calls.length,0);
});
test('missing SQL, unexpected fields, fabricated official passes and invalid backups are not displayed as successful records',async()=>{
  const f=fixture();f.state.error={message:'private diagnostic with secret'};
  assert.deepEqual((await call(f.handler)).body,{error:'OPERATIONS_RECORD_UNAVAILABLE'});
  f.state.error=null;
  for(const alter of [
    v=>{v.title='private memo';},v=>{v.recovery.body='private memo';},v=>{v.revocation.userId='other';},
    v=>{v.officialTests.passed=41;},v=>{v.detection.events=0;},v=>{v.policy.ruleIds.push('invented');},
    v=>{v.checkedAt='invalid';},v=>{v.commit='b'.repeat(40);},
    v=>{v.recovery={state:'available',version:'b'.repeat(64),backedUpAt:v.checkedAt,backupVerified:true,liveMatchesBackup:true,restoreEvents:1,lastRestoredAt:v.checkedAt};},
  ]) {
    f.state.data=record();alter(f.state.data);const r=await call(f.handler);
    assert.equal(r.code,503);assert.deepEqual(r.body,{error:'OPERATIONS_RECORD_UNAVAILABLE'});
  }
  assert.equal(f.state.logs.length,0);
  const valid=record();assert.equal(validOperationsRecord(valid,commit),true);
});

const source=await readFile(new URL('../public/operations-ui.js',import.meta.url),'utf8');
function ui() {
  const controls=new Map();const events={};const calls=[];let observer;
  for(const id of ['operations-panel','memo-panel','operations-refresh','operations-status',
    ...['policy','detection','revocation','recovery','official','reference','record'].map(x=>`operations-${x}`)]) {
    controls.set(`#${id}`,{hidden:true,disabled:false,textContent:'',addEventListener:(name,fn)=>{events[`${id}:${name}`]=fn;}});
  }
  const navigator={onLine:true};
  const fetch=()=>new Promise(resolve=>{calls.push({resolve});});
  vm.runInNewContext(source,{document:{querySelector:id=>controls.get(id)},navigator,
    window:{addEventListener:(name,fn)=>{events[name]=fn;}},
    MutationObserver:class {constructor(fn){observer=fn;}observe(){}},fetch,AbortController,JSON,Object});
  return {controls,events,calls,navigator,change:()=>observer()};
}
const settle=async()=>{await new Promise(resolve=>setImmediate(resolve));};
test('operations UI does not fetch before approval and uses the real response record for cards and proof',async()=>{
  const f=ui();assert.equal(f.calls.length,0);
  f.controls.get('#memo-panel').hidden=false;f.change();assert.equal(f.calls.length,1);
  const data=record();f.calls[0].resolve({ok:true,json:async()=>data});await settle();
  assert.match(f.controls.get('#operations-policy').textContent,/3개 규칙/u);
  assert.match(f.controls.get('#operations-detection').textContent,/미실행/u);
  assert.match(f.controls.get('#operations-official').textContent,/실행 결과 미수신/u);
  assert.deepEqual(JSON.parse(f.controls.get('#operations-record').textContent),data);
  assert.equal(f.controls.get('#operations-panel').hidden,false);
  f.controls.get('#memo-panel').hidden=true;f.change();
  assert.equal(f.controls.get('#operations-panel').hidden,true);assert.equal(f.controls.get('#operations-record').textContent,'');
});
test('operations UI clears on offline/logout and discards a late response from an older login',async()=>{
  const f=ui();f.controls.get('#memo-panel').hidden=false;f.change();
  f.controls.get('#memo-panel').hidden=true;f.change();
  f.calls[0].resolve({ok:true,json:async()=>record()});await settle();
  assert.equal(f.controls.get('#operations-record').textContent,'');
  f.controls.get('#memo-panel').hidden=false;f.change();
  f.calls[1].resolve({ok:true,json:async()=>record()});await settle();
  f.navigator.onLine=false;f.events.offline();
  assert.equal(f.controls.get('#operations-record').textContent,'');assert.equal(f.controls.get('#operations-panel').hidden,true);
  assert.doesNotMatch(source,/localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML/u);
});
