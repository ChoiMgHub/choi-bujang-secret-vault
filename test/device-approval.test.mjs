import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { createDeviceHandler } from '../api/device.js';
import { bindDeviceSession, enforceDeviceApproval, readDeviceApproval, sessionDeviceId } from '../src/device-approval.mjs';
import { createResourceHandler } from '../src/resource-api.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';
import { ACCESS_COOKIE } from '../src/browser-session.mjs';

const identity={kind:'student',userId:'10000000-0000-4000-8000-000000000001',sessionId:'20000000-0000-4000-8000-000000000001'};
const deviceId=sessionDeviceId(identity);
const config={step:11,publicAppUrl:'https://fixture.example/'};
const target={noteId:'80000000-0000-4000-8000-000000000010',contentSha256:'a'.repeat(64)};
const origin=new URL(config.publicAppUrl).origin;
const reply=()=>({code:0,headers:{},setHeader(k,v){this.headers[k]=v;},status(v){this.code=v;return this;},json(v){this.body=v;return this;}});
function fixture() {
  const state={status:'unrequested',rpcCalls:[],reads:0,claims:{sub:identity.userId,session_id:identity.sessionId}};
  const db={auth:{getClaims:async()=>({data:{claims:state.claims}})},
    rpc(name,args){state.rpcCalls.push({name,args});return {abortSignal:async()=>({data:{schema:'aleph.device-status.v1',deviceId,status:state.status=(args.p_request&&state.status==='unrequested'?'pending':state.status)}})};},
    from(){state.reads++; return {select(){return this;},eq(){return this;},limit(){return this;},abortSignal:async()=>({data:[]})};}};
  const handler=createDeviceHandler({deploymentConfig:config,runtimeFactory:()=>({db,verifyLogin:async value=>value==='Bearer a.b.c'?{kind:'student',userId:identity.userId}:null})});
  return {state,db,handler};
}
async function call(handler,{method='GET',url='/api/device',body,headers={}}={}) {
  const r=reply(); await handler({method,url,body,headers:{'x-requested-with':'vault-ui',origin,'content-type':'application/json',cookie:`${ACCESS_COOKIE}=a.b.c`,...headers}},r);return r;
}

test('verified session binding ignores browser identity and rejects absent, mismatched or invalid claims',async()=>{
  const f=fixture();
  const base={kind:'student',userId:identity.userId};
  assert.equal(sessionDeviceId(await bindDeviceSession(f.db,base,'Bearer a.b.c')),deviceId);
  for(const claims of [{sub:identity.userId},{sub:identity.userId,session_id:'fake'},{sub:'other',session_id:identity.sessionId}]){
    f.state.claims=claims;assert.equal(await bindDeviceSession(f.db,base,'Bearer a.b.c'),null);
  }
  assert.equal(sessionDeviceId({kind:'judge',userId:identity.userId,sessionId:identity.sessionId}),null);
});
test('status never submits an approval and request only changes unrequested to pending',async()=>{
  const f=fixture(); const initial=await call(f.handler);
  assert.deepEqual(initial.body,{schema:'aleph.device-status.v1',status:'unrequested',deviceId});
  assert.equal(f.state.rpcCalls[0].args.p_request,false);
  for(let i=0;i<2;i++) assert.equal((await call(f.handler,{method:'POST',body:{}})).body.status,'pending');
  assert.ok(f.state.rpcCalls.every(c=>c.name==='aleph_step11_device_status'));
  assert.ok(f.state.rpcCalls.every(c=>c.args.p_user_id===identity.userId&&c.args.p_session_id===identity.sessionId));
  assert.equal(f.state.reads,0);
  assert.doesNotMatch(JSON.stringify(initial.body),/sessionId|session_id|a\.b\.c|userId/u);
  assert.match(initial.headers['Cache-Control'],/no-store/u);
});
test('forged role, installation, approval, device and owner fields cannot change the registered target',async()=>{
  const f=fixture();
  for(const body of [{approved:true},{status:'approved'},{deviceRegistered:true},{role:'admin'},{deviceId},{userId:identity.userId},[],null,'{']){
    assert.equal((await call(f.handler,{method:'POST',body})).code,400);
  }
  assert.equal(f.state.rpcCalls.length,0);
  const r=await call(f.handler,{method:'POST',body:{},headers:{'x-device-approved':'true','x-role':'instructor'}});
  assert.equal(r.body.status,'pending');
  for(const state of ['revoked','expired']){f.state.status=state;assert.equal((await call(f.handler,{method:'POST',body:{}})).body.status,state);}
});
test('device endpoint requires verified login, exact path and same-origin requests',async()=>{
  const f=fixture();
  assert.equal((await call(f.handler,{headers:{origin:'https://other.example'}})).code,403);
  assert.equal((await call(f.handler,{headers:{cookie:undefined}})).code,401);
  assert.equal((await call(f.handler,{headers:{authorization:'Bearer forged'}})).code,401);
  for(const url of ['/api/device?approved=true','/api/device/approve']) assert.equal((await call(f.handler,{url})).code,400);
  assert.equal((await call(f.handler,{method:'PUT'})).code,405);
  assert.equal(f.state.rpcCalls.length,0);
});
test('server approval guard checks every request, fails closed and applies the shared decider device rule',async()=>{
  const f=fixture();
  for(const status of ['unrequested','pending','approved','revoked','expired']){
    f.state.status=status;const r=reply();
    assert.equal(await enforceDeviceApproval({db:f.db,identity,config},r),status==='approved');
    if(status!=='approved')assert.deepEqual(r.body,{error:'DEVICE_APPROVAL_REQUIRED'});
  }
  f.state.status='invented';const r=reply();
  assert.equal(await enforceDeviceApproval({db:f.db,identity,config},r),false);assert.equal(r.code,503);
  const broken={rpc(){throw Error('private diagnostic');}};
  assert.deepEqual(await readDeviceApproval(broken,identity),{status:'unavailable',deviceId:null});
  const decider=await readFile(new URL('../src/decider.mjs',import.meta.url),'utf8');
  assert.match(decider,/permitsRegisteredDevice\(request\?\.deviceRegistered\)/u);
});
test('zone and restoration APIs refuse unapproved direct requests before reading data or restoring anything',async()=>{
  const f=fixture();const runtimeFactory=()=>({db:f.db,verifyLogin:async()=>identity});
  for(const handler of [createResourceHandler({area:'notices',config,runtimeFactory}),createResourceHandler({area:'instructor',config,runtimeFactory}),createResourceHandler({area:'notices',admin:true,config,runtimeFactory}),createRestoreHandler({config,target,runtimeFactory})]){
    const r=await call(handler,{method:'POST',url:'/api/restore',body:{id:target.noteId}});
    assert.equal(r.code,403);assert.deepEqual(r.body,{error:'DEVICE_APPROVAL_REQUIRED'});
  }
  assert.equal(f.state.reads,0);assert.ok(f.state.rpcCalls.every(c=>c.name==='aleph_step11_device_status'));
});
