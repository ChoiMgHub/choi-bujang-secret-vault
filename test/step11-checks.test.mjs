import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { checkStep11 } from '../src/step11-checks.mjs';
const config=JSON.parse(await readFile(new URL('../aleph.config.json',import.meta.url),'utf8'));
function fixture({missingManifest=false,deviceLeak=false,approvalAllowed=false,oldStep=false}={}){
  const calls=[];
  const priorCheck=async(c,options)=>{
    assert.equal(options.expectedStep,11);
    return Array.from({length:20},(_,i)=>({attackId:`old_${i}`,passed:!(oldStep&&i===0)}));
  };
  const fetchImpl=async(target,init={})=>{
    const path=new URL(target).pathname;calls.push(path);
    if(path.startsWith('/rest/v1/rpc/')){
      if(approvalAllowed&&path.endsWith('review_device'))return Response.json({status:'approved'});
      return Response.json({code:'42501'},{status:401});
    }
    if(path==='/api/device')return deviceLeak?Response.json({deviceId:'0123456789abcdef'}):Response.json({error:'AUTH_REQUIRED'},{status:401,headers:{'cache-control':'no-store'}});
    if(path==='/app.webmanifest'&&missingManifest)return new Response('missing',{status:404});
    const relative=path==='/'?'index.html':path.slice(1);
    return new Response(await readFile(new URL(`../public/${relative}`,import.meta.url)));
  };
  return {fetchImpl,priorCheck,calls};
}
test('stage 11 checker keeps prior requests and observes only public PWA files and anonymous denials',async()=>{
  const f=fixture();const checks=await checkStep11(config,f);
  assert.equal(checks.length,9);assert.ok(checks.every(c=>c.passed));
  assert.ok(f.calls.includes('/rest/v1/rpc/aleph_step11_review_device'));
  assert.ok(!JSON.stringify(checks).includes('learner-a@'));
});
test('missing deployment, leaked device identity and permissive approval RPC never count as passing',async()=>{
  for(const options of [{missingManifest:true},{deviceLeak:true},{approvalAllowed:true},{oldStep:true}]){
    const checks=await checkStep11(config,fixture(options));assert.ok(checks.some(c=>!c.passed));
  }
});
