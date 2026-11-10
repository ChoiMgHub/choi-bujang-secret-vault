import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep12 } from '../src/step12-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
const config={...JSON.parse(await readFile(new URL('../aleph.config.json',import.meta.url),'utf8')),step:12,expectedCommit:'a'.repeat(40)};
function fixture({leak=false,rpcAllowed=false,missing=false,stale=false}={}){
  const calls=[];
  const priorCheck=async(c,o)=>{assert.equal(o.expectedStep,12);return Array.from({length:9},()=>({passed:true}));};
  const fetchImpl=async(target,init={})=>{
    const url=new URL(target),path=url.pathname;calls.push(path);
    if(url.origin===new URL(config.originalApiUrl).origin){
      assert.ok(!Object.keys(init.headers).some(k=>k.toLowerCase()==='authorization'));
      return rpcAllowed?Response.json({rows:[]}):Response.json({code:'42501'},{status:401});
    }
    if(path==='/aleph.json')return Response.json({schema:'aleph.defense.deployment.v1',step:stale?11:12,
      commit:config.expectedCommit,repoUrl:config.repoUrl,judgeIssuer:config.judgeIssuer});
    if(path==='/api/auth'){
      if(init.method==='POST'){
        const same=init.headers.origin===new URL(config.publicAppUrl).origin;
        return Response.json({error:same?'INVALID_INPUT':'ORIGIN_NOT_ALLOWED'},{status:same?400:403});
      }
      return Response.json({user:null},{headers:{'cache-control':'no-store'}});
    }
    if(['/data.json','/vendor/supabase.js'].includes(path))return new Response(null,{status:404});
    if(path.startsWith('/api/')){
      if(url.search)return Response.json({error:'INVALID_OPERATIONS_PATH'},{status:400});
      if(leak&&path==='/api/operations-check')return Response.json({rows:[]});
      if(missing&&path==='/api/operations-rule')return new Response(null,{status:404});
      return Response.json({error:'AUTH_REQUIRED'},{status:401,headers:{'cache-control':'private, no-store'}});
    }
    return new Response(await readFile(new URL(`../public/${path==='/'?'index.html':path.slice(1)}`,import.meta.url)),
      {headers:{'x-content-type-options':'nosniff'}});
  };
  return {fetchImpl,priorCheck,calls};
}
test('step 12 measures public assets and anonymous denials without fabricating authenticated passes',async()=>{
  const f=fixture();const checks=await checkStep12(config,f);
  assert.equal(checks.length,10);assert.ok(checks.every(c=>c.passed));
  assert.ok(f.calls.includes('/rest/v1/rpc/aleph_step12_verification'));
});
test('missing route, successful anonymous read and permissive DB RPC fail the self-check',async()=>{
  for(const options of [{missing:true},{leak:true},{rpcAllowed:true}]){
    assert.ok((await checkStep12(config,fixture(options))).some(c=>!c.passed));
  }
});
test('step 12 runs the entire prior chain and rejects a stale deployment identity',async()=>{
  for(const stale of [false,true]){
    const f=fixture({stale});const checks=await checkStep12(config,{fetchImpl:f.fetchImpl});
    assert.equal(checks.every(c=>c.passed),!stale);
    for(const path of ['/api/auth','/api/restore','/rest/v1/rpc/aleph_step10_restore_note',
      '/rest/v1/rpc/aleph_step11_review_device'])assert.ok(f.calls.includes(path));
  }
});
test('step 12 bundle returns only observed redacted fields and refuses a failed check',async()=>{
  const original=globalThis.fetch;
  try{
    globalThis.fetch=fixture().fetchImpl;
    const attempts=await runAttackChecks(config);
    assert.equal(attempts.length,10);
    assert.ok(attempts.every(c=>Object.keys(c).sort().join(',')==='attackId,expected,observed'));
    assert.ok(!JSON.stringify(attempts).includes('learner-a@'));
    globalThis.fetch=fixture({leak:true}).fetchImpl;
    await assert.rejects(runAttackChecks(config),/12단계 점검 실패/u);
  }finally{globalThis.fetch=original;}
});

test('submission entry imports and runs step 12 while unrelated stage modules are unavailable',async()=>{
  const {mkdtemp,writeFile,rm}=await import('node:fs/promises');
  const {tmpdir}=await import('node:os');
  const {join}=await import('node:path');
  const {spawnSync}=await import('node:child_process');
  const {pathToFileURL}=await import('node:url');
  const directory=await mkdtemp(join(tmpdir(),'aleph-step12-import-'));
  try{
    await writeFile(join(directory,'attack-check.mjs'),await readFile(new URL('../src/attack-check.mjs',import.meta.url)));
    // Only the selected checker exists in this fixture. An unused older module
    // must not prevent entry import or dispatch. Actual checks are tested above.
    await writeFile(join(directory,'step12-checks.mjs'),
      `export async function checkStep12(){return [{attackId:'isolated_fixture',expected:'fixture',observed:'fixture',passed:true}];}`);
    const entry=pathToFileURL(join(directory,'attack-check.mjs')).href;
    const script=`import assert from 'node:assert/strict';
      const {runAttackChecks}=await import(${JSON.stringify(entry)});
      const result=await runAttackChecks({step:12});
      assert.deepEqual(result,[{attackId:'isolated_fixture',expected:'fixture',observed:'fixture'}]);
      await assert.rejects(runAttackChecks({step:2}),{code:'ERR_MODULE_NOT_FOUND'});
      console.log('isolated_stage_import_ok');`;
    const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});
    assert.equal(child.status,0,child.stderr);
    assert.match(child.stdout,/isolated_stage_import_ok/u);
  }finally{await rm(directory,{recursive:true,force:true});}
});
