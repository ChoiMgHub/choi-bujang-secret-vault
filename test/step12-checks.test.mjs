import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep12 } from '../src/step12-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
const config={...JSON.parse(await readFile(new URL('../aleph.config.json',import.meta.url),'utf8')),step:12,expectedCommit:'a'.repeat(40)};
function fixture({leak=false,databaseAllowed=false,missing=false,stale=false}={}){
  const calls=[];
  const fetchImpl=async(target,init={})=>{
    const url=new URL(target),path=url.pathname;
    assert.equal(url.protocol,'https:');
    assert.ok(['GET','HEAD'].includes(init.method||'GET'),'submission attempted a forbidden HTTP method');
    assert.equal(init.body,undefined,'submission attempted a request body');
    calls.push({path,method:init.method||'GET'});
    if(url.origin===new URL(config.originalApiUrl).origin){
      assert.ok(!path.includes('/rpc/'),'submission invoked a DB function');
      assert.ok(!Object.keys(init.headers).some(k=>k.toLowerCase()==='authorization'));
      return databaseAllowed?Response.json([]):Response.json({code:'42501'},{status:401});
    }
    if(path==='/aleph.json')return Response.json({schema:'aleph.defense.deployment.v1',step:stale?11:12,
      commit:config.expectedCommit,repoUrl:config.repoUrl,judgeIssuer:config.judgeIssuer});
    if(path==='/api/auth')return Response.json({user:null},{headers:{'cache-control':'no-store'}});
    if(['/data.json','/vendor/supabase.js'].includes(path))return new Response(null,{status:404});
    if(path==='/api/restore')return Response.json({error:'METHOD_NOT_ALLOWED'},{status:405});
    if(path.startsWith('/api/')){
      if(url.search)return Response.json({error:'INVALID_OPERATIONS_PATH'},{status:400});
      if(leak&&path==='/api/operations-check')return Response.json({error:'AUTH_REQUIRED',rows:[]},{status:401});
      if(missing&&path==='/api/operations-check')return new Response(null,{status:404});
      return Response.json({error:'AUTH_REQUIRED'},{status:401,headers:{'cache-control':'private, no-store'}});
    }
    return new Response(await readFile(new URL(`../public/${path==='/'?'index.html':path.slice(1)}`,import.meta.url)),
      {headers:{'x-content-type-options':'nosniff'}});
  };
  return {fetchImpl,calls};
}
test('step 12 sends only public HTTPS GET/HEAD and leaves all write-dependent groups not_run',async()=>{
  const f=fixture();const checks=await checkStep12(config,f);
  assert.equal(checks.length,19);
  assert.equal(checks.filter(c=>c.passed===true).length,16);
  const notRun=checks.filter(c=>c.observed==='not_run');
  assert.equal(notRun.length,3);assert.ok(notRun.every(c=>c.passed===null));
  assert.equal(f.calls.length,27);
  assert.ok(!f.calls.some(c=>c.path.includes('/rpc/')||c.path==='/api/operations-rule'||c.path==='/api/admin/notices'));
});
test('missing API, leaked error payload, permissive original DB and stale identity fail read-only checks',async()=>{
  for(const options of [{missing:true},{leak:true},{databaseAllowed:true},{stale:true}]){
    const checks=await checkStep12(config,fixture(options));
    assert.ok(checks.some(c=>c.observed!=='not_run'&&!c.passed));
  }
});
test('step 12 rejects non-public or mismatched origins before sending a request',async()=>{
  for(const values of [{publicAppUrl:'http://localhost/'},{publicAppUrl:'https://127.0.0.1/'},
    {originalApiUrl:'https://other.supabase.co/rest/v1/vault_notes'}]){
    const f=fixture();await assert.rejects(checkStep12({...config,...values},f),/HTTPS/u);
    assert.equal(f.calls.length,0);
  }
});
test('step 12 submission preserves exact not_run observations without treating them as passes',async()=>{
  const original=globalThis.fetch;
  try{
    const f=fixture();globalThis.fetch=f.fetchImpl;
    const attempts=await runAttackChecks(config);
    assert.equal(attempts.length,19);
    assert.ok(attempts.every(c=>Object.keys(c).sort().join(',')==='attackId,expected,observed'));
    assert.equal(attempts.filter(c=>c.observed==='not_run').length,3);
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


test('actual step 12 module imports with only its public-key constant and no legacy runner',async()=>{
  const {mkdtemp,writeFile,rm}=await import('node:fs/promises');
  const {tmpdir}=await import('node:os');
  const {join}=await import('node:path');
  const {pathToFileURL}=await import('node:url');
  const directory=await mkdtemp(join(tmpdir(),'aleph-step12-readonly-'));
  try{
    for(const name of ['step12-checks.mjs','supabase-public.mjs'])
      await writeFile(join(directory,name),await readFile(new URL(`../src/${name}`,import.meta.url)));
    const module=await import(pathToFileURL(join(directory,'step12-checks.mjs')).href);
    const checks=await module.checkStep12(config,fixture());
    assert.equal(checks.filter(c=>c.observed==='not_run').length,3);
    assert.ok(checks.every(c=>c.observed==='not_run'||c.passed));
  }finally{await rm(directory,{recursive:true,force:true});}
});
