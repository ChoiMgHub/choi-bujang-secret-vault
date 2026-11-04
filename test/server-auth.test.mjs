import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, mkdtemp, cp, writeFile, access, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignJWT } from 'jose';
import { createAuthHandler } from '../api/auth.js';
import { ACCESS_COOKIE, REFRESH_COOKIE, browserCookies, trustedBrowserRequest,
  cookieAuthorization, usesCookieAuthorization } from '../src/browser-session.mjs';
import { SUPABASE_PUBLIC_KEY } from '../src/supabase-public.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const origin = new URL(config.publicAppUrl).origin;
const supabase = new URL(config.identityProvider.issuer).origin;
const env = { SUPABASE_URL: supabase };
const user = { id: '10000000-0000-4000-8000-000000000001', email: 'learner-a@example.com' };
const key = new TextEncoder().encode('isolated-test-signing-key-only-32-bytes');
const expires = Math.floor(Date.now() / 1000) + 3600;
const token = await new SignJWT({ role: 'authenticated' }).setProtectedHeader({ alg: 'HS256' })
  .setIssuer(config.identityProvider.issuer).setAudience('authenticated').setSubject(user.id)
  .setExpirationTime(expires).sign(key);
const session = { user, access_token: token, refresh_token: 'fixture-refresh', expires_at: expires, expires_in: 3600, token_type: 'bearer' };

function reply() {
  return { code: 200, headers: {}, setHeader(k,v) { this.headers[k.toLowerCase()] = v; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
}
function request(method = 'GET', extras = {}) {
  return { method, url: '/api/auth', ...extras, headers: {
    'x-requested-with': 'vault-ui', origin, 'content-type': 'application/json', ...(extras.headers || {}),
  } };
}
async function call(handler, req) { const r = reply(); await handler(req,r); return r; }
const cookieHeader = r => r.headers['set-cookie'].map(value => value.split(';')[0]).join('; ');

function stub(overrides = {}) {
  const calls = [];
  const factory = (_url, appKey, options) => {
    assert.equal(appKey, SUPABASE_PUBLIC_KEY);
    assert.equal(options.auth.persistSession, false); assert.equal(options.auth.autoRefreshToken, false);
    return { auth: {
      async signInWithPassword(input) { calls.push(['login',input]); return overrides.login || { data: { session }, error: null }; },
      async getUser(access) { calls.push(['user',access]); return overrides.user || { data: { user }, error: null }; },
      async refreshSession(input) { calls.push(['refresh',input]); return overrides.refresh || { data: { session }, error: null }; },
      admin: { async signOut(access,scope) { calls.push(['logout',access,scope]); return overrides.logout || { error: null }; } },
    } };
  };
  return { handler: createAuthHandler({ env, clientFactory: factory }), calls };
}

test('Auth response exposes metadata only and sets two bounded Secure HttpOnly SameSite cookies', async () => {
  const { handler, calls } = stub();
  const r = await call(handler, request('POST', { body: { email: ' learner-a@example.com ', password: 'fixture-input' } }));
  assert.equal(r.code,200); assert.deepEqual(r.body,{ user, expiresAt:expires });
  assert.equal(calls[0][1].email,user.email);
  assert.ok(!JSON.stringify(r.body).includes(token));
  assert.ok(!JSON.stringify(r.body).includes('fixture-refresh'));
  assert.ok(!JSON.stringify(r.body).includes(SUPABASE_PUBLIC_KEY));
  assert.match(r.headers['cache-control'],/no-store/u);
  for (const value of r.headers['set-cookie']) {
    assert.match(value,/^__Host-/u); assert.match(value,/; Path=\//u);
    assert.match(value,/; HttpOnly; Secure; SameSite=Strict; Max-Age=/u);
    assert.doesNotMatch(value,/Domain=/u); assert.ok(value.length<4096);
  }
  const restored = await call(handler, request('GET', { headers: { cookie:cookieHeader(r) } }));
  assert.deepEqual(restored.body,{ user, expiresAt:expires });
  assert.ok(calls.some(c=>c[0]==='user'&&c[1]===token));
});

test('Auth rejects cross-site, missing markers, malformed/oversized input before authenticating', async () => {
  const { handler,calls } = stub();
  for (const headers of [{ origin:'https://other.example' }, { origin:undefined },
    { 'x-requested-with':undefined }, { 'sec-fetch-site':'cross-site' }]) {
    const r=await call(handler,request('POST',{body:{email:user.email,password:'x'},headers}));
    assert.equal(r.code,403);
  }
  for (const body of [undefined,'{bad',{},[],{email:user.email,password:''},
    {email:user.email,password:'x',role:'admin'}]) {
    assert.equal((await call(handler,request('POST',{body}))).code,400);
  }
  assert.equal((await call(handler,request('POST',{body:'x'.repeat(9000)}))).code,413);
  assert.equal((await call(handler,request('POST',{body:{},headers:{'content-type':'text/plain'}}))).code,415);
  assert.equal((await call(handler,request('OPTIONS'))).code,405);
  assert.equal(calls.length,0);
});

test('Auth errors are fixed JSON codes and do not echo upstream credentials or diagnostics', async () => {
  const broken = createAuthHandler({ env, clientFactory: () => { throw new Error('private-diagnostic'); } });
  assert.deepEqual((await call(broken, request())).body, { error: 'AUTH_UNAVAILABLE' });
  for (const [error,status,code] of [
    [{status:400,code:'invalid_credentials',message:token},401,'INVALID_CREDENTIALS'],
    [{status:403,code:'email_not_confirmed'},403,'EMAIL_NOT_CONFIRMED'],
    [{status:429},429,'TOO_MANY_REQUESTS'], [{status:503,message:'private-diagnostic'},503,'AUTH_UNAVAILABLE'],
  ]) {
    const {handler}=stub({login:{data:null,error}});
    const r=await call(handler,request('POST',{body:{email:user.email,password:'fixture-input'}}));
    assert.equal(r.code,status); assert.deepEqual(r.body,{error:code}); assert.equal(r.headers['set-cookie'],undefined);
  }
});

test('session restoration verifies access with Auth, refreshes on server and clears invalid sessions', async () => {
  const valid=stub(); const anonymous=await call(valid.handler,request());
  assert.deepEqual(anonymous.body,{user:null}); assert.equal(valid.calls.length,0);
  const denied={data:{user:null},error:{status:401}};
  const refreshing=stub({user:denied});
  const refreshed=await call(refreshing.handler,request('GET',{headers:{cookie:`${ACCESS_COOKIE}=${token}; ${REFRESH_COOKIE}=fixture-refresh`}}));
  assert.equal(refreshed.code,200); assert.equal(refreshed.body.user.id,user.id);
  assert.ok(refreshing.calls.some(c=>c[0]==='refresh'));
  assert.equal(refreshed.headers['set-cookie'].length,2);
  const invalid=stub({user:denied,refresh:{data:null,error:{status:400}}});
  const r=await call(invalid.handler,request('GET',{headers:{cookie:`${ACCESS_COOKIE}=${token}; ${REFRESH_COOKIE}=invalid-refresh`}}));
  assert.deepEqual(r.body,{user:null}); assert.ok(r.headers['set-cookie'].every(v=>v.endsWith('Max-Age=0')));
  const unavailable=stub({user:{data:null,error:{status:503}}});
  const fail=await call(unavailable.handler,request('GET',{headers:{cookie:`${ACCESS_COOKIE}=${token}`}}));
  assert.equal(fail.code,503); assert.equal(fail.headers['set-cookie'],undefined);
});

test('logout revokes only current Supabase session then clears both cookies; failures stay failures', async () => {
  const good=stub(); const req=request('DELETE',{headers:{cookie:`${ACCESS_COOKIE}=${token}; ${REFRESH_COOKIE}=fixture-refresh`}});
  const r=await call(good.handler,req);
  assert.equal(r.code,200); assert.deepEqual(r.body,{user:null});
  assert.ok(good.calls.some(c=>c[0]==='logout'&&c[1]===token&&c[2]==='local'));
  assert.ok(r.headers['set-cookie'].every(v=>v.endsWith('Max-Age=0')));
  const bad=stub({logout:{error:{status:503}}});
  const failed=await call(bad.handler,req); assert.equal(failed.code,503); assert.equal(failed.headers['set-cookie'],undefined);
});

test('real official SDK performs password login, getUser, refresh and local logout only in server', async () => {
  const observed=[];
  const handler=createAuthHandler({env,fetchImpl:async(target,init)=>{
    const url=new URL(target); const headers=new Headers(init.headers);
    assert.equal(url.origin,supabase); assert.equal(headers.get('apikey'),SUPABASE_PUBLIC_KEY);
    observed.push(url.pathname+url.search);
    if(url.pathname==='/auth/v1/token') {
      const body=JSON.parse(init.body);
      if(url.searchParams.get('grant_type')==='password') {
        assert.equal(body.email,user.email); assert.equal(body.password,'fixture-input');
      } else { assert.equal(url.searchParams.get('grant_type'),'refresh_token'); assert.equal(body.refresh_token,'fixture-refresh'); }
      return Response.json(session);
    }
    assert.equal(headers.get('authorization'),`Bearer ${token}`);
    if(url.pathname==='/auth/v1/user') return Response.json(user);
    assert.equal(url.pathname,'/auth/v1/logout'); assert.equal(url.searchParams.get('scope'),'local');
    return new Response(null,{status:204});
  }});
  const login=await call(handler,request('POST',{body:{email:user.email,password:'fixture-input'}}));
  assert.equal(login.code,200); assert.ok(!JSON.stringify(login.body).includes(token));
  const get=await call(handler,request('GET',{headers:{cookie:cookieHeader(login)}})); assert.equal(get.code,200);
  const refresh=await call(handler,request('GET',{headers:{cookie:`${REFRESH_COOKIE}=fixture-refresh`}})); assert.equal(refresh.code,200);
  const logout=await call(handler,request('DELETE',{headers:{cookie:cookieHeader(refresh)}})); assert.equal(logout.code,200);
  assert.ok(observed.includes('/auth/v1/token?grant_type=password'));
  assert.ok(observed.includes('/auth/v1/token?grant_type=refresh_token'));
  assert.ok(observed.includes('/auth/v1/user')); assert.ok(observed.includes('/auth/v1/logout?scope=local'));
});

test('cookie parsing rejects duplicates and bearer precedence never accepts client identity metadata', async () => {
  assert.deepEqual(browserCookies({headers:{cookie:`${ACCESS_COOKIE}=x.y.z; ${ACCESS_COOKIE}=a.b.c`}}),{});
  assert.deepEqual(browserCookies({headers:{cookie:`${ACCESS_COOKIE}=%invalid`}}),{});
  assert.equal(cookieAuthorization({headers:{cookie:`${ACCESS_COOKIE}=x.y.z`}}),'Bearer x.y.z');
  const both={headers:{cookie:`${ACCESS_COOKIE}=x.y.z`,authorization:'Bearer wrong'}};
  assert.equal(cookieAuthorization(both),'Bearer wrong'); assert.equal(usesCookieAuthorization(both),false);
  assert.equal(trustedBrowserRequest(request('POST',{headers:{origin:'https://other.example'}}),config),false);
});

test('stage 5 build removes cached browser SDK and rejects keys left in public assets', async () => {
  const root=await mkdtemp(join(tmpdir(),'vault-auth-build-'));
  try {
    await cp(new URL('../scripts/',import.meta.url),join(root,'scripts'),{recursive:true});
    await cp(new URL('../public/',import.meta.url),join(root,'public'),{recursive:true});
    await writeFile(join(root,'aleph.config.json'),JSON.stringify(config));
    execFileSync(process.execPath,['scripts/build-public.mjs','--local'],{cwd:root});
    await assert.rejects(access(join(root,'public/vendor')));
    await writeFile(join(root,'public/leak.js'),`const key=${JSON.stringify(SUPABASE_PUBLIC_KEY)};`);
    assert.throws(()=>execFileSync(process.execPath,['scripts/build-public.mjs','--local'],{cwd:root,stdio:'pipe'}),/브라우저 배포 파일/u);
  } finally {await rm(root,{recursive:true,force:true});}
});
