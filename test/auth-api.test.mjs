import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createNotesHandler } from '../api/notes.js';
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet } from 'jose';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const pair = await generateKeyPair('ES256');
const jwk = { ...await exportJWK(pair.publicKey), kid: 'local-unit-test', alg: 'ES256', use: 'sig' };
const attacker = await generateKeyPair('ES256');
const judgePair = await generateKeyPair('ES256');
const judgeJwk = { ...await exportJWK(judgePair.publicKey), kid: 'local-judge-test', alg: 'ES256' };
const judgeKeySet = createLocalJWKSet({ keys: [judgeJwk] });
const fakeKey = ['sb', 'secret', 'localtest'].join('_');
const env = { SUPABASE_URL: config.identityProvider.issuer.replace('/auth/v1', ''), SUPABASE_SECRET_KEY: fakeKey };
const userId = '10000000-0000-4000-8000-000000000001';
const rows = Array.from({ length: 4 }, (_, i) => ({ id: String(i), title: `가상 ${i}`, content: `연습 ${i}`, owner_id: 'not-returned' }));
const token = async (changes = {}, key = pair.privateKey) => new SignJWT({ role: 'authenticated', ...changes })
  .setProtectedHeader({ alg: 'ES256', kid: jwk.kid }).setIssuer(changes.iss ?? config.identityProvider.issuer)
  .setSubject(changes.sub ?? userId).setAudience(changes.aud ?? 'authenticated')
  .setIssuedAt().setExpirationTime(changes.exp ?? Math.floor(Date.now() / 1000) + 600).sign(key);
function response() { return { code: 0, headers: {}, body: null,
  setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } }; }
function fixture({ envOverride = env, records = rows, upstreamStatus = 200 } = {}) {
  let recordCalls = 0; const targets = [];
  const handler = createNotesHandler({ env: envOverride, judgeKeySet, fetchImpl: async (url, init) => {
    const target = new URL(url); targets.push(target.pathname);
    if (target.pathname.endsWith('/.well-known/jwks.json')) return Response.json({ keys: [jwk] });
    recordCalls++;
    assert.equal(target.origin, env.SUPABASE_URL);
    assert.equal(target.pathname, '/rest/v1/vault_notes');
    assert.equal(target.searchParams.get('select'), 'id,title,content');
    assert.equal(target.searchParams.get('order'), 'id.asc');
    assert.equal(new Headers(init.headers).get('apikey'), fakeKey);
    return Response.json(records, { status: upstreamStatus });
  } });
  return { handler, get recordCalls() { return recordCalls; }, targets };
}

test('missing token and browser identity spoofing get 401 JSON without any DB query', async () => {
  const f = fixture();
  for (const request of [{ method: 'GET' }, { method: 'GET', headers: { 'x-user-id': userId, role: 'authenticated' }, query: { userId }, body: { userId, role: 'admin' } }]) {
    const res = response(); await f.handler(request, res);
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'AUTH_REQUIRED' });
    assert.equal(res.headers['cache-control'], 'no-store');
  }
  assert.equal(f.recordCalls, 0); assert.equal(f.targets.length, 0);
});

test('unchanged starter verifier and real SDK verify student ES256 signature before DB read', async () => {
  const f = fixture(); const res = response();
  await f.handler({ method: 'GET', headers: { authorization: `Bearer ${await token()}`, 'x-user-id': 'spoofed' }, query: { owner_id: 'spoofed', table: 'users' } }, res);
  assert.equal(res.code, 200); assert.equal(f.recordCalls, 1);
  assert.deepEqual(res.body.notes, rows.map(({ id, title, content }) => ({ id, title, content })));
  assert.ok(!JSON.stringify(res.body).includes(fakeKey));
});

test('malformed, forged, expired, wrong-issuer/audience/role and invalid-user tokens deny without reading notes', async () => {
  const f = fixture();
  const bad = ['not-a-token', await token({}, attacker.privateKey), await token({ exp: Math.floor(Date.now() / 1000) - 10 }),
    await token({ iss: 'https://other-project.supabase.co/auth/v1' }), await token({ aud: 'other-app' }),
    await token({ role: 'service_role' }), await token({ sub: 'not-a-user' })];
  for (const value of bad) {
    const res = response(); await f.handler({ method: 'GET', headers: { authorization: `Bearer ${value}` } }, res);
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'AUTH_REQUIRED' });
  }
  assert.equal(f.recordCalls, 0);
});

test('starter judge token path verifies trusted signature and claims without changing the helper', async () => {
  const judge = await new SignJWT({ aleph_run: '20000000-0000-4000-8000-000000000002', aleph_role: 'judge', aleph_identity: 'a' })
    .setProtectedHeader({ alg: 'ES256', kid: judgeJwk.kid }).setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname).setSubject(userId)
    .setIssuedAt().setExpirationTime('10m').sign(judgePair.privateKey);
  const f = fixture(); const res = response();
  await f.handler({ method: 'GET', headers: { authorization: `Bearer ${judge}` } }, res);
  assert.equal(res.code, 200); assert.equal(f.recordCalls, 1);
  const hash = createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${(await readFile(new URL('../src/verify-login.mjs', import.meta.url))).length}\0`), await readFile(new URL('../src/verify-login.mjs', import.meta.url))])).digest('hex');
  assert.equal(hash, '784ec5af7067e01c6b7f83cf423db0b8c63d9e09');
});

test('missing server config and upstream errors return no secret; unimplemented write methods remain 405', async () => {
  const auth = `Bearer ${await token()}`;
  for (const invalid of [{}, { ...env, SUPABASE_SECRET_KEY: 'publishable' }, { ...env, SUPABASE_URL: 'https://other.supabase.co' }]) {
    const f = fixture({ envOverride: invalid }); const res = response();
    await f.handler({ method: 'GET', headers: { authorization: auth } }, res);
    assert.equal(res.code, 503); assert.equal(f.recordCalls, 0);
    assert.ok(!JSON.stringify(res.body).includes(fakeKey));
  }
  for (const options of [{ records: { message: fakeKey }, upstreamStatus: 403 }, { records: [{ title: 'bad' }] }]) {
    const f = fixture(options); const res = response();
    await f.handler({ method: 'GET', headers: { authorization: auth } }, res);
    assert.equal(res.code, 502); assert.deepEqual(res.body, { error: 'NOTES_UNAVAILABLE' });
  }
  for (const method of ['POST', 'PUT', 'DELETE']) {
    const f = fixture(); const res = response(); await f.handler({ method, headers: { authorization: auth } }, res);
    assert.equal(res.code, 405); assert.equal(f.recordCalls, 0);
  }
});
