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
const otherId = '10000000-0000-4000-8000-000000000002';
const rows = Array.from({ length: 4 }, (_, i) => ({ id: `20000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
  title: `가상 ${i}`, content: `연습 ${i}`, owner_id: i < 2 ? userId : i === 2 ? otherId : null,
  created_at: '2026-10-29T00:00:00Z' }));
const safe = ({ id, title, content }) => ({ id, title, body: content });
const token = async (changes = {}, key = pair.privateKey) => new SignJWT({ role: 'authenticated', ...changes })
  .setProtectedHeader({ alg: 'ES256', kid: jwk.kid }).setIssuer(changes.iss ?? config.identityProvider.issuer)
  .setSubject(changes.sub ?? userId).setAudience(changes.aud ?? 'authenticated')
  .setIssuedAt().setExpirationTime(changes.exp ?? Math.floor(Date.now() / 1000) + 600).sign(key);
function response() { return { code: 0, headers: {}, body: null,
  setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } }; }
function fixture({ envOverride = env, upstreamError = false, malformed = false,
  unexpectedOwner = false, transferBeforeWrite } = {}) {
  let recordCalls = 0; const targets = []; const records = new Map(rows.map(row => [row.id, { ...row }]));
  const handler = createNotesHandler({ env: envOverride, judgeKeySet, fetchImpl: async (url, init) => {
    const target = new URL(url); targets.push(target.pathname);
    if (target.pathname.endsWith('/.well-known/jwks.json')) return Response.json({ keys: [jwk] });
    recordCalls++;
    assert.equal(target.origin, env.SUPABASE_URL);
    assert.equal(target.pathname, '/rest/v1/vault_notes');
    assert.equal(new Headers(init.headers).get('apikey'), fakeKey);
    if (upstreamError) return Response.json({ message: fakeKey, code: '42501' }, { status: 403 });
    if (malformed) return Response.json([{ title: 'bad' }]);
    if (unexpectedOwner) return Response.json([rows[2]]);
    const method = init.method || 'GET';
    if (transferBeforeWrite && ['PATCH', 'DELETE'].includes(method)) {
      records.get(rows[0].id).owner_id = transferBeforeWrite;
    }
    const matches = row => ['id', 'owner_id'].every(field => {
      const filter = target.searchParams.get(field); return !filter || `eq.${row[field]}` === filter;
    });
    let result = [...records.values()].filter(matches);
    if (method === 'POST') {
      const value = JSON.parse(init.body);
      if (records.has(value.id)) return Response.json({ code: '23505', message: fakeKey }, { status: 409 });
      const row = { ...value, created_at: '2026-10-29T01:00:00Z' }; records.set(row.id, row); result = [row];
    } else if (method === 'PATCH') {
      const value = JSON.parse(init.body); result = result.map(row => ({ ...row, ...value }));
      for (const row of result) records.set(row.id, row);
    } else if (method === 'DELETE') {
      for (const row of result) records.delete(row.id);
    }
    if (target.searchParams.get('limit')) result = result.slice(0, Number(target.searchParams.get('limit')));
    const columns = target.searchParams.get('select')?.split(',');
    if (columns) result = result.map(row => Object.fromEntries(columns.map(column => [column, row[column]])));
    return Response.json(result, { status: method === 'POST' ? 201 : 200 });
  } });
  return { handler, records, get recordCalls() { return recordCalls; }, targets };
}
async function call(f, authorization, method = 'GET', url = '/api/notes', body, extras = {}) {
  const res = response();
  await f.handler({ method, url, body, headers: authorization ? { authorization, ...extras } : extras }, res);
  return res;
}

test('all list and single-note methods require login; browser identity spoofing cannot bypass 401', async () => {
  const f = fixture();
  for (const [method, path] of [['GET', '/api/notes'], ['POST', '/api/notes'], ['GET', `/api/notes/${rows[0].id}`], ['PUT', `/api/notes/${rows[0].id}`], ['DELETE', `/api/notes/${rows[0].id}`]]) {
    const res = await call(f, null, method, path, { userId, role: 'admin' }, { 'x-user-id': userId, role: 'authenticated' });
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'AUTH_REQUIRED' });
    assert.equal(res.headers['cache-control'], 'no-store');
  }
  assert.equal(f.recordCalls, 0); assert.equal(f.targets.length, 0);
});

test('unchanged verifier and SDK verify the signature; list returns only verified user records as id/title/body', async () => {
  const f = fixture();
  const res = await call(f, `Bearer ${await token()}`, 'GET', `/api/notes?owner_id=${otherId}&userId=${otherId}`, undefined, { 'x-user-id': otherId });
  assert.equal(res.code, 200); assert.equal(f.recordCalls, 1);
  assert.deepEqual(res.body, rows.filter(row => row.owner_id === userId).map(safe));
  assert.ok(!JSON.stringify(res.body).includes(fakeKey));
});

test('malformed, forged, expired, wrong-issuer/audience/role and invalid-user tokens cannot read notes', async () => {
  const f = fixture();
  const bad = ['not-a-token', await token({}, attacker.privateKey), await token({ exp: Math.floor(Date.now() / 1000) - 10 }),
    await token({ iss: 'https://other-project.supabase.co/auth/v1' }), await token({ aud: 'other-app' }),
    await token({ role: 'service_role' }), await token({ sub: 'not-a-user' })];
  for (const value of bad) {
    const res = await call(f, `Bearer ${value}`);
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'AUTH_REQUIRED' });
  }
  assert.equal(f.recordCalls, 0);
});

test('starter judge path keeps signature/claim verification and the helper remains byte-identical', async () => {
  const judge = await new SignJWT({ aleph_run: '20000000-0000-4000-8000-000000000002', aleph_role: 'judge', aleph_identity: 'a' })
    .setProtectedHeader({ alg: 'ES256', kid: judgeJwk.kid }).setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname).setSubject(userId)
    .setIssuedAt().setExpirationTime('10m').sign(judgePair.privateKey);
  const f = fixture(); assert.equal((await call(f, `Bearer ${judge}`)).code, 200);
  const helper = await readFile(new URL('../src/verify-login.mjs', import.meta.url));
  const hash = createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${helper.length}\0`), helper])).digest('hex');
  assert.equal(hash, '784ec5af7067e01c6b7f83cf423db0b8c63d9e09');
});

test('CRUD supports generated/supplied UUIDs, server-owned creation, safe update, deletion and subsequent 404', async () => {
  const f = fixture(); const auth = `Bearer ${await token()}`;
  const created = await call(f, auth, 'POST', '/api/notes', { title: '새 연습', body: '가상 내용', owner_id: otherId, userId: otherId, role: 'admin' });
  assert.equal(created.code, 201); assert.deepEqual(Object.keys(created.body), ['id']);
  const id = created.body.id; assert.match(id, /^[a-f0-9-]{36}$/u);
  assert.equal(f.records.get(id).owner_id, userId);
  assert.deepEqual((await call(f, auth, 'GET', `/api/notes/${id}`)).body, { id, title: '새 연습', body: '가상 내용' });
  const updated = await call(f, auth, 'PUT', `/api/notes/${id}`, { title: '수정 연습', body: '<script>text only</script>' });
  assert.equal(updated.code, 200); assert.equal(updated.body.body, '<script>text only</script>');
  assert.equal(f.records.get(id).owner_id, userId);
  assert.equal((await call(f, auth, 'DELETE', `/api/notes/${id}`)).code, 200);
  assert.equal((await call(f, auth, 'GET', `/api/notes/${id}`)).code, 404);
  assert.equal((await call(f, auth, 'DELETE', `/api/notes/${id}`)).code, 404);
  const supplied = '30000000-0000-4000-8000-000000000003';
  assert.equal((await call(f, auth, 'POST', '/api/notes', { id: supplied, title: '지정 번호', body: '' })).body.id, supplied);
  const duplicate = await call(f, auth, 'POST', '/api/notes', { id: supplied, title: '덮어쓰기 금지', body: '' });
  assert.equal(duplicate.code, 409); assert.equal(f.records.get(supplied).title, '지정 번호');
  assert.equal(f.records.get(rows[3].id).owner_id, null);
});

test('invalid JSON/fields, oversized bodies, invalid UUIDs and mismatched update IDs do not write', async () => {
  const f = fixture(); const auth = `Bearer ${await token()}`;
  for (const input of ['{bad', [], { title: ' ', body: '' }, { title: 'a', body: 3 }, { title: 'a', body: '', id: 'bad' }]) {
    assert.equal((await call(f, auth, 'POST', '/api/notes', input)).code, 400);
  }
  assert.equal((await call(f, auth, 'POST', '/api/notes', 'x'.repeat(70000))).code, 413);
  assert.equal((await call(f, auth, 'GET', '/api/notes/not-a-uuid')).code, 400);
  assert.equal((await call(f, auth, 'PUT', `/api/notes/${rows[0].id}`, { id: rows[1].id, title: 'a', body: '' })).code, 400);
  assert.equal(f.recordCalls, 0);
  assert.equal((await call(f, auth, 'DELETE', '/api/notes')).code, 405);
  assert.equal((await call(f, auth, 'POST', `/api/notes/${rows[0].id}`, { title: 'a', body: '' })).code, 405);
});

test('stage 4: A and B each keep own CRUD; client owner/user/role cannot choose the inserted owner', async () => {
  const f = fixture();
  for (const [owner, other] of [[userId, otherId], [otherId, userId]]) {
    const auth = `Bearer ${await token({ sub: owner })}`;
    assert.deepEqual((await call(f, auth)).body, rows.filter(row => row.owner_id === owner).map(safe));
    const created = await call(f, auth, 'POST', `/api/notes?owner_id=${other}`, {
      title: '가상 작성', body: '가상 내용', owner_id: other, userId: other, role: 'admin',
    }, { 'x-user-id': other });
    assert.equal(created.code, 201);
    const id = created.body.id;
    assert.equal(f.records.get(id).owner_id, owner);
    const one = await call(f, auth, 'GET', `/api/notes/${id}`);
    assert.equal(one.code, 200); assert.deepEqual(Object.keys(one.body).sort(), ['body', 'id', 'title']);
    const updated = await call(f, auth, 'PUT', `/api/notes/${id}`, { title: '수정', body: '수정 내용' });
    assert.equal(updated.code, 200); assert.equal(updated.body.body, '수정 내용');
    assert.equal(f.records.get(id).owner_id, owner);
    assert.equal((await call(f, auth, 'DELETE', `/api/notes/${id}`)).code, 200);
    assert.equal((await call(f, auth, 'GET', `/api/notes/${id}`)).code, 404);
  }
});

test('stage 4: both directions deny cross-account and unowned single GET/PUT/DELETE without changing any row', async () => {
  const f = fixture();
  const original = structuredClone([...f.records.values()]);
  for (const [owner, victim] of [[userId, rows[2]], [otherId, rows[0]]]) {
    const auth = `Bearer ${await token({ sub: owner })}`;
    for (const row of [victim, rows[3]]) {
      for (const method of ['GET', 'PUT', 'DELETE']) {
        const res = await call(f, auth, method, `/api/notes/${row.id}?owner_id=${row.owner_id}&userId=${row.owner_id}`,
          { title: '변경 시도', body: '변경 시도', userId: row.owner_id, role: 'admin' },
          { 'x-user-id': row.owner_id ?? userId, role: 'admin' });
        assert.equal(res.code, 404); assert.deepEqual(res.body, { error: 'NOT_FOUND' });
      }
    }
  }
  assert.deepEqual([...f.records.values()], original);
});

test('stage 4: PUT rejects owner_id fields and cannot transfer, clear or claim ownership', async () => {
  const f = fixture();
  for (const [owner, row, other] of [[userId, rows[0], otherId], [otherId, rows[2], userId]]) {
    const auth = `Bearer ${await token({ sub: owner })}`;
    for (const owner_id of [other, null, owner]) {
      const res = await call(f, auth, 'PUT', `/api/notes/${row.id}`, { title: '변경', body: '', owner_id });
      assert.equal(res.code, 400); assert.deepEqual(res.body, { error: 'INVALID_NOTE' });
    }
    assert.deepEqual(f.records.get(row.id), row);
  }
  assert.equal(f.recordCalls, 0);
});

test('stage 4: writes match the current owner in the same DB statement even if ownership changed first', async () => {
  for (const method of ['PUT', 'DELETE']) {
    const f = fixture({ transferBeforeWrite: otherId });
    const res = await call(f, `Bearer ${await token()}`, method, `/api/notes/${rows[0].id}`, { title: '변경', body: '' });
    assert.equal(res.code, 404);
    assert.deepEqual(f.records.get(rows[0].id), { ...rows[0], owner_id: otherId });
    assert.equal(f.recordCalls, 1);
  }
});

test('stage 4: an unexpected foreign row in an upstream response is never sent to the browser', async () => {
  const f = fixture({ unexpectedOwner: true });
  for (const [method, path] of [['GET', '/api/notes'], ['GET', `/api/notes/${rows[0].id}`],
    ['PUT', `/api/notes/${rows[0].id}`], ['DELETE', `/api/notes/${rows[0].id}`]]) {
    const res = await call(f, `Bearer ${await token()}`, method, path, { title: '가상', body: '' });
    assert.equal(res.code, 502); assert.deepEqual(res.body, { error: 'NOTES_UNAVAILABLE' });
  }
});

test('configuration and DB failures never echo server keys or upstream diagnostics', async () => {
  const auth = `Bearer ${await token()}`;
  for (const invalid of [{}, { ...env, SUPABASE_SECRET_KEY: 'publishable' }, { ...env, SUPABASE_URL: 'https://other.supabase.co' }]) {
    const f = fixture({ envOverride: invalid }); const res = await call(f, auth);
    assert.equal(res.code, 503); assert.equal(f.recordCalls, 0);
    assert.ok(!JSON.stringify(res.body).includes(fakeKey));
  }
  for (const options of [{ upstreamError: true }, { malformed: true }]) {
    const f = fixture(options); const res = await call(f, auth);
    assert.equal(res.code, 502); assert.deepEqual(res.body, { error: 'NOTES_UNAVAILABLE' });
  }
});
