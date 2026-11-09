import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRestoreHandler } from '../src/restore-api.mjs';
import { ACCESS_COOKIE } from '../src/browser-session.mjs';

const a = '10000000-0000-4000-8000-000000000001';
const b = '10000000-0000-4000-8000-000000000002';
const id = '80000000-0000-4000-8000-000000000010';
const other = '80000000-0000-4000-8000-000000000011';
const target = { noteId: id, contentSha256: 'a'.repeat(64) };
const config = { step: 10, publicAppUrl: 'https://fixture.example/' };
const success = () => ({ schema: 'aleph.note-restore.v1', id, restored: true, idMatches: true,
  ownerMatches: true, contentHashMatches: true, contentSha256: target.contentSha256,
  otherNotesUnchanged: true, auditRowsBefore: 1, auditRowsAfter: 2 });
function fixture({ data = success(), error, throws = false } = {}) {
  const calls = [];
  const handler = createRestoreHandler({ config, target,
    runtimeFactory: () => ({ verifyLogin: async token => ({ 'Bearer a': { userId: a },
      'Bearer b': { userId: b }, 'Bearer a.b.c': { userId: b } })[token] || null,
    db: { async rpc(name, args) {
      calls.push({ name, args });
      if (throws) throw Error('private upstream secret');
      return args.p_actor_id !== b ? { error: { code: 'P0001', message: 'RESTORE_TARGET_DENIED' } }
        : { data, error };
    } } }) });
  return { handler, calls };
}
async function call(f, { token = 'b', method = 'POST', url = '/api/restore', body = { id }, headers = {} } = {}) {
  const response = { code: null, body: null, headers: {},
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(v) { this.code = v; return this; }, json(v) { this.body = v; return this; } };
  await f.handler({ method, url, body, headers: { 'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers } }, response);
  return response;
}

test('anonymous and unverified callers cannot reach the recovery RPC', async () => {
  const f = fixture();
  for (const token of [null, 'forged']) assert.equal((await call(f, { token })).code, 401);
  assert.equal(f.calls.length, 0);
});
test('only POST at the exact recovery path and one ID field can call the RPC', async () => {
  const f = fixture();
  for (const method of ['GET', 'PUT', 'PATCH', 'DELETE']) assert.equal((await call(f, { method })).code, 405);
  for (const url of ['/api/restore?operation=all', '/api/restore/other']) assert.equal((await call(f, { url })).code, 400);
  for (const body of [{ id, ownerId: b }, { id, role: 'instructor' }, { id, content: 'replacement' }, {}, [], '{']) {
    assert.equal((await call(f, { body })).code, 400);
  }
  assert.equal((await call(f, { body: { id: other } })).code, 404);
  assert.equal(f.calls.length, 0);
});
test('RPC actor comes from the verifier; another user cannot restore B through role headers', async () => {
  const f = fixture();
  const denied = await call(f, { token: 'a', headers: { 'x-role': 'instructor', 'x-user-id': b } });
  assert.equal(denied.code, 404);
  assert.equal(f.calls[0].args.p_actor_id, a);
  const restored = await call(f);
  assert.equal(restored.code, 200);
  assert.deepEqual(restored.body, success());
  assert.deepEqual(f.calls[1], { name: 'aleph_step10_restore_note', args: {
    p_note_id: id, p_actor_id: b, p_expected_sha256: target.contentSha256 } });
  assert.equal(restored.headers['cache-control'], 'private, no-store');
});
test('cookie recovery requires same-origin markers and never reads browser owner claims', async () => {
  const f = fixture();
  const cookie = { cookie: `${ACCESS_COOKIE}=a.b.c` };
  assert.equal((await call(f, { token: null, headers: cookie })).code, 403);
  assert.equal((await call(f, { token: null, headers: { ...cookie,
    origin: 'https://other.example', 'x-requested-with': 'vault-ui' } })).code, 403);
  const result = await call(f, { token: null, headers: { ...cookie,
    origin: 'https://fixture.example', 'sec-fetch-site': 'same-origin', 'x-requested-with': 'vault-ui' } });
  assert.equal(result.code, 200);
  assert.equal(f.calls.length, 1);
});
test('backup errors have fixed codes and never echo private upstream diagnostics', async () => {
  for (const [message, code] of [['RESTORE_BACKUP_MISSING', 'BACKUP_NOT_READY'],
    ['RESTORE_BACKUP_HASH_MISMATCH', 'BACKUP_INVALID'],
    ['RESTORE_BACKUP_IDENTITY_MISMATCH', 'BACKUP_INVALID'], ['RESTORE_OWNER_CHANGED', 'TARGET_OWNER_CHANGED']]) {
    const r = await call(fixture({ error: { code: 'P0001', message, details: 'private upstream secret' } }));
    assert.equal(r.code, 409); assert.deepEqual(r.body, { error: code });
  }
  for (const f of [fixture({ error: { code: 'other', message: 'private upstream secret' } }), fixture({ throws: true })]) {
    const r = await call(f); assert.equal(r.code, 502); assert.deepEqual(r.body, { error: 'RESTORE_UNAVAILABLE' });
  }
});
test('a malformed or leaking RPC success is not reported as a successful restore', async () => {
  for (const change of [v => { v.id = other; }, v => { v.ownerMatches = false; },
    v => { v.contentSha256 = 'b'.repeat(64); }, v => { v.auditRowsAfter = 1; },
    v => { v.body = 'unexpected memo content'; }, v => { v.otherNotesUnchanged = false; }]) {
    const data = success(); change(data);
    const r = await call(fixture({ data }));
    assert.equal(r.code, 502); assert.deepEqual(r.body, { error: 'RESTORE_UNAVAILABLE' });
  }
});
