import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep10 } from '../src/step10-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const commit = 'a'.repeat(40);
function remote({ step = 10, sha = commit, app = 'denied', rpc = 'denied', zone = 'denied' } = {}) {
  const calls = [];
  const fetchImpl = async (target, init = {}) => {
    const url = new URL(target);
    calls.push({ path: url.pathname, method: init.method || 'GET' });
    if (url.origin === new URL(config.originalApiUrl).origin) {
      assert.ok(!Object.keys(init.headers).some(k => /authorization/iu.test(k)));
      if (url.pathname.includes('/rpc/')) {
        assert.equal(init.method, 'POST');
        assert.deepEqual(Object.keys(init.headers).sort(), ['apikey', 'content-type']);
        const args = JSON.parse(init.body);
        assert.equal(args.p_actor_id, '10000000-0000-4000-8000-000000000099');
        if (rpc === 'allowed') return Response.json({ restored: true });
        if (rpc === 'missing') return Response.json({ code: 'PGRST202' }, { status: 404 });
        if (rpc === 'wrong_denial') return Response.json({ code: 'P0001' }, { status: 403 });
        if (rpc === 'html') return new Response('<h1>denied</h1>', { status: 403 });
      }
      return Response.json({ code: '42501', message: 'private upstream diagnostic' }, { status: 401 });
    }
    if (url.pathname === '/api/restore') {
      assert.equal(init.method, 'POST');
      if (app === 'allowed') return Response.json({ restored: true });
      if (app === 'missing') return new Response(null, { status: 404 });
      if (app === 'leak') return Response.json({ error: 'AUTH_REQUIRED', data: [] }, { status: 401 });
      if (app === 'html') return new Response('<h1>denied</h1>', { status: 401 });
      return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
    }
    if (url.pathname === '/') return new Response('<form id="login-form"></form><form id="memo-form"></form><ul id="notes" aria-live="polite" hidden></ul><script src="/auth-ui.js"></script>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (url.pathname === '/auth-ui.js') return new Response('fetch("/api/auth")');
    if (['/vendor/supabase.js', '/data.json'].includes(url.pathname)) return new Response(null, { status: 404 });
    if (url.pathname === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step, commit: sha,
      repoUrl: config.repoUrl, judgeIssuer: config.judgeIssuer });
    if (url.pathname === '/api/auth') {
      if (init.method === 'POST') {
        const same = init.headers.origin === new URL(config.publicAppUrl).origin;
        return Response.json({ error: same ? 'INVALID_INPUT' : 'ORIGIN_NOT_ALLOWED' }, { status: same ? 400 : 403 });
      }
      return Response.json({ user: null }, { headers: { 'cache-control': 'no-store' } });
    }
    if (zone === 'missing' && url.pathname.startsWith('/api/instructor')) return new Response(null, { status: 404 });
    return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
  };
  return { calls, fetchImpl };
}

test('stage 10 retains earlier requests, groups two reads and checks both anonymous recovery paths in twenty items', async () => {
  const f = remote();
  const checks = await checkStep10({ ...config, expectedCommit: commit }, f);
  assert.equal(checks.length, 20);
  assert.ok(checks.every(c => c.passed));
  assert.equal(new Set(checks.map(c => c.attackId)).size, 20);
  for (const path of ['/api/notices/80000000-0000-4000-8000-000000000001',
    '/api/instructor/80000000-0000-4000-8000-000000000002', '/api/restore',
    '/rest/v1/rpc/aleph_step10_restore_note']) assert.ok(f.calls.some(c => c.path === path));
  assert.ok(!JSON.stringify(checks).includes('private upstream diagnostic'));
});
test('stage 10 does not mistake missing APIs, data, HTML or unrelated errors for recovery denial', async () => {
  for (const options of [{ app: 'allowed' }, { app: 'missing' }, { app: 'leak' }, { app: 'html' },
    { rpc: 'allowed' }, { rpc: 'missing' }, { rpc: 'wrong_denial' }, { rpc: 'html' }]) {
    const checks = await checkStep10({ ...config, expectedCommit: commit }, remote(options));
    assert.equal(checks.find(c => c.attackId === 'anonymous_recovery_denied').passed, false);
  }
});
test('stage 10 still rejects stale deployment and either missing legacy zone read, and requires the fixed recovery path', async () => {
  for (const options of [{ step: 9 }, { sha: 'b'.repeat(40) }, { zone: 'missing' }]) {
    const checks = await checkStep10({ ...config, expectedCommit: commit }, remote(options));
    assert.ok(checks.some(c => !c.passed));
  }
  await assert.rejects(checkStep10({ ...config, restoreRoute: '/api/other' }, remote()), /복구 경로/u);
});
test('stage 10 bundle exports only redacted observed fields and refuses a failed recovery check', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = remote().fetchImpl;
    const attempts = await runAttackChecks({ ...config, step: 10, expectedCommit: commit });
    assert.equal(attempts.length, 20);
    assert.ok(attempts.every(c => Object.keys(c).sort().join(',') === 'attackId,expected,observed'));
    assert.ok(!JSON.stringify(attempts).includes('private upstream diagnostic'));
    globalThis.fetch = remote({ rpc: 'missing' }).fetchImpl;
    await assert.rejects(runAttackChecks({ ...config, step: 10, expectedCommit: commit }), /anonymous_recovery_denied/u);
  } finally { globalThis.fetch = original; }
});
