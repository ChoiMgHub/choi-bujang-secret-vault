import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep8 } from '../src/step8-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const commit = 'a'.repeat(40);
function remote({ step = 8, sha = commit, direct = 'denied', zone = 'denied' } = {}) {
  return async (target, init) => {
    const url = new URL(target);
    if (url.origin === new URL(config.originalApiUrl).origin) {
      assert.equal(init.method, 'GET');
      assert.deepEqual(Object.keys(init.headers), ['apikey']);
      assert.ok(!url.search.includes('*'));
      if (url.pathname !== '/rest/v1/vault_notes' && direct !== 'denied') {
        if (direct === 'allowed') return Response.json([]);
        if (direct === 'missing') return Response.json({ code: 'PGRST205' }, { status: 404 });
        if (direct === 'html') return new Response('<h1>denied</h1>', { status: 403 });
      }
      return Response.json({ code: '42501', message: 'private fixture diagnostic' }, { status: 401 });
    }
    if (url.pathname === '/') return new Response('<form id="login-form"></form><form id="memo-form"></form><ul id="notes" aria-live="polite" hidden></ul><script src="/auth-ui.js"></script>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (url.pathname === '/auth-ui.js') return new Response('fetch("/api/auth")');
    if (url.pathname === '/vendor/supabase.js' || url.pathname === '/data.json') return new Response(null, { status: 404 });
    if (url.pathname === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step, commit: sha,
      repoUrl: config.repoUrl, judgeIssuer: config.judgeIssuer });
    if (url.pathname === '/api/auth') {
      if (init.method === 'POST') {
        const same = init.headers.origin === new URL(config.publicAppUrl).origin;
        return Response.json({ error: same ? 'INVALID_INPUT' : 'ORIGIN_NOT_ALLOWED' }, { status: same ? 400 : 403 });
      }
      return Response.json({ user: null }, { headers: { 'cache-control': 'no-store' } });
    }
    if ((url.pathname.startsWith('/api/notices') || url.pathname.startsWith('/api/instructor')
        || url.pathname.startsWith('/api/admin/notices')) && zone !== 'denied') {
      if (zone === 'missing') return new Response(null, { status: 404 });
      return Response.json({ error: 'AUTH_REQUIRED', data: [] }, { status: 401 });
    }
    return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
  };
}

test('stage 8 keeps sixteen checks and adds real zone/API denial checks without reading private contents', async () => {
  const checks = await checkStep8({ ...config, expectedCommit: commit }, { fetchImpl: remote() });
  assert.equal(checks.length, 20); assert.ok(checks.every(item => item.passed));
  assert.ok(!JSON.stringify(checks).includes('private fixture diagnostic'));
});

test('stage 8 refuses stale deployment, missing routes/tables and successful direct reads', async () => {
  for (const options of [{ step: 7 }, { sha: 'b'.repeat(40) }, { direct: 'allowed' },
    { direct: 'missing' }, { direct: 'html' }, { zone: 'missing' }, { zone: 'leak' }]) {
    const checks = await checkStep8({ ...config, expectedCommit: commit }, { fetchImpl: remote(options) });
    assert.ok(checks.some(check => !check.passed));
  }
});

test('stage 8 submission keeps only redacted observations and refuses failed zone checks', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = remote();
    const attempts = await runAttackChecks({ ...config, step: 8, expectedCommit: commit });
    assert.equal(attempts.length, 20);
    assert.ok(attempts.every(item => Object.keys(item).sort().join(',') === 'attackId,expected,observed'));
    assert.ok(!JSON.stringify(attempts).includes('private fixture diagnostic'));
    globalThis.fetch = remote({ direct: 'allowed' });
    await assert.rejects(runAttackChecks({ ...config, step: 8 }), /zone_tables_direct_read/);
  } finally { globalThis.fetch = original; }
});
