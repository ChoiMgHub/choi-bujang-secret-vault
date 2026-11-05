import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep5 } from '../src/step5-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
config.step = 5;
const source = await readFile(new URL('../src/supabase-public.mjs', import.meta.url), 'utf8');
const commit = 'a'.repeat(40);
const originalUrl = new URL(config.originalApiUrl);
function remote({ direct = 'denied', step = 5, sha = commit, assets = 'clean', session = 'clean' } = {}) {
  return async (target, init) => {
    const url = new URL(target);
    assert.equal(init.redirect, 'error');
    if (!(url.pathname === '/api/auth' && init.method === 'POST')) assert.equal(init.body, undefined);
    if (url.origin === originalUrl.origin) {
      assert.equal(url.pathname, originalUrl.pathname);
      assert.equal(url.search, '?select=id&limit=1');
      assert.equal(init.method, 'GET');
      assert.deepEqual(Object.keys(init.headers), ['apikey']);
      assert.ok(init.headers.apikey.startsWith('sb_publishable_'));
      assert.ok(source.includes(init.headers.apikey));
      if (direct === 'allowed') return Response.json([{ id: 'fixture' }]);
      if (direct === 'empty') return Response.json([]);
      if (direct === 'bad_key') return Response.json({ code: 'PGRST301' }, { status: 401 });
      if (direct === 'html') return new Response('<h1>denied</h1>', { status: 403 });
      if (direct === 'leak') return Response.json({ code: '42501', notes: [] }, { status: 403 });
      if (direct === 'wrong_status') return Response.json({ code: '42501' }, { status: 500 });
      return Response.json({ code: '42501', message: 'fixture diagnostic', details: null, hint: null }, { status: 401 });
    }
    assert.equal(url.origin, new URL(config.publicAppUrl).origin);
    if (url.pathname === '/') return new Response('<form id="login-form"></form><form id="memo-form"></form><ul id="notes" aria-live="polite" hidden></ul><script src="/auth-ui.js"></script>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (url.pathname === '/auth-ui.js') return new Response(assets === 'leak' ? 'const key="sb_publishable_fixture";' : 'fetch("/api/auth");');
    if (url.pathname === '/vendor/supabase.js') return new Response(null, { status: assets === 'sdk' ? 200 : 404 });
    if (url.pathname === '/api/auth') {
      if (init.method === 'POST') {
        assert.equal(init.body, '{}');
        const same = init.headers.origin === new URL(config.publicAppUrl).origin;
        return Response.json({ error: same ? 'INVALID_INPUT' : 'ORIGIN_NOT_ALLOWED' }, { status: same ? 400 : 403 });
      }
      return Response.json(session === 'leak' ? { user: null, access_token: 'fixture' } : { user: null }, { headers: { 'cache-control': 'private, no-store' } });
    }
    if (url.pathname === '/data.json') return new Response(null, { status: 404 });
    if (url.pathname === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1',
      step, commit: sha, repoUrl: config.repoUrl, judgeIssuer: config.judgeIssuer });
    return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
  };
}

test('stage 5 checker validates deployment and probes configured original API with public key only', async () => {
  const checks = await checkStep5({ ...config, expectedCommit: commit }, { fetchImpl: remote() });
  assert.equal(checks.length, 16);
  assert.ok(checks.every(check => check.passed));
  assert.ok(!JSON.stringify(checks).includes('fixture diagnostic'));
  for (const opts of [{ step: 4 }, { sha: 'b'.repeat(40) }]) {
    const failed = await checkStep5({ ...config, expectedCommit: commit }, { fetchImpl: remote(opts) });
    assert.equal(failed.find(check => check.attackId === 'deployment_identity').passed, false);
  }
});

test('stage 5 bonus checks fail for leaked browser keys, cached SDK files and session token responses', async () => {
  for (const [opts, attackId] of [[{ assets: 'leak' }, 'browser_public_key_absent'],
    [{ assets: 'sdk' }, 'browser_sdk_removed'], [{ session: 'leak' }, 'anonymous_server_session']]) {
    const checks = await checkStep5(config, { fetchImpl: remote(opts) });
    assert.equal(checks.find(check => check.attackId === attackId).passed, false);
  }
});

test('stage 5 checker does not mistake data, empty arrays, bad keys, HTML or unrelated errors for a grant denial', async () => {
  for (const direct of ['allowed', 'empty', 'bad_key', 'html', 'leak', 'wrong_status']) {
    const checks = await checkStep5(config, { fetchImpl: remote({ direct }) });
    assert.equal(checks.find(check => check.attackId === 'original_api_public_key').passed, false);
  }
});

test('stage 5 original URL must be the same project and exact table without queries, fragments or credentials', async () => {
  for (const originalApiUrl of [
    null, 'http://example.com/rest/v1/vault_notes',
    'https://other-project.supabase.co/rest/v1/vault_notes',
    `${originalUrl}?select=*`, `${originalUrl}#fragment`,
    `${originalUrl.origin}/rest/v1/other_table`,
    `${originalUrl.origin}/auth/v1`,
    `https://user:pass@${originalUrl.host}${originalUrl.pathname}`,
  ]) {
    await assert.rejects(checkStep5({ ...config, originalApiUrl }, {
      fetchImpl: () => { assert.fail('invalid source must be rejected before any request'); },
    }));
  }
});

test('stage 5 bundle uses redacted observations and refuses a failed original-API check', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = remote();
    const attempts = await runAttackChecks({ ...config, expectedCommit: commit });
    assert.equal(attempts.length, 16);
    assert.ok(attempts.every(item => Object.keys(item).sort().join(',') === 'attackId,expected,observed'));
    assert.ok(!JSON.stringify(attempts).includes('fixture diagnostic'));
    assert.ok(!JSON.stringify(attempts).includes('sb_publishable_'));
    globalThis.fetch = remote({ direct: 'allowed' });
    await assert.rejects(runAttackChecks(config), /original_api_public_key/u);
  } finally { globalThis.fetch = original; }
});
