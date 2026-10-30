import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep4 } from '../src/step4-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const publicSource = await readFile(new URL('../public/auth-ui.js', import.meta.url), 'utf8');
const commit = 'a'.repeat(40);
function remote({ direct = 'denied', step = 4 } = {}) {
  return async (target, init) => {
    const url = new URL(target);
    assert.equal(init.redirect, 'error'); assert.equal(init.body, undefined);
    if (url.origin === config.identityProvider.issuer.replace('/auth/v1', '')) {
      assert.equal(url.pathname, '/rest/v1/vault_notes');
      assert.equal(url.search, '?select=id&limit=1'); assert.equal(init.method, 'GET');
      assert.equal(Object.keys(init.headers).join(','), 'apikey');
      assert.ok(init.headers.apikey.startsWith('sb_publishable_'));
      assert.ok(publicSource.includes(init.headers.apikey));
      if (direct === 'allowed') return Response.json([{ id: 'not-secret-fixture' }]);
      if (direct === 'invalid_key') return Response.json({ code: 'PGRST301', message: 'invalid API key' }, { status: 401 });
      if (direct === 'html') return new Response('not JSON', { status: 403 });
      if (direct === 'leak') return Response.json({ code: '42501', notes: [] }, { status: 403 });
      return Response.json({ code: '42501', message: 'permission denied', details: null, hint: null }, { status: 401 });
    }
    assert.equal(url.origin, new URL(config.publicAppUrl).origin);
    if (url.pathname === '/') return new Response('<form id="login-form"></form><form id="memo-form"></form><ul id="notes" aria-live="polite" hidden></ul>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (url.pathname === '/data.json') return new Response(null, { status: 404 });
    if (url.pathname === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step,
      commit, repoUrl: config.repoUrl, judgeIssuer: config.judgeIssuer });
    return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
  };
}

test('stage 4 self-check has eleven HTTP observations, validates step/commit and uses only the public key for direct Data API', async () => {
  const checks = await checkStep4({ ...config, expectedCommit: commit }, { fetchImpl: remote() });
  assert.equal(checks.length, 11); assert.ok(checks.every(check => check.passed));
  assert.ok(!JSON.stringify(checks).includes('apikey'));
  for (const overrides of [{ expectedCommit: 'b'.repeat(40) }, {}]) {
    const result = await checkStep4({ ...config, expectedCommit: commit, ...overrides }, { fetchImpl: remote({ step: 3 }) });
    assert.equal(result.find(check => check.attackId === 'deployment_identity').passed, false);
  }
});

test('stage 4 direct Data API check rejects allowed data, bad keys, HTML and errors mixed with data', async () => {
  for (const direct of ['allowed', 'invalid_key', 'html', 'leak']) {
    const checks = await checkStep4(config, { fetchImpl: remote({ direct }) });
    assert.equal(checks.find(check => check.attackId === 'anonymous_data_api').passed, false);
  }
});

test('stage 4 bundle keeps only redacted observed fields and refuses a failed direct Data API check', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = remote();
    const attempts = await runAttackChecks({ ...config, expectedCommit: commit });
    assert.equal(attempts.length,11);
    assert.ok(attempts.every(item => Object.keys(item).sort().join(',') === 'attackId,expected,observed'));
    globalThis.fetch = remote({ direct: 'allowed' });
    await assert.rejects(runAttackChecks(config), /anonymous_data_api/u);
  } finally { globalThis.fetch = original; }
});
