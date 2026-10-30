import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { checkStep3 } from '../src/step3-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
// This historical suite checks stage 3 even after the active deployment advances.
config.step = 3;
function remote(failure) {
  return async (url, init) => {
    const path = new URL(url).pathname;
    assert.equal(init.redirect, 'error'); assert.equal(init.body, undefined);
    if (path === '/') return new Response('<form id="login-form"></form><form id="memo-form"></form><ul id="notes" aria-live="polite" hidden></ul>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (path === '/data.json') return new Response(null, { status: 404 });
    if (path === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step: 3, repoUrl: config.repoUrl,
      commit: 'a'.repeat(40), judgeIssuer: config.judgeIssuer });
    if (failure === 'accepted') return Response.json([]);
    if (failure === 'html') return new Response('<h1>sign in</h1>', { status: 401 });
    if (failure === 'leak') return Response.json({ error: 'AUTH_REQUIRED', notes: [] }, { status: 401 });
    if (init.headers) assert.equal(init.headers.Authorization, 'Bearer not-a-token');
    return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
  };
}
test('stage 3 self-check records ten real HTTP observations, uses an unused ID and contains no memo bodies', async () => {
  const checks = await checkStep3({ ...config, expectedCommit: 'a'.repeat(40) }, { fetchImpl: remote() });
  assert.equal(checks.length, 10); assert.ok(checks.every(check => check.passed));
  assert.deepEqual(checks.filter(check => check.attackId.startsWith('anonymous')).map(check => check.attackId),
    ['anonymous_list', 'anonymous_create', 'anonymous_single', 'anonymous_update', 'anonymous_delete']);
  const mismatch = await checkStep3({ ...config, expectedCommit: 'b'.repeat(40) }, { fetchImpl: remote() });
  assert.equal(mismatch.find(check => check.attackId === 'deployment_identity').passed, false);
});
test('stage 3 self-check rejects accepted anonymous requests, HTML errors and JSON containing data', async () => {
  for (const failure of ['accepted', 'html', 'leak']) {
    const checks = await checkStep3(config, { fetchImpl: remote(failure) });
    assert.equal(checks.find(check => check.attackId === 'anonymous_list').passed, false);
  }
  const original = globalThis.fetch;
  try {
    globalThis.fetch = remote('accepted'); await assert.rejects(runAttackChecks(config), /anonymous_list/u);
    globalThis.fetch = remote();
    const bundleChecks = await runAttackChecks(config);
    assert.equal(bundleChecks.length, 10);
    assert.ok(bundleChecks.every(check => Object.keys(check).sort().join(',') === 'attackId,expected,observed'));
  } finally { globalThis.fetch = original; }
});
