import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, cp, readFile, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { checkStep2 } from '../src/step2-checks.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

// Historical stage-2 behavior stays tested independently of the current stage.
const config = { ...JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8')), step: 2 };
const rows = Array.from({ length: 4 }, (_, i) => ({ id: String(i), title: `가상 ${i}`, content: `연습 ${i}`, owner_id: 'hidden' }));

test('stage 2 build removes stale public data and keeps validated current-step deployment identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'vault-build-'));
  try {
    await cp(new URL('../scripts/', import.meta.url), join(root, 'scripts'), { recursive: true });
    await cp(new URL('../public/', import.meta.url), join(root, 'public'), { recursive: true });
    await cp(new URL('../node_modules/@supabase/supabase-js/dist/umd/', import.meta.url),
      join(root, 'node_modules/@supabase/supabase-js/dist/umd'), { recursive: true });
    await cp(new URL('../node_modules/@supabase/supabase-js/LICENSE', import.meta.url),
      join(root, 'node_modules/@supabase/supabase-js/LICENSE'));
    await writeFile(join(root, 'aleph.config.json'), JSON.stringify(config));
    await writeFile(join(root, 'public/data.json'), JSON.stringify({ notes: rows }));
    const buildEnv = { ...process.env, VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'ChoiMgHub',
      VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'example-deployment.vercel.app' };
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: root, env: buildEnv });
    await assert.rejects(access(join(root, 'public/data.json')));
    const identity = JSON.parse(await readFile(join(root, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 2); assert.equal(identity.commit, 'a'.repeat(40));
    assert.equal(identity.repoUrl, config.repoUrl.toLowerCase());
    for (const step of [2, 3, 12]) assert.equal(deploymentIdentity(buildEnv, { ...config, step }).step, step);
    for (const step of [0, 13, '2']) assert.throws(() => deploymentIdentity(buildEnv, { ...config, step }));
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'], { cwd: root });
    await assert.rejects(access(join(root, 'public/aleph.json')));
    await assert.rejects(access(join(root, 'public/data.json')));
  } finally { await rm(root, { recursive: true, force: true }); }
});

function fakeRemote(failure) {
  return async (url, options) => {
    assert.equal(options.redirect, 'error'); assert.ok(!options.headers);
    const path = new URL(url).pathname;
    if (path === '/') return new Response('<script>fetch(\'/api/notes\')</script>', { headers: { 'x-content-type-options': 'nosniff' } });
    if (path === '/data.json') return failure === 'static' ? Response.json({ notes: rows }) : new Response(null, { status: 404 });
    if (path === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step: 2, repoUrl: config.repoUrl, commit: 'a'.repeat(40), judgeIssuer: config.judgeIssuer });
    if (options.method === 'POST') return new Response(null, { status: 405 });
    return Response.json({ sampleMarker: config.sampleMarker, notes: rows.map(({ id, title, content }) => ({ id, title, content })) });
  };
}

test('stage 2 HTTP checks observe real responses, reject stale files/commit and omit memo bodies', async () => {
  const checks = await checkStep2({ ...config, expectedCommit: 'a'.repeat(40) }, { fetchImpl: fakeRemote() });
  assert.equal(checks.length, 6); assert.ok(checks.every(check => check.passed));
  assert.ok(!JSON.stringify(checks).includes(rows[0].content));
  const wrongCommit = await checkStep2({ ...config, expectedCommit: 'b'.repeat(40) }, { fetchImpl: fakeRemote() });
  assert.equal(wrongCommit.find(check => check.attackId === 'deployment_identity').passed, false);
  const original = globalThis.fetch;
  try {
    globalThis.fetch = fakeRemote('static');
    await assert.rejects(runAttackChecks(config), /static_note_seed/u);
  } finally { globalThis.fetch = original; }
});
