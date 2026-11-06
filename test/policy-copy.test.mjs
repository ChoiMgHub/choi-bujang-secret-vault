import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { POLICY_SOURCES, createPolicyCopy, previewPolicyCopy, readDbSnapshot,
  restorePolicyCopy, verifyPolicyCopy, sha256 } from '../src/policy-copy.mjs';

const BASE = 'a'.repeat(40);
function dbFixture() {
  return { schema: 'aleph.db-policy-snapshot.v1', tables: [
    'vault_instructor_materials', 'vault_notes', 'vault_notices', 'vault_resource_roles',
  ].map(table => ({ table, rlsEnabled: true, rlsForced: false,
    policies: [], grants: [], columnGrants: [],
    effectivePrivileges: ['anon', 'authenticated', 'service_role'].map(role => {
      const server = role === 'service_role';
      const writable = server && ['vault_notes', 'vault_notices'].includes(table);
      return { role, select: server, insert: writable, update: writable, delete: writable,
        columnSelect: server, columnInsert: writable, columnUpdate: writable,
        truncate: false, references: false, trigger: false, maintain: false, columnReferences: false };
    }),
  })) };
}

async function setup(t) {
  const root = await mkdtemp(join(tmpdir(), 'aleph-policy-copy-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'src'));
  for (const name of POLICY_SOURCES) {
    await writeFile(join(root, name), await readFile(new URL(`../${name}`, import.meta.url)));
  }
  await writeFile(join(root, 'aleph.config.json'), JSON.stringify({ allowedRoutes: ['GET /api/notes/:id'] }));
  const dbFile = join(root, 'db-export.json');
  await writeFile(dbFile, JSON.stringify(dbFixture()));
  return { root, dbFile, baseCommit: BASE };
}
const paths = (root, id) => ({
  run: join(root, '.private', 'step10-policy', id),
  backup: join(root, '.private', 'step10-policy', id, 'backup'),
  trial: join(root, '.private', 'step10-policy', id, 'trial'),
});

test('snapshot accepts the SQL export wrapper and rejects missing, extra or unsafe DB state', () => {
  const value = dbFixture();
  assert.deepEqual(readDbSnapshot(JSON.stringify([{ policy_snapshot: value }])), value);
  assert.throws(() => readDbSnapshot('{}'), /invalid_db_policy_export/u);
  assert.throws(() => readDbSnapshot(JSON.stringify({ ...value, memo: 'not policy metadata' })), /invalid_db_policy_export/u);
  for (const change of [v => v.tables.pop(), v => { v.tables[0].rlsEnabled = false; },
    v => { v.tables[0].effectivePrivileges[0].select = true; },
    v => { v.tables[0].effectivePrivileges[0].truncate = true; },
    v => { v.tables[0].effectivePrivileges[1].columnReferences = true; },
    v => { v.tables[0].effectivePrivileges[2].update = true; }]) {
    const input = structuredClone(value); change(input);
    assert.throws(() => readDbSnapshot(JSON.stringify(input)), /invalid_db_policy_export|db_policy_not_known_good/u);
  }
});

test('create re-reads the backup, mutates just one private trial line and preserves real source/config', async t => {
  const options = await setup(t);
  const source = await readFile(join(options.root, 'src/decider.mjs'));
  const config = await readFile(join(options.root, 'aleph.config.json'));
  const result = await createPolicyCopy(options);
  assert.equal(result.files, 7);
  const input = { root: options.root, id: result.id, expectedHash: result.expectedHash };
  const diff = await previewPolicyCopy(input);
  assert.equal(diff.baseCommit, BASE);
  assert.equal(diff.target, 'private_trial_only');
  assert.equal(diff.changes.length, 1);
  assert.equal(diff.changes[0].path, 'src/decider.mjs');
  assert.equal(diff.changes[0].before.length, 1);
  assert.equal(diff.changes[0].after.length, 1);
  assert.match(diff.changes[0].before[0], /deviceRegistered !== true/u);
  assert.match(diff.changes[0].after[0], /if \(false\)/u);
  assert.deepEqual(await readFile(join(options.root, 'src/decider.mjs')), source);
  assert.deepEqual(await readFile(join(options.root, 'aleph.config.json')), config);
  const p = paths(options.root, result.id);
  assert.deepEqual(await readFile(join(p.backup, 'src/decider.mjs')), source);
  const audit = await readFile(join(p.run, 'audit.jsonl'), 'utf8');
  await previewPolicyCopy(input);
  assert.equal(await readFile(join(p.run, 'audit.jsonl'), 'utf8'), audit);
});

test('missing or corrupted backup stops before preview and never rewrites trial or audit', async t => {
  for (const missing of [false, true]) {
    const options = await setup(t);
    const result = await createPolicyCopy(options);
    const p = paths(options.root, result.id);
    const trial = await readFile(join(p.trial, 'src/decider.mjs'));
    const audit = await readFile(join(p.run, 'audit.jsonl'));
    if (missing) await rm(join(p.backup, 'src/decider.mjs'));
    else await writeFile(join(p.backup, 'src/decider.mjs'), 'modified backup');
    await assert.rejects(previewPolicyCopy({ root: options.root, id: result.id, expectedHash: result.expectedHash }));
    assert.deepEqual(await readFile(join(p.trial, 'src/decider.mjs')), trial);
    assert.deepEqual(await readFile(join(p.run, 'audit.jsonl')), audit);
  }
});

test('a corrupted manifest or an unrecorded expected hash cannot be accepted', async t => {
  const options = await setup(t);
  const result = await createPolicyCopy(options);
  const input = { root: options.root, id: result.id, expectedHash: result.expectedHash };
  await assert.rejects(verifyPolicyCopy({ ...input, expectedHash: undefined }), /expected_backup_hash_required/u);
  await assert.rejects(verifyPolicyCopy({ ...input, expectedHash: '0'.repeat(64) }), /backup_manifest_hash_mismatch/u);
  const manifest = join(paths(options.root, result.id).run, 'manifest.json');
  await writeFile(manifest, `${await readFile(manifest, 'utf8')} `);
  await assert.rejects(previewPolicyCopy(input), /backup_manifest_hash_mismatch/u);
});

test('manifest cannot add a restore target outside the fixed policy set even with a matching digest', async t => {
  const options = await setup(t);
  const result = await createPolicyCopy(options);
  const manifest = join(paths(options.root, result.id).run, 'manifest.json');
  const value = JSON.parse(await readFile(manifest, 'utf8'));
  value.files[0].path = '../../other-service';
  const bytes = JSON.stringify(value);
  await writeFile(manifest, bytes);
  await assert.rejects(previewPolicyCopy({ root: options.root, id: result.id,
    expectedHash: sha256(bytes) }), /invalid_policy_manifest/u);
});

test('unexpected backup or trial files stop preview instead of silently omitting another change', async t => {
  for (const side of ['backup', 'trial']) {
    const options = await setup(t);
    const result = await createPolicyCopy(options);
    await writeFile(join(paths(options.root, result.id)[side], 'unrelated.txt'), 'another change');
    await assert.rejects(previewPolicyCopy({ root: options.root, id: result.id,
      expectedHash: result.expectedHash }), /unexpected_backup_files|unexpected_trial_files/u);
  }
});

test('reviewed trial restore restores the device rule, preserves live files and appends to audit', async t => {
  const options = await setup(t);
  const copy = await createPolicyCopy(options);
  const input = { root: options.root, id: copy.id, expectedHash: copy.expectedHash };
  const p = paths(options.root, copy.id);
  const auditBefore = await readFile(join(p.run, 'audit.jsonl'), 'utf8');
  const liveBefore = await readFile(join(options.root, 'src/decider.mjs'));
  const configBefore = await readFile(join(options.root, 'aleph.config.json'));
  const moduleUrl = pathToFileURL(join(p.trial, 'src/decider.mjs')).href;
  const broken = await import(`${moduleUrl}?phase=before`);
  const { normal } = fixtureRequests();
  assert.equal((await broken.decide({ ...normal, deviceRegistered: false })).decision, 'allow');
  const plan = await previewPolicyCopy(input);
  const result = await restorePolicyCopy({ ...input, expectedPlanHash: plan.planSha256 });
  assert.equal(result.restored, true);
  assert.deepEqual(result.changes, []);
  assert.deepEqual(await readFile(join(p.trial, 'src/decider.mjs')), liveBefore);
  assert.deepEqual(await readFile(join(options.root, 'src/decider.mjs')), liveBefore);
  assert.deepEqual(await readFile(join(options.root, 'aleph.config.json')), configBefore);
  const auditAfter = await readFile(join(p.run, 'audit.jsonl'), 'utf8');
  assert.ok(auditAfter.startsWith(auditBefore));
  assert.equal(JSON.parse(auditAfter.trim().split('\n').at(-1)).action, 'trial_policy_restored');
  assert.deepEqual((await previewPolicyCopy(input)).changes, []);
  const restored = await import(`${moduleUrl}?phase=after`);
  assert.equal((await restored.decide(normal)).decision, 'allow');
  const denied = await restored.decide({ ...normal, deviceRegistered: false });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reasonCode, 'device_not_registered');
});

test('a stale preview and an unrelated trial change cannot be restored or erase audit', async t => {
  const options = await setup(t);
  const copy = await createPolicyCopy(options);
  const input = { root: options.root, id: copy.id, expectedHash: copy.expectedHash };
  const p = paths(options.root, copy.id);
  const before = await previewPolicyCopy(input);
  const audit = await readFile(join(p.run, 'audit.jsonl'));
  const other = join(p.trial, 'allowedRoutes.json');
  await writeFile(other, '[]\n');
  await assert.rejects(restorePolicyCopy({ ...input, expectedPlanHash: before.planSha256 }), /reviewed_policy_plan_mismatch/u);
  const fresh = await previewPolicyCopy(input);
  await assert.rejects(restorePolicyCopy({ ...input, expectedPlanHash: fresh.planSha256 }), /unexpected_policy_trial_change/u);
  assert.equal(await readFile(other, 'utf8'), '[]\n');
  assert.deepEqual(await readFile(join(p.run, 'audit.jsonl')), audit);
});
