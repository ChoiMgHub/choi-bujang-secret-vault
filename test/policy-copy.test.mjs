import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { POLICY_SOURCES, createPolicyCopy, previewPolicyCopy, readDbSnapshot,
  verifyPolicyCopy, sha256 } from '../src/policy-copy.mjs';

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
