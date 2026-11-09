import { createHash, randomUUID } from 'node:crypto';
import { appendFile, lstat, mkdir, readFile, readdir, realpath, rename, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

export const POLICY_SOURCES = Object.freeze([
  'src/decider.mjs', 'src/decider-input.mjs', 'src/resource-policy.mjs',
  'src/resource-zones.mjs', 'src/detect.mjs',
]);
const NAMES = [...POLICY_SOURCES, 'allowedRoutes.json', 'db-policies.json'].sort();
const TABLES = ['vault_instructor_materials', 'vault_notes', 'vault_notices', 'vault_resource_roles'];
const CRUD = ['select', 'insert', 'update', 'delete'];
const ROLE_FIELDS = [...CRUD, 'columnSelect', 'columnInsert', 'columnUpdate'];
const EXTRA_ROLE_FIELDS = ['truncate', 'references', 'trigger', 'maintain', 'columnReferences'];
const ID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const SHA = /^[a-f0-9]{64}$/u;
const fail = code => { throw new Error(code); };
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => `${JSON.stringify(value, null, 2)}\n`;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => object(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

// Export wrappers from the SQL editor are accepted; extra row data is not.
export function readDbSnapshot(text) {
  let value;
  try {
    value = JSON.parse(text);
    if (Array.isArray(value) && value.length === 1) [value] = value;
    if (exactKeys(value, ['policy_snapshot'])) value = value.policy_snapshot;
    if (typeof value === 'string') value = JSON.parse(value);
  } catch { fail('invalid_db_policy_export'); }
  if (!exactKeys(value, ['schema', 'tables']) || value.schema !== 'aleph.db-policy-snapshot.v1'
      || !Array.isArray(value.tables) || value.tables.length !== TABLES.length
      || value.tables.map(t => t?.table).sort().join(',') !== TABLES.join(',')) {
    fail('invalid_db_policy_export');
  }
  for (const table of value.tables) {
    if (!exactKeys(table, ['table', 'rlsEnabled', 'rlsForced', 'policies', 'grants',
      'columnGrants', 'effectivePrivileges']) || typeof table.rlsForced !== 'boolean'
      || table.rlsEnabled !== true) fail('db_policy_not_known_good');
    if (!Array.isArray(table.policies) || !Array.isArray(table.grants)
        || !Array.isArray(table.columnGrants) || !Array.isArray(table.effectivePrivileges)) {
      fail('invalid_db_policy_export');
    }
    for (const p of table.policies) {
      if (!exactKeys(p, ['name', 'permissive', 'roles', 'command', 'using', 'check'])
          || typeof p.name !== 'string' || !['PERMISSIVE', 'RESTRICTIVE'].includes(p.permissive)
          || !Array.isArray(p.roles) || !p.roles.every(r => typeof r === 'string')
          || !['ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE'].includes(p.command)
          || ![p.using, p.check].every(v => v === null || typeof v === 'string')) {
        fail('invalid_db_policy_export');
      }
    }
    for (const [entries, column] of [[table.grants, false], [table.columnGrants, true]]) {
      for (const g of entries) {
        if (!exactKeys(g, [...(column ? ['column'] : []), 'grantee', 'privilege', 'isGrantable'])
            || typeof g.grantee !== 'string' || typeof g.privilege !== 'string'
            || typeof g.isGrantable !== 'boolean' || (column && typeof g.column !== 'string')) {
          fail('invalid_db_policy_export');
        }
      }
    }
    const roles = table.effectivePrivileges;
    if (roles.length !== 3 || roles.map(r => r?.role).sort().join(',') !== 'anon,authenticated,service_role') {
      fail('invalid_db_policy_export');
    }
    for (const r of roles) {
      if (!exactKeys(r, ['role', ...ROLE_FIELDS, ...EXTRA_ROLE_FIELDS])
          || ![...ROLE_FIELDS, ...EXTRA_ROLE_FIELDS].every(k => typeof r[k] === 'boolean')) {
        fail('invalid_db_policy_export');
      }
      const server = r.role === 'service_role';
      const writable = ['vault_notes', 'vault_notices'].includes(table.table);
      if (ROLE_FIELDS.some(k => r[k] !== (server && (writable || k === 'select' || k === 'columnSelect')))
          || (!server && EXTRA_ROLE_FIELDS.some(k => r[k]))) {
        fail('db_policy_not_known_good');
      }
    }
  }
  return value;
}

async function regular(root, name) {
  const base = await realpath(root);
  if (base !== resolve(root)) fail('unsafe_policy_directory');
  const path = join(base, name);
  const st = await lstat(path);
  if (!st.isFile() || st.size > 1024 * 1024 || !(await realpath(path)).startsWith(`${base}${sep}`)) {
    fail('unsafe_policy_file');
  }
  return readFile(path);
}

async function directory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (!(await lstat(path)).isDirectory() || (await realpath(path)) !== resolve(path)) {
    fail('unsafe_policy_directory');
  }
}

async function writePrivate(root, name, bytes) {
  const parts = name.split('/');
  if (parts.length > 1) await directory(join(root, ...parts.slice(0, -1)));
  await writeFile(join(root, name), bytes, { flag: 'wx', mode: 0o600 });
}

function runPath(root, id) {
  if (!ID.test(id)) fail('invalid_policy_copy_id');
  return join(root, '.private', 'step10-policy', id);
}

export async function verifyPolicyCopy({ root, id, expectedHash }) {
  if (!SHA.test(expectedHash)) fail('expected_backup_hash_required');
  const run = runPath(root, id);
  const manifestBytes = await regular(run, 'manifest.json');
  if (sha256(manifestBytes) !== expectedHash) fail('backup_manifest_hash_mismatch');
  let manifest;
  try { manifest = JSON.parse(manifestBytes); } catch { fail('invalid_policy_manifest'); }
  if (!exactKeys(manifest, ['schema', 'baseCommit', 'createdAt', 'files'])
      || manifest.schema !== 'aleph.policy-copy.v1' || !/^[a-f0-9]{40}$/u.test(manifest.baseCommit)
      || !Array.isArray(manifest.files) || manifest.files.length !== NAMES.length
      || manifest.files.map(f => f?.path).sort().join(',') !== NAMES.join(',')) {
    fail('invalid_policy_manifest');
  }
  if ((await inventory(join(run, 'backup'))).join(',') !== NAMES.join(',')) fail('unexpected_backup_files');
  for (const entry of manifest.files) {
    if (!exactKeys(entry, ['path', 'sha256']) || !SHA.test(entry.sha256)) fail('invalid_policy_manifest');
    if (sha256(await regular(join(run, 'backup'), entry.path)) !== entry.sha256) {
      fail('backup_file_hash_mismatch');
    }
  }
  readDbSnapshot((await regular(join(run, 'backup'), 'db-policies.json')).toString('utf8'));
  return { run, manifest };
}

export async function createPolicyCopy({ root, dbFile, baseCommit }) {
  if (!/^[a-f0-9]{40}$/u.test(baseCommit)) fail('invalid_base_commit');
  const db = readDbSnapshot(await readFile(dbFile, 'utf8'));
  const config = JSON.parse((await regular(root, 'aleph.config.json')).toString('utf8'));
  if (!Array.isArray(config.allowedRoutes) || !config.allowedRoutes.length
      || !config.allowedRoutes.every(v => typeof v === 'string')) fail('invalid_allowed_routes');
  const payload = new Map();
  for (const name of POLICY_SOURCES) payload.set(name, await regular(root, name));
  payload.set('allowedRoutes.json', Buffer.from(json(config.allowedRoutes)));
  payload.set('db-policies.json', Buffer.from(json(db)));
  const id = randomUUID();
  const run = runPath(root, id);
  await directory(join(root, '.private'));
  await directory(join(root, '.private', 'step10-policy'));
  await directory(run);
  await directory(join(run, 'backup'));
  for (const [name, bytes] of payload) await writePrivate(join(run, 'backup'), name, bytes);
  const manifest = { schema: 'aleph.policy-copy.v1', baseCommit, createdAt: new Date().toISOString(),
    files: NAMES.map(path => ({ path, sha256: sha256(payload.get(path)) })) };
  const manifestBytes = Buffer.from(json(manifest));
  await writePrivate(run, 'manifest.json', manifestBytes);
  const expectedHash = sha256(manifestBytes);
  await writePrivate(run, 'manifest.sha256', `${expectedHash}\n`);
  // Re-read and verify every saved file before creating or mutating the trial.
  await verifyPolicyCopy({ root, id, expectedHash });
  const markers = ['if (request?.deviceRegistered !== true) {',
    'if (!permitsRegisteredDevice(request?.deviceRegistered)) {'];
  const original = payload.get('src/decider.mjs').toString('utf8');
  const matches = markers.filter(marker => original.split(marker).length === 2);
  if (matches.length !== 1) fail('trial_rule_marker_not_unique');
  const [marker] = matches;
  await directory(join(run, 'trial'));
  for (const [name, bytes] of payload) {
    const contents = name === 'src/decider.mjs'
      ? original.replace(marker, 'if (false) { // STEP10 TRIAL ONLY: device condition bypassed') : bytes;
    await writePrivate(join(run, 'trial'), name, contents);
  }
  await writePrivate(run, 'audit.jsonl', `${JSON.stringify({ at: manifest.createdAt,
    action: 'backup_verified_and_trial_created', baseCommit, manifestSha256: expectedHash,
    changedPath: 'src/decider.mjs' })}\n`);
  return { id, expectedHash, baseCommit, files: NAMES.length };
}

async function inventory(root, prefix = '') {
  const current = join(root, prefix);
  if (!(await lstat(current)).isDirectory() || (await realpath(current)) !== resolve(current)) {
    fail('unsafe_policy_directory');
  }
  const names = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) names.push(...await inventory(root, path));
    else if (entry.isFile()) names.push(path);
    else fail('unsafe_policy_file');
  }
  return names.sort();
}

export async function previewPolicyCopy(options) {
  const { run, manifest } = await verifyPolicyCopy(options);
  const trial = join(run, 'trial');
  if ((await inventory(trial)).join(',') !== NAMES.join(',')) fail('unexpected_trial_files');
  const changes = [];
  for (const entry of manifest.files) {
    const before = await regular(join(run, 'backup'), entry.path);
    const after = await regular(trial, entry.path);
    if (before.equals(after)) continue;
    const a = before.toString('utf8').split('\n');
    const b = after.toString('utf8').split('\n');
    let first = 0;
    while (first < Math.min(a.length, b.length) && a[first] === b[first]) first += 1;
    let endA = a.length, endB = b.length;
    while (endA > first && endB > first && a[endA - 1] === b[endB - 1]) { endA -= 1; endB -= 1; }
    changes.push({ path: entry.path, line: first + 1,
      before: a.slice(first, endA), after: b.slice(first, endB),
      backupSha256: entry.sha256, trialSha256: sha256(after) });
  }
  const report = { id: options.id, baseCommit: manifest.baseCommit, manifestSha256: options.expectedHash,
    target: 'private_trial_only', changes };
  return { ...report, planSha256: sha256(JSON.stringify(report)) };
}

// Restore exactly the one-line trial made by createPolicyCopy, never live paths.
export async function restorePolicyCopy(options) {
  const preview = await previewPolicyCopy(options);
  if (!SHA.test(options.expectedPlanHash) || options.expectedPlanHash !== preview.planSha256) {
    fail('reviewed_policy_plan_mismatch');
  }
  if (preview.changes.length === 0) return { ...preview, restored: false };
  const [change] = preview.changes;
  if (preview.changes.length !== 1 || change.path !== 'src/decider.mjs'
      || change.before.length !== 1 || change.after.length !== 1
      || !['  if (request?.deviceRegistered !== true) {',
        '  if (!permitsRegisteredDevice(request?.deviceRegistered)) {'].includes(change.before[0])
      || change.after[0] !== '  if (false) { // STEP10 TRIAL ONLY: device condition bypassed') {
    fail('unexpected_policy_trial_change');
  }
  const run = runPath(options.root, options.id);
  const bytes = await regular(join(run, 'backup'), change.path);
  if (sha256(bytes) !== change.backupSha256
      || sha256(await regular(join(run, 'trial'), change.path)) !== change.trialSha256) {
    fail('policy_changed_after_review');
  }
  // Audit must exist and remain a regular private file before any trial write.
  await regular(run, 'audit.jsonl');
  const trial = join(run, 'trial');
  const temp = `${change.path}.${randomUUID()}.tmp`;
  await writePrivate(trial, temp, bytes);
  await rename(join(trial, temp), join(trial, change.path));
  const after = await previewPolicyCopy(options);
  if (after.changes.length !== 0) fail('trial_restore_verification_failed');
  await appendFile(join(run, 'audit.jsonl'), `${JSON.stringify({ at: new Date().toISOString(),
    action: 'trial_policy_restored', path: change.path, reviewedPlanSha256: preview.planSha256,
    manifestSha256: options.expectedHash })}\n`);
  return { ...after, restored: true, restoredPaths: [change.path] };
}
