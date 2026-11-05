import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createResourceHandler } from '../src/resource-api.mjs';
import { ACCESS_COOKIE } from '../src/browser-session.mjs';

const a = '10000000-0000-4000-8000-000000000001';
const b = '10000000-0000-4000-8000-000000000002';
const teacher = '10000000-0000-4000-8000-000000000003';
const noticeId = '80000000-0000-4000-8000-000000000001';
const materialId = '80000000-0000-4000-8000-000000000002';
const otherMaterialId = '80000000-0000-4000-8000-000000000003';
const config = { publicAppUrl: 'https://fixture.example/' };

function fixture({ area = 'notices', admin = false, failTable, foreignRows = false } = {}) {
  const stores = {
    vault_notices: [{ id: noticeId, title: '가상 공지', body: '시험 자료', created_by: teacher }],
    vault_instructor_materials: [
      { id: materialId, title: '가상 자료', body: '시험 자료', owner_id: teacher },
      { id: otherMaterialId, title: '다른 자료', body: '다른 시험 자료', owner_id: b }],
    vault_resource_roles: [{ user_id: teacher, role: 'instructor', active: true }],
  };
  const calls = [];
  const db = { from(name) {
    const filters = []; let columns; let operation = 'GET'; let values; let limit;
    const q = {
      select(value) { columns = value.split(','); return q; },
      eq(key, value) { filters.push([key, value]); return q; },
      limit(value) { limit = value; return q; }, order() { return q; }, abortSignal() { return q; },
      insert(value) { operation = 'POST'; values = value; return q; },
      update(value) { operation = 'PATCH'; values = value; return q; },
      delete() { operation = 'DELETE'; return q; },
      then(resolve, reject) {
        calls.push({ name, operation, filters, values });
        if (name === failTable) return Promise.resolve({ error: { message: 'private fixture diagnostic' } }).then(resolve, reject);
        let rows = stores[name].filter(row => filters.every(([key, value]) => row[key] === value));
        if (operation === 'POST') { rows = [{ ...values }]; stores[name].push(rows[0]); }
        if (operation === 'PATCH') rows.forEach(row => Object.assign(row, values));
        if (operation === 'DELETE') stores[name] = stores[name].filter(row => !rows.includes(row));
        if (foreignRows && name === 'vault_instructor_materials') rows = [stores[name][1]];
        if (limit) rows = rows.slice(0, limit);
        if (columns) rows = rows.map(row => Object.fromEntries(columns.map(key => [key, row[key]])));
        return Promise.resolve({ data: rows, error: null }).then(resolve, reject);
      },
    }; return q;
  } };
  const identities = { 'Bearer a': a, 'Bearer b': b, 'Bearer instructor': teacher, 'Bearer a.b.c': teacher };
  const handler = createResourceHandler({ area, admin, config,
    runtimeFactory: () => ({ db, verifyLogin: async authorization => identities[authorization]
      ? { userId: identities[authorization] } : null }) });
  return { stores, calls, handler };
}

async function call(f, token, method, url, body, headers = {}) {
  const res = { code: null, headers: {}, body: null,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
  await f.handler({ method, url, body, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers } }, res);
  return res;
}

test('zone APIs require verified identity before any resource or role lookup', async () => {
  for (const options of [{}, { admin: true }, { area: 'instructor' }]) {
    const f = fixture(options);
    for (const token of [null, 'unverified']) {
      const res = await call(f, token, 'GET', '/api/notices', { role: 'instructor', userId: teacher });
      assert.equal(res.code, 401);
      assert.deepEqual(res.body, { error: 'AUTH_REQUIRED' });
    }
    assert.equal(f.calls.length, 0);
  }
});

test('public notices allow student reads but reject every write, even for an instructor', async () => {
  const f = fixture(); const before = structuredClone(f.stores.vault_notices);
  for (const user of ['a', 'b']) {
    const res = await call(f, user, 'GET', `/api/notices/${noticeId}`);
    assert.equal(res.code, 200);
    assert.deepEqual(Object.keys(res.body).sort(), ['body', 'id', 'title']);
    assert.equal(res.headers['x-resource-zone'], 'class_notices');
  }
  for (const user of ['a', 'instructor']) for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const res = await call(f, user, method, `/api/notices/${noticeId}`, { role: 'instructor' });
    assert.equal(res.code, 403); assert.deepEqual(res.body, { error: 'NOTICE_READ_ONLY' });
  }
  assert.deepEqual(f.stores.vault_notices, before);
});

test('a router-mirrored path ID preserves notice reads and instructor permission checks', async () => {
  const notices = fixture();
  const read = await call(notices, 'a', 'GET', `/api/notices/${noticeId}?id=${noticeId}`);
  assert.equal(read.code, 200);
  assert.equal(read.body.id, noticeId);
  const instructor = fixture({ area: 'instructor' });
  const denied = await call(instructor, 'a', 'GET', `/api/instructor/${materialId}?id=${materialId}`);
  assert.equal(denied.code, 403);
  assert.deepEqual(denied.body, { error: 'INSTRUCTOR_REQUIRED' });
  assert.ok(instructor.calls.every(c => c.name === 'vault_resource_roles'));
});

test('query IDs cannot select or replace path resources, duplicate IDs or choose operations', async () => {
  const f = fixture();
  for (const path of [
    `/api/notices?id=${noticeId}`,
    `/api/notices/${noticeId}?id=${materialId}`,
    `/api/notices/${noticeId}?id=${noticeId}&id=${noticeId}`,
    `/api/notices/${noticeId}?id=${noticeId}&operation=export`,
    `/api/notices/${noticeId}?operation=export`,
    `/api/notices/${noticeId}?id=${noticeId}#fragment`,
  ]) {
    const res = await call(f, 'a', 'GET', path);
    assert.equal(res.code, 400);
    assert.deepEqual(res.body, { error: 'QUERY_NOT_ALLOWED' });
  }
  assert.equal(f.calls.length, 0);
});

test('stored role, not forged body/header identity, gates instructor and notice-management paths', async () => {
  for (const options of [{ area: 'instructor' }, { admin: true }]) {
    const f = fixture(options); const before = structuredClone(f.stores);
    for (const user of ['a', 'b']) {
      const path = options.admin ? '/api/admin/notices' : `/api/instructor/${materialId}`;
      const res = await call(f, user, options.admin ? 'POST' : 'GET', path,
        { role: 'instructor', userId: teacher }, { 'x-role': 'instructor', 'x-user-id': teacher });
      assert.equal(res.code, 403); assert.deepEqual(res.body, { error: 'INSTRUCTOR_REQUIRED' });
    }
    assert.ok(f.calls.every(c => c.name === 'vault_resource_roles'));
    assert.deepEqual(f.stores, before);
  }
});

test('active instructor uses only the server management path; revoking stored role affects the next request', async () => {
  const f = fixture({ admin: true });
  const created = await call(f, 'instructor', 'POST', '/api/admin/notices', { title: '새 공지', body: '가상 내용' });
  assert.equal(created.code, 201); const id = created.body.id;
  assert.equal(f.stores.vault_notices.find(row => row.id === id).created_by, teacher);
  assert.equal((await call(f, 'instructor', 'PUT', `/api/admin/notices/${id}`, { title: '수정', body: '' })).code, 200);
  assert.equal((await call(f, 'instructor', 'POST', '/api/admin/notices', { title: 'x', body: '', created_by: a })).code, 400);
  assert.equal((await call(f, 'instructor', 'DELETE', `/api/admin/notices/${id}`)).code, 200);
  f.stores.vault_resource_roles[0].active = false;
  const denied = await call(f, 'instructor', 'PUT', `/api/admin/notices/${noticeId}`, { title: 'x', body: '' });
  assert.equal(denied.code, 403);
});

test('instructor resources require both stored instructor authority and matching stored ownership', async () => {
  const f = fixture({ area: 'instructor' });
  assert.equal((await call(f, 'instructor', 'GET', `/api/instructor/${materialId}`)).code, 200);
  assert.equal((await call(f, 'instructor', 'GET', `/api/instructor/${otherMaterialId}`)).code, 404);
  const broken = fixture({ area: 'instructor', foreignRows: true });
  const res = await call(broken, 'instructor', 'GET', `/api/instructor/${materialId}`);
  assert.equal(res.code, 503);
  assert.deepEqual(res.body, { error: 'RESOURCE_STORE_UNAVAILABLE' });
});

test('cookie authorization still requires same-origin markers on zone requests', async () => {
  const f = fixture({ admin: true });
  for (const headers of [
    { cookie: `${ACCESS_COOKIE}=a.b.c` },
    { cookie: `${ACCESS_COOKIE}=a.b.c`, 'x-requested-with': 'vault-ui', origin: 'https://other.example' },
  ]) {
    const res = await call(f, null, 'POST', '/api/admin/notices', { title: 'x', body: '' }, headers);
    assert.equal(res.code, 403);
  }
  assert.equal(f.calls.length, 0);
});

test('missing role/store data and query selectors fail without echoing diagnostics or resource content', async () => {
  for (const [options, token, path] of [
    [{ admin: true, failTable: 'vault_resource_roles' }, 'instructor', '/api/admin/notices'],
    [{ failTable: 'vault_notices' }, 'a', `/api/notices/${noticeId}`],
  ]) {
    const f = fixture(options);
    const res = await call(f, token, options.admin ? 'POST' : 'GET', path, { title: 'x', body: '' });
    assert.equal(res.code, 503);
    assert.deepEqual(Object.keys(res.body), ['error']);
    assert.ok(!JSON.stringify(res.body).includes('private fixture diagnostic'));
  }
  const f = fixture();
  assert.equal((await call(f, 'a', 'GET', '/api/notices?operation=export')).code, 400);
  assert.equal((await call(f, 'a', 'GET', '/api/notices/export')).code, 400);
  assert.equal(f.calls.length, 0);
});
