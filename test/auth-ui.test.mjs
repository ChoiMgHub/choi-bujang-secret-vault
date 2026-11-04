import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../public/auth-ui.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
const profile = (email = 'learner-a@example.com') => ({ user: {
  id: email.includes('learner-b') ? '20000000-0000-4000-8000-000000000001' : '10000000-0000-4000-8000-000000000001', email,
}, expiresAt: Math.floor(Date.now() / 1000) + 3600 });

function ui({ initial = null, noteFetch, authFetch } = {}) {
  const elements = new Map();
  for (const id of ['login-form', 'login-email', 'login-password', 'login-button', 'logout-button', 'auth-status', 'auth-error', 'notes', 'memo-panel', 'memo-form', 'memo-title', 'memo-body', 'memo-save', 'memo-cancel', 'memo-message', 'owner-check', 'owner-check-result']) {
    elements.set(`#${id}`, { value: '', textContent: '', hidden: id === 'login-form' || id === 'logout-button', disabled: false,
      children: [], append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, events: {}, addEventListener(name, handler) { this.events[name] = handler; } });
  }
  const state = { session: initial, loginCalls: 0, logoutCalls: 0, getCalls: 0, loginError: null, logoutError: false, wait: null };
  const calls = []; const timers = [];
  const fetchImpl = async (path, init) => {
    calls.push({ path, method: init.method, init });
    assert.ok(path.startsWith('/api/'));
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.cache, 'no-store');
    assert.equal(init.headers['x-requested-with'], 'vault-ui');
    assert.equal(init.headers.Authorization, undefined);
    if (path !== '/api/auth') return noteFetch ? noteFetch(path, init)
      : Response.json([{ id: '10000000-0000-4000-8000-000000000001', title: '<img src=x onerror=alert(1)>', body: '가상 메모' }]);
    if (authFetch) return authFetch(init, state);
    if (init.method === 'GET') { state.getCalls++; return Response.json(state.session || { user: null }); }
    if (init.method === 'POST') {
      state.loginCalls++;
      const input = JSON.parse(init.body);
      assert.equal(input.password, 'test-input');
      if (state.wait) await state.wait;
      if (state.loginError) return Response.json({ error: state.loginError.code }, { status: state.loginError.status });
      state.session = profile(input.email); return Response.json(state.session);
    }
    assert.equal(init.method, 'DELETE'); state.logoutCalls++;
    if (state.logoutError) return Response.json({ error: 'AUTH_UNAVAILABLE' }, { status: 503 });
    state.session = null; return Response.json({ user: null });
  };
  const window = { confirm: () => true };
  const document = { querySelector: id => elements.get(id), createElement: () => ({ textContent: '', children: [], events: {}, addEventListener(name, handler) { this.events[name] = handler; }, append(...items) { this.children.push(...items); } }) };
  Object.defineProperty(document, 'cookie', { get() { assert.fail('JS must not read cookies'); }, set() { assert.fail('JS must not write cookies'); } });
  vm.runInNewContext(source, { window, document, fetch: fetchImpl, AbortController,
    setTimeout: callback => { const timer = { callback, unref() {} }; timers.push(timer); return timer; }, clearTimeout: () => {} });
  return { get: id => elements.get(`#${id}`), state, calls, timers,
    ready: async () => { await tick(); await tick(); },
    submit: () => elements.get('#login-form').events.submit({ preventDefault() {} }),
    logout: () => elements.get('#logout-button').events.click(),
    checkOwner: () => elements.get('#owner-check').events.click() };
}
function fill(view, email = 'learner-a@example.com') { view.get('login-email').value = ` ${email} `; view.get('login-password').value = 'test-input'; }

test('server-session UI restores metadata, logs in and out without browser SDK or tokens', async () => {
  const view = ui(); await view.ready();
  assert.equal(view.get('login-form').hidden, false);
  assert.equal(view.calls.filter(c => c.path === '/api/notes').length, 0);
  fill(view); await view.submit(); await view.ready();
  assert.equal(view.state.loginCalls, 1); assert.equal(view.get('login-password').value, '');
  assert.equal(view.get('login-form').hidden, true);
  assert.equal(view.get('auth-status').textContent, '로그인 중: learner-a@example.com');
  assert.equal(view.get('notes').children[0].children[0].textContent, '<img src=x onerror=alert(1)>');
  await view.logout();
  assert.equal(view.state.logoutCalls, 1); assert.equal(view.get('login-form').hidden, false);
  assert.equal(view.get('notes').hidden, true); assert.equal(view.get('notes').children.length, 0);
  assert.equal(view.get('auth-status').textContent, '로그아웃했습니다.');
  const restored = ui({ initial: profile() }); await restored.ready();
  assert.equal(restored.get('login-form').hidden, true);
  assert.equal(restored.get('notes').hidden, false);
});

test('login errors are safe, double submits are prevented and failed logout is not called success', async () => {
  const view = ui(); await view.ready();
  for (const [code, status, message] of [['INVALID_CREDENTIALS',401,/이메일 또는 비밀번호/u], ['EMAIL_NOT_CONFIRMED',403,/이메일 확인/u], ['TOO_MANY_REQUESTS',429,/요청이 많/u], ['AUTH_UNAVAILABLE',503,/연결하지 못/u], ['private-upstream-message',500,/로그인에 실패/u]]) {
    view.state.loginError = { code, status }; fill(view); await view.submit();
    assert.match(view.get('auth-error').textContent, message);
    assert.doesNotMatch(view.get('auth-error').textContent, /private-upstream/u);
    assert.equal(view.get('login-password').value, '');
  }
  view.state.loginError = null;
  let release; view.state.wait = new Promise(resolve => { release = resolve; });
  fill(view); const before = view.state.loginCalls; const pending = view.submit();
  await view.submit(); assert.equal(view.state.loginCalls, before + 1); release(); await pending;
  view.state.logoutError = true; await view.logout();
  assert.match(view.get('auth-error').textContent, /로그아웃 처리를 확인하지 못/u);
  assert.equal(view.get('login-form').hidden, true);
});

test('public assets have no publishable/secret/legacy JWT values, SDK calls, browser token storage or custom credential verification', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /type="password"/u);
  assert.doesNotMatch(html, /vendor\/supabase/u);
  assert.match(html, /src="\/auth-ui.js" defer/u);
  assert.doesNotMatch(source + html, /sb_publishable_|sb_secret_|SUPABASE_SECRET_KEY|Authorization|access_token|refresh_token|sessionStorage|localStorage|document\.cookie|window\.supabase|console\.|[\u3040-\u30ff]/u);
});

test('logout ignores late memo responses and cancels their ability to restore notes', async () => {
  const pending = []; const view = ui({ noteFetch: () => new Promise(resolve => pending.push(resolve)) });
  await view.ready(); fill(view); await view.submit(); await view.ready();
  await view.logout();
  for (const resolve of pending) resolve(Response.json([{ id: '1', title: 'must stay hidden', body: 'late' }]));
  await view.ready(); assert.equal(view.get('notes').hidden, true); assert.equal(view.get('notes').children.length, 0);
});

test('expired authorization restores the server session once; invalid sessions clear the private screen', async () => {
  let noteCalls = 0;
  const view = ui({ initial: profile(), noteFetch: () => ++noteCalls === 1
    ? Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 }) : Response.json([]) });
  await view.ready(); assert.equal(noteCalls, 2); assert.equal(view.state.getCalls, 2);
  assert.equal(view.get('memo-panel').hidden, false);
  const invalid = ui({ initial: profile(), authFetch: async (_init, state) => {
    state.getCalls++; return Response.json(state.getCalls === 1 ? profile() : { user: null });
  }, noteFetch: async () => Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 }) });
  await invalid.ready(); assert.equal(invalid.get('memo-panel').hidden, true);
});

test('memo UI keeps create/read/update/delete contracts and text-only rendering through cookie requests', async () => {
  const records = new Map(); const calls = []; const id = '40000000-0000-4000-8000-000000000004';
  const view = ui({ noteFetch: async (path, init) => {
    const method = init.method || 'GET'; calls.push(`${method} ${path}`);
    if (method === 'GET' && path === '/api/notes') return Response.json([...records.values()]);
    if (method === 'POST') {
      assert.equal(path, '/api/notes'); const data = JSON.parse(init.body);
      assert.deepEqual(Object.keys(data).sort(), ['body','title']); records.set(id, { id, ...data });
      return Response.json({ id }, { status: 201 });
    }
    assert.equal(path, `/api/notes/${id}`);
    if (method === 'GET') return Response.json(records.get(id));
    if (method === 'PUT') { records.set(id, { id, ...JSON.parse(init.body) }); return Response.json(records.get(id)); }
    assert.equal(method, 'DELETE'); records.delete(id); return Response.json({ id });
  } });
  await view.ready(); fill(view); await view.submit(); await view.ready();
  assert.match(view.get('notes').children[0].textContent, /아직 내가 작성한 메모/u);
  view.get('memo-title').value = '연습 제목'; view.get('memo-body').value = '<script>입력은 글자</script>';
  await view.get('memo-form').events.submit({ preventDefault() {} });
  assert.equal(view.get('notes').children[0].children[1].textContent, '<script>입력은 글자</script>');
  await view.get('notes').children[0].children[2].children[0].events.click();
  assert.equal(view.get('memo-save').textContent, '수정 저장');
  view.get('memo-title').value = '수정 제목'; view.get('memo-body').value = '수정 내용';
  await view.get('memo-form').events.submit({ preventDefault() {} });
  assert.equal(records.get(id).title, '수정 제목');
  await view.get('notes').children[0].children[2].children[1].events.click();
  assert.equal(records.size, 0);
  assert.ok(calls.includes(`GET /api/notes/${id}`)); assert.ok(calls.includes(`PUT /api/notes/${id}`));
  view.get('memo-title').value = '초안'; await view.logout(); assert.equal(view.get('memo-title').value, '');
});

test('failed memo write keeps the draft and safe error message', async () => {
  const view = ui({ noteFetch: async (_path, init) => init.method === 'GET' ? Response.json([])
    : Response.json({ error: 'INVALID_NOTE' }, { status: 400 }) });
  await view.ready(); fill(view); await view.submit(); await view.ready();
  view.get('memo-title').value = '초안 유지'; view.get('memo-body').value = '연습';
  await view.get('memo-form').events.submit({ preventDefault() {} });
  assert.equal(view.get('memo-title').value, '초안 유지'); assert.match(view.get('memo-message').textContent, /200자/u);
});

test('both account read-only checks validate own 200 and other 404; missing or readable fixtures never count as success', async () => {
  const a = '10000000-0000-4000-8000-000000000001'; const b = '20000000-0000-4000-8000-000000000001';
  for (const [email, own, other] of [['learner-a@example.com',a,b],['learner-b@example.com',b,a]]) {
    const calls = []; const view = ui({ initial: profile(email), noteFetch: async (path, init) => {
      calls.push(path); assert.equal(init.method, 'GET'); assert.equal(init.body, undefined);
      if (path === '/api/notes') return Response.json([]);
      if (path === `/api/notes/${own}`) return Response.json({ id: own, title: 'not shown', body: 'not shown' });
      assert.equal(path, `/api/notes/${other}`); return Response.json({ error: 'NOT_FOUND' }, { status: 404 });
    } });
    await view.ready(); await view.checkOwner(); assert.match(view.get('owner-check-result').textContent, /확인 완료.*200.*404/u);
    assert.doesNotMatch(view.get('owner-check-result').textContent, /not shown/u);
    assert.ok(calls.includes(`/api/notes/${own}`)); assert.ok(calls.includes(`/api/notes/${other}`));
  }
  for (const missing of [false, true]) {
    const view = ui({ initial: profile(), noteFetch: async path => path === '/api/notes' ? Response.json([])
      : missing ? Response.json({ error: 'NOT_FOUND' }, { status: 404 })
        : Response.json({ id: path.split('/').at(-1), title: 'foreign fixture', body: 'foreign fixture' }) });
    await view.ready(); await view.checkOwner(); assert.doesNotMatch(view.get('owner-check-result').textContent, /확인 완료|foreign fixture/u);
  }
});

test('logout clears pending cross-account results and waits for an in-flight session refresh', async () => {
  let release; const view = ui({ initial: profile(), noteFetch: async path => {
    if (path === '/api/notes') return Response.json([]);
    if (path.endsWith('10000000-0000-4000-8000-000000000001')) return Response.json({ id: path.split('/').at(-1), title: 'own', body: 'own' });
    return new Promise(resolve => { release = resolve; });
  } });
  await view.ready(); const pending = view.checkOwner(); await view.ready();
  await view.logout(); release(Response.json({ error: 'NOT_FOUND' }, { status: 404 })); await pending;
  assert.equal(view.get('owner-check-result').textContent, ''); assert.equal(view.get('memo-panel').hidden, true);
  let finishRefresh; let gets = 0; const order = [];
  const refreshView = ui({ authFetch: async init => {
    if (init.method === 'GET') { gets++; if (gets > 1) return new Promise(resolve => { finishRefresh = resolve; }); return Response.json(profile()); }
    order.push('logout'); return Response.json({ user: null });
  }, noteFetch: async () => Response.json([]) });
  await refreshView.ready(); refreshView.timers.at(-1).callback(); await refreshView.ready();
  const logout = refreshView.logout(); await tick(); assert.equal(order.length, 0);
  finishRefresh(Response.json(profile())); await logout;
  assert.deepEqual(order, ['logout']); assert.equal(refreshView.get('memo-panel').hidden, true);
});
