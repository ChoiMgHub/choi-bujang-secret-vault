import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';
import { createClient } from '@supabase/supabase-js';

const source = await readFile(new URL('../public/auth-ui.js', import.meta.url), 'utf8');
function ui(factory, fetchImpl = async () => Response.json({ notes: [{ id: '1', title: '<img src=x onerror=alert(1)>', content: '가상 메모' }] })) {
  const elements = new Map();
  for (const id of ['login-form', 'login-email', 'login-password', 'login-button', 'logout-button', 'auth-status', 'auth-error', 'notes']) {
    elements.set(`#${id}`, { value: '', textContent: '', hidden: id === 'login-form' || id === 'logout-button', disabled: false,
      children: [], append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, events: {}, addEventListener(name, handler) { this.events[name] = handler; } });
  }
  const storageData = new Map();
  const storage = { getItem: key => storageData.get(key) ?? null, setItem: (key, value) => storageData.set(key, value), removeItem: key => storageData.delete(key) };
  const window = { supabase: { createClient: (...args) => factory(...args) }, sessionStorage: storage };
  vm.runInNewContext(source, { window, document: { querySelector: id => elements.get(id), createElement: () => ({ textContent: '', children: [], append(...items) { this.children.push(...items); } }) }, fetch: fetchImpl, AbortController });
  return { get: id => elements.get(`#${id}`), storageData, storage,
    submit: () => elements.get('#login-form').events.submit({ preventDefault() {} }),
    logout: () => elements.get('#logout-button').events.click() };
}
function stub() {
  let listener;
  const state = { loginCalls: 0, logoutCalls: 0, loginError: null, logoutError: null, wait: null };
  const user = { id: '10000000-0000-4000-8000-000000000001', email: 'learner-a@example.com' };
  const factory = (_url, key, options) => {
    assert.ok(key.startsWith('sb_publishable_'));
    assert.equal(options.auth.detectSessionInUrl, false);
    assert.ok(options.auth.storage);
    return { auth: {
      onAuthStateChange(callback) { listener = callback; callback('INITIAL_SESSION', null); },
      async signInWithPassword(credentials) {
        state.loginCalls++;
        assert.equal(credentials.email, 'learner-a@example.com');
        assert.equal(credentials.password, 'test-input');
        if (state.wait) await state.wait;
        if (state.loginError) return { error: state.loginError };
        listener('SIGNED_IN', { user, access_token: 'local-test-session' }); return { data: { session: { user, access_token: 'local-test-session' } }, error: null };
      },
      async signOut(options) {
        state.logoutCalls++;
        assert.equal(options.scope, 'local');
        if (state.logoutError) return { error: state.logoutError };
        listener('SIGNED_OUT', null); return { error: null };
      },
    } };
  };
  return { state, factory };
}
function fill(view) { view.get('login-email').value = ' learner-a@example.com '; view.get('login-password').value = 'test-input'; }

test('login UI changes with SDK session events, clears password and logs out through SDK', async () => {
  const { state, factory } = stub(); const view = ui(factory);
  assert.equal(view.get('login-form').hidden, false);
  assert.match(view.get('auth-status').textContent, /로그인하지 않은/u);
  fill(view); await view.submit();
  assert.equal(view.get('login-form').hidden, true); assert.equal(view.get('logout-button').hidden, false);
  assert.equal(view.get('auth-status').textContent, '로그인 중: learner-a@example.com');
  assert.equal(view.get('login-password').value, '');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('notes').hidden, false);
  assert.equal(view.get('notes').children[0].children[0].textContent, '<img src=x onerror=alert(1)>');
  await view.logout(); assert.equal(state.logoutCalls, 1);
  assert.equal(view.get('login-form').hidden, false); assert.equal(view.get('logout-button').hidden, true);
  assert.equal(view.get('auth-status').textContent, '로그아웃했습니다.');
  assert.equal(view.get('notes').hidden, true); assert.equal(view.get('notes').children.length, 0);
});

test('login failures show safe reasons, double submits call SDK once and failed logout is not reported as success', async () => {
  const { state, factory } = stub(); const view = ui(factory);
  for (const [error, message] of [[{ code: 'invalid_credentials' }, /이메일 또는 비밀번호/u], [{ code: 'email_not_confirmed' }, /이메일 확인/u], [{ status: 429 }, /요청이 많/u], [{ name: 'AuthRetryableFetchError' }, /연결하지 못/u], [{ message: '<script>private-input</script>' }, /로그인에 실패/u]]) {
    state.loginError = error; fill(view); await view.submit();
    assert.match(view.get('auth-error').textContent, message);
    assert.ok(!view.get('auth-error').textContent.includes('private-input'));
    assert.equal(view.get('login-password').value, ''); assert.equal(view.get('login-form').hidden, false);
  }
  state.loginError = null;
  let release; state.wait = new Promise(resolve => { release = resolve; });
  fill(view); const before = state.loginCalls; const pending = view.submit();
  await view.submit(); assert.equal(state.loginCalls, before + 1); release(); await pending;
  state.logoutError = { message: 'network error' }; await view.logout();
  assert.match(view.get('auth-error').textContent, /로그아웃 처리를 확인하지 못/u);
  assert.notEqual(view.get('auth-status').textContent, '로그아웃했습니다.');
});

test('UI connects the installed official SDK to the correct public project and sign-in/sign-out HTTP flows (mock Auth server)', async () => {
  let client; let login = 0; let logout = 0;
  const userId = '10000000-0000-4000-8000-000000000001';
  const encode = object => Buffer.from(JSON.stringify(object)).toString('base64url');
  const access = [encode({ alg: 'HS256', typ: 'JWT' }), encode({ sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 }), 'local-signature'].join('.');
  const view = ui((url, key, options) => {
    assert.equal(url, 'https://prplojzcswmpaqhcnmwl.supabase.co');
    assert.ok(key.startsWith('sb_publishable_'));
    client = createClient(url, key, { ...options, auth: { ...options.auth, autoRefreshToken: false }, global: { fetch: async (target, init) => {
      const parsed = new URL(target);
      assert.equal(parsed.origin, url);
      assert.equal(new Headers(init.headers).get('apikey'), key);
      if (parsed.pathname === '/auth/v1/token') {
        login++;
        assert.equal(parsed.searchParams.get('grant_type'), 'password');
        const data = JSON.parse(init.body);
        assert.equal(data.email, 'learner-a@example.com'); assert.equal(data.password, 'test-input');
        return Response.json({ access_token: access, refresh_token: 'local-refresh', expires_in: 3600, token_type: 'bearer',
          user: { id: userId, email: 'learner-a@example.com', aud: 'authenticated', app_metadata: {}, user_metadata: {} } });
      }
      assert.equal(parsed.pathname, '/auth/v1/logout'); assert.equal(parsed.searchParams.get('scope'), 'local');
      logout++; return new Response(null, { status: 204 });
    } } });
    return client;
  });
  try {
    await client.auth.getSession();
    assert.equal(view.get('login-form').hidden, false);
    fill(view); await view.submit();
    assert.equal(login, 1); assert.equal(view.get('login-form').hidden, true);
    assert.ok([...view.storageData.keys()].some(key => key.endsWith('-auth-token')));
    await view.logout(); assert.equal(logout, 1);
    assert.equal(view.get('login-form').hidden, false);
    assert.ok(![...view.storageData.keys()].some(key => key.endsWith('-auth-token')));
  } finally { client.auth.stopAutoRefresh(); }
});

test('public login code contains no secret key, token writer or custom password verification', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /type="password"/u);
  assert.match(html, /src="\/vendor\/supabase.js" defer/u);
  assert.match(html, /src="\/auth-ui.js" defer/u);
  assert.doesNotMatch(source, /sb_secret_|SUPABASE_SECRET_KEY|localStorage|\.setItem\(|console\.|[\u3040-\u30ff]/u);
  assert.match(source, /signInWithPassword/u); assert.match(source, /signOut/u);
});

test('anonymous UI never requests notes; requests use SDK bearer and late responses cannot restore logged-out data', async () => {
  const { factory } = stub();
  const pending = []; let calls = 0;
  const view = ui(factory, (url, init) => {
    calls++;
    assert.equal(url, '/api/notes'); assert.equal(init.headers.Authorization, 'Bearer local-test-session');
    assert.equal(init.cache, 'no-store'); assert.ok(init.signal);
    return new Promise(resolve => pending.push(resolve));
  });
  assert.equal(calls, 0); assert.equal(view.get('notes').hidden, true);
  fill(view); await view.submit(); assert.ok(calls > 0);
  await view.logout();
  for (const resolve of pending) resolve(Response.json({ notes: [{ title: 'must stay hidden', content: 'late response' }] }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(view.get('notes').hidden, true); assert.equal(view.get('notes').children.length, 0);
});

test('unauthorized API response clears notes and displays a safe reauthentication reason', async () => {
  const { factory } = stub();
  const view = ui(factory, async () => Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 }));
  fill(view); await view.submit(); await new Promise(resolve => setImmediate(resolve));
  assert.match(view.get('notes').children[0].textContent, /로그인 정보를 확인하지 못/u);
});
