import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const sw = await readFile(new URL('../public/service-worker.js', import.meta.url), 'utf8');
function worker({ online = true, notice = true } = {}) {
  const handlers = {}, network = [], writes = [], opened = [], removed = [];
  const cached = new Response('offline notice', { headers: { 'content-type': 'text/html' } });
  const scope = {
    self: { location: { origin: 'https://vault.example' }, clients: { claim: async () => {} },
      addEventListener: (name, handler) => { handlers[name] = handler; } },
    caches: {
      open: async name => { opened.push(name); return { add: async request => { writes.push(request); } }; },
      keys: async () => ['vault-offline-notice-old', 'unrelated-app'],
      delete: async name => { removed.push(name); },
      match: async (path, options) => { assert.equal(path, '/offline.html'); assert.equal(options.cacheName, 'vault-offline-notice-v1'); return notice ? cached : undefined; },
    },
    fetch: async (request, options) => { network.push({ request, options }); if (!online) throw new TypeError('offline'); return new Response('network response'); },
    URL, Response,
    Request: class extends Request { constructor(path, init) { super(new URL(path, 'https://vault.example'), init); } },
  };
  vm.runInNewContext(sw, scope);
  function event(request) { const state = { response: null }; handlers.fetch({ request,
    respondWith: value => { state.response = value; } }); return state; }
  return { handlers, event, network, writes, opened, removed };
}

test('PWA manifest has actual install icons, and installation never claims device approval', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/app.webmanifest', import.meta.url), 'utf8'));
  assert.equal(manifest.start_url, '/'); assert.equal(manifest.scope, '/'); assert.equal(manifest.display, 'standalone');
  for (const icon of manifest.icons) {
    const png = await readFile(new URL(`../public${icon.src}`, import.meta.url));
    assert.equal(png.subarray(1, 4).toString(), 'PNG');
    const [width, height] = icon.sizes.split('x').map(Number);
    assert.equal(png.readUInt32BE(16), width); assert.equal(png.readUInt32BE(20), height);
  }
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /rel="manifest" href="\/app.webmanifest"/u);
  assert.match(html, /서버 확인 기능을 준비 중/u);
  assert.match(html, /설치 여부는 기기 승인 근거가 아닙니다/u);
});

test('offline install caches only a public notice without credentials and preserves unrelated caches', async () => {
  const view = worker(); let pending;
  view.handlers.install({ waitUntil: value => { pending = value; } }); await pending;
  assert.equal(view.writes.length, 1);
  assert.equal(new URL(view.writes[0].url).pathname, '/offline.html');
  assert.equal(view.writes[0].credentials, 'omit');
  view.handlers.activate({ waitUntil: value => { pending = value; } }); await pending;
  assert.deepEqual(view.removed, ['vault-offline-notice-old']);
});

test('offline worker never intercepts APIs, writes, scripts or cross-origin requests', () => {
  const view = worker({ online: false });
  for (const request of [
    { url: 'https://vault.example/api/auth', mode: 'navigate', method: 'GET' },
    { url: 'https://vault.example/api/notes/id', mode: 'navigate', method: 'GET' },
    { url: 'https://vault.example/api', mode: 'navigate', method: 'GET' },
    { url: 'https://vault.example/', mode: 'navigate', method: 'POST' },
    { url: 'https://vault.example/auth-ui.js', mode: 'same-origin', method: 'GET' },
    { url: 'https://other.example/', mode: 'navigate', method: 'GET' },
  ]) assert.equal(view.event(request).response, null);
  assert.equal(view.writes.length, 0); assert.equal(view.network.length, 0);
});

test('navigation uses network without caching its response and offline fallback contains no protected response', async () => {
  const request = { url: 'https://vault.example/', mode: 'navigate', method: 'GET' };
  const online = worker(); assert.equal(await (await online.event(request).response).text(), 'network response');
  assert.equal(online.network[0].options.cache, 'no-store'); assert.equal(online.writes.length, 0);
  const offline = worker({ online: false }); assert.equal(await (await offline.event(request).response).text(), 'offline notice');
  const missing = worker({ online: false, notice: false }); assert.equal((await missing.event(request).response).status, 503);
});

test('PWA installation and offline status UI do not fetch data or change approval state', async () => {
  const source = await readFile(new URL('../public/pwa-ui.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|document\.cookie|access_token|refresh_token|[\u3040-\u30ff]/u);
  const events = {}, controls = new Map();
  for (const id of ['app-install', 'app-install-status', 'connection-status']) controls.set(`#${id}`, {
    hidden: true, textContent: '', addEventListener: (name, handler) => { events[`${id}:${name}`] = handler; },
  });
  const device = { textContent: 'server confirmation pending' }; controls.set('#device-approval-status', device);
  const navigator = { onLine: true, serviceWorker: { register: async (path, options) => {
    assert.equal(path, '/service-worker.js'); assert.equal(options.updateViaCache, 'none');
  } } };
  vm.runInNewContext(source, { window: { matchMedia: () => ({ matches: false }), addEventListener: (name, handler) => { events[name] = handler; } },
    navigator, document: { querySelector: id => controls.get(id) },
    fetch: () => { assert.fail('installation must not fetch or approve protected data'); } });
  events.beforeinstallprompt({ preventDefault() {}, prompt: async () => {}, userChoice: Promise.resolve({ outcome: 'accepted' }) });
  await events['app-install:click'](); assert.equal(device.textContent, 'server confirmation pending');
  assert.match(controls.get('#app-install-status').textContent, /기기 승인은 별도/u);
  navigator.onLine = false; events.offline(); assert.match(controls.get('#connection-status').textContent, /오프라인/u);
  assert.equal(device.textContent, 'server confirmation pending');
});
