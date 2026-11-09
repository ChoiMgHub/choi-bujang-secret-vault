// Cache only the generic offline notice, never HTML sessions, scripts, or APIs.
const CACHE = 'vault-offline-notice-v1';
const OFFLINE = '/offline.html';
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.add(new Request(OFFLINE, {
    credentials: 'omit', cache: 'reload',
  }))));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys
    .filter(key => key.startsWith('vault-offline-notice-') && key !== CACHE)
    .map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || request.mode !== 'navigate'
      || url.origin !== self.location.origin || url.pathname === '/api' || url.pathname.startsWith('/api/')) return;
  event.respondWith(fetch(request, { cache: 'no-store' }).catch(async () => {
    const notice = await caches.match(OFFLINE, { cacheName: CACHE });
    return notice || new Response('서버 연결이 필요합니다.', {
      status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }));
});
