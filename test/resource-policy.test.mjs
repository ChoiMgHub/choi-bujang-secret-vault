import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';

function input(service, method, path, route) {
  return { ...fixtureRequests().normal, service, method, path, route };
}
async function result(request, expected) {
  const out = await decide(request);
  assert.equal(out.decision, expected);
  assert.equal(Object.keys(out).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
  assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)));
  assert.equal(out.requestId, request.requestId);
  if (expected === 'deny') assert.equal(out.reasonCode, 'resource_not_allowed');
}

test('zone policy allows only item note paths, without requiring UUID fixture IDs', async () => {
  for (const base of ['/notes', '/api/notes']) {
    for (const method of ['GET', 'PUT', 'DELETE']) {
      await result(input('notes', method, `${base}/demo`, `${method} ${base}/:id`), 'allow');
    }
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
      await result(input('notes', method, base, `${method} ${base}`), 'deny');
    }
  }
});

test('class notices are GET-only, even if a caller adds instructor role claims', async () => {
  for (const base of ['/notices', '/api/notices']) {
    for (const item of ['', '/sample']) {
      await result(input('notices', 'GET', base + item, `GET ${base}${item ? '/:id' : ''}`), 'allow');
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        await result({ ...input('notices', method, base + item, `${method} ${base}${item ? '/:id' : ''}`),
          role: 'instructor' }, 'deny');
      }
    }
  }
});

test('instructor resources and unknown or mismatched service/routes are never granted', async () => {
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    await result(input('instructor', method, '/api/instructor/sample', `${method} /api/instructor/:id`), 'deny');
  }
  for (const request of [
    input('notes', 'GET', '/api/instructor/sample', 'GET /api/instructor/:id'),
    input('notices', 'GET', '/api/notes/demo', 'GET /api/notes/:id'),
    input('unknown', 'GET', '/api/unknown/demo', 'GET /api/unknown/:id'),
    input('notes', 'GET', '/api/notes/demo', 'GET /api/notes'),
    input('notes', 'GET', '/api/notes/demo/extra', 'GET /api/notes/:id'),
  ]) await result(request, 'deny');
});

test('query selectors, encoded/ambiguous paths and reserved action names cannot become note IDs', async () => {
  for (const name of ['export', 'EXPORT', 'search', 'bulk', 'admin', 'e%78port', 'a%2fb', 'a/b', 'demo/']) {
    await result(input('notes', 'GET', `/api/notes/${name}`, 'GET /api/notes/:id'), 'deny');
  }
  await result({ ...input('notes', 'GET', '/api/notes/demo', 'GET /api/notes/:id'), queryLength: 9 }, 'deny');
  await result({ ...input('notes', 'GET', '/api/notes/demo', 'GET /api/notes/:id'), subjectId: '' }, 'deny');
});

test('resource restrictions still apply when live risk signals are unavailable or fixture recheck succeeded', async () => {
  const { suspicious } = fixtureRequests();
  for (const connection of [
    { signals: { source: 'none', region: 'unknown', network: 'unknown' } },
    { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } },
  ]) {
    await result({ ...input('notes', 'GET', '/api/notes', 'GET /api/notes'), ...connection,
      service: 'notes', method: 'GET', path: '/api/notes', route: 'GET /api/notes' }, 'deny');
  }
});
