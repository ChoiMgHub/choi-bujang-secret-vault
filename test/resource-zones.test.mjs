import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESOURCE_ZONES, identifyResourcePath } from '../src/resource-zones.mjs';
import { createNotesHandler } from '../api/notes.js';

test('notes, class notices and instructor materials have distinct server resource IDs', () => {
  assert.equal(new Set(Object.values(RESOURCE_ZONES).map(zone => zone.id)).size, 3);
  for (const zone of Object.values(RESOURCE_ZONES)) {
    for (const base of [zone.apiBase, zone.engineBase]) {
      const collection = identifyResourcePath(base);
      assert.equal(collection.zoneId, zone.id);
      assert.equal(collection.service, zone.service);
      assert.equal(collection.itemId, null);
      assert.deepEqual(identifyResourcePath(`${base}/sample-id-not-a-uuid`), {
        zoneId: zone.id, service: zone.service,
        resourceId: `${zone.id}:item:sample-id-not-a-uuid`, itemId: 'sample-id-not-a-uuid',
      });
    }
  }
});

test('resource matching does not classify similar prefixes, nested paths or query selectors', () => {
  for (const path of ['/api/notes-other/a', '/api/notices-old', '/api/instructor-copy/a',
    '/api/notes/a/more', '/api/notes//', '/api/notes/.', '/api/notes/..',
    '/api/notes/a?action=export', '/api/notes/a#export', '/api/notes\\a', null]) {
    assert.equal(identifyResourcePath(path), null);
  }
});

test('resource item IDs stay distinct across both items and zones without changing note addresses', () => {
  const a = identifyResourcePath('/api/notes/a');
  const b = identifyResourcePath('/api/notes/b');
  const notice = identifyResourcePath('/api/notices/a');
  assert.notEqual(a.resourceId, b.resourceId);
  assert.notEqual(a.resourceId, notice.resourceId);
  assert.deepEqual(a, identifyResourcePath('/notes/a'));
  assert.deepEqual(a, identifyResourcePath('/api/notes/a/'));
});

test('note API derives its zone from the path; client zone and role claims cannot bypass login', async () => {
  const handler = createNotesHandler({ env: {} });
  const response = { code: null, headers: {}, body: null,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await handler({ method: 'GET', url: '/api/notes/00000000-0000-4000-8000-000000000001',
    headers: { 'x-resource-zone': 'instructor_materials', 'x-role': 'teacher' } }, response);
  assert.equal(response.headers['x-resource-zone'], 'student_notes');
  assert.equal(response.code, 401);
  assert.deepEqual(response.body, { error: 'AUTH_REQUIRED' });
});
