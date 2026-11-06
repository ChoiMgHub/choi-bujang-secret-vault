import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';

const START = Date.UTC(2026, 9, 1);
const event = (offset = 0, subject = 'learner_fixture', method = 'GET') => ({
  at: new Date(START + offset).toISOString(), method, identity: { sub: subject },
});

test('detection reads only contract fields and never inspects unrelated event or identity data', () => {
  const identity = new Proxy({ sub: 'learner_fixture' }, {
    get(target, key) { assert.equal(key, 'sub'); return target[key]; },
    ownKeys() { throw new Error('unexpected_identity_enumeration'); },
  });
  const input = new Proxy({ at: event().at, method: 'GET', identity }, {
    get(target, key) { assert.ok(['at', 'method', 'identity'].includes(key)); return target[key]; },
    ownKeys() { throw new Error('unexpected_event_enumeration'); },
  });
  assert.deepEqual(detect([input]), { action: 'observe' });
});

test('missing or malformed contract data produces fixed errors without echoing input', () => {
  for (const input of [null, {}, 'events']) {
    assert.throws(() => detect(input), { name: 'TypeError', message: 'invalid_detection_events' });
  }
  for (const input of [null, [], {}, { ...event(), at: 'private fixture detail' },
    { ...event(), at: '2026-10-01' }, { ...event(), at: START },
    { ...event(), method: '' }, { ...event(), identity: {} },
    { ...event(), identity: { sub: ' ' } }]) {
    assert.throws(() => detect([input]), { name: 'TypeError', message: 'invalid_detection_event' });
  }
});

test('empty and normal event batches remain observation-only without changing input', () => {
  assert.deepEqual(detect([]), { action: 'observe' });
  const input = [event(), event(2000)];
  const before = structuredClone(input);
  assert.deepEqual(detect(input), { action: 'observe' });
  assert.deepEqual(input, before);
});

const reads = (count, { subject = 'learner_fixture', spacing = 2000, start = 0,
  method = 'GET' } = {}) => Array.from({ length: count }, (_, i) => event(start + i * spacing, subject, method));
const proposal = (subject = 'learner_fixture') => ({
  action: 'propose_revocation', reasonCode: 'burst_read', subject,
});

test('all six supplied practice batches satisfy exact observe/proposal response contracts', async () => {
  const results = await checkDetection(detect);
  assert.equal(results.length, 6);
  assert.ok(results.every(result => result.passed));
});

test('121 reads spanning exactly ten minutes qualify; moving the last read 1 ms outside does not', () => {
  const input = reads(121, { spacing: 5000 });
  assert.deepEqual(detect(input.slice(0, 120)), { action: 'observe' });
  assert.deepEqual(detect(input), proposal());
  input[120] = event(600001);
  assert.deepEqual(detect(input), { action: 'observe' });
});

test('the rolling window crosses fixed ten-minute buckets and handles out-of-order events', () => {
  const input = reads(121, { start: 9 * 60 * 1000, spacing: 1000 }).reverse();
  const before = structuredClone(input);
  assert.deepEqual(detect(input), proposal());
  assert.deepEqual(input, before);
});

test('a long batch can still contain a short burst, while uniformly slow reads remain observation-only', () => {
  assert.deepEqual(detect([event(-3600000), ...reads(121)]), proposal());
  assert.deepEqual(detect(reads(200, { spacing: 7000 })), { action: 'observe' });
});

test('user counts stay separate and the proposed subject is the one who actually exceeded the limit', () => {
  const first = reads(120);
  const second = reads(120, { subject: 'other_fixture' });
  assert.deepEqual(detect([...first, ...second]), { action: 'observe' });
  assert.deepEqual(detect([...first, ...second, event(240000, 'other_fixture')]), proposal('other_fixture'));
});

test('only exact GET events count and multiple requests at the same instant are counted individually', () => {
  const input = [...reads(120), ...reads(200, { method: 'POST' }), ...reads(200, { method: 'get' })];
  assert.deepEqual(detect(input), { action: 'observe' });
  assert.deepEqual(detect([...input, event(240000)]), proposal());
  assert.deepEqual(detect(reads(121, { spacing: 0 })), proposal());
});

test('equivalent timezone offsets are evaluated as the same timeline', () => {
  const input = reads(121).map((item, i) => i % 2 ? { ...item,
    at: new Date(START + i * 2000 + 9 * 3600000).toISOString().replace('Z', '+09:00') } : item);
  assert.deepEqual(detect(input), proposal());
});

test('calls do not accumulate prior batch state and the rule never uses wall-clock time', () => {
  const original = Date.now;
  try {
    Date.now = () => { throw new Error('wall_clock_not_allowed'); };
    assert.deepEqual(detect(reads(120)), { action: 'observe' });
    assert.deepEqual(detect(reads(120)), { action: 'observe' });
    assert.deepEqual(detect(reads(121)), proposal());
    assert.deepEqual(detect([]), { action: 'observe' });
  } finally { Date.now = original; }
});
