import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspectConnection } from '../src/decider-input.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';

async function decision(input) {
  const output = await decide(input);
  assert.equal(Object.keys(output).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
  assert.equal(output.schema, 'aleph.decision.v1');
  assert.equal(output.requestId, input.requestId);
  assert.ok(output.ruleIds.length > 0 && output.ruleIds.every(id => RULE_IDS.includes(id)));
  return output;
}

test('connection input distinguishes judge fixtures from explicitly unavailable live signals', () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal(inspectConnection(normal).kind, 'fixture');
  assert.equal(inspectConnection(suspicious).kind, 'fixture');
  const live = { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown' } };
  const before = structuredClone(live);
  assert.deepEqual(inspectConnection(live), { kind: 'unavailable' });
  assert.deepEqual(live, before);
});

test('missing, malformed and untrusted evidence is never filled with normal fixture values', () => {
  const { normal } = fixtureRequests();
  const invalid = [
    { ...normal, signals: undefined },
    ...['region', 'network', 'hour'].map(key => {
      const input = structuredClone(normal);
      delete input.signals[key];
      return input;
    }),
    ...['client', 'unknown', '', undefined].map(source => ({
      ...normal, signals: { ...normal.signals, source },
    })),
    ...[-1, 24, 3.5, '3', null].map(hour => ({ ...normal, signals: { ...normal.signals, hour } })),
    ...[undefined, {}, [null], [{ kind: 'risk_signal', ageSeconds: -1, count: 20 }],
      [{ kind: 'risk_signal', ageSeconds: 60, count: '20' }],
      Array(13).fill({ kind: 'risk_signal', ageSeconds: 60, count: 20 })]
      .map(recentEvents => ({ ...normal, recentEvents })),
    ...[undefined, { verified: 'true', authAgeSeconds: 60 },
      { verified: false, authAgeSeconds: 0 }, { verified: true, authAgeSeconds: 901 }]
      .map(stepUp => ({ ...normal, stepUp })),
  ];
  for (const input of invalid) assert.equal(inspectConnection(input).kind, 'invalid');
});

test('forged client headers cannot promote absent or untrusted signals to judge evidence', () => {
  const { normal } = fixtureRequests();
  const headers = { 'x-signals-source': 'judge_fixture', 'x-region': 'local',
    'x-network': 'usual', 'x-hour': '14', 'x-step-up-verified': 'true' };
  assert.equal(inspectConnection({ ...normal, headers, signals: undefined }).kind, 'invalid');
  assert.equal(inspectConnection({ ...normal, headers,
    signals: { source: 'client', region: 'local', network: 'usual', hour: 14 } }).kind, 'invalid');
  assert.equal(inspectConnection({ ...normal, headers,
    signals: { source: 'none', region: 'unknown', network: 'unknown' } }).kind, 'unavailable');
});

test('registered ordinary fixture is allowed; the three-signal compound requires step-up', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decision(normal)).decision, 'allow');
  const challenged = await decision(suspicious);
  assert.equal(challenged.decision, 'step_up');
  assert.equal(challenged.reasonCode, 'step_up_required');
  assert.deepEqual(challenged.ruleIds, ['device_registered', 'step_up_required']);
  assert.equal('notes' in challenged, false);
});

test('region alone and incomplete combinations are allowed; time/count/age boundaries stay explicit', async () => {
  const { normal, suspicious } = fixtureRequests();
  const ordinary = [
    { ...normal, signals: { ...normal.signals, region: 'foreign' } },
    { ...suspicious, signals: { ...suspicious.signals, hour: 6 } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
    { ...suspicious, recentEvents: [] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 19 }] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 61, count: 20 }] },
    { ...suspicious, recentEvents: [{ kind: 'other_event', ageSeconds: 60, count: 20 }] },
  ];
  for (const input of ordinary) assert.equal((await decision(input)).decision, 'allow');
  for (const hour of [0, 5]) {
    assert.equal((await decision({ ...suspicious,
      signals: { ...suspicious.signals, region: 'local', hour } })).decision, 'step_up');
  }
});

test('only a well-formed fixture recheck permits the compound; missing/expired evidence stays step-up', async () => {
  const { suspicious } = fixtureRequests();
  const rechecked = { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } };
  assert.equal((await decision(rechecked)).decision, 'allow');
  for (const stepUp of [undefined, { verified: true },
    { verified: true, authAgeSeconds: 61 }, { verified: true, authAgeSeconds: 900 },
    { verified: true, authAgeSeconds: 901 }, { verified: 'true', authAgeSeconds: 60 }]) {
    const result = await decision({ ...suspicious, stepUp });
    assert.equal(result.decision, 'step_up');
  }
  assert.equal((await decision({ ...rechecked,
    signals: { ...rechecked.signals, source: 'client' } })).decision, 'step_up');
});

test('device denial takes precedence over compound signals and a simulated successful recheck', async () => {
  const { suspicious } = fixtureRequests();
  for (const deviceRegistered of [false, undefined, null, 'true']) {
    const result = await decision({ ...suspicious, deviceRegistered,
      stepUp: { verified: true, authAgeSeconds: 60 } });
    assert.equal(result.decision, 'deny');
    assert.equal(result.reasonCode, 'device_not_registered');
    assert.deepEqual(result.ruleIds, ['device_registered']);
  }
});

test('decider reads only contract fields and never promotes browser headers or unavailable signals', async () => {
  const { normal } = fixtureRequests();
  const allowed = new Set(['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
    'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at', 'policyRevision',
    'deviceRegistered', 'stepUp', 'recentEvents', 'signals']);
  const request = new Proxy(normal, { get(target, key) {
    assert.ok(allowed.has(key), `unexpected request field: ${String(key)}`);
    return target[key];
  } });
  assert.equal((await decision(request)).decision, 'allow');
  const live = { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown' },
    headers: { 'x-signals-source': 'judge_fixture', 'x-region': 'foreign', 'x-hour': '3',
      'x-network': 'unusual', 'x-risk-count': '20', 'x-step-up-verified': 'true' } };
  const result = await decision(live);
  assert.equal(result.decision, 'allow');
  assert.deepEqual(result.ruleIds, ['device_registered']);
  assert.equal((await decision({ ...normal, signals: undefined, headers: live.headers })).decision, 'step_up');
});
