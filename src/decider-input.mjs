// Only the engine's documented fields are inspected. Browser headers are never inputs.
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonnegativeInteger = value => Number.isSafeInteger(value) && value >= 0;

export function inspectConnection(request) {
  const signals = request?.signals;
  if (!record(signals)) return { kind: 'invalid' };

  // The current live contract explicitly supplies no location/network evidence.
  // Preserve that absence; do not manufacture a normal region, network or hour.
  if (signals.source === 'none') {
    return signals.region === 'unknown' && signals.network === 'unknown'
      ? { kind: 'unavailable' } : { kind: 'invalid' };
  }
  if (signals.source !== 'judge_fixture') return { kind: 'invalid' };

  const recentEvents = request.recentEvents;
  const stepUp = request.stepUp;
  if (typeof signals.region !== 'string' || !signals.region.trim()
      || signals.region === 'unknown'
      || !['usual', 'unusual'].includes(signals.network)
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23
      || !Array.isArray(recentEvents) || recentEvents.length > 12
      || recentEvents.some(event => !record(event)
        || typeof event.kind !== 'string' || !event.kind.trim()
        || !nonnegativeInteger(event.ageSeconds) || !nonnegativeInteger(event.count))
      || !record(stepUp) || typeof stepUp.verified !== 'boolean'
      || (stepUp.verified
        ? !nonnegativeInteger(stepUp.authAgeSeconds) || stepUp.authAgeSeconds > 900
        : stepUp.authAgeSeconds !== null)) {
    return { kind: 'invalid' };
  }
  return { kind: 'fixture', signals, recentEvents, stepUp };
}
