import { inspectConnection } from './decider-input.mjs';
import { permitsResource } from './resource-policy.mjs';

// Requests reach this function only after the engine's identity/device/route checks.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

// Local fixture policy, not a measured baseline of the real user.
const EARLY_HOUR_END = 6;
const SIGNAL_MAX_AGE_SECONDS = 60;
const BURST_LIMIT = 20;
const FIXTURE_RECHECK_MAX_AGE_SECONDS = 60;

const response = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds,
});

export async function decide(request) {
  // A fixture recheck must never override the stage 6 device rule.
  if (request?.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', ['device_registered']);
  }

  if (!permitsResource(request)) {
    return response(request, 'deny', 'resource_not_allowed', ['device_registered', 'resource_zone']);
  }

  const connection = inspectConnection(request);
  if (connection.kind === 'unavailable') {
    // Live signals are explicitly unavailable in the supplied contract.
    // Keep stage 6 behavior; this is not a successful stage 7 risk assessment.
    return response(request, 'allow', 'approved', ['device_registered', 'resource_zone']);
  }
  if (connection.kind === 'invalid') {
    return response(request, 'step_up', 'step_up_required', [...RULE_IDS]);
  }

  const earlyHour = connection.signals.hour < EARLY_HOUR_END;
  const unfamiliarNetwork = connection.signals.network === 'unusual';
  const recentBurst = connection.recentEvents.some(event => event.kind === 'risk_signal'
    && event.ageSeconds <= SIGNAL_MAX_AGE_SECONDS && event.count >= BURST_LIMIT);
  const compound = earlyHour && unfamiliarNetwork && recentBurst;

  // verified + age is a simulated recheck only on judge_fixture input.
  // No live challenge, fresh-login binding or data relay is implemented here.
  const fixtureRechecked = connection.stepUp.verified
    && connection.stepUp.authAgeSeconds <= FIXTURE_RECHECK_MAX_AGE_SECONDS;
  if (compound && !fixtureRechecked) {
    return response(request, 'step_up', 'step_up_required', [...RULE_IDS]);
  }
  return response(request, 'allow', 'approved', [...RULE_IDS]);
}
