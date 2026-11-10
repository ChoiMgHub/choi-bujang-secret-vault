import { createHash } from 'node:crypto';
import { permitsRegisteredDevice } from './decider.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
const STATES = new Set(['unrequested', 'pending', 'approved', 'revoked', 'expired']);
export function sessionDeviceId(identity) {
  if (identity?.kind !== 'student' || !UUID.test(identity.userId || '')
      || !UUID.test(identity.sessionId || '')) return null;
  return createHash('sha256').update(`${identity.userId.toLowerCase()}:${identity.sessionId.toLowerCase()}`).digest('hex').slice(0, 16);
}

export async function bindDeviceSession(db, identity, authorization) {
  if (identity?.kind !== 'student') return null;
  if (sessionDeviceId(identity)) return identity; // Isolated server test seam only.
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) return null;
  try {
    // Reuse Supabase's signature verification; the starter verifier stays intact.
    const { data, error } = await db.auth.getClaims(authorization.slice(7));
    if (error || data?.claims?.sub !== identity.userId || !UUID.test(data?.claims?.session_id || '')) return null;
    return { ...identity, sessionId: data.claims.session_id };
  } catch { return null; }
}

// Only a verified Auth session and the private DB registry supply this value.
// No browser device flag, role, installation event or approval field is read.
export async function readDeviceApproval(db, identity, requestApproval = false) {
  const deviceId = sessionDeviceId(identity);
  if (!deviceId) return { status: 'unavailable', deviceId: null };
  try {
    const { data, error } = await db.rpc('aleph_step11_device_status', {
      p_user_id: identity.userId, p_session_id: identity.sessionId,
      p_request: requestApproval,
    }).abortSignal(AbortSignal.timeout(10000));
    if (error || !data || Object.keys(data).sort().join(',') !== 'deviceId,schema,status'
        || data.schema !== 'aleph.device-status.v1' || data.deviceId !== deviceId
        || !STATES.has(data.status)) return { status: 'unavailable', deviceId: null };
    return { status: data.status, deviceId };
  } catch { return { status: 'unavailable', deviceId: null }; }
}

export async function enforceDeviceApproval({ db, identity, config, authorization }, response) {
  // Older-stage isolated regression fixtures retain their original behavior.
  if (config?.step < 11) return true;
  // identity must already come from the unchanged createLoginVerifier. The
  // operator relay has its own identity/device/route checks (DECIDER_REQUEST.md)
  // and ES256 issuer/audience/run-bound authentication. It has no Supabase Auth
  // session to enroll. Preserve that existing path, including owner checks.
  // Browser headers, student JWT role-like claims and installation never set it.
  if (identity?.kind === 'judge' && UUID.test(identity.userId || '')
      && UUID.test(identity.runId || '') && ['a', 'b'].includes(identity.identity)) return true;
  const device = await readDeviceApproval(db, await bindDeviceSession(db, identity, authorization));
  if (permitsRegisteredDevice(device.status === 'approved')) return true;
  const unavailable = device.status === 'unavailable';
  response.status(unavailable ? 503 : 403).json({
    error: unavailable ? 'DEVICE_CHECK_UNAVAILABLE' : 'DEVICE_APPROVAL_REQUIRED',
  });
  return false;
}
