import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';
import { cookieAuthorization, trustedBrowserRequest } from './browser-session.mjs';
import { bindDeviceSession, readDeviceApproval, sessionDeviceId } from './device-approval.mjs';
import { RULE_IDS } from './decider.mjs';
import { RECOVERY_TARGET } from './recovery-target.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
const SHA = /^[a-f0-9]{40}$/u;
const keys = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === names.split(',').sort().join(',');
const at = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
const count = value => Number.isSafeInteger(value) && value >= 0;
const maybeAt = value => value === null || at(value);

// Validate the whole allowlisted shape before returning/logging DB data. An
// unexpected title, body, token or identity key must never reach the dashboard.
export function validOperationsRecord(value, commit) {
  if (!keys(value,'schema,requestId,checkedAt,commit,scope,policy,detection,revocation,recovery,officialTests')
      || value.schema !== 'aleph.operations.record.v1' || !UUID.test(value.requestId || '')
      || !at(value.checkedAt) || value.commit !== commit || value.scope !== 'current_login_session') return false;
  const { policy, detection, revocation, recovery, officialTests } = value;
  if (!keys(policy,'ruleIds,decisionTests') || !Array.isArray(policy.ruleIds)
      || policy.ruleIds.join(',') !== RULE_IDS.join(',') || policy.decisionTests !== 'not_executed'
      || !keys(detection,'state,events,proposals') || detection.state !== 'not_executed'
      || detection.events !== null || detection.proposals !== null
      || !keys(officialTests,'total,state,passed') || officialTests.total !== 41
      || officialTests.state !== 'not_executed' || officialTests.passed !== null
      || !keys(revocation,'scope,sessionStatus,events,lastRevokedAt,engineExecution')
      || revocation.scope !== 'student_session_registry' || revocation.sessionStatus !== 'approved'
      || !count(revocation.events) || !maybeAt(revocation.lastRevokedAt)
      || (revocation.events === 0) !== (revocation.lastRevokedAt === null)
      || revocation.engineExecution !== 'not_executed'
      || !keys(recovery,'state,version,backedUpAt,backupVerified,liveMatchesBackup,restoreEvents,lastRestoredAt')) return false;
  if (recovery.state === 'not_available_for_this_account') {
    return ['version','backedUpAt','backupVerified','liveMatchesBackup','restoreEvents','lastRestoredAt']
      .every(key => recovery[key] === null);
  }
  return recovery.state === 'available' && /^[a-f0-9]{64}$/u.test(recovery.version || '')
    && at(recovery.backedUpAt) && typeof recovery.backupVerified === 'boolean'
    && (!recovery.backupVerified || recovery.version === RECOVERY_TARGET.contentSha256)
    && typeof recovery.liveMatchesBackup === 'boolean' && count(recovery.restoreEvents)
    && maybeAt(recovery.lastRestoredAt)
    && (recovery.restoreEvents === 0) === (recovery.lastRestoredAt === null);
}

export function createOperationsHandler({ deploymentConfig = config, env = process.env,
  fetchImpl = globalThis.fetch, runtimeFactory, log = value => console.info(value) } = {}) {
  let runtime;
  return async function handler(request, response) {
    response.setHeader('Cache-Control','private, no-store');
    response.setHeader('Vary','Cookie, Authorization');
    response.setHeader('X-Content-Type-Options','nosniff');
    const fail = (status,error) => response.status(status).json({error});
    if (request.method !== 'GET') return fail(405,'METHOD_NOT_ALLOWED');
    let url;
    try { url = new URL(request.url || '/api/operations','https://app.invalid'); }
    catch { return fail(400,'INVALID_OPERATIONS_PATH'); }
    if (url.pathname !== '/api/operations' || url.search || url.hash) return fail(400,'INVALID_OPERATIONS_PATH');
    if (!trustedBrowserRequest(request,deploymentConfig)) return fail(403,'ORIGIN_NOT_ALLOWED');
    const authorization = cookieAuthorization(request);
    if (!authorization) return fail(401,'AUTH_REQUIRED');
    try {
      if (!runtime) {
        if (runtimeFactory) runtime = runtimeFactory();
        else {
          const url = env.SUPABASE_URL?.trim(), key = env.SUPABASE_SECRET_KEY?.trim();
          if (!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url || '')
              || !/^sb_secret_[A-Za-z0-9_-]+$/u.test(key || '')
              || deploymentConfig.identityProvider?.issuer !== `${url.replace(/\/$/u,'')}/auth/v1`) return fail(503,'SERVER_NOT_CONFIGURED');
          const db = createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false},global:{fetch:fetchImpl}});
          runtime = {db,verifyLogin:createLoginVerifier({config:deploymentConfig,supabaseClient:db})};
        }
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity) return fail(401,'AUTH_REQUIRED');
      const bound = await bindDeviceSession(runtime.db,identity,authorization);
      if (!sessionDeviceId(bound)) return fail(403,'DEVICE_SESSION_REQUIRED');
      const device = await readDeviceApproval(runtime.db,bound);
      if (device.status !== 'approved') return fail(device.status === 'unavailable' ? 503 : 403,
        device.status === 'unavailable' ? 'DEVICE_CHECK_UNAVAILABLE' : 'DEVICE_APPROVAL_REQUIRED');
      const commit = env.VERCEL_GIT_COMMIT_SHA;
      if (!SHA.test(commit || '')) return fail(503,'DEPLOYMENT_REVISION_UNAVAILABLE');
      const {data,error} = await runtime.db.rpc('aleph_step12_operations_snapshot',{
        p_user_id:bound.userId,p_session_id:bound.sessionId,p_commit:commit,p_rule_ids:[...RULE_IDS],
      }).abortSignal(AbortSignal.timeout(10000));
      if (error || !validOperationsRecord(data,commit)) return fail(503,'OPERATIONS_RECORD_UNAVAILABLE');
      response.setHeader('X-Request-ID',data.requestId);
      // Exactly the same redacted record is stored by SQL and returned to the UI.
      log(JSON.stringify(data));
      return response.status(200).json(data);
    } catch { return fail(503,'OPERATIONS_RECORD_UNAVAILABLE'); }
  };
}
export default createOperationsHandler();
