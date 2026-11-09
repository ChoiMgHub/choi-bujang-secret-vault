import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { cookieAuthorization, trustedBrowserRequest } from '../src/browser-session.mjs';
import { bindDeviceSession, readDeviceApproval, sessionDeviceId } from '../src/device-approval.mjs';

export function createDeviceHandler({ deploymentConfig = config, env = process.env,
  fetchImpl = globalThis.fetch, runtimeFactory } = {}) {
  let runtime;
  return async (request, response) => {
    response.setHeader('Cache-Control', 'private, no-store');
    response.setHeader('Vary', 'Cookie, Authorization');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => response.status(status).json({ error });
    if (!['GET', 'POST'].includes(request.method)) return fail(405, 'METHOD_NOT_ALLOWED');
    const path = new URL(request.url || '/api/device', 'https://app.invalid');
    if (path.pathname !== '/api/device' || path.search || path.hash) return fail(400, 'INVALID_DEVICE_PATH');
    if (!trustedBrowserRequest(request, deploymentConfig)) return fail(403, 'ORIGIN_NOT_ALLOWED');
    const authorization = cookieAuthorization(request);
    if (!authorization) return fail(401, 'AUTH_REQUIRED');
    // POST is a request, never an approval or a client-selected device identity.
    if (request.method === 'POST') {
      if (!request.headers?.['content-type']?.toLowerCase().startsWith('application/json')) return fail(415, 'JSON_REQUIRED');
      try {
        const body = typeof request.body === 'string' || Buffer.isBuffer(request.body)
          ? JSON.parse(String(request.body)) : request.body;
        if (!body || Array.isArray(body) || typeof body !== 'object' || Object.keys(body).length) return fail(400, 'INVALID_DEVICE_INPUT');
      } catch { return fail(400, 'INVALID_DEVICE_INPUT'); }
    }
    try {
      if (!runtime) {
        if (runtimeFactory) runtime = runtimeFactory();
        else {
          const url = env.SUPABASE_URL?.trim(), key = env.SUPABASE_SECRET_KEY?.trim();
          if (!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url || '')
              || !/^sb_secret_[A-Za-z0-9_-]+$/u.test(key || '')
              || deploymentConfig.identityProvider?.issuer !== `${url.replace(/\/$/u, '')}/auth/v1`) return fail(503, 'SERVER_NOT_CONFIGURED');
          const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false,
            detectSessionInUrl: false }, global: { fetch: fetchImpl } });
          runtime = { db, verifyLogin: createLoginVerifier({ config: deploymentConfig, supabaseClient: db }) };
        }
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity) return fail(401, 'AUTH_REQUIRED');
      const bound = await bindDeviceSession(runtime.db, identity, authorization);
      if (!sessionDeviceId(bound)) return fail(403, 'DEVICE_SESSION_REQUIRED');
      const device = await readDeviceApproval(runtime.db, bound, request.method === 'POST');
      if (device.status === 'unavailable') return fail(503, 'DEVICE_CHECK_UNAVAILABLE');
      return response.status(200).json({ schema: 'aleph.device-status.v1', ...device });
    } catch { return fail(503, 'DEVICE_CHECK_UNAVAILABLE'); }
  };
}
export default createDeviceHandler();
