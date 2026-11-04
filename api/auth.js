import { createClient } from '@supabase/supabase-js';
import { decodeJwt } from 'jose';
import config from '../aleph.config.json' with { type: 'json' };
import { SUPABASE_PUBLIC_KEY } from '../src/supabase-public.mjs';
import { ACCESS_COOKIE, REFRESH_COOKIE, browserCookies, clearBrowserSession,
  trustedBrowserRequest, writeBrowserSession } from '../src/browser-session.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const invalidAuth = error => [400, 401, 403, 404, 422].includes(error?.status);
const safeUser = user => user && UUID.test(user.id || '') && typeof user.email === 'string'
  && user.email.length <= 254 ? { id: user.id, email: user.email } : null;
function needsRefresh(access) {
  try {
    const exp = decodeJwt(access).exp;
    return !Number.isSafeInteger(exp) || exp <= Date.now() / 1000 + 120;
  } catch { return true; }
}

// decodeJwt is used only for expiry after Supabase has authenticated the token.
// Identity comes from getUser/signInWithPassword/refreshSession, never decoding alone.
function expiry(access, user, bound) {
  try {
    const claims = decodeJwt(access);
    if (claims.sub !== user.id || claims.iss !== bound.identityProvider.issuer
        || claims.aud !== bound.identityProvider.audience || claims.role !== 'authenticated'
        || !Number.isSafeInteger(claims.exp)) return 0;
    return claims.exp;
  } catch { return 0; }
}

export function createAuthHandler({ env = process.env, fetchImpl = globalThis.fetch,
  deploymentConfig = config, clientFactory = createClient } = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'private, no-store, max-age=0');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Vary', 'Cookie');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (!['GET', 'POST', 'DELETE'].includes(request.method)) {
      response.setHeader('Allow', 'GET, POST, DELETE');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    if (!trustedBrowserRequest(request, deploymentConfig)) {
      return response.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
    }
    const url = typeof env.SUPABASE_URL === 'string' ? env.SUPABASE_URL.trim().replace(/\/$/u, '') : '';
    if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/u.test(url)
        || deploymentConfig.identityProvider?.issuer !== `${url}/auth/v1`) {
      return response.status(503).json({ error: 'AUTH_NOT_CONFIGURED' });
    }
    // A fresh SDK client for each request prevents users sharing in-memory state.
    let client;
    try {
      client = clientFactory(url, SUPABASE_PUBLIC_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        global: { fetch: (target, init) => fetchImpl(target, {
          ...init, signal: AbortSignal.timeout(10000),
        }) },
      });
    } catch { return response.status(503).json({ error: 'AUTH_UNAVAILABLE' }); }
    const cookies = browserCookies(request);
    const access = cookies[ACCESS_COOKIE];
    const refresh = cookies[REFRESH_COOKIE];
    const fail = (status, code) => response.status(status).json({ error: code });
    const issue = session => {
      const user = safeUser(session?.user);
      const expiresAt = user ? expiry(session?.access_token, user, deploymentConfig) : 0;
      if (!user || expiresAt <= Date.now() / 1000) {
        throw new Error('invalid_auth_session');
      }
      writeBrowserSession(response, { ...session, expires_at: expiresAt });
      return response.status(200).json({ user, expiresAt });
    };
    try {
      if (request.method === 'POST') {
        if (!request.headers?.['content-type']?.toLowerCase().startsWith('application/json')) {
          return fail(415, 'JSON_REQUIRED');
        }
        let body = request.body;
        try {
          if (Buffer.isBuffer(body)) body = body.toString('utf8');
          if (typeof body === 'string') {
            if (Buffer.byteLength(body) > 8192) return fail(413, 'INPUT_TOO_LARGE');
            body = JSON.parse(body);
          }
          if (!body || typeof body !== 'object' || Array.isArray(body)
              || Buffer.byteLength(JSON.stringify(body)) > 8192
              || Object.keys(body).some(key => !['email', 'password'].includes(key))
              || typeof body.email !== 'string' || !body.email.trim() || body.email.length > 254
              || typeof body.password !== 'string' || !body.password || body.password.length > 1024) {
            return fail(400, 'INVALID_INPUT');
          }
        } catch { return fail(400, 'INVALID_INPUT'); }
        const { data, error } = await client.auth.signInWithPassword({
          email: body.email.trim(), password: body.password,
        });
        if (error) {
          if (error.status === 429) return fail(429, 'TOO_MANY_REQUESTS');
          if (error.code === 'email_not_confirmed') return fail(403, 'EMAIL_NOT_CONFIRMED');
          return invalidAuth(error) ? fail(401, 'INVALID_CREDENTIALS') : fail(503, 'AUTH_UNAVAILABLE');
        }
        return issue(data?.session);
      }
      if (request.method === 'DELETE') {
        let logoutAccess = access;
        if (refresh && (!access || needsRefresh(access))) {
          const { data, error } = await client.auth.refreshSession({ refresh_token: refresh });
          if (error && !invalidAuth(error)) return fail(503, 'AUTH_UNAVAILABLE');
          logoutAccess = data?.session?.access_token;
        }
        if (logoutAccess) {
          const { error } = await client.auth.admin.signOut(logoutAccess, 'local');
          if (error && !invalidAuth(error)) return fail(503, 'AUTH_UNAVAILABLE');
        }
        clearBrowserSession(response);
        return response.status(200).json({ user: null });
      }
      if (access) {
        const { data, error } = await client.auth.getUser(access);
        if (error && !invalidAuth(error)) return fail(503, 'AUTH_UNAVAILABLE');
        const user = safeUser(data?.user);
        const expiresAt = user ? expiry(access, user, deploymentConfig) : 0;
        if (!error && user && expiresAt > Date.now() / 1000 + 120) {
          return response.status(200).json({ user, expiresAt });
        }
      }
      if (refresh) {
        const { data, error } = await client.auth.refreshSession({ refresh_token: refresh });
        if (error && !invalidAuth(error)) return fail(503, 'AUTH_UNAVAILABLE');
        if (!error) return issue(data?.session);
      }
      if (access || refresh) clearBrowserSession(response);
      return response.status(200).json({ user: null });
    } catch {
      // No credential, upstream diagnostics or token is returned or logged.
      return fail(503, 'AUTH_UNAVAILABLE');
    }
  };
}

export default createAuthHandler();
