import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { cookieAuthorization, trustedBrowserRequest, usesCookieAuthorization } from './browser-session.mjs';
import { RECOVERY_TARGET } from './recovery-target.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
const RESULT_KEYS = ['schema', 'id', 'restored', 'idMatches', 'ownerMatches',
  'contentHashMatches', 'contentSha256', 'otherNotesUnchanged', 'auditRowsBefore', 'auditRowsAfter'];
const ERRORS = Object.freeze({
  RESTORE_TARGET_DENIED: [404, 'NOT_FOUND'],
  RESTORE_BACKUP_MISSING: [409, 'BACKUP_NOT_READY'],
  RESTORE_BACKUP_HASH_MISMATCH: [409, 'BACKUP_INVALID'],
  RESTORE_BACKUP_IDENTITY_MISMATCH: [409, 'BACKUP_INVALID'],
  RESTORE_OWNER_CHANGED: [409, 'TARGET_OWNER_CHANGED'],
});

export function createRestoreHandler({ config, target = RECOVERY_TARGET,
  env = process.env, fetchImpl = globalThis.fetch, runtimeFactory, judgeKeySet } = {}) {
  let runtime;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'private, no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Vary', 'Cookie, Authorization');
    const deny = (status, error) => response.status(status).json({ error });
    const authorization = cookieAuthorization(request);
    if (!authorization) return deny(401, 'AUTH_REQUIRED');
    if (usesCookieAuthorization(request) && !trustedBrowserRequest(request, config)) {
      return deny(403, 'ORIGIN_NOT_ALLOWED');
    }
    try {
      if (!UUID.test(target?.noteId || '') || !/^[a-f0-9]{64}$/u.test(target?.contentSha256 || '')) {
        return deny(503, 'RESTORE_NOT_CONFIGURED');
      }
      if (!runtime) {
        if (runtimeFactory) runtime = await runtimeFactory();
        else {
          const url = env.SUPABASE_URL?.trim();
          const key = env.SUPABASE_SECRET_KEY?.trim();
          if (!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url || '')
              || !/^sb_secret_[A-Za-z0-9_-]+$/u.test(key || '')
              || config?.identityProvider?.issuer !== `${url.replace(/\/$/u, '')}/auth/v1`) {
            return deny(503, 'RESTORE_NOT_CONFIGURED');
          }
          const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false },
            global: { fetch: (u, init) => fetchImpl(u, { ...init, signal: AbortSignal.timeout(15000) }) } });
          runtime = { db, verifyLogin: createLoginVerifier({ config, supabaseClient: db,
            supabaseSecretKey: key, judgeKeySet }) };
        }
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity || !UUID.test(identity.userId || '')) return deny(401, 'AUTH_REQUIRED');
      if (request.method !== 'POST') {
        response.setHeader('Allow', 'POST');
        return deny(405, 'METHOD_NOT_ALLOWED');
      }
      const url = new URL(request.url || '/api/restore', 'https://app.invalid');
      if (url.pathname !== '/api/restore' || url.search || url.hash) return deny(400, 'INVALID_RESTORE_PATH');
      if (!request.headers?.['content-type']?.toLowerCase().startsWith('application/json')) return deny(415, 'JSON_REQUIRED');
      let body = request.body;
      try {
        if (Buffer.isBuffer(body)) body = body.toString('utf8');
        if (typeof body === 'string') {
          if (Buffer.byteLength(body) > 2048) return deny(413, 'BODY_TOO_LARGE');
          body = JSON.parse(body);
        }
        if (!body || typeof body !== 'object' || Array.isArray(body)
            || Object.keys(body).join(',') !== 'id' || typeof body.id !== 'string'
            || !UUID.test(body.id)) return deny(400, 'INVALID_RESTORE_INPUT');
      } catch { return deny(400, 'INVALID_RESTORE_INPUT'); }
      if (body.id.toLowerCase() !== target.noteId) return deny(404, 'NOT_FOUND');
      const { data, error } = await runtime.db.rpc('aleph_step10_restore_note', {
        p_note_id: target.noteId, p_actor_id: identity.userId,
        p_expected_sha256: target.contentSha256,
      });
      if (error) {
        const mapped = error.code === 'P0001' && ERRORS[error.message];
        return mapped ? deny(...mapped) : deny(502, 'RESTORE_UNAVAILABLE');
      }
      const valid = data && typeof data === 'object' && !Array.isArray(data)
        && Object.keys(data).sort().join(',') === [...RESULT_KEYS].sort().join(',')
        && data.schema === 'aleph.note-restore.v1' && data.id === target.noteId
        && data.contentSha256 === target.contentSha256
        && ['restored', 'idMatches', 'ownerMatches', 'contentHashMatches', 'otherNotesUnchanged'].every(k => data[k] === true)
        && Number.isSafeInteger(data.auditRowsBefore) && data.auditRowsBefore >= 0
        && data.auditRowsAfter === data.auditRowsBefore + 1;
      return valid ? response.status(200).json(data) : deny(502, 'RESTORE_UNAVAILABLE');
    } catch {
      return deny(502, 'RESTORE_UNAVAILABLE');
    }
  };
}
