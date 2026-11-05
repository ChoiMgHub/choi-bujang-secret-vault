import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import deploymentConfig from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';
import { cookieAuthorization, trustedBrowserRequest, usesCookieAuthorization } from './browser-session.mjs';
import { RESOURCE_ZONES } from './resource-zones.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const timed = query => query.abortSignal(AbortSignal.timeout(10000));
const valid = row => row && UUID.test(row.id) && typeof row.title === 'string'
  && typeof row.body === 'string';
const visible = ({ id, title, body }) => ({ id, title, body });

function runtimeFromServer(env, config, fetchImpl, judgeKeySet) {
  const url = env.SUPABASE_URL?.trim();
  const key = env.SUPABASE_SECRET_KEY?.trim();
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url || '')
      || !/^sb_secret_[A-Za-z0-9_-]+$/u.test(key || '')
      || config.identityProvider?.issuer !== `${url.replace(/\/$/u, '')}/auth/v1`) {
    throw new Error('SERVER_NOT_CONFIGURED');
  }
  const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false,
    detectSessionInUrl: false }, global: { fetch: fetchImpl } });
  return { db, verifyLogin: createLoginVerifier({ config,
    supabaseSecretKey: key, supabaseClient: db, judgeKeySet }) };
}

function bodyForNotice(request) {
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf8');
  if (typeof body === 'string') {
    if (Buffer.byteLength(body) > 65536) throw new Error('INVALID_INPUT');
    body = JSON.parse(body);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['id', 'title', 'body'].includes(key))
      || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
      || typeof body.body !== 'string' || body.body.length > 10000
      || (body.id !== undefined && !UUID.test(body.id))) throw new Error('INVALID_INPUT');
  return { id: body.id?.toLowerCase(), title: body.title.trim(), body: body.body };
}

// runtimeFactory is a local test seam; HTTP request fields cannot replace it.
export function createResourceHandler({ area, admin = false, env = process.env,
  config = deploymentConfig, fetchImpl = globalThis.fetch, judgeKeySet,
  runtimeFactory = () => runtimeFromServer(env, config, fetchImpl, judgeKeySet) } = {}) {
  if (!['notices', 'instructor'].includes(area) || (admin && area !== 'notices')) {
    throw new TypeError('invalid_resource_handler');
  }
  const base = admin ? '/api/admin/notices' : `/api/${area}`;
  let runtime;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Resource-Zone', RESOURCE_ZONES[area].id);
    const fail = (status, error) => response.status(status).json({ error });
    const authorization = cookieAuthorization(request);
    if (!authorization) return fail(401, 'AUTH_REQUIRED');
    if (usesCookieAuthorization(request) && !trustedBrowserRequest(request, config)) {
      return fail(403, 'ORIGIN_NOT_ALLOWED');
    }
    try {
      runtime ??= runtimeFactory();
      const identity = await runtime.verifyLogin(authorization);
      if (!identity || !UUID.test(identity.userId)) return fail(401, 'AUTH_REQUIRED');
      const { db } = runtime;
      const url = new URL(request.url || base, 'https://app.invalid');
      if (url.search || url.hash) return fail(400, 'QUERY_NOT_ALLOWED');
      const path = url.pathname;
      const suffix = path === base ? '' : path.startsWith(`${base}/`) ? path.slice(base.length + 1) : null;
      if (suffix === null || suffix.includes('/')) return fail(404, 'NOT_FOUND');
      const id = suffix ? suffix.toLowerCase() : null;
      if (id && !UUID.test(id)) return fail(400, 'INVALID_ID');

      // The public notice path remains read-only even for a verified instructor.
      if (!admin && area === 'notices' && request.method !== 'GET') return fail(403, 'NOTICE_READ_ONLY');
      if (admin || area === 'instructor') {
        const roles = await timed(db.from('vault_resource_roles').select('user_id,role,active')
          .eq('user_id', identity.userId).eq('active', true).limit(1));
        if (roles.error || !Array.isArray(roles.data)
            || roles.data.some(row => row.user_id !== identity.userId
              || row.role !== 'instructor' || row.active !== true)) return fail(503, 'RESOURCE_PERMISSIONS_UNAVAILABLE');
        if (!roles.data.length) return fail(403, 'INSTRUCTOR_REQUIRED');
      }

      const tableName = area === 'notices' ? 'vault_notices' : 'vault_instructor_materials';
      const table = () => db.from(tableName);
      if (!admin) {
        if (request.method !== 'GET') return fail(405, 'METHOD_NOT_ALLOWED');
        let query = table().select(area === 'instructor' ? 'id,title,body,owner_id' : 'id,title,body');
        if (area === 'instructor') query = query.eq('owner_id', identity.userId);
        query = id ? query.eq('id', id).limit(1) : query.order('created_at').limit(100);
        const rows = await timed(query);
        if (rows.error || !Array.isArray(rows.data) || rows.data.some(row => !valid(row)
            || (id && row.id !== id) || (area === 'instructor' && row.owner_id !== identity.userId))) {
          return fail(503, 'RESOURCE_STORE_UNAVAILABLE');
        }
        if (id) return rows.data.length ? response.status(200).json(visible(rows.data[0])) : fail(404, 'NOT_FOUND');
        return response.status(200).json(rows.data.map(visible));
      }

      if ((!id && request.method !== 'POST') || (id && !['PUT', 'DELETE'].includes(request.method))) {
        return fail(405, 'METHOD_NOT_ALLOWED');
      }
      if (request.method === 'DELETE') {
        const rows = await timed(table().delete().eq('id', id).select('id'));
        if (rows.error || !Array.isArray(rows.data) || rows.data.some(row => row.id !== id)) return fail(503, 'RESOURCE_STORE_UNAVAILABLE');
        return rows.data.length ? response.status(200).json({ id }) : fail(404, 'NOT_FOUND');
      }
      let input;
      try { input = bodyForNotice(request); } catch { return fail(400, 'INVALID_INPUT'); }
      if (id && input.id && input.id !== id) return fail(400, 'INVALID_INPUT');
      const noticeId = id || input.id || randomUUID();
      const values = { title: input.title, body: input.body, updated_at: new Date().toISOString() };
      const rows = request.method === 'POST'
        ? await timed(table().insert({ ...values, id: noticeId, created_by: identity.userId }).select('id,title,body'))
        : await timed(table().update(values).eq('id', id).select('id,title,body'));
      if (rows.error?.code === '23505') return fail(409, 'ID_ALREADY_EXISTS');
      if (rows.error || !Array.isArray(rows.data) || rows.data.length > 1
          || rows.data.some(row => !valid(row) || row.id !== noticeId)) return fail(503, 'RESOURCE_STORE_UNAVAILABLE');
      if (!rows.data.length) return fail(404, 'NOT_FOUND');
      return response.status(request.method === 'POST' ? 201 : 200).json(visible(rows.data[0]));
    } catch (error) {
      return fail(error?.message === 'SERVER_NOT_CONFIGURED' ? 503 : 502,
        error?.message === 'SERVER_NOT_CONFIGURED' ? 'SERVER_NOT_CONFIGURED' : 'RESOURCE_UNAVAILABLE');
    }
  };
}
