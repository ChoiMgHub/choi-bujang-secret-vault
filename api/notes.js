import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import deploymentConfig from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const COLUMNS = 'id,title,content';
const MAX_BYTES = 65536;
const safeNote = row => ({ id: row.id, title: row.title, body: row.content });
const validNote = row => row && typeof row.id === 'string'
  && typeof row.title === 'string' && typeof row.content === 'string';

function inputBody(request) {
  let value = request.body;
  if (Buffer.isBuffer(value)) value = value.toString('utf8');
  if (typeof value === 'string') {
    if (Buffer.byteLength(value) > MAX_BYTES) throw new RangeError('body_too_large');
    value = JSON.parse(value);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('invalid_body');
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) throw new RangeError('body_too_large');
  if (typeof value.title !== 'string' || !value.title.trim() || value.title.length > 200
      || typeof value.body !== 'string' || value.body.length > 10000) throw new TypeError('invalid_note');
  if (value.id !== undefined && (typeof value.id !== 'string' || !UUID.test(value.id))) throw new TypeError('invalid_id');
  return { id: value.id?.toLowerCase(), title: value.title.trim(), content: value.body };
}

// Stage 3: authentication is required. Per-ID owner authorization intentionally follows in stage 4.
// The browser cannot set owner_id on creation or change it on update.
export function createNotesHandler({ env = process.env, fetchImpl = globalThis.fetch,
  config = deploymentConfig, judgeKeySet } = {}) {
  let runtime;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string' || !authorization) {
      return response.status(401).json({ error: 'AUTH_REQUIRED' });
    }
    const url = typeof env.SUPABASE_URL === 'string' ? env.SUPABASE_URL.trim() : '';
    const key = typeof env.SUPABASE_SECRET_KEY === 'string' ? env.SUPABASE_SECRET_KEY.trim() : '';
    const issues = [];
    if (!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url)) {
      issues.push({ name: 'SUPABASE_URL', reason: url ? 'INVALID_FORMAT' : 'MISSING' });
    }
    if (!/^sb_secret_[A-Za-z0-9_-]+$/u.test(key)) {
      issues.push({ name: 'SUPABASE_SECRET_KEY', reason: key ? 'INVALID_FORMAT' : 'MISSING' });
    }
    if (issues.length) return response.status(503).json({ error: 'SERVER_NOT_CONFIGURED', issues });
    try {
      if (!runtime) {
        const db = createClient(url, key, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
          global: { fetch: fetchImpl },
        });
        if (config.identityProvider?.issuer !== `${url.replace(/\/$/u, '')}/auth/v1`) {
          return response.status(503).json({ error: 'SERVER_NOT_CONFIGURED' });
        }
        // The starter verifier stays unchanged and is reused in this server runtime.
        runtime = { db, verifyLogin: createLoginVerifier({ config,
          supabaseSecretKey: key, supabaseClient: db, judgeKeySet }) };
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity) return response.status(401).json({ error: 'AUTH_REQUIRED' });
      const { db } = runtime;
      const path = new URL(request.url || '/api/notes', 'https://app.invalid').pathname;
      const match = /^\/api\/notes(?:\/([^/]+))?\/?$/u.exec(path);
      if (!match) return response.status(404).json({ error: 'NOT_FOUND' });
      const id = match[1]?.toLowerCase();
      if (id && !UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
      const methods = id ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
      if (!methods.includes(request.method)) {
        response.setHeader('Allow', methods.join(', '));
        return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
      }
      const table = () => db.from('vault_notes');
      const timed = query => query.abortSignal(AbortSignal.timeout(10000));
      if (request.method === 'GET') {
        // List reads are account-scoped. Single-ID reads intentionally lack owner checks in stage 3.
        let query = table().select(COLUMNS);
        query = id ? query.eq('id', id).limit(1)
          : query.eq('owner_id', identity.userId).order('created_at', { ascending: true }).order('id', { ascending: true });
        const { data, error } = await timed(query);
        if (error || !Array.isArray(data) || data.some(row => !validNote(row))) {
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        if (id) return data.length ? response.status(200).json(safeNote(data[0]))
          : response.status(404).json({ error: 'NOT_FOUND' });
        return response.status(200).json(data.map(safeNote));
      }
      if (request.method === 'DELETE') {
        const { data, error } = await timed(table().delete().eq('id', id).select('id'));
        if (error || !Array.isArray(data)) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        return data.length ? response.status(200).json({ id: data[0].id })
          : response.status(404).json({ error: 'NOT_FOUND' });
      }
      let input;
      try { input = inputBody(request); }
      catch (error) {
        return response.status(error instanceof RangeError ? 413 : 400)
          .json({ error: error instanceof RangeError ? 'BODY_TOO_LARGE' : 'INVALID_NOTE' });
      }
      if (request.method === 'POST') {
        const noteId = input.id || randomUUID();
        const { data, error } = await timed(table().insert({ id: noteId,
          owner_id: identity.userId, title: input.title, content: input.content }).select('id'));
        if (error?.code === '23505') return response.status(409).json({ error: 'ID_ALREADY_EXISTS' });
        if (error || !Array.isArray(data) || data.length !== 1 || data[0].id !== noteId) {
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        return response.status(201).json({ id: noteId });
      }
      if (input.id && input.id !== id) return response.status(400).json({ error: 'INVALID_NOTE' });
      const { data, error } = await timed(table().update({ title: input.title, content: input.content })
        .eq('id', id).select(COLUMNS));
      if (error || !Array.isArray(data) || data.some(row => !validNote(row))) {
        return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      }
      return data.length ? response.status(200).json(safeNote(data[0]))
        : response.status(404).json({ error: 'NOT_FOUND' });
    } catch {
      // No token, key, upstream diagnostic or memo body is echoed to logs or errors.
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  };
}

export default createNotesHandler();
