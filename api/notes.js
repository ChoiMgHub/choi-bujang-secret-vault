import { createClient } from '@supabase/supabase-js';
import deploymentConfig from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

// Stage 3 unit 2: authenticated reads. Owner authorization follows in stage 4.
// Never pass a browser-supplied key, owner, table or URL to the server client.
export function createNotesHandler({ env = process.env, fetchImpl = globalThis.fetch,
  config = deploymentConfig, judgeKeySet } = {}) {
  let runtime;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
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
    if (issues.length) {
      // Only configuration names/reasons are public. Never include their values.
      return response.status(503).json({ error: 'SERVER_NOT_CONFIGURED', issues });
    }
    try {
      if (!runtime) {
        const db = createClient(url, key, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
          global: { fetch: fetchImpl },
        });
        if (config.identityProvider?.issuer !== `${url.replace(/\/$/u, '')}/auth/v1`) {
          return response.status(503).json({ error: 'SERVER_NOT_CONFIGURED' });
        }
        // Use the starter verifier unchanged, once per server runtime.
        runtime = { db, verifyLogin: createLoginVerifier({ config,
          supabaseSecretKey: key, supabaseClient: db, judgeKeySet }) };
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity) return response.status(401).json({ error: 'AUTH_REQUIRED' });
      const { db } = runtime;
      const { data, error } = await db.from('vault_notes')
        .select('id,title,content').order('id', { ascending: true })
        .abortSignal(AbortSignal.timeout(10000));
      if (error || !Array.isArray(data) || data.some(note =>
        typeof note.id !== 'string' || typeof note.title !== 'string' || typeof note.content !== 'string')) {
        return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      }
      return response.status(200).json({
        sampleMarker: 'SAMPLE_NOTE_1',
        notes: data.map(({ id, title, content }) => ({ id, title, content })),
      });
    } catch {
      // Do not echo upstream errors, URLs, keys or note text to logs or responses.
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  };
}

export default createNotesHandler();
