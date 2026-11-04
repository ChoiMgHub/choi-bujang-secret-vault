// Server-only cookie transport. The existing login verifier still verifies JWTs.
export const ACCESS_COOKIE = '__Host-vault-access';
export const REFRESH_COOKIE = '__Host-vault-refresh';
export const UI_HEADER = 'vault-ui';
const TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;

export function browserCookies(request) {
  const raw = request.headers?.cookie;
  if (raw === undefined) return {};
  if (typeof raw !== 'string' || raw.length > 16384) return {};
  const cookies = {};
  for (const part of raw.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    const name = part.slice(0, at).trim();
    if (![ACCESS_COOKIE, REFRESH_COOKIE].includes(name)) continue;
    if (Object.hasOwn(cookies, name)) return {};
    try { cookies[name] = decodeURIComponent(part.slice(at + 1).trim()); }
    catch { return {}; }
  }
  if (cookies[ACCESS_COOKIE] && (!TOKEN.test(cookies[ACCESS_COOKIE])
      || cookies[ACCESS_COOKIE].length > 3500)) delete cookies[ACCESS_COOKIE];
  if (cookies[REFRESH_COOKIE] && !/^[A-Za-z0-9._~-]{1,2000}$/u.test(cookies[REFRESH_COOKIE])) {
    delete cookies[REFRESH_COOKIE];
  }
  return cookies;
}

export function trustedBrowserRequest(request, config) {
  const headers = request.headers || {};
  if (headers['x-requested-with'] !== UI_HEADER) return false;
  if (headers['sec-fetch-site'] && headers['sec-fetch-site'] !== 'same-origin') return false;
  let origin;
  try { origin = new URL(config.publicAppUrl).origin; } catch { return false; }
  const supplied = headers.origin;
  if (supplied !== undefined && supplied !== origin) return false;
  return ['GET', 'HEAD'].includes(request.method) || supplied === origin;
}

export function cookieAuthorization(request) {
  if (request.headers?.authorization !== undefined) return request.headers.authorization;
  const access = browserCookies(request)[ACCESS_COOKIE];
  return access ? `Bearer ${access}` : undefined;
}

export function usesCookieAuthorization(request) {
  return request.headers?.authorization === undefined
    && Boolean(browserCookies(request)[ACCESS_COOKIE]);
}

export function clearBrowserSession(response) {
  response.setHeader('Set-Cookie', [ACCESS_COOKIE, REFRESH_COOKIE].map(name =>
    `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`));
}

export function writeBrowserSession(response, session, now = Date.now()) {
  const access = session?.access_token;
  const refresh = session?.refresh_token;
  const age = Math.floor(session?.expires_at - now / 1000);
  if (typeof access !== 'string' || !TOKEN.test(access) || access.length > 3500
      || typeof refresh !== 'string' || !/^[A-Za-z0-9._~-]{1,2000}$/u.test(refresh)
      || !Number.isSafeInteger(age) || age <= 0 || age > 86400) {
    throw new Error('invalid_auth_session');
  }
  response.setHeader('Set-Cookie', [
    `${ACCESS_COOKIE}=${encodeURIComponent(access)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`,
    `${REFRESH_COOKIE}=${encodeURIComponent(refresh)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`,
  ]);
}
