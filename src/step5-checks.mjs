import { checkStep3 } from './step3-checks.mjs';
import { SUPABASE_PUBLIC_KEY as PUBLIC_KEY } from './supabase-public.mjs';

// Public application key only: no password, user JWT or server secret is used.

export async function checkStep5(config, { fetchImpl = globalThis.fetch, expectedStep = 5 } = {}) {
  const issuer = new URL(config.identityProvider.issuer);
  const source = new URL(config.originalApiUrl);
  if (issuer.protocol !== 'https:' || !/^[a-z0-9-]+\.supabase\.co$/u.test(issuer.hostname)
      || issuer.username || issuer.password || issuer.port || issuer.pathname !== '/auth/v1'
      || issuer.search || issuer.hash || source.protocol !== 'https:'
      || source.origin !== issuer.origin || source.pathname !== '/rest/v1/vault_notes'
      || source.username || source.password || source.port || source.search || source.hash) {
    throw new Error('originalApiUrl은 같은 Supabase 프로젝트 메모 테이블의 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  const checks = await checkStep3(config, { fetchImpl, expectedStep });
  const target = new URL(source);
  target.search = '?select=id&limit=1';
  const response = await fetchImpl(target, {
    method: 'GET', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
    headers: { apikey: PUBLIC_KEY },
  });
  let payload;
  try { payload = await response.json(); } catch { /* Invalid JSON is not proof of denial. */ }
  const denied = [401, 403].includes(response.status)
    && response.headers.get('content-type')?.toLowerCase().includes('application/json')
    && payload && !Array.isArray(payload) && payload.code === '42501'
    && Object.keys(payload).every(key => ['code', 'message', 'details', 'hint'].includes(key));
  checks.push({ attackId: 'original_api_public_key', passed: Boolean(denied),
    expected: '원본 메모 API의 공개 키 직접 읽기는 401/403과 권한 오류 42501로 거부',
    observed: `원본 직접 요청 HTTP ${response.status}, 권한 오류 확인 ${Boolean(denied)}` });
  const app = new URL(config.publicAppUrl);
  const send = (path, init = {}) => fetchImpl(new URL(path, app), {
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000), ...init,
  });
  const htmlResponse = await send('/');
  const html = await htmlResponse.text();
  const jsResponse = await send('/auth-ui.js');
  const js = await jsResponse.text();
  const forbidden = /sb_publishable_[A-Za-z0-9_-]+|sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u;
  const keyAbsent = htmlResponse.status === 200 && jsResponse.status === 200
    && html.includes('src="/auth-ui.js"') && !html.includes('/vendor/supabase.js')
    && !forbidden.test(html + js);
  checks.push({ attackId: 'browser_public_key_absent', passed: keyAbsent,
    expected: '실제 화면 HTML·로그인 JS에 공개 키·서버 키·JWT 원문 없음',
    observed: `로그인 JS HTTP ${jsResponse.status}, 화면 키 부재 ${keyAbsent}` });
  const vendor = await send('/vendor/supabase.js');
  checks.push({ attackId: 'browser_sdk_removed', passed: vendor.status === 404,
    expected: '기존 브라우저 Supabase SDK 배포 파일 제거', observed: `기존 SDK HTTP ${vendor.status}` });
  const sessionResponse = await send('/api/auth', { headers: { 'x-requested-with': 'vault-ui' } });
  let session;
  try { session = await sessionResponse.json(); } catch { /* fail */ }
  const anonymous = sessionResponse.status === 200 && session?.user === null
    && Object.keys(session).length === 1 && sessionResponse.headers.get('cache-control')?.includes('no-store');
  checks.push({ attackId: 'anonymous_server_session', passed: Boolean(anonymous),
    expected: '미로그인 서버 세션 조회는 캐시 없이 사용자 없음만 반환',
    observed: `세션 HTTP ${sessionResponse.status}, 익명·토큰 미노출 ${Boolean(anonymous)}` });
  for (const [attackId, origin, status, code] of [
    ['invalid_login_input', app.origin, 400, 'INVALID_INPUT'],
    ['cross_origin_login', 'https://untrusted.example', 403, 'ORIGIN_NOT_ALLOWED'],
  ]) {
    const result = await send('/api/auth', { method: 'POST', body: '{}',
      headers: { origin, 'x-requested-with': 'vault-ui', 'content-type': 'application/json' } });
    let payload;
    try { payload = await result.json(); } catch { /* fail */ }
    const blocked = result.status === status && payload?.error === code && Object.keys(payload).length === 1;
    checks.push({ attackId, passed: blocked,
      expected: '잘못된 로그인 입력과 외부 출처 요청은 안전한 JSON 오류로 거부',
      observed: `로그인 요청 HTTP ${result.status}, 입력·출처 거부 ${blocked}` });
  }
  return checks;
}
