import { checkStep3 } from './step3-checks.mjs';

// Public application key only: no password, user JWT or server secret is used.
const PUBLIC_KEY = 'sb_publishable_z3tY48lOSOJ8NqLhTpuTXg_aNgHDGKd';

export async function checkStep5(config, { fetchImpl = globalThis.fetch } = {}) {
  const issuer = new URL(config.identityProvider.issuer);
  const source = new URL(config.originalApiUrl);
  if (issuer.protocol !== 'https:' || !/^[a-z0-9-]+\.supabase\.co$/u.test(issuer.hostname)
      || issuer.username || issuer.password || issuer.port || issuer.pathname !== '/auth/v1'
      || issuer.search || issuer.hash || source.protocol !== 'https:'
      || source.origin !== issuer.origin || source.pathname !== '/rest/v1/vault_notes'
      || source.username || source.password || source.port || source.search || source.hash) {
    throw new Error('originalApiUrl은 같은 Supabase 프로젝트 메모 테이블의 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  const checks = await checkStep3(config, { fetchImpl, expectedStep: 5 });
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
  return checks;
}
