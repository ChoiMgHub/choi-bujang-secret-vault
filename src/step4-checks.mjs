import { checkStep3 } from './step3-checks.mjs';

// Public browser key only. No student token/password or server secret is used.
const PUBLIC_KEY = 'sb_publishable_z3tY48lOSOJ8NqLhTpuTXg_aNgHDGKd';

export async function checkStep4(config, { fetchImpl = globalThis.fetch } = {}) {
  const checks = await checkStep3(config, { fetchImpl, expectedStep: 4 });
  const issuer = new URL(config.identityProvider.issuer);
  if (issuer.protocol !== 'https:' || !/^[a-z0-9-]+\.supabase\.co$/u.test(issuer.hostname)
      || issuer.username || issuer.password || issuer.port || issuer.pathname !== '/auth/v1'
      || issuer.search || issuer.hash) throw new Error('Supabase 공개 발급자 주소를 확인하세요.');
  const response = await fetchImpl(new URL('/rest/v1/vault_notes?select=id&limit=1', issuer.origin), {
    method: 'GET', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
    headers: { apikey: PUBLIC_KEY },
  });
  let payload;
  try { payload = await response.json(); } catch { /* HTML and invalid JSON are not proof of denial. */ }
  const denied = [401, 403].includes(response.status)
    && response.headers.get('content-type')?.includes('application/json')
    && payload && !Array.isArray(payload) && payload.code === '42501'
    && Object.keys(payload).every(key => ['code', 'message', 'details', 'hint'].includes(key));
  checks.push({ attackId: 'anonymous_data_api', passed: Boolean(denied),
    expected: '공개 키만 사용한 직접 Data API 읽기는 401/403과 권한 오류 42501로 거부',
    observed: `직접 Data API HTTP ${response.status}, 권한 오류 확인 ${Boolean(denied)}` });
  return checks;
}
