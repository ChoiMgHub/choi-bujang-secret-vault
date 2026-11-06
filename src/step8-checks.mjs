import { checkStep5 } from './step5-checks.mjs';
import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';

export async function checkStep8(config, { fetchImpl = globalThis.fetch, expectedStep = 8 } = {}) {
  if (![8, 9].includes(expectedStep)) throw new Error('지원하는 구역 점검 단계는 8~9입니다.');
  const checks = await checkStep5(config, { fetchImpl, expectedStep });
  const app = new URL(config.publicAppUrl);
  for (const [attackId, method, path] of [
    ['anonymous_notice_read', 'GET', '/api/notices/80000000-0000-4000-8000-000000000001'],
    ['anonymous_instructor_read', 'GET', '/api/instructor/80000000-0000-4000-8000-000000000002'],
    ['anonymous_notice_management', 'POST', '/api/admin/notices'],
  ]) {
    const result = await fetchImpl(new URL(path, app), { method, redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(15000) });
    let payload;
    try { payload = await result.json(); } catch { /* fail */ }
    const passed = result.status === 401 && payload?.error === 'AUTH_REQUIRED'
      && Object.keys(payload).length === 1
      && result.headers.get('content-type')?.toLowerCase().includes('application/json');
    checks.push({ attackId, passed: Boolean(passed), expected: '새 자료 API는 미로그인 요청을 자료 없는 401 JSON으로 거부',
      observed: `${method} HTTP ${result.status}, 자료 없는 인증 거부 ${Boolean(passed)}` });
  }
  const source = new URL(config.originalApiUrl);
  const statuses = []; let denied = true;
  for (const table of ['vault_notices', 'vault_instructor_materials', 'vault_resource_roles']) {
    const column = table === 'vault_resource_roles' ? 'role' : 'id';
    const target = new URL(`/rest/v1/${table}?select=${column}&limit=1`, source.origin);
    const result = await fetchImpl(target, { method: 'GET', redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(15000), headers: { apikey: SUPABASE_PUBLIC_KEY } });
    let payload;
    try { payload = await result.json(); } catch { /* fail */ }
    const blocked = [401, 403].includes(result.status) && payload?.code === '42501'
      && result.headers.get('content-type')?.toLowerCase().includes('application/json')
      && Object.keys(payload).every(key => ['code', 'message', 'details', 'hint'].includes(key));
    denied &&= Boolean(blocked); statuses.push(result.status);
  }
  checks.push({ attackId: 'zone_tables_direct_read', passed: denied,
    expected: '공지·강사 자료·권한 표 3개의 공개 키 직접 읽기는 권한 오류로 거부',
    observed: `원본 HTTP ${statuses.join('/')}, 세 표 권한 거부 ${denied}` });
  return checks;
}
