import { checkStep8 } from './step8-checks.mjs';
import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';
import { RECOVERY_TARGET } from './recovery-target.mjs';

// Anonymous probes only. Never invoke recovery as an authenticated owner here.
export async function checkStep10(config, { fetchImpl = globalThis.fetch } = {}) {
  if (config.restoreRoute !== '/api/restore') throw new Error('10단계 복구 경로는 /api/restore여야 합니다.');
  const original = await checkStep8(config, { fetchImpl, expectedStep: 10 });
  // Keep all earlier HTTP requests; combine two read-denial observations so
  // the submission still contains at most twenty items.
  const readIds = ['anonymous_notice_read', 'anonymous_instructor_read'];
  const reads = original.filter(c => readIds.includes(c.attackId));
  if (reads.length !== 2) throw new Error('기존 구역 조회 점검 항목을 확인하세요.');
  const checks = original.filter(c => !readIds.includes(c.attackId));
  checks.push({ attackId: 'anonymous_zone_reads', passed: reads.every(c => c.passed),
    expected: '공지·강사 자료 두 읽기 요청을 모두 자료 없는 401 JSON으로 거부',
    observed: `공지 ${reads[0].observed}, 강사 자료 ${reads[1].observed}` });
  const send = (target, init) => fetchImpl(target, { redirect: 'error', cache: 'no-store',
    signal: AbortSignal.timeout(15000), ...init });
  const app = await send(new URL(config.restoreRoute, config.publicAppUrl), {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: RECOVERY_TARGET.noteId }),
  });
  let payload;
  try { payload = await app.json(); } catch { /* fail */ }
  const appDenied = app.status === 401 && payload?.error === 'AUTH_REQUIRED'
    && Object.keys(payload).length === 1 && app.headers.get('content-type')?.includes('application/json');
  const direct = await send(new URL('/rest/v1/rpc/aleph_step10_restore_note', config.originalApiUrl), {
    method: 'POST', headers: { apikey: SUPABASE_PUBLIC_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ p_note_id: RECOVERY_TARGET.noteId,
      p_actor_id: '10000000-0000-4000-8000-000000000099', p_expected_sha256: RECOVERY_TARGET.contentSha256 }),
  });
  let rpc;
  try { rpc = await direct.json(); } catch { /* fail */ }
  const rpcDenied = [401, 403].includes(direct.status) && rpc?.code === '42501'
    && Object.keys(rpc).every(k => ['code', 'message', 'details', 'hint'].includes(k))
    && direct.headers.get('content-type')?.includes('application/json');
  const passed = Boolean(appDenied && rpcDenied);
  checks.push({ attackId: 'anonymous_recovery_denied', passed,
    expected: '복구 API 미로그인 호출과 원본 DB 함수의 공개 키 직접 호출을 모두 거부',
    observed: `복구 API POST HTTP ${app.status}, 원본 함수 POST HTTP ${direct.status}, 미인증 거부 ${passed}` });
  return checks;
}
