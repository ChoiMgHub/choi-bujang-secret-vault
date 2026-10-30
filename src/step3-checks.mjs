import { randomUUID } from 'node:crypto';

// Submission self-check only: never a replacement for src/verify-login.mjs.
// These requests verify anonymous denial and deployment metadata, not signed-in CRUD.
export async function checkStep3(config, { fetchImpl = globalThis.fetch, expectedStep = 3 } = {}) {
  if (![3, 4].includes(expectedStep)) throw new Error('지원하는 로그인 점검 단계는 3 또는 4입니다.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash || app.pathname !== '/') {
    throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
  }
  const checks = [];
  const send = (path, init = {}) => fetchImpl(new URL(path, app), {
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000), ...init,
  });
  const root = await send('/');
  const html = await root.text();
  checks.push({ attackId: 'login_page', passed: root.status === 200 && html.includes('id="login-form"')
    && html.includes('id="memo-form"') && html.includes('id="notes" aria-live="polite" hidden')
    && !/실습용\s+가상\s+[^<\n]{1,30}\s+기록/u.test(html),
  expected: '첫 화면에 로그인·메모 양식, 비로그인 메모 원문 없음', observed: `첫 화면 HTTP ${root.status}, 양식·숨김 목록 ${html.includes('id="memo-form"') && html.includes('id="notes" aria-live="polite" hidden')}` });
  const secure = root.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
    || Boolean(root.headers.get('content-security-policy'));
  checks.push({ attackId: 'security_header', passed: secure, expected: '첫 화면에 nosniff 또는 CSP', observed: `보안 헤더 확인 ${secure}` });
  const file = await send('/data.json');
  let empty = false;
  if (file.status === 200) { try { const data = await file.json(); empty = Array.isArray(data.notes) && data.notes.length === 0; } catch { /* fail */ } }
  checks.push({ attackId: 'static_note_seed', passed: file.status === 404 || empty,
    expected: '공개 메모 파일은 404 또는 메모 0건', observed: `data.json HTTP ${file.status}, 빈 목록 ${empty}` });
  const identityResponse = await send('/aleph.json');
  let identity;
  try { identity = await identityResponse.json(); } catch { /* fail */ }
  const normalized = value => typeof value === 'string' ? value.replace(/\/$/u, '').toLowerCase() : '';
  const matches = identityResponse.status === 200 && identity?.step === expectedStep
    && identity.schema === 'aleph.defense.deployment.v1'
    && normalized(identity.repoUrl) === normalized(config.repoUrl)
    && /^[a-f0-9]{40}$/u.test(identity.commit || '')
    && (!config.expectedCommit || identity.commit === config.expectedCommit)
    && identity.judgeIssuer === config.judgeIssuer;
  checks.push({ attackId: 'deployment_identity', passed: matches,
    expected: `${expectedStep}단계·저장소·제출 커밋·심판 발급자 일치`, observed: `aleph.json HTTP ${identityResponse.status}, 일치 ${matches}` });
  // A newly generated, unused ID avoids touching a real memo even if a broken API permits a request.
  const path = `/api/notes/${randomUUID()}`;
  const probes = [
    ['anonymous_list', 'GET', '/api/notes'], ['anonymous_create', 'POST', '/api/notes'],
    ['anonymous_single', 'GET', path], ['anonymous_update', 'PUT', path], ['anonymous_delete', 'DELETE', path],
    ['invalid_token', 'GET', '/api/notes', { Authorization: 'Bearer not-a-token' }],
  ];
  for (const [attackId, method, endpoint, headers] of probes) {
    const response = await send(endpoint, { method, ...(headers ? { headers } : {}) });
    let payload;
    try { payload = await response.json(); } catch { /* fail */ }
    const jsonError = response.headers.get('content-type')?.toLowerCase().includes('application/json')
      && payload && !Array.isArray(payload) && typeof payload.error === 'string'
      && Object.keys(payload).every(key => key === 'error');
    checks.push({ attackId, passed: [401, 403].includes(response.status) && Boolean(jsonError),
      expected: '미인증 요청은 401/403 JSON 오류와 함께 자료 없이 거부',
      observed: `${method} HTTP ${response.status}, 자료 없는 JSON 오류 ${Boolean(jsonError)}` });
  }
  return checks;
}
