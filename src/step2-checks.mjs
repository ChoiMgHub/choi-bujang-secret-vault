// Real unauthenticated HTTP checks. Reports contain status/counts, never bodies or keys.
export async function checkStep2(config, { fetchImpl = globalThis.fetch } = {}) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
  }
  const checks = [];
  const get = path => fetchImpl(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(15000), cache: 'no-store',
  });
  const root = await get('/');
  const html = await root.text();
  checks.push({ attackId: 'static_page', passed: root.status === 200
    && html.includes('/api/notes') && !html.includes("fetch('/data.json'")
    && !/실습용\s+가상\s+[^<\n]{1,30}\s+기록/u.test(html),
  expected: '첫 화면은 메모 원문 없이 서버 API를 사용', observed: `첫 화면 HTTP ${root.status}, 서버 API 연결 ${html.includes('/api/notes')}` });
  checks.push({ attackId: 'security_header', passed:
    root.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
      || Boolean(root.headers.get('content-security-policy')),
  expected: '첫 화면에 nosniff 또는 CSP 헤더', observed:
    `nosniff ${root.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'}, CSP ${Boolean(root.headers.get('content-security-policy'))}` });
  const file = await get('/data.json');
  let empty = false;
  if (file.status === 200) {
    try { const data = await file.json(); empty = Array.isArray(data.notes) && data.notes.length === 0; } catch { /* invalid */ }
  }
  checks.push({ attackId: 'static_note_seed', passed: file.status === 404 || empty,
    expected: '공개 data.json은 404 또는 메모 0건', observed: `data.json HTTP ${file.status}, 메모 0건 응답 ${empty}` });
  const identityResponse = await get('/aleph.json');
  let identity = null;
  try { identity = await identityResponse.json(); } catch { /* invalid */ }
  const normalized = value => typeof value === 'string' ? value.replace(/\/$/u, '').toLowerCase() : '';
  const matches = identityResponse.status === 200
    && identity?.schema === 'aleph.defense.deployment.v1' && identity.step === 2
    && normalized(identity.repoUrl) === normalized(config.repoUrl)
    && /^[a-f0-9]{40}$/u.test(identity.commit || '')
    && (!config.expectedCommit || identity.commit === config.expectedCommit)
    && identity.judgeIssuer === config.judgeIssuer;
  checks.push({ attackId: 'deployment_identity', passed: matches,
    expected: 'aleph.json의 2단계·저장소·제출 커밋·심판 발급자 일치',
    observed: `aleph.json HTTP ${identityResponse.status}, 식별 정보 일치 ${matches}` });
  const apiResponse = await get('/api/notes');
  let payload = null;
  try { payload = await apiResponse.json(); } catch { /* invalid */ }
  const count = Array.isArray(payload?.notes) ? payload.notes.length : -1;
  const readable = apiResponse.status === 200 && payload?.sampleMarker === config.sampleMarker
    && count === 4 && payload.notes.every(note => typeof note.title === 'string'
      && typeof note.content === 'string' && note.content.length > 0
      && Object.keys(note).sort().join(',') === 'content,id,title');
  checks.push({ attackId: 'anonymous_api_remaining', passed: readable,
    expected: '남은 약점: 비로그인 서버 API에서 가상 메모 4건 조회',
    observed: `API HTTP ${apiResponse.status}, 메모 ${count}건, 예상 형식 ${readable}` });
  const write = await fetchImpl(new URL('/api/notes', app), {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
  });
  checks.push({ attackId: 'read_only_api', passed: write.status === 405,
    expected: '조회 API의 POST는 405 거부', observed: `POST HTTP ${write.status}` });
  return checks;
}
