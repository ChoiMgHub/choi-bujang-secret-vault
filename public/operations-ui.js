// Read-only summary UI. The server, never this panel's visibility, authorizes it.
(() => {
  const panel = document.querySelector('#operations-panel');
  const memo = document.querySelector('#memo-panel');
  const refresh = document.querySelector('#operations-refresh');
  const ids = ['policy','detection','revocation','recovery','official','reference','record'];
  const fields = Object.fromEntries(ids.map(id => [id,document.querySelector(`#operations-${id}`)]));
  const status = document.querySelector('#operations-status');
  let version = 0;
  let pending;
  function clear() {
    version++;
    pending?.abort(); pending = null;
    for (const field of Object.values(fields)) field.textContent = '';
    refresh.disabled = false;
  }
  function render(data) {
    fields.policy.textContent = `${data.policy.ruleIds.length}개 규칙: ${data.policy.ruleIds.join(' · ')}. 이번 API 판정 시험: 미실행.`;
    fields.detection.textContent = '운영 엔진 사건 전달·탐지 집계: 미실행. 사건 0건 또는 회수 성공으로 표시하지 않습니다.';
    fields.revocation.textContent = `현재 세션: 서버 승인 완료. 이 세션의 DB 승인 철회 기록 ${data.revocation.events}건. 운영 엔진 회수 집행: 미실행.`;
    const r = data.recovery;
    fields.recovery.textContent = r.state === 'available'
      ? `사본 재검증: ${r.backupVerified ? '일치' : '불일치 — 복구 중단 필요'}. 현재 메모와 사본: ${r.liveMatchesBackup ? '일치' : '불일치'}. 이 계정의 기존 복구 기록 ${r.restoreEvents}건. 사본 버전: ${r.version}. 이번 조회는 복구를 실행하지 않습니다.`
      : '이 계정 소유의 복구 사본 정보가 없습니다. 다른 계정의 사본과 복구 기록은 표시하지 않습니다.';
    fields.official.textContent = `41종 공식 시험: ${data.officialTests.state === 'not_executed' ? '실행 결과 미수신' : '미확인'}. 자체 점검과 공식 판정을 구분합니다.`;
    fields.reference.textContent = `요청 ID: ${data.requestId} · DB 확인 시각(UTC): ${data.checkedAt} · 조회한 배포 커밋: ${data.commit}`;
    fields.record.textContent = JSON.stringify(data,null,2);
  }
  async function load() {
    clear();
    if (memo.hidden || navigator.onLine === false) { panel.hidden = true; return; }
    panel.hidden = false;
    const current = version;
    const controller = new AbortController(); pending = controller;
    refresh.disabled = true;
    status.textContent = '서버가 현재 승인과 DB 기록을 확인하는 중입니다.';
    try {
      const response = await fetch('/api/operations',{
        credentials:'same-origin',cache:'no-store',headers:{'x-requested-with':'vault-ui'},signal:controller.signal,
      });
      const data = await response.json();
      if (current !== version || memo.hidden || navigator.onLine === false) return;
      if (!response.ok || data?.schema !== 'aleph.operations.record.v1'
          || !data.policy || !Array.isArray(data.policy.ruleIds) || !data.recovery || !data.revocation
          || data.detection?.state !== 'not_executed' || data.officialTests?.state !== 'not_executed') throw Error('record_unavailable');
      render(data);
      status.textContent = '현재 계정의 요약을 DB 기록과 같은 값으로 읽었습니다. 미실행 항목은 별도로 표시합니다.';
    } catch (error) {
      if (current === version && error.name !== 'AbortError') {
        for (const field of Object.values(fields)) field.textContent = '';
        status.textContent = '서버 기록을 확인하지 못했습니다. 성공으로 표시하지 않았습니다. DB 준비와 기기 승인 상태를 확인하세요.';
      }
    } finally {
      if (current === version) { refresh.disabled = false; pending = null; }
    }
  }
  const observer = new MutationObserver(() => {
    if (memo.hidden) { clear(); panel.hidden = true; status.textContent = ''; }
    else void load();
  });
  observer.observe(memo,{attributes:true,attributeFilter:['hidden']});
  refresh.addEventListener('click',() => { void load(); });
  window.addEventListener('offline',() => { clear(); panel.hidden = true; status.textContent = ''; });
  window.addEventListener('pagehide',() => { clear(); panel.hidden = true; });
  if (!memo.hidden) void load();
})();
