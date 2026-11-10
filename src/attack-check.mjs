// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step === 12) {
    const { checkStep12 } = await import('./step12-checks.mjs');
    const checks = await checkStep12(config);
    const failed = checks.find(check => check.observed !== 'not_run' && !check.passed);
    if (failed) throw new Error(`12단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 11) {
    const { checkStep11 } = await import('./step11-checks.mjs');
    const checks = await checkStep11(config);
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`11단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 10) {
    const { checkStep10 } = await import('./step10-checks.mjs');
    const checks = await checkStep10(config);
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`10단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 8 || config.step === 9) {
    const { checkStep8 } = await import('./step8-checks.mjs');
    const checks = await checkStep8(config, { expectedStep: config.step });
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`${config.step}단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if ([5, 6, 7].includes(config.step)) {
    const { checkStep5 } = await import('./step5-checks.mjs');
    const checks = await checkStep5(config, { expectedStep: config.step });
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`${config.step}단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 4) {
    const { checkStep4 } = await import('./step4-checks.mjs');
    const checks = await checkStep4(config);
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`4단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 3) {
    const { checkStep3 } = await import('./step3-checks.mjs');
    const checks = await checkStep3(config);
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`3단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step === 2) {
    const { checkStep2 } = await import('./step2-checks.mjs');
    const checks = await checkStep2(config);
    const failed = checks.find(check => !check.passed);
    if (failed) throw new Error(`2단계 점검 실패: ${failed.attackId} (${failed.observed})`);
    return checks.map(({ attackId, expected, observed }) => ({ attackId, expected, observed }));
  }
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
