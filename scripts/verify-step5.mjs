import { execFileSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { checkStep5 } from '../src/step5-checks.mjs';

const root = new URL('../', import.meta.url);
try {
  const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));
  config.expectedCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true,
  }).trim();
  const checks = await checkStep5(config);
  for (const check of checks) console.log(`[${check.passed ? 'PASS' : 'FAIL'}] ${check.attackId}: ${check.observed}`);
  await mkdir(new URL('artifacts/', root), { recursive: true });
  await writeFile(new URL('artifacts/step5-verification.json', root), JSON.stringify({
    checkedAt: new Date().toISOString(), commit: config.expectedCommit,
    publicAppUrl: config.publicAppUrl, checks,
    scope: '실제 HTTP: 미인증·무효 토큰 거부, 공개 키의 원본 DB 직접 읽기 거부, 배포 확인. A/B 정상 사용과 authenticated 권한은 사용자 별도 확인.',
  }, null, 2) + '\n');
  if (checks.some(check => !check.passed)) throw new Error('미통과 항목을 확인하세요.');
  console.log('STEP 5 ANONYMOUS/ORIGINAL-API SELF-CHECK PASSED (포털 심판 판정과 별도)');
} catch (error) { console.error(`5단계 자기 점검 오류: ${error.message}`); process.exitCode = 1; }
