import { execFileSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { checkStep4 } from '../src/step4-checks.mjs';

const root = new URL('../', import.meta.url);
try {
  const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));
  config.expectedCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true }).trim();
  const checks = await checkStep4(config);
  for (const check of checks) console.log(`[${check.passed ? 'PASS' : 'FAIL'}] ${check.attackId}: ${check.observed}`);
  await mkdir(new URL('artifacts/', root), { recursive: true });
  await writeFile(new URL('artifacts/step4-verification.json', root), JSON.stringify({
    checkedAt: new Date().toISOString(), commit: config.expectedCommit,
    publicAppUrl: config.publicAppUrl, checks,
    scope: '익명·무효 토큰 차단, 익명 직접 Data API, 배포 점검. 실제 A/B 단건 조회·CRUD는 사용자 별도 확인.',
  }, null, 2) + '\n');
  if (checks.some(check => !check.passed)) throw new Error('미통과 항목을 확인하세요.');
  console.log('STEP 4 ANONYMOUS/DEPLOYMENT SELF-CHECK PASSED (포털 심판 판정과 별도)');
} catch (error) { console.error(`4단계 자기 점검 오류: ${error.message}`); process.exitCode = 1; }
