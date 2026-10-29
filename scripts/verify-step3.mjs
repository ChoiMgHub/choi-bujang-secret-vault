import { execFileSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { checkStep3 } from '../src/step3-checks.mjs';

const root = new URL('../', import.meta.url);
try {
  const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));
  config.expectedCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true }).trim();
  const checks = await checkStep3(config);
  for (const check of checks) console.log(`[${check.passed ? 'PASS' : 'FAIL'}] ${check.attackId}: ${check.observed}`);
  await mkdir(new URL('artifacts/', root), { recursive: true });
  await writeFile(new URL('artifacts/step3-verification.json', root), `${JSON.stringify({ checkedAt: new Date().toISOString(),
    commit: config.expectedCommit, publicAppUrl: config.publicAppUrl, checks,
    scope: '익명·무효 토큰 거부와 배포 점검. 실제 A 로그인 CRUD는 별도 사용자 확인.',
  }, null, 2)}\n`);
  if (checks.some(check => !check.passed)) throw new Error('미통과 항목을 확인하세요.');
  console.log('STEP 3 ANONYMOUS/DEPLOYMENT SELF-CHECK PASSED');
  console.log('실제 A 계정의 추가·수정·삭제는 브라우저에서 별도로 확인합니다. 심판 판정과 별도입니다.');
} catch (error) { console.error(`3단계 자기 점검 오류: ${error.message}`); process.exitCode = 1; }
