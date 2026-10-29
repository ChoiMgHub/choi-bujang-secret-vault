import { execFileSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { checkStep2 } from '../src/step2-checks.mjs';

const root = new URL('../', import.meta.url);
try {
  const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));
  config.expectedCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true,
  }).trim();
  const checks = await checkStep2(config);
  for (const check of checks) console.log(`[${check.passed ? 'PASS' : 'FAIL'}] ${check.attackId}: ${check.observed}`);
  await mkdir(new URL('artifacts/', root), { recursive: true });
  await writeFile(new URL('artifacts/step2-verification.json', root), `${JSON.stringify({
    checkedAt: new Date().toISOString(), commit: config.expectedCommit,
    publicAppUrl: config.publicAppUrl, checks,
  }, null, 2)}\n`);
  if (checks.some(check => !check.passed)) throw new Error('미통과 항목을 확인하세요.');
  console.log('STEP 2 SELF-CHECK PASSED (심판 판정과 별도)');
} catch (error) {
  console.error(`2단계 점검 오류: ${error.message}`);
  process.exitCode = 1;
}
