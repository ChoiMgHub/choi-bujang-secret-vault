import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createPolicyCopy, previewPolicyCopy, restorePolicyCopy } from '../src/policy-copy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const [command, first, second, ...extra] = process.argv.slice(2);
try {
  let result;
  if (command === 'create' && first && !second) {
    const baseCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    result = await createPolicyCopy({ root, dbFile: first, baseCommit });
    process.stdout.write('실행 범위: 정책 사본 검증과 시험 사본 한 줄 변경. 운영 정책·DB는 변경하지 않음.\n');
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.stdout.write(`차이 확인: node scripts/policy-copy.mjs preview ${result.id} ${result.expectedHash}\n`);
  } else if (command === 'preview' && first && second && !extra.length) {
    result = await previewPolicyCopy({ root, id: first, expectedHash: second });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (command === 'restore' && first && second && extra.length === 1) {
    result = await restorePolicyCopy({ root, id: first, expectedHash: second, expectedPlanHash: extra[0] });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    throw new Error('usage_create_db_export_or_preview_id_hash');
  }
} catch (error) {
  const code = /^[a-z_]+$/u.test(error.message) ? error.message : 'policy_copy_stopped';
  process.stderr.write(`정책 사본 작업 중단: ${code}\n`);
  process.exitCode = 1;
}
