import config from '../aleph.config.json' with { type: 'json' };
import { execFileSync } from 'node:child_process';
import { checkStep11 } from '../src/step11-checks.mjs';
const expectedCommit=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const checks=await checkStep11({...config,expectedCommit});
for(const check of checks)console.log(`${check.passed?'통과':'실패'} · ${check.attackId} · ${check.observed}`);
console.log('범위: 공개 파일·미로그인 HTTP. 로그인 세션 승인·설치·오프라인 실제 화면은 별도 확인.');
if(checks.some(c=>!c.passed))process.exitCode=1;
