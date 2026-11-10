import config from '../aleph.config.json' with {type:'json'};
import { execFileSync } from 'node:child_process';
import { checkStep12 } from '../src/step12-checks.mjs';
const expectedCommit=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const checks=await checkStep12({...config,expectedCommit});
for(const c of checks)console.log(`${c.passed?'통과':'실패'} · ${c.attackId} · ${c.observed}`);
console.log('범위: 공개·미인증 HTTP 자기 점검. A·B 실측·미실행 수동 시험·공식 41종과 구분.');
if(checks.some(c=>!c.passed))process.exitCode=1;
