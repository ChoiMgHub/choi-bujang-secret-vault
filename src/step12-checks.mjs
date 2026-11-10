import { checkStep11 } from './step11-checks.mjs';
import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';
import { RULE_IDS } from './decider.mjs';

// Public/anonymous self-checks only. Authenticated records and official attacks
// are separate evidence, never inferred from the availability of this UI.
export async function checkStep12(config,{fetchImpl=globalThis.fetch,priorCheck=checkStep11}={}) {
  const prior=await priorCheck(config,{fetchImpl,expectedStep:12});
  const checks=[{attackId:'prior_stage_http_checks',expected:'1~11단계 공개·미인증 점검 전체 유지',
    observed:`이전 점검 ${prior.length}묶음 중 ${prior.filter(c=>c.passed).length}묶음 일치`,
    passed:prior.length===9&&prior.every(c=>c.passed)}];
  const send=(path,init={})=>fetchImpl(new URL(path,config.publicAppUrl),{
    redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000),...init});
  const root=await send('/');const html=await root.text();
  const controls=root.status===200&&/id="operations-panel"[^>]*hidden/u.test(html)
    &&['verification-run','verification-read','verification-rows','verification-record'].every(id=>html.includes(`id="${id}"`))
    &&html.includes('/operations-ui.js')&&html.includes('/verification-ui.js');
  checks.push({attackId:'operations_screen',expected:'초기 숨김 작전실·요청표·기록 대조 요소 배포; 로그인 검사는 별도',
    observed:`HTML HTTP ${root.status}, 화면 요소 확인 ${controls}`,passed:controls});
  let assets=true;const statuses=[];
  for(const path of ['/operations-ui.js','/verification-ui.js']){
    const response=await send(path);const source=await response.text();statuses.push(response.status);
    assets&&=response.status===200&&source.includes('/api/operations')
      &&!/(?:localStorage|sessionStorage|indexedDB|innerHTML)/u.test(source);
  }
  checks.push({attackId:'operations_public_assets',expected:'작전실 JS 배포·브라우저 저장소 미사용; 실제 승인 검사는 별도',
    observed:`JS HTTP ${statuses.join('/')}, 파일 확인 ${assets}`,passed:assets});
  for(const [id,path,method] of [
    ['anonymous_operations','/api/operations','GET'],
    ['anonymous_verification_read','/api/operations-check','GET'],
    ['anonymous_verification_run','/api/operations-check','POST'],
    ['anonymous_rule_fixture','/api/operations-rule','POST'],
  ]){
    const response=await send(path,{method,headers:{origin:new URL(config.publicAppUrl).origin,
      'x-requested-with':'vault-ui','content-type':'application/json'},...(method==='POST'?{body:'{}'}:{})});
    let payload;try{payload=await response.json();}catch{/* fail closed */}
    const passed=response.status===401&&payload?.error==='AUTH_REQUIRED'&&Object.keys(payload).length===1
      &&Boolean(response.headers.get('cache-control')?.includes('no-store'));
    checks.push({attackId:id,expected:'미로그인 요청은 자료 없는 401 AUTH_REQUIRED·캐시 금지',
      observed:`${method} HTTP ${response.status}, 미인증 거부 ${passed}`,passed});
  }
  const invalid=await send('/api/operations-check?passed=41');
  let body;try{body=await invalid.json();}catch{/* fail */}
  const queryDenied=invalid.status===400&&body?.error==='INVALID_OPERATIONS_PATH'&&Object.keys(body).length===1;
  checks.push({attackId:'verification_query_rejected',expected:'통과 수 쿼리 조작은 400; 검사 결과로 채택하지 않음',
    observed:`HTTP ${invalid.status}, 쿼리 거부 ${queryDenied}`,passed:queryDenied});
  const common={p_user_id:'10000000-0000-4000-8000-000000000099',p_session_id:'20000000-0000-4000-8000-000000000099',p_commit:config.expectedCommit||'0'.repeat(40)};
  for(const [name,args] of [
    ['aleph_step12_operations_snapshot',{...common,p_rule_ids:RULE_IDS}],
    ['aleph_step12_verification',{...common,p_mode:'read',p_run_id:null,p_item:null}],
  ]){
    const response=await fetchImpl(new URL(`/rest/v1/rpc/${name}`,config.originalApiUrl),{
      method:'POST',headers:{apikey:SUPABASE_PUBLIC_KEY,'content-type':'application/json'},body:JSON.stringify(args),
      redirect:'error',signal:AbortSignal.timeout(15000)});
    let payload;try{payload=await response.json();}catch{/* fail */}
    const passed=[401,403].includes(response.status)&&payload?.code==='42501'
      &&Object.keys(payload).every(k=>['code','message','details','hint'].includes(k));
    checks.push({attackId:name.endsWith('snapshot')?'operations_db_denied':'verification_db_denied',
      expected:'공개 키로 서버 전용 DB 기록 함수를 직접 실행할 수 없음',
      observed:`원본 함수 HTTP ${response.status}, 권한 거부 ${passed}`,passed});
  }
  return checks;
}
