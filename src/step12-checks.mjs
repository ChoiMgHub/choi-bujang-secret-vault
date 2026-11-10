// The stage-12 submission runner permits public HTTPS GET/HEAD only.
// Do not import older runners: they perform POST/PUT/DELETE checks.
export async function checkStep12(config,{fetchImpl=globalThis.fetch}={}) {
  const app=new URL(config.publicAppUrl),source=new URL(config.originalApiUrl),issuer=new URL(config.identityProvider.issuer);
  const publicHost=host=>!['localhost','127.0.0.1','[::1]'].includes(host)&&!host.endsWith('.local')&&!/^\d+\.\d+\.\d+\.\d+$/u.test(host);
  if(app.protocol!=='https:'||!publicHost(app.hostname)||app.username||app.password||app.port||app.search||app.hash||app.pathname!=='/'
    ||source.protocol!=='https:'||source.origin!==issuer.origin||!/^https:\/\/[a-z0-9-]+\.supabase\.co\/auth\/v1$/u.test(issuer.href)
    ||source.pathname!=='/rest/v1/vault_notes'||source.username||source.password||source.port||source.search||source.hash)throw Error('공개 HTTPS 배포·원본 API 주소를 확인하세요.');
  const checks=[],requests=[];
  const responseEvidence=new WeakMap();
  const trace=value=>typeof value==='string'&&/^[A-Za-z0-9:-]{1,96}$/u.test(value)?value:null;
  let recordedThrough=0;
  const add=(attackId,expected,_summary,passed)=>{
    const actual=requests.slice(recordedThrough);recordedThrough=requests.length;
    // A result is built only from fetch responses captured for this check.
    // Missing case linkage or a mismatched operation record is not verified.
    if(actual.length!==1||actual[0].caseId!==attackId||actual[0].idMismatch){
      checks.push({attackId,expected,observed:'not_run',passed:null});return;
    }
    const observed=`HTTP ${actual[0].status}`;
    if(observed.length>300){checks.push({attackId,expected,observed:'not_run',passed:null});return;}
    checks.push({attackId,expected,observed,passed:Boolean(passed)});
  };
  let requestCount=0;
  const requestedCases=new Set();
  const send=async(caseId,target,headers={})=>{
    if(requestedCases.has(caseId))throw Error('한 점검 ID에는 요청 하나만 연결할 수 있습니다.');
    requestedCases.add(caseId);
    if(requestCount>=24)throw Error('12단계 점검 요청 상한 24회를 초과할 수 없습니다.');
    requestCount++;
    const url=new URL(target,app);
    const response=await fetchImpl(url,{
      method:'GET',headers,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000),
      alephEvidence:{caseId,requestKey:'read'}});
    const headerId=trace(response.headers.get('x-request-id'));
    const evidence={caseId,origin:url.origin,path:url.pathname+url.search,status:response.status,headerId,
      responseId:headerId||trace(response.headers.get('sb-request-id'))||trace(response.headers.get('x-vercel-id'))};
    requests.push(evidence);responseEvidence.set(response,evidence);
    return response;
  };
  const json=async response=>{
    try{
      const data=await response.json(),evidence=responseEvidence.get(response);
      if(evidence){
        if(typeof data?.error==='string'&&/^[A-Z0-9_]{1,48}$/u.test(data.error))evidence.error=data.error;
        if(evidence.path==='/api/device'&&['not_requested','pending','approved','revoked','expired'].includes(data?.status))evidence.deviceStatus=data.status;
        if(evidence.path==='/api/operations'&&data?.schema==='aleph.operations.record.v1'){
          const id=trace(data.requestId);
          evidence.idMismatch=!id||!evidence.headerId||id!==evidence.headerId
            ||(config.expectedCommit&&data.commit!==config.expectedCommit);
          if(!evidence.idMismatch)evidence.operationsRequestId=id;
        }
      }
      return data;
    }catch{return null;}
  };
  const errorOnly=(data,error)=>data&&Object.keys(data).length===1&&data.error===error;
  const uiHeaders={'x-requested-with':'vault-ui'};
  const identityResponse=await send('deployment_identity','/aleph.json'),identity=await json(identityResponse);
  const normalize=s=>typeof s==='string'?s.replace(/\/$/u,'').toLowerCase():'';
  const identityMatches=identityResponse.status===200&&identity?.schema==='aleph.defense.deployment.v1'&&identity.step===12
    &&normalize(identity.repoUrl)===normalize(config.repoUrl)&&identity.judgeIssuer===config.judgeIssuer
    &&/^[a-f0-9]{40}$/u.test(identity.commit||'')&&(!config.expectedCommit||identity.commit===config.expectedCommit);
  add('deployment_identity','GET 식별 정보의 12단계·커밋·저장소·발급자 일치',`HTTP ${identityResponse.status}, 일치 ${identityMatches}`,identityMatches);
  const root=await send('initial_screen','/'),html=await root.text();
  const hidden=root.status===200&&['operations-panel','memo-panel','device-panel'].every(id=>new RegExp(`id="${id}"[^>]*hidden`,'u').test(html))
    &&html.includes('id="notes" aria-live="polite" hidden')&&html.includes('id="login-form"')
    &&['verification-run','verification-read','verification-rows','verification-record'].every(id=>html.includes(`id="${id}"`))
    &&Boolean(root.headers.get('x-content-type-options')?.toLowerCase()==='nosniff'||root.headers.get('content-security-policy'));
  add('initial_screen','GET 초기 화면은 보호 패널·목록 숨김, 로그인·작전실 요소와 보안 헤더 포함',`HTTP ${root.status}, 화면 확인 ${hidden}`,hidden);
  const seed=await send('public_source_absent','/data.json');
  add('public_source_absent','GET 공개 메모 원문 파일 404',`HTTP ${seed.status}`,seed.status===404);
  checks.push({attackId:'browser_assets',expected:'로그인·작전실·요청표 JS 3개별 본문 검사는 요청 예산 제한으로 미실행',observed:'not_run',passed:null});
  const vendor=await send('browser_sdk_removed','/vendor/supabase.js');
  add('browser_sdk_removed','GET 기존 브라우저 SDK 파일 404',`HTTP ${vendor.status}`,vendor.status===404);
  const auth=await send('anonymous_session','/api/auth',uiHeaders),session=await json(auth);
  const anonymous=auth.status===200&&session&&Object.keys(session).length===1&&session.user===null&&auth.headers.get('cache-control')?.includes('no-store');
  add('anonymous_session','GET 익명 세션은 토큰 없이 user null만 반환',`HTTP ${auth.status}, 익명 확인 ${Boolean(anonymous)}`,anonymous);
  // Compound legacy checks have no one-request-per-case receipt. They are not
  // executed or reported as blocked in this isolated submission run.
  for(const [attackId,expected] of [
    ['anonymous_note_reads','목록·단일·잘못된 토큰의 복합 조회 검사는 이번 제출에서 미실행'],
    ['anonymous_zone_reads','공지·강사 자료의 복합 조회 검사는 이번 제출에서 미실행'],
    ['original_database_reads','원본 DB 4개 표의 복합 조회 검사는 이번 제출에서 미실행'],
    ['pwa_public_assets','manifest·두 아이콘의 복합 배포 검사는 이번 제출에서 미실행'],
    ['icon_pixel_dimensions_not_run','PNG 픽셀 크기 검사는 이번 제출에서 미실행'],
    ['offline_public_assets','오프라인 안내·워커의 복합 조회 검사는 이번 제출에서 미실행'],
  ])checks.push({attackId,expected,observed:'not_run',passed:null});
  for(const [id,path,status,error] of [
    ['anonymous_device_read','/api/device',401,'AUTH_REQUIRED'],
    ['restore_get_rejected','/api/restore',401,'AUTH_REQUIRED'],
    ['anonymous_operations','/api/operations',401,'AUTH_REQUIRED'],
    ['anonymous_verification_read','/api/operations-check',401,'AUTH_REQUIRED'],
    ['verification_query_rejected','/api/operations-check?passed=41',400,'INVALID_OPERATIONS_PATH'],
  ]){
    const response=await send(id,path,uiHeaders),data=await json(response);
    add(id,`GET ${path}는 자료 없는 ${status} ${error}`,`HTTP ${response.status}, 거부 ${Boolean(errorOnly(data,error))}`,response.status===status&&errorOnly(data,error));
  }
  // These requests are not sent. null is not a passing result; the submission
  // exports the exact observed marker required by the isolated runner.
  for(const [attackId,expected] of [
    ['write_requests_not_run','POST/PUT/PATCH/DELETE 로그인·메모·공지·관리 요청은 격리 제한으로 미실행'],
    ['rule_and_verification_posts_not_run','POST 학생 가상 규칙·통합 검사 실행은 격리 제한으로 미실행'],
    ['device_restore_rpc_posts_not_run','POST 기기 요청·복구·서버 전용 DB 함수 호출은 격리 제한으로 미실행'],
  ])checks.push({attackId,expected,observed:'not_run',passed:null});
  return checks;
}
