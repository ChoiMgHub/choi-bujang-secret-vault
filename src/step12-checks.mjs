import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';

// The stage-12 submission runner permits public HTTPS GET/HEAD only.
// Do not import older runners: they perform POST/PUT/DELETE checks.
export async function checkStep12(config,{fetchImpl=globalThis.fetch}={}) {
  const app=new URL(config.publicAppUrl),source=new URL(config.originalApiUrl),issuer=new URL(config.identityProvider.issuer);
  const publicHost=host=>!['localhost','127.0.0.1','[::1]'].includes(host)&&!host.endsWith('.local')&&!/^\d+\.\d+\.\d+\.\d+$/u.test(host);
  if(app.protocol!=='https:'||!publicHost(app.hostname)||app.username||app.password||app.port||app.search||app.hash||app.pathname!=='/'
    ||source.protocol!=='https:'||source.origin!==issuer.origin||!/^https:\/\/[a-z0-9-]+\.supabase\.co\/auth\/v1$/u.test(issuer.href)
    ||source.pathname!=='/rest/v1/vault_notes'||source.username||source.password||source.port||source.search||source.hash)throw Error('공개 HTTPS 배포·원본 API 주소를 확인하세요.');
  const checks=[];
  const add=(attackId,expected,observed,passed)=>checks.push({attackId,expected,observed,passed:Boolean(passed)});
  const send=(target,headers={})=>fetchImpl(new URL(target,app),{
    method:'GET',headers,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
  const json=async response=>{try{return await response.json();}catch{return null;}};
  const errorOnly=(data,error)=>data&&Object.keys(data).length===1&&data.error===error;
  const uiHeaders={'x-requested-with':'vault-ui'};
  const identityResponse=await send('/aleph.json'),identity=await json(identityResponse);
  const normalize=s=>typeof s==='string'?s.replace(/\/$/u,'').toLowerCase():'';
  const identityMatches=identityResponse.status===200&&identity?.schema==='aleph.defense.deployment.v1'&&identity.step===12
    &&normalize(identity.repoUrl)===normalize(config.repoUrl)&&identity.judgeIssuer===config.judgeIssuer
    &&/^[a-f0-9]{40}$/u.test(identity.commit||'')&&(!config.expectedCommit||identity.commit===config.expectedCommit);
  add('deployment_identity','GET 식별 정보의 12단계·커밋·저장소·발급자 일치',`HTTP ${identityResponse.status}, 일치 ${identityMatches}`,identityMatches);
  const root=await send('/'),html=await root.text();
  const hidden=root.status===200&&['operations-panel','memo-panel','device-panel'].every(id=>new RegExp(`id="${id}"[^>]*hidden`,'u').test(html))
    &&html.includes('id="notes" aria-live="polite" hidden')&&html.includes('id="login-form"')
    &&['verification-run','verification-read','verification-rows','verification-record'].every(id=>html.includes(`id="${id}"`))
    &&Boolean(root.headers.get('x-content-type-options')?.toLowerCase()==='nosniff'||root.headers.get('content-security-policy'));
  add('initial_screen','GET 초기 화면은 보호 패널·목록 숨김, 로그인·작전실 요소와 보안 헤더 포함',`HTTP ${root.status}, 화면 확인 ${hidden}`,hidden);
  const seed=await send('/data.json');
  add('public_source_absent','GET 공개 메모 원문 파일 404',`HTTP ${seed.status}`,seed.status===404);
  let assets=true;const assetStatuses=[];
  for(const path of ['/auth-ui.js','/operations-ui.js','/verification-ui.js']){
    const response=await send(path),text=await response.text();assetStatuses.push(response.status);
    assets&&=response.status===200&&text.includes('/api/')&&!/(?:localStorage|sessionStorage|indexedDB|innerHTML|sb_secret_[A-Za-z0-9_-]{12,}|sb_publishable_[A-Za-z0-9_-]{8,})/u.test(text);
  }
  add('browser_assets','GET 로그인·작전실·요청표 JS 배포, 브라우저 저장소·키 원문 없음',`HTTP ${assetStatuses.join('/')}, 파일 확인 ${assets}`,assets);
  const vendor=await send('/vendor/supabase.js');
  add('browser_sdk_removed','GET 기존 브라우저 SDK 파일 404',`HTTP ${vendor.status}`,vendor.status===404);
  const auth=await send('/api/auth',uiHeaders),session=await json(auth);
  const anonymous=auth.status===200&&session&&Object.keys(session).length===1&&session.user===null&&auth.headers.get('cache-control')?.includes('no-store');
  add('anonymous_session','GET 익명 세션은 토큰 없이 user null만 반환',`HTTP ${auth.status}, 익명 확인 ${Boolean(anonymous)}`,anonymous);
  let noteDenied=true;const noteStatuses=[];
  for(const [path,headers] of [['/api/notes',uiHeaders],['/api/notes/10000000-0000-4000-8000-000000000099',uiHeaders],['/api/notes',{...uiHeaders,authorization:'Bearer not-a-token'}]]){
    const response=await send(path,headers),data=await json(response);noteStatuses.push(response.status);
    noteDenied&&=[401,403].includes(response.status)&&errorOnly(data,'AUTH_REQUIRED');
  }
  add('anonymous_note_reads','GET 익명 목록·단일·잘못된 토큰 조회는 자료 없는 401/403',`HTTP ${noteStatuses.join('/')}, 거부 ${noteDenied}`,noteDenied);
  let zones=true;const zoneStatuses=[];
  for(const path of ['/api/notices/80000000-0000-4000-8000-000000000001','/api/instructor/80000000-0000-4000-8000-000000000002']){
    const response=await send(path,uiHeaders),data=await json(response);zoneStatuses.push(response.status);
    zones&&=response.status===401&&errorOnly(data,'AUTH_REQUIRED');
  }
  add('anonymous_zone_reads','GET 공지·강사 자료는 미로그인 시 자료 없는 401',`HTTP ${zoneStatuses.join('/')}, 거부 ${zones}`,zones);
  let dbDenied=true;const dbStatuses=[];
  for(const table of ['vault_notes','vault_notices','vault_instructor_materials','vault_resource_roles']){
    const column=table==='vault_resource_roles'?'role':'id';
    const response=await send(new URL(`/rest/v1/${table}?select=${column}&limit=1`,source),{apikey:SUPABASE_PUBLIC_KEY});
    const data=await json(response);dbStatuses.push(response.status);
    dbDenied&&=[401,403].includes(response.status)&&data?.code==='42501'&&Object.keys(data).every(k=>['code','message','details','hint'].includes(k));
  }
  add('original_database_reads','GET 원본 4개 표의 공개 키 읽기는 401/403·42501',`HTTP ${dbStatuses.join('/')}, 권한 거부 ${dbDenied}`,dbDenied);
  const manifestResponse=await send('/app.webmanifest'),manifest=await json(manifestResponse);
  let pwa=manifestResponse.status===200&&Boolean(manifest?.name)&&manifest.start_url==='/'&&manifest.scope==='/'&&manifest.display==='standalone'
    &&Array.isArray(manifest.icons)&&manifest.icons.length===2&&manifest.icons.every(i=>['/icons/vault-192.png','/icons/vault-512.png'].includes(i.src));
  const iconStatuses=[];
  for(const size of [192,512]){
    const response=await send(`/icons/vault-${size}.png`),bytes=new Uint8Array(await response.arrayBuffer());iconStatuses.push(response.status);
    pwa&&=response.status===200&&bytes.length>24&&bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71
      &&new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(16)===size
      &&new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(20)===size;
  }
  add('pwa_public_assets','GET manifest·192/512 PNG 배포; 설치·승인 실측과 구분',`manifest HTTP ${manifestResponse.status}, 아이콘 HTTP ${iconStatuses.join('/')}, 확인 ${pwa}`,pwa);
  const offline=await send('/offline.html'),notice=await offline.text(),worker=await send('/service-worker.js'),script=await worker.text();
  const offlineAssets=offline.status===200&&worker.status===200&&notice.includes('서버에 연결할 수 없습니다')&&script.includes('/offline.html')&&script.includes("'/api/'");
  add('offline_public_assets','GET 공개 오프라인 안내·API 제외 워커; 실제 오프라인 전환은 별도',`HTTP ${offline.status}/${worker.status}, 파일 확인 ${offlineAssets}`,offlineAssets);
  for(const [id,path,status,error] of [
    ['anonymous_device_read','/api/device',401,'AUTH_REQUIRED'],
    ['restore_get_rejected','/api/restore',405,'METHOD_NOT_ALLOWED'],
    ['anonymous_operations','/api/operations',401,'AUTH_REQUIRED'],
    ['anonymous_verification_read','/api/operations-check',401,'AUTH_REQUIRED'],
    ['verification_query_rejected','/api/operations-check?passed=41',400,'INVALID_OPERATIONS_PATH'],
  ]){
    const response=await send(path,uiHeaders),data=await json(response);
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
