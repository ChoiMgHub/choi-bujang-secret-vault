import { checkStep10 } from './step10-checks.mjs';
import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';

// Anonymous live requests only. Browser installation and approved sessions are
// separate manual checks; this function never describes them as executed.
export async function checkStep11(config, {fetchImpl=globalThis.fetch, priorCheck=checkStep10}={}) {
  const previous=await priorCheck(config,{fetchImpl,expectedStep:11});
  const checks=[{attackId:'prior_stage_http_checks',expected:'기존 1~10단계의 공개·미로그인 HTTP 점검 20항목 유지',
    passed:previous.length===20&&previous.every(v=>v.passed),
    observed:`기존 HTTP ${previous.length}항목 중 ${previous.filter(v=>v.passed).length}항목 일치; 실패 ${previous.filter(v=>!v.passed).map(v=>v.attackId).join(',')||'없음'}`}];
  const send=(path,init={})=>fetchImpl(new URL(path,config.publicAppUrl),{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(15000),...init});
  const manifestResponse=await send('/app.webmanifest');
  let manifest;try{manifest=await manifestResponse.json();}catch{/* fail */}
  const manifestValid=manifestResponse.status===200&&manifest?.name&&manifest.start_url==='/'&&manifest.scope==='/'&&manifest.display==='standalone'
    &&Array.isArray(manifest.icons)&&manifest.icons.length===2
    &&manifest.icons.every(i=>['/icons/vault-192.png','/icons/vault-512.png'].includes(i.src));
  checks.push({attackId:'pwa_manifest',expected:'앱 이름·시작 주소·독립 화면·아이콘 두 개가 있는 manifest 배포',observed:`manifest HTTP ${manifestResponse.status}, 설정 확인 ${Boolean(manifestValid)}`,passed:Boolean(manifestValid)});
  let icons=true;const iconStatuses=[];
  for(const size of [192,512]){const response=await send(`/icons/vault-${size}.png`);const b=Buffer.from(await response.arrayBuffer());iconStatuses.push(response.status);
    icons&&=response.status===200&&b.length>24&&b.subarray(1,4).toString()==='PNG'&&b.readUInt32BE(16)===size&&b.readUInt32BE(20)===size;}
  checks.push({attackId:'pwa_icon_assets',expected:'실제 192·512 PNG 파일 배포',observed:`아이콘 HTTP ${iconStatuses.join('/')}, 크기 확인 ${icons}`,passed:icons});
  const html=await send('/');const text=await html.text();
  const hidden=html.status===200&&/id="device-panel"[^>]*hidden/u.test(text)&&/id="memo-panel"[^>]*hidden/u.test(text)
    &&/id="notes"[^>]*hidden/u.test(text)&&text.includes('rel="manifest"')&&text.includes('설치 여부는 기기 승인 근거가 아닙니다');
  checks.push({attackId:'approval_screen_initially_hidden',expected:'초기 HTML에 메모·승인 패널 숨김, 설치와 승인을 구분한 안내',observed:`화면 HTTP ${html.status}, 초기 숨김·안내 확인 ${hidden}`,passed:hidden});
  for(const method of ['GET','POST']){
    const response=await send('/api/device',{method,headers:{'x-requested-with':'vault-ui',origin:new URL(config.publicAppUrl).origin,'content-type':'application/json'},...(method==='POST'?{body:'{}'}:{})});
    let body;try{body=await response.json();}catch{/* fail */}
    const passed=response.status===401&&body?.error==='AUTH_REQUIRED'&&Object.keys(body).length===1&&response.headers.get('cache-control')?.includes('no-store');
    checks.push({attackId:`anonymous_device_${method.toLowerCase()}`,expected:'미로그인 기기 상태·요청은 401, 식별자·자료 미반환',observed:`${method} HTTP ${response.status}, 미인증 거부 ${Boolean(passed)}`,passed:Boolean(passed)});
  }
  const offline=await send('/offline.html');const notice=await offline.text();const worker=await send('/service-worker.js');const source=await worker.text();
  const assets=offline.status===200&&notice.includes('서버에 연결할 수 없습니다')&&worker.status===200&&source.includes('/offline.html')&&source.includes("'/api/'");
  checks.push({attackId:'offline_public_assets',expected:'공개 오프라인 안내와 API 제외 서비스 워커 파일 배포; 실제 오프라인 동작은 별도 시험',observed:`안내 HTTP ${offline.status}, 워커 HTTP ${worker.status}, 파일 확인 ${assets}`,passed:assets});
  for(const [name,args] of [
    ['aleph_step11_device_status',{p_user_id:'10000000-0000-4000-8000-000000000099',p_session_id:'20000000-0000-4000-8000-000000000099',p_request:false}],
    ['aleph_step11_review_device',{p_practice_email:'learner-a@example.com',p_device_id:'0000000000000000',p_approve:false}],
  ]){
    const response=await fetchImpl(new URL(`/rest/v1/rpc/${name}`,config.originalApiUrl),{method:'POST',headers:{apikey:SUPABASE_PUBLIC_KEY,'content-type':'application/json'},body:JSON.stringify(args),redirect:'error',signal:AbortSignal.timeout(15000)});
    let payload;try{payload=await response.json();}catch{/* fail */}
    const passed=[401,403].includes(response.status)&&payload?.code==='42501'&&Object.keys(payload).every(k=>['code','message','details','hint'].includes(k));
    checks.push({attackId:name.endsWith('status')?'device_db_status_denied':'device_db_approval_denied',expected:'공개 키로 DB 기기 함수 직접 실행 불가',observed:`원본 함수 HTTP ${response.status}, 권한 거부 ${passed}`,passed});
  }
  return checks;
}
