(() => {
  const memo=document.querySelector('#memo-panel');
  const run=document.querySelector('#verification-run');
  const read=document.querySelector('#verification-read');
  const status=document.querySelector('#verification-status');
  const reference=document.querySelector('#verification-reference');
  const rows=document.querySelector('#verification-rows');
  const proof=document.querySelector('#verification-record');
  const details=document.querySelector('#verification-details');
  let generation=0,controller;
  const stateLabels={not_executed:'미실행',passed:'기대와 일치',failed:'불일치',error:'응답 확인 실패',not_applicable:'현재 계정·전제에서 제외'};
  const sourceLabels={live_api:'실서비스 API',student_fixture_api:'가상 규칙 API',manual:'별도 수동 시험'};
  function clear() {
    generation++;controller?.abort();controller=null;
    rows.replaceChildren();proof.textContent='';reference.textContent='';status.textContent='';
    run.disabled=false;read.disabled=false;
  }
  function render(view) {
    const report=view.report;
    const states={not_executed:0,passed:0,failed:0,error:0,not_applicable:0};
    rows.replaceChildren(...view.catalog.map(item=>{
      const measured=report.rows.find(row=>row.caseId===item.caseId);
      const state=measured?.state||'not_executed';states[state]++;
      const row=document.createElement('tr');
      const values=[`${item.step} · ${sourceLabels[item.source]}`,
        `${item.label}\n${item.method} ${item.path}`,
        `${item.expectedStatus} / ${item.expectedResult}`,
        measured ? `${measured.actualStatus??'—'} / ${measured.actualResult}` : '미실행',
        stateLabels[state],measured?.requestId||'—',measured?.checkedAt||'—'];
      for(const value of values) {const cell=document.createElement('td');cell.textContent=value;row.append(cell);}
      return row;
    }));
    proof.textContent=JSON.stringify(report,null,2);
    reference.textContent=report.runId
      ? `계정 ${report.account} · 검사 묶음 ID: ${report.runId} · 시작 시각: ${report.startedAt} · 검사 커밋: ${report.commit}`
      : `계정 ${report.account} · 이 로그인 세션·배포의 실행 기록 없음`;
    status.textContent=`기대와 일치 ${states.passed} · 불일치 ${states.failed} · 응답 실패 ${states.error} · 제외 ${states.not_applicable} · 미실행 ${states.not_executed}. 공식 41종 판정과 별개입니다.`;
  }
  async function api(body,token) {
    const response=await fetch('/api/operations-check',{
      method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,
      headers:{'x-requested-with':'vault-ui',...(body?{'content-type':'application/json'}:{})},
      ...(body?{body:JSON.stringify(body)}:{}),
    });
    const view=await response.json();
    if(token!==generation||memo.hidden||navigator.onLine===false)throw Object.assign(Error('stale'),{name:'AbortError'});
    if(!response.ok) {
      const known=['VERIFICATION_UNAVAILABLE','AUTH_REQUIRED','DEVICE_APPROVAL_REQUIRED',
        'DEVICE_CHECK_UNAVAILABLE','INVALID_INPUT','ORIGIN_NOT_ALLOWED','DEVICE_SESSION_REQUIRED',
        'DEPLOYMENT_REVISION_UNAVAILABLE','SERVER_NOT_CONFIGURED'];
      throw Object.assign(Error('unavailable'),{publicCode:`HTTP ${response.status} / ${known.includes(view?.error)?view.error:'응답 확인 실패'}`});
    }
    if(view?.schema!=='aleph.verification.view.v1'||!Array.isArray(view.catalog)
      ||view.report?.schema!=='aleph.verification.record.v1'||!Array.isArray(view.report.rows))throw Error('unavailable');
    return view;
  }
  async function load(execute=false) {
    clear();if(memo.hidden||navigator.onLine===false)return;
    const token=generation;controller=new AbortController();run.disabled=true;read.disabled=true;
    status.textContent=execute?'서버에서 요청을 한 건씩 실행합니다. 기대와 다른 결과가 나오면 중단합니다.':'현재 계정의 DB 검사 기록을 읽는 중입니다.';
    try {
      let view=await api(execute?{action:'start'}:null,token);render(view);
      if(execute) {
        details.open=true;
        for(const item of view.catalog.filter(item=>item.source!=='manual')) {
          status.textContent=`검사 중: ${item.label}`;
          view=await api({action:'check',runId:view.report.runId,caseId:item.caseId},token);render(view);
          const result=view.report.rows.find(row=>row.caseId===item.caseId);
          if(!result||['failed','error'].includes(result.state)) {
            status.textContent+=' 첫 불일치에서 중단했습니다. 남은 항목은 미실행입니다.';break;
          }
        }
      }
    }catch(error) {
      if(token===generation&&error.name!=='AbortError')status.textContent=`검사 실행 또는 DB 기록 조회를 확인하지 못했습니다. ${error.publicCode||'응답 형식 확인 실패'}. 성공으로 채우지 않고 중단했습니다.`;
    }finally {if(token===generation){controller=null;run.disabled=false;read.disabled=false;}}
  }
  const observer=new MutationObserver(()=>{if(memo.hidden)clear();else void load();});
  observer.observe(memo,{attributes:true,attributeFilter:['hidden']});
  run.addEventListener('click',()=>{void load(true);});
  read.addEventListener('click',()=>{void load();});
  window.addEventListener('offline',clear);window.addEventListener('pagehide',clear);
  if(!memo.hidden)void load();
})();
