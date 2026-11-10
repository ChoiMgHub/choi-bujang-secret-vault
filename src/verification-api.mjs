import config from '../aleph.config.json' with {type:'json'};
import { createOperationsAccess,operationsBody,operationsPath,OPS_UUID } from './operations-access.mjs';
import { VERIFICATION_CASES,caseById } from './verification-catalog.mjs';
import { SUPABASE_PUBLIC_KEY } from './supabase-public.mjs';
import { validOperationsRecord } from './operations-api.mjs';

const sameKeys=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)
  &&Object.keys(v).sort().join(',')===names.split(',').sort().join(',');
const date=v=>typeof v==='string'&&/^20\d\d-\d\d-\d\dT[0-9:.]+Z$/u.test(v)&&Number.isFinite(Date.parse(v));
const trace=v=>typeof v==='string'&&/^[-a-zA-Z0-9:]{1,200}$/u.test(v);
const canonicalStatuses=item=>item.expectedStatus.split('/').map(Number);
const fixtureNotes={A:['10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001'],
  B:['20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001']};

export function validVerificationReport(report,commit) {
  if(!sameKeys(report,'schema,runId,startedAt,commit,account,fixtureNotesReady,rows')
    || report.schema!=='aleph.verification.record.v1'||report.commit!==commit
    || !['A','B'].includes(report.account)||typeof report.fixtureNotesReady!=='boolean'
    || !Array.isArray(report.rows)||report.rows.length>21
    || (report.runId===null ? report.startedAt!==null||report.rows.length!==0
      : typeof report.runId!=='string'||!OPS_UUID.test(report.runId)||typeof report.startedAt!=='string'||!Number.isFinite(Date.parse(report.startedAt))))return false;
  const seen=new Set();
  return report.rows.every(row=>{
    const item=caseById(row?.caseId);
    if(!item||item.source==='manual'||seen.has(item.caseId)
      ||!sameKeys(row,'caseId,source,method,path,expectedStatus,expectedResult,state,actualStatus,actualResult,requestId,checkedAt')
      ||!['source','method','path','expectedStatus','expectedResult'].every(k=>row[k]===item[k])
      ||!['passed','failed','error','not_applicable'].includes(row.state)
      ||(row.actualStatus!==null&&(!Number.isInteger(row.actualStatus)||row.actualStatus<100||row.actualStatus>599))
      ||(row.requestId!==null&&!trace(row.requestId))||(row.checkedAt!==null&&!date(row.checkedAt))
      ||![item.expectedResult,'UNEXPECTED_RESPONSE','REQUEST_ID_UNAVAILABLE','RESPONSE_UNAVAILABLE','ACCOUNT_NOT_APPLICABLE','FIXTURE_NOT_READY'].includes(row.actualResult))return false;
    seen.add(item.caseId);
    if(row.state==='passed')return canonicalStatuses(item).includes(row.actualStatus)
      &&row.actualResult===item.expectedResult&&trace(row.requestId)&&date(row.checkedAt);
    if(row.state==='not_applicable')return row.actualStatus===null&&row.requestId===null&&row.checkedAt===null
      &&['ACCOUNT_NOT_APPLICABLE','FIXTURE_NOT_READY'].includes(row.actualResult);
    if(row.state==='error')return row.actualStatus===null&&row.requestId===null&&date(row.checkedAt)&&row.actualResult==='RESPONSE_UNAVAILABLE';
    return row.actualStatus!==null&&date(row.checkedAt);
  });
}

function verifyBody(item,data,status,context) {
  if(!canonicalStatuses(item).includes(status))return false;
  if(item.caseId==='public_source')return status===404;
  if(item.caseId==='direct_database')return data?.code==='42501'&&sameKeys(data,'code,details,hint,message');
  if(item.caseId==='own_note'||item.caseId==='notice_read') {
    const id=item.caseId==='own_note'?fixtureNotes[context.account][0]:'80000000-0000-4000-8000-000000000001';
    return sameKeys(data,'id,title,body')&&data.id===id&&typeof data.title==='string'&&typeof data.body==='string';
  }
  if(item.caseId==='approved_device')return sameKeys(data,'schema,status,deviceId')
    &&data.schema==='aleph.device-status.v1'&&data.status==='approved'&&/^[a-f0-9]{16}$/u.test(data.deviceId||'');
  if(item.caseId==='backup_snapshot')return validOperationsRecord(data,context.commit)
    &&data.recovery.state==='available'&&data.recovery.backupVerified===true;
  if(item.source==='student_fixture_api')return sameKeys(data,'schema,source,caseId,requestId,checkedAt,commit,result')
    &&data.schema==='aleph.rule-fixture-result.v1'&&data.source===item.source&&data.caseId===item.caseId
    &&data.commit===context.commit&&OPS_UUID.test(data.requestId||'')&&date(data.checkedAt)
    &&sameKeys(data.result,'outcome,reasonCode,ruleIds')&&data.result.outcome===item.expectedResult
    &&Array.isArray(data.result.ruleIds)
    &&(item.expectedResult!=='propose_revocation'||data.result.reasonCode==='burst_read');
  return sameKeys(data,'error')&&data.error===item.expectedResult;
}

// The server chooses every URL/method/body. Browser input cannot select a URL,
// identity, HTTP result, timestamp or response content to be stored.
export async function measureVerificationCase(item,context,{deploymentConfig=config,fetchImpl=globalThis.fetch}={}) {
  const base={caseId:item.caseId,source:item.source,method:item.method,path:item.path,
    expectedStatus:item.expectedStatus,expectedResult:item.expectedResult};
  const skipped=actualResult=>({...base,state:'not_applicable',actualStatus:null,actualResult,requestId:null,checkedAt:null});
  if(item.account&&item.account!==context.account)return skipped('ACCOUNT_NOT_APPLICABLE');
  if(item.needsFixtures&&!context.fixtureNotesReady)return skipped('FIXTURE_NOT_READY');
  try {
    const origin=new URL(deploymentConfig.publicAppUrl).origin;
    let path=item.path.replace(':own',fixtureNotes[context.account][0]).replace(':other',fixtureNotes[context.account][1]);
    let target=new URL(path,origin);
    const headers={'x-requested-with':'vault-ui',origin};
    let body;
    if(!['public_source','anonymous_notes','anonymous_operations','direct_database'].includes(item.caseId))headers.authorization=context.authorization;
    if(item.method==='POST') {
      headers['content-type']='application/json';
      body=item.source==='student_fixture_api'?JSON.stringify({caseId:item.caseId}):'{}';
    }
    if(item.caseId==='direct_database') {
      const issuer=new URL(deploymentConfig.identityProvider.issuer),source=new URL(deploymentConfig.originalApiUrl);
      if(issuer.protocol!=='https:'||!/^https:\/\/[a-z0-9-]+\.supabase\.co\/auth\/v1$/u.test(issuer.href)
        ||source.origin!==issuer.origin||source.pathname!=='/rest/v1/vault_notes'||source.search||source.hash||source.username||source.password)throw Error('invalid_source');
      target=new URL(source);target.search='?select=id&limit=1';
      for(const key of Object.keys(headers))delete headers[key];
      headers.apikey=SUPABASE_PUBLIC_KEY;
    }else if(target.origin!==origin)throw Error('invalid_target');
    const response=await fetchImpl(target,{method:item.method,headers,body,cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
    const raw=await response.text();
    let data;
    if(raw.length<=65536&&response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
      try {data=JSON.parse(raw);}catch{/* A malformed response never passes. */}
    }
    const requestId=[response.headers.get('x-request-id'),response.headers.get('sb-request-id'),response.headers.get('x-vercel-id')].find(trace)||null;
    const matched=raw.length<=65536&&verifyBody(item,data,response.status,context)
      &&(item.source!=='student_fixture_api'||data.requestId===requestId);
    return {...base,state:matched&&requestId?'passed':'failed',actualStatus:response.status,
      actualResult:matched?(requestId?item.expectedResult:'REQUEST_ID_UNAVAILABLE'):'UNEXPECTED_RESPONSE',requestId,checkedAt:new Date().toISOString()};
  }catch{return {...base,state:'error',actualStatus:null,actualResult:'RESPONSE_UNAVAILABLE',requestId:null,checkedAt:new Date().toISOString()};}
}

export function createVerificationHandler(options={}) {
  const deploymentConfig=options.deploymentConfig||config;
  const authorize=createOperationsAccess({...options,deploymentConfig});
  const fetchImpl=options.fetchImpl||globalThis.fetch;
  const log=options.log||((value)=>console.info(value));
  return async(request,response)=>{
    const fail=(status,error)=>response.status(status).json({error});
    response.setHeader('Cache-Control','private, no-store');
    if(!['GET','POST'].includes(request.method))return fail(405,'METHOD_NOT_ALLOWED');
    if(!operationsPath(request,'/api/operations-check'))return fail(400,'INVALID_OPERATIONS_PATH');
    const access=await authorize(request,response);if(!access)return;
    const rpc=async(mode,runId=null,item=null)=>{
      const {data,error}=await access.db.rpc('aleph_step12_verification',{
        p_user_id:access.identity.userId,p_session_id:access.identity.sessionId,p_commit:access.commit,
        p_mode:mode,p_run_id:runId,p_item:item,
      }).abortSignal(AbortSignal.timeout(10000));
      if(error||!validVerificationReport(data,access.commit))throw Error('VERIFICATION_UNAVAILABLE');
      return data;
    };
    try {
      let report;
      if(request.method==='GET')report=await rpc('read');
      else {
        let body;
        try {body=operationsBody(request);}catch{return fail(400,'INVALID_INPUT');}
        if(body.action==='start'&&Object.keys(body).join(',')==='action')report=await rpc('start');
        else if(body.action==='check'&&sameKeys(body,'action,runId,caseId')&&typeof body.runId==='string'&&OPS_UUID.test(body.runId)) {
          const item=caseById(body.caseId);
          if(!item||item.source==='manual')return fail(400,'INVALID_INPUT');
          report=await rpc('read',body.runId);
          if(!report.rows.some(row=>row.caseId===item.caseId)) {
            const row=await measureVerificationCase(item,{...access,account:report.account,fixtureNotesReady:report.fixtureNotesReady},
              {deploymentConfig,fetchImpl});
            report=await rpc('append',report.runId,row);
          }
        }else return fail(400,'INVALID_INPUT');
      }
      // A first-class DB record, not client-reported status or invented passes.
      log(JSON.stringify(report));
      if(report.runId)response.setHeader('X-Verification-Run-ID',report.runId);
      return response.status(200).json({schema:'aleph.verification.view.v1',catalog:VERIFICATION_CASES,report});
    }catch{return fail(503,'VERIFICATION_UNAVAILABLE');}
  };
}
export default createVerificationHandler();
