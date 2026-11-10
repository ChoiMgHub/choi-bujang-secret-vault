import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with {type:'json'};
import { createOperationsAccess,operationsBody,operationsPath } from './operations-access.mjs';
import { caseById } from './verification-catalog.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide,RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';

export async function executeRuleFixture(caseId,requestId) {
  const {normal,suspicious}=fixtureRequests();
  if(caseId.startsWith('decider_')) {
    let input;
    if(caseId==='decider_allow')input=normal;
    if(caseId==='decider_deny')input={...normal,deviceRegistered:false};
    if(caseId==='decider_step_up')input=suspicious;
    if(caseId==='decider_recheck')input={...suspicious,stepUp:{verified:true,authAgeSeconds:60}};
    if(!input)throw Error('UNKNOWN_CASE');
    const result=await decide({...input,requestId});
    if(Object.keys(result).sort().join(',')!=='decision,reasonCode,requestId,ruleIds,schema'
      || result.schema!=='aleph.decision.v1'||result.requestId!==requestId
      || !['allow','deny','step_up'].includes(result.decision)
      || !['approved','device_not_registered','step_up_required','resource_not_allowed'].includes(result.reasonCode)
      || !Array.isArray(result.ruleIds)||!result.ruleIds.length||!result.ruleIds.every(id=>RULE_IDS.includes(id)))throw Error('INVALID_DECISION');
    return {outcome:result.decision,reasonCode:result.reasonCode,ruleIds:result.ruleIds};
  }
  const start=Date.UTC(2026,9,1);
  const reads=(n,sub='learner_fixture',interval=2000)=>Array.from({length:n},(_,i)=>({
    at:new Date(start+i*interval).toISOString(),method:'GET',identity:{sub},
  }));
  const inputs={detect_120:()=>reads(120),detect_121:()=>reads(121),
    detect_users:()=>[...reads(100),...reads(100,'other_fixture')],detect_slow:()=>reads(121,'learner_fixture',7000)};
  if(!inputs[caseId])throw Error('UNKNOWN_CASE');
  const result=await detect(inputs[caseId]());
  if(result.action==='observe'&&Object.keys(result).join(',')==='action')return {outcome:'observe',reasonCode:null,ruleIds:[]};
  if(result.action==='propose_revocation'&&result.reasonCode==='burst_read'
    &&result.subject==='learner_fixture'&&Object.keys(result).sort().join(',')==='action,reasonCode,subject') {
    return {outcome:'propose_revocation',reasonCode:'burst_read',ruleIds:[]};
  }
  throw Error('INVALID_DETECTION');
}
export function createOperationsRuleHandler(options={}) {
  const deploymentConfig=options.deploymentConfig||config;
  const authorize=createOperationsAccess({...options,deploymentConfig});
  return async(request,response)=>{
    const fail=(status,error)=>response.status(status).json({error});
    response.setHeader('Cache-Control','private, no-store');
    if(request.method!=='POST')return fail(405,'METHOD_NOT_ALLOWED');
    if(!operationsPath(request,'/api/operations-rule'))return fail(400,'INVALID_OPERATIONS_PATH');
    const context=await authorize(request,response);if(!context)return;
    let body;
    try {body=operationsBody(request);}catch{return fail(400,'INVALID_INPUT');}
    const selected=caseById(body.caseId);
    if(Object.keys(body).join(',')!=='caseId'||selected?.source!=='student_fixture_api')return fail(400,'INVALID_INPUT');
    try {
      const requestId=randomUUID();
      const result=await executeRuleFixture(selected.caseId,requestId);
      response.setHeader('X-Request-ID',requestId);
      return response.status(200).json({schema:'aleph.rule-fixture-result.v1',source:'student_fixture_api',
        caseId:selected.caseId,requestId,checkedAt:new Date().toISOString(),commit:context.commit,result});
    }catch{return fail(503,'RULE_FIXTURE_UNAVAILABLE');}
  };
}
export default createOperationsRuleHandler();
