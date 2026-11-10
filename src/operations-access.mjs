import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { cookieAuthorization, trustedBrowserRequest } from './browser-session.mjs';
import { bindDeviceSession, readDeviceApproval, sessionDeviceId } from './device-approval.mjs';

export const OPS_UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
export function operationsPath(request,path) {
  try {
    const url=new URL(request.url||path,'https://app.invalid');
    const params=[...url.searchParams];
    const mirror=params.length===1 && params[0][0]==='feature' && params[0][1]===path.slice(5);
    return url.pathname===path && !url.hash && (!url.search||mirror);
  } catch {return false;}
}
export function operationsBody(request) {
  if(!request.headers?.['content-type']?.toLowerCase().startsWith('application/json')) throw Error('JSON_REQUIRED');
  let body=request.body;
  if(typeof body==='string'||Buffer.isBuffer(body)) {
    if(Buffer.byteLength(body)>1024)throw Error('INVALID_INPUT');
    body=JSON.parse(String(body));
  }
  if(!body||Array.isArray(body)||typeof body!=='object')throw Error('INVALID_INPUT');
  return body;
}
export function createOperationsAccess({deploymentConfig,env=process.env,fetchImpl=globalThis.fetch,runtimeFactory}) {
  let runtime;
  return async(request,response)=>{
    response.setHeader('Cache-Control','private, no-store');
    response.setHeader('Vary','Cookie, Authorization');
    response.setHeader('X-Content-Type-Options','nosniff');
    const fail=(status,error)=>{response.status(status).json({error});return null;};
    if(!trustedBrowserRequest(request,deploymentConfig))return fail(403,'ORIGIN_NOT_ALLOWED');
    const authorization=cookieAuthorization(request);
    if(!authorization)return fail(401,'AUTH_REQUIRED');
    try {
      if(!runtime) {
        if(runtimeFactory)runtime=runtimeFactory();
        else {
          const url=env.SUPABASE_URL?.trim(),key=env.SUPABASE_SECRET_KEY?.trim();
          if(!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/u.test(url||'')
            || !/^sb_secret_[A-Za-z0-9_-]+$/u.test(key||'')
            || deploymentConfig.identityProvider?.issuer!==`${url.replace(/\/$/u,'')}/auth/v1`)return fail(503,'SERVER_NOT_CONFIGURED');
          const db=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false},global:{fetch:fetchImpl}});
          runtime={db,verifyLogin:createLoginVerifier({config:deploymentConfig,supabaseClient:db})};
        }
      }
      const identity=await runtime.verifyLogin(authorization);
      if(!identity)return fail(401,'AUTH_REQUIRED');
      const bound=await bindDeviceSession(runtime.db,identity,authorization);
      if(!sessionDeviceId(bound))return fail(403,'DEVICE_SESSION_REQUIRED');
      const device=await readDeviceApproval(runtime.db,bound);
      if(device.status!=='approved')return fail(device.status==='unavailable'?503:403,
        device.status==='unavailable'?'DEVICE_CHECK_UNAVAILABLE':'DEVICE_APPROVAL_REQUIRED');
      if(!/^[a-f0-9]{40}$/u.test(env.VERCEL_GIT_COMMIT_SHA||''))return fail(503,'DEPLOYMENT_REVISION_UNAVAILABLE');
      return {db:runtime.db,identity:bound,authorization,commit:env.VERCEL_GIT_COMMIT_SHA};
    }catch{return fail(503,'OPERATIONS_RECORD_UNAVAILABLE');}
  };
}
