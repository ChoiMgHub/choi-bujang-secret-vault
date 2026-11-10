// Isolated PostgreSQL/WASM validation, never a real Supabase result.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { validOperationsRecord } from '../src/operations-api.mjs';
if (!process.argv[2]) throw Error('Supply the local PGlite module path.');
const { PGlite } = await import(pathToFileURL(process.argv[2]).href);
const db = new PGlite();
const a='10000000-0000-4000-8000-000000000001',b='10000000-0000-4000-8000-000000000002';
const sa='20000000-0000-4000-8000-000000000001',sb='20000000-0000-4000-8000-000000000002';
const note='ec10d0d2-ea65-42e8-97d3-2edc907e3943';
const hash='7312aaf08b8a099439939bb1b5e284a9887a3592bee31978986c74fa41341aa1';
const commit='a'.repeat(40);
const rules="ARRAY['device_registered','step_up_required','resource_zone']";
const q=async sql=>(await db.query(sql)).rows;
const code=(u,s)=>createHash('sha256').update(`${u}:${s}`).digest('hex').slice(0,16);
const snapshot=async(u=a,s=sa)=>(await q(`SELECT public.aleph_step12_operations_snapshot('${u}','${s}','${commit}',${rules}) AS value`))[0].value;
let count=0;const pass=name=>{count++;console.log(`통과 · ${name}`);};
const oldState=async()=>({
  notes:await q('SELECT * FROM public.vault_notes ORDER BY id'),
  devices:await q('SELECT * FROM aleph_device_step11.devices ORDER BY user_id,session_id'),
  deviceAudit:await q('SELECT * FROM aleph_device_step11.audit ORDER BY id'),
  backup:await q('SELECT * FROM aleph_recovery_step10.note_backup'),
  recoveryAudit:await q('SELECT * FROM aleph_recovery_step10.recovery_audit ORDER BY occurred_at'),
});
try {
  await db.exec(`CREATE ROLE anon;CREATE ROLE authenticated;CREATE ROLE service_role BYPASSRLS;
    CREATE SCHEMA auth;CREATE TABLE auth.users(id uuid PRIMARY KEY,email text UNIQUE);
    CREATE TABLE auth.sessions(id uuid PRIMARY KEY,user_id uuid);
    INSERT INTO auth.users VALUES('${a}','learner-a@example.com'),('${b}','learner-b@example.com');
    INSERT INTO auth.sessions VALUES('${sa}','${a}'),('${sb}','${b}');
    CREATE TABLE public.vault_notes(id uuid PRIMARY KEY,owner_id uuid,title text,content text,created_at timestamptz);
    INSERT INTO public.vault_notes VALUES('${note}','${b}','방어전 9단계 테스트','',now()),
      ('80000000-0000-4000-8000-000000000001','${a}','unrelated virtual title','preserve this virtual memo',now());`);
  const deviceSQL=await readFile(new URL('../sql/step11-device-approval.sql',import.meta.url),'utf8');
  await db.exec(deviceSQL);
  for(const [u,s,email] of [[a,sa,'learner-a@example.com'],[b,sb,'learner-b@example.com']]) {
    await q(`SELECT public.aleph_step11_device_status('${u}','${s}',true)`);
    await q(`SELECT public.aleph_step11_review_device('${email}','${code(u,s)}',true)`);
  }
  const backupSQL=(await readFile(new URL('../sql/step10-note-backup-and-restore.sql',import.meta.url),'utf8'))
    .replaceAll('__NOTE_ID__',note).replaceAll('__OWNER_ID__',b).replaceAll('__CONTENT_SHA256__',hash);
  await db.exec(backupSQL);
  await q(`SELECT public.aleph_step10_restore_note('${note}','${b}','${hash}')`);
  const before=await oldState();
  const sql=await readFile(new URL('../sql/step12-operations.sql',import.meta.url),'utf8');
  await db.exec(sql);assert.deepEqual(await oldState(),before);
  pass('새 준비 SQL 전체 실행, 기존 메모·사본·승인·감사 행 보존');
  const result=await snapshot();assert.equal(validOperationsRecord(result,commit),true);
  assert.deepEqual((await q(`SELECT record FROM aleph_operations_step12.snapshots WHERE request_id='${result.requestId}'`))[0].record,result);
  assert.equal(result.detection.events,null);assert.equal(result.officialTests.passed,null);
  pass('DB에 저장된 요약과 반환한 API 근거 값 일치, 미실행 수치는 null');
  assert.equal(result.recovery.state,'not_available_for_this_account');
  assert.equal(result.recovery.version,null);assert.equal(result.recovery.restoreEvents,null);
  assert.doesNotMatch(JSON.stringify(result),/preserve this virtual memo|방어전 9단계 테스트|owner_id|session_id|actor_id/u);
  pass('A는 B의 사본·복구 횟수·본문을 읽지 못함');
  const rb=await snapshot(b,sb);assert.equal(validOperationsRecord(rb,commit),true);
  assert.equal(rb.recovery.backupVerified,true);assert.equal(rb.recovery.liveMatchesBackup,true);
  assert.equal(rb.recovery.version,hash);assert.equal(rb.recovery.restoreEvents,1);
  pass('B 소유 사본 재검증과 실제 기존 복구 감사 1건 조회');
  for(const role of ['anon','authenticated','service_role']) {
    await db.exec(`SET ROLE ${role}`);
    try {
      await assert.rejects(q('SELECT * FROM aleph_operations_step12.snapshots'),/permission denied/u);
      if(role==='service_role') assert.equal((await snapshot()).scope,'current_login_session');
      else await assert.rejects(snapshot(),/permission denied/u);
    } finally {await db.exec('RESET ROLE');}
  }
  pass('브라우저 직접 실행·표 접근 거부, 서버 역할만 제한 함수 사용');
  await assert.rejects(snapshot(a,sb),/OPERATIONS_INPUT_INVALID/u);
  await assert.rejects(q(`SELECT public.aleph_step12_operations_snapshot('${a}','${sa}','invalid',${rules})`),/OPERATIONS_INPUT_INVALID/u);
  await assert.rejects(q(`SELECT public.aleph_step12_operations_snapshot('${a}','${sa}','${commit}',ARRAY['invented'])`),/OPERATIONS_INPUT_INVALID/u);
  pass('사용자·세션 불일치, 임의 버전·규칙 입력 거부');
  const summaries=await q('SELECT * FROM aleph_operations_step12.snapshots ORDER BY checked_at');
  await db.exec(sql);assert.deepEqual(await oldState(),before);
  assert.deepEqual(await q('SELECT * FROM aleph_operations_step12.snapshots ORDER BY checked_at'),summaries);
  pass('SQL 재실행이 이전 작전실 기록과 기존 자료를 보존');
  await db.exec(`UPDATE public.vault_notes SET content='changed virtual content' WHERE id='${note}'`);
  const changed=await snapshot(b,sb);assert.equal(changed.recovery.liveMatchesBackup,false);
  assert.equal(changed.recovery.restoreEvents,1);
  assert.equal((await q(`SELECT content FROM public.vault_notes WHERE id='${note}'`))[0].content,'changed virtual content');
  pass('현재 메모 불일치를 사실대로 반환하고 조회가 복구를 실행하지 않음');
  await db.exec("UPDATE aleph_recovery_step10.note_backup SET content='damaged virtual backup'");
  assert.equal((await snapshot(b,sb)).recovery.backupVerified,false);
  pass('사본 내용이 훼손되면 재검증 불일치 표시');
  await q(`SELECT public.aleph_step11_review_device('learner-a@example.com','${code(a,sa)}',false)`);
  await assert.rejects(snapshot(),/OPERATIONS_APPROVAL_REQUIRED/u);
  await db.exec(`UPDATE aleph_device_step11.devices SET expires_at=now()-interval '1 second' WHERE user_id='${b}'`);
  await assert.rejects(snapshot(b,sb),/OPERATIONS_APPROVAL_REQUIRED/u);
  pass('철회·만료 세션은 요약 기록을 읽거나 새로 생성하지 못함');
  console.log(`격리 PostgreSQL 시험 ${count}개 통과. 실제 Supabase 결과가 아니다.`);
} finally {await db.close();}
