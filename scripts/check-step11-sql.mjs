// Isolated PostgreSQL/WASM only; pass a local PGlite module path.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
if (!process.argv[2]) throw Error('Supply the local PGlite module path.');
const { PGlite } = await import(pathToFileURL(process.argv[2]).href);
const db = new PGlite();
const a = '10000000-0000-4000-8000-000000000001', b = '10000000-0000-4000-8000-000000000002';
const sa = '20000000-0000-4000-8000-000000000001', sb = '20000000-0000-4000-8000-000000000002';
const code = createHash('sha256').update(`${a}:${sa}`).digest('hex').slice(0,16);
const q = async sql => (await db.query(sql)).rows;
const state = async (user=a,session=sa,request=false) => (await q(`SELECT public.aleph_step11_device_status('${user}','${session}',${request}) AS value`))[0].value;
const review = (approve=true,email='learner-a@example.com',device=code) => q(`SELECT public.aleph_step11_review_device('${email}','${device}',${approve}) AS value`);
let count=0; const pass = name => { count++; console.log(`통과 · ${name}`); };
try {
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
    CREATE SCHEMA auth;
    CREATE TABLE auth.users(id uuid PRIMARY KEY,email text UNIQUE);
    CREATE TABLE auth.sessions(id uuid PRIMARY KEY,user_id uuid);
    INSERT INTO auth.users VALUES ('${a}','learner-a@example.com'),('${b}','learner-b@example.com');
    INSERT INTO auth.sessions VALUES ('${sa}','${a}'),('${sb}','${b}');
    CREATE TABLE public.unrelated_memos(id integer, content text);
    INSERT INTO public.unrelated_memos VALUES (1,'preserved virtual memo');`);
  const source=await readFile(new URL('../sql/step11-device-approval.sql',import.meta.url),'utf8');
  await db.exec(source);
  pass('준비 SQL 전체 실행 성공');
  const initial=await state(); assert.equal(initial.status,'unrequested'); assert.equal(initial.deviceId,code);
  assert.equal((await q('SELECT count(*)::int AS n FROM aleph_device_step11.devices'))[0].n,0);
  pass('조회가 대기 요청을 임의 생성하지 않음');
  assert.equal((await state(a,sa,true)).status,'pending');
  assert.equal((await state(a,sa,true)).status,'pending');
  assert.equal((await q('SELECT count(*)::int AS n FROM aleph_device_step11.audit'))[0].n,1);
  pass('요청은 대기만 생성하고 재요청은 승인·감사 중복 생성하지 않음');
  for (const role of ['anon','authenticated','service_role']) {
    await db.exec(`SET ROLE ${role}`);
    try {
      await assert.rejects(review(),/permission denied/u);
      await assert.rejects(q('UPDATE aleph_device_step11.devices SET status=\'approved\''),/permission denied/u);
      if (role==='service_role') assert.equal((await state()).status,'pending');
      else await assert.rejects(state(),/permission denied/u);
    } finally { await db.exec('RESET ROLE'); }
  }
  pass('클라이언트·서버 승인 불가, 서버만 상태 조회 가능');
  await assert.rejects(review(true,'learner-b@example.com'),/no rows/u);
  pass('관리자도 계정과 확인 코드가 다르면 승인 중단');
  assert.equal((await review())[0].value.status,'approved');
  assert.equal((await state()).status,'approved');
  pass('관리자가 일치한 A 요청을 승인한 뒤 서버 재조회에서만 승인 확인');
  assert.equal((await state(b,sb)).status,'unrequested');
  await assert.rejects(state(b,sa),/DEVICE_SESSION_INVALID/u);
  pass('A 승인을 다른 사용자·세션에서 재사용 불가');
  await db.exec(source);
  assert.equal((await state()).status,'approved');
  assert.equal((await q('SELECT count(*)::int AS n FROM aleph_device_step11.audit'))[0].n,2);
  pass('준비 SQL 재실행이 승인과 감사 이력 보존');
  assert.equal((await review(false))[0].value.status,'revoked');
  assert.equal((await state(a,sa,true)).status,'revoked');
  await assert.rejects(review(),/DEVICE_NOT_PENDING/u);
  pass('철회 직후 차단, 재요청·재승인으로 되살리지 않음');
  await state(b,sb,true);
  await db.exec(`UPDATE aleph_device_step11.devices SET expires_at=now()-interval '1 second' WHERE user_id='${b}'`);
  assert.equal((await state(b,sb)).status,'expired');
  assert.equal((await state(b,sb,true)).status,'expired');
  pass('기한 만료와 재요청으로 기간 연장 불가');
  await db.exec(`DELETE FROM auth.sessions WHERE id='${sa}'`);
  await assert.rejects(state(),/DEVICE_SESSION_INVALID/u);
  pass('사라진 로그인 세션의 승인 사용 불가');
  assert.deepEqual(await q('SELECT * FROM public.unrelated_memos'),[{id:1,content:'preserved virtual memo'}]);
  assert.equal((await q('SELECT count(*)::int AS n FROM aleph_device_step11.audit'))[0].n,4);
  pass('다른 메모와 누적 감사 기록 보존');
  console.log(`격리 PostgreSQL 시험 ${count}개 통과. 실제 Supabase 결과가 아니다.`);
} finally { await db.close(); }
