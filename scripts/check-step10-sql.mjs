// Optional isolated PostgreSQL/WASM check. No production DB or credentials used.
// Supply a locally installed @electric-sql/pglite module path as the only argument.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

if (!process.argv[2]) throw new Error('Supply the local PGlite module path.');
const { PGlite } = await import(pathToFileURL(process.argv[2]).href);
const db = new PGlite();
let checks = 0;
const passed = name => { checks += 1; console.log(`통과 · ${name}`); };
const a = '10000000-0000-4000-8000-000000000001';
const b = '10000000-0000-4000-8000-000000000002';
const id = '80000000-0000-4000-8000-000000000010';
const literal = value => `'${value.replaceAll("'", "''")}'`;
const query = async sql => (await db.query(sql)).rows;
const hash = async note => (await query(`SELECT encode(sha256(convert_to(jsonb_build_object(
  'title', title, 'content', content)::text,'UTF8')),'hex') AS hash
  FROM public.vault_notes WHERE id=${literal(note)}`))[0]?.hash;
const dump = async () => query('SELECT * FROM public.vault_notes ORDER BY id');
try {
  await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS;
    CREATE TABLE public.vault_notes(id uuid PRIMARY KEY, owner_id uuid NOT NULL,
      title text NOT NULL, content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
    ALTER TABLE public.vault_notes ENABLE ROW LEVEL SECURITY;
    GRANT SELECT,INSERT,UPDATE,DELETE ON public.vault_notes TO service_role;
    INSERT INTO public.vault_notes(id,owner_id,title,content) VALUES
      ('${id}','${b}','가상 복구 대상','복구할 가상 본문'),
      ('80000000-0000-4000-8000-000000000011','${b}','다른 B 가상 메모','보존할 자료'),
      ('80000000-0000-4000-8000-000000000012','${a}','A 가상 메모','보존할 자료');`);
  const expected = await hash(id);
  const template = await readFile(new URL('../sql/step10-note-backup-and-restore.sql', import.meta.url), 'utf8');
  const sql = template.replaceAll('__NOTE_ID__', id).replaceAll('__OWNER_ID__', b)
    .replaceAll('__CONTENT_SHA256__', expected);
  const original = await dump();
  await db.exec(sql);
  assert.deepEqual(await dump(), original);
  passed('백업 준비가 실제 메모 행을 변경하지 않음');
  await db.exec(sql);
  assert.equal((await query('SELECT count(*)::int AS n FROM aleph_recovery_step10.note_backup'))[0].n, 1);
  assert.equal((await query('SELECT count(*)::int AS n FROM aleph_recovery_step10.recovery_audit'))[0].n, 1);
  passed('반복 실행이 사본과 감사 이력을 덮어쓰지 않음');
  for (const role of ['anon', 'authenticated', 'service_role']) {
    const [r] = await query(`SELECT has_schema_privilege('${role}','aleph_recovery_step10','USAGE') AS direct,
      has_function_privilege('${role}','public.aleph_step10_restore_note(uuid,uuid,text)','EXECUTE') AS rpc`);
    assert.equal(r.direct, false); assert.equal(r.rpc, role === 'service_role');
  }
  passed('사본 직접 접근 차단과 서버 전용 RPC 실행 권한');
  const restore = actor => query(`SELECT public.aleph_step10_restore_note('${id}','${actor}','${expected}') AS result`);
  for (const role of ['anon', 'authenticated']) {
    await db.exec(`SET ROLE ${role}`);
    try { await assert.rejects(restore(b), /permission denied/u); }
    finally { await db.exec('RESET ROLE'); }
  }
  await db.exec('SET ROLE service_role');
  try { assert.equal((await restore(b))[0].result.restored, true); }
  finally { await db.exec('RESET ROLE'); }
  passed('실제 역할을 바꾼 호출에서도 일반 사용자 거부·서버 역할 실행');
  const initialAudit = await query('SELECT * FROM aleph_recovery_step10.recovery_audit ORDER BY occurred_at,event_id');
  await assert.rejects(restore(a), /RESTORE_TARGET_DENIED/u);
  assert.deepEqual(await dump(), original);
  passed('다른 사용자 A의 복구 요청 거부');
  await db.exec(`UPDATE public.vault_notes SET content='시험으로 바꾼 가상 본문' WHERE id='${id}'`);
  assert.notEqual(await hash(id), expected);
  const [restored] = await restore(b);
  assert.equal(restored.result.contentHashMatches, true);
  assert.equal(restored.result.otherNotesUnchanged, true);
  assert.deepEqual(await dump(), original);
  assert.deepEqual((await query('SELECT * FROM aleph_recovery_step10.recovery_audit ORDER BY occurred_at,event_id')).slice(0, initialAudit.length), initialAudit);
  passed('B의 한 건 복구와 다른 메모·기존 감사 행 보존');
  await db.exec(`DELETE FROM public.vault_notes WHERE id='${id}'`);
  await restore(b);
  assert.deepEqual(await dump(), original);
  passed('삭제된 대상도 원래 ID·소유자·생성 시각으로 복구');
  await db.exec(`UPDATE public.vault_notes SET owner_id='${a}' WHERE id='${id}'`);
  const beforeOwnerError = await dump();
  await assert.rejects(restore(b), /RESTORE_OWNER_CHANGED/u);
  assert.deepEqual(await dump(), beforeOwnerError);
  passed('현재 소유자가 달라진 행을 임의로 덮어쓰지 않음');
  await db.exec(`UPDATE public.vault_notes SET owner_id='${b}' WHERE id='${id}';
    UPDATE aleph_recovery_step10.note_backup SET owner_id='${a}' WHERE slot;`);
  await assert.rejects(restore(b), /RESTORE_BACKUP_IDENTITY_MISMATCH/u);
  assert.deepEqual(await dump(), original);
  passed('사본의 소유자가 바뀌어도 복구 전에 원래 대상과 대조해 중단');
  await db.exec(`UPDATE aleph_recovery_step10.note_backup SET owner_id='${b}', content='변조한 사본' WHERE slot;`);
  const beforeBadBackup = await dump();
  await assert.rejects(restore(b), /RESTORE_BACKUP_HASH_MISMATCH/u);
  assert.deepEqual(await dump(), beforeBadBackup);
  passed('사본 내용 해시가 틀리면 메모를 변경하기 전에 중단');
  await assert.rejects(db.exec(sql), /STEP10_EXISTING_BACKUP_MISMATCH/u);
  await db.exec('ROLLBACK');
  passed('변조된 기존 사본을 새 준비 실행으로 덮어쓰지 않음');
  await db.exec('DELETE FROM aleph_recovery_step10.note_backup');
  await assert.rejects(restore(b), /RESTORE_BACKUP_MISSING/u);
  assert.deepEqual(await dump(), beforeBadBackup);
  passed('비공개 사본이 없으면 원본 메모를 변경하지 않고 중단');
  const ddl = (await query(`SELECT proconfig,prosecdef FROM pg_proc
    WHERE oid='public.aleph_step10_restore_note(uuid,uuid,text)'::regprocedure`))[0];
  assert.equal(ddl.prosecdef, true);
  assert.ok(ddl.proconfig.includes('search_path=pg_catalog, pg_temp'));
  passed('복구 함수의 고정 검색 경로와 권한 실행 방식');
  console.log(`격리된 가상 PostgreSQL 시험 ${checks}개 통과 · 실제 Supabase 복구 결과와 구분`);
} finally {
  await db.close();
}
