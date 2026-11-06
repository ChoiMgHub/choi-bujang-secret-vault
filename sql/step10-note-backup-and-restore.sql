-- Template: fill the three markers privately in the SQL Editor.
-- Creates a private one-note backup and a server-only recovery function.
-- Does not change live memo rows, existing policies, or existing audit tables.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '20s';

DO $$
BEGIN
  IF to_regnamespace('aleph_recovery_step10') IS NOT NULL
     AND obj_description(to_regnamespace('aleph_recovery_step10'), 'pg_namespace')
         IS DISTINCT FROM 'aleph.step10.recovery.v1' THEN
    RAISE EXCEPTION 'STEP10_UNRELATED_SCHEMA';
  END IF;
  IF to_regprocedure('public.aleph_step10_restore_note(uuid,uuid,text)') IS NOT NULL
     AND obj_description(to_regprocedure('public.aleph_step10_restore_note(uuid,uuid,text)'), 'pg_proc')
         IS DISTINCT FROM 'aleph.step10.recovery.v1' THEN
    RAISE EXCEPTION 'STEP10_UNRELATED_FUNCTION';
  END IF;
END;
$$;

CREATE SCHEMA IF NOT EXISTS aleph_recovery_step10;
COMMENT ON SCHEMA aleph_recovery_step10 IS 'aleph.step10.recovery.v1';
REVOKE ALL ON SCHEMA aleph_recovery_step10 FROM PUBLIC, anon, authenticated, service_role;

DO $$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['note_backup', 'recovery_audit'] LOOP
    IF to_regclass('aleph_recovery_step10.' || name) IS NOT NULL
       AND obj_description(to_regclass('aleph_recovery_step10.' || name), 'pg_class')
           IS DISTINCT FROM 'aleph.step10.recovery.v1' THEN
      RAISE EXCEPTION 'STEP10_UNRELATED_TABLE';
    END IF;
  END LOOP;
END;
$$;

CREATE TABLE IF NOT EXISTS aleph_recovery_step10.note_backup (
  slot boolean PRIMARY KEY DEFAULT true CHECK (slot),
  note_id uuid NOT NULL UNIQUE,
  owner_id uuid NOT NULL,
  title text NOT NULL,
  content text NOT NULL,
  source_created_at timestamptz NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
  backed_up_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS aleph_recovery_step10.recovery_audit (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  action text NOT NULL CHECK (action IN ('backup_created', 'note_restored')),
  note_id uuid NOT NULL,
  actor_id uuid NOT NULL,
  before_sha256 text,
  after_sha256 text NOT NULL
);
COMMENT ON TABLE aleph_recovery_step10.note_backup IS 'aleph.step10.recovery.v1';
COMMENT ON TABLE aleph_recovery_step10.recovery_audit IS 'aleph.step10.recovery.v1';
ALTER TABLE aleph_recovery_step10.note_backup ENABLE ROW LEVEL SECURITY;
ALTER TABLE aleph_recovery_step10.recovery_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE aleph_recovery_step10.note_backup,
  aleph_recovery_step10.recovery_audit FROM PUBLIC, anon, authenticated, service_role;

-- Only the initial verified live note can create the immutable exercise backup.
-- Re-running this setup verifies the existing backup instead of overwriting it.
DO $$
DECLARE
  target_id uuid := '__NOTE_ID__';
  target_owner uuid := '__OWNER_ID__';
  expected_hash text := '__CONTENT_SHA256__';
  saved aleph_recovery_step10.note_backup%ROWTYPE;
  original public.vault_notes%ROWTYPE;
  actual_hash text;
BEGIN
  IF expected_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'STEP10_INVALID_HASH'; END IF;
  LOCK TABLE public.vault_notes IN SHARE MODE;
  SELECT * INTO saved FROM aleph_recovery_step10.note_backup WHERE slot;
  IF FOUND THEN
    actual_hash := encode(sha256(convert_to(jsonb_build_object(
      'title', saved.title, 'content', saved.content)::text, 'UTF8')), 'hex');
    IF saved.note_id <> target_id OR saved.owner_id <> target_owner
       OR saved.content_sha256 <> expected_hash OR actual_hash <> expected_hash THEN
      RAISE EXCEPTION 'STEP10_EXISTING_BACKUP_MISMATCH';
    END IF;
  ELSE
    SELECT * INTO original FROM public.vault_notes WHERE id = target_id;
    IF NOT FOUND OR original.owner_id <> target_owner THEN
      RAISE EXCEPTION 'STEP10_TARGET_NOT_FOUND';
    END IF;
    actual_hash := encode(sha256(convert_to(jsonb_build_object(
      'title', original.title, 'content', original.content)::text, 'UTF8')), 'hex');
    IF actual_hash <> expected_hash THEN RAISE EXCEPTION 'STEP10_LIVE_HASH_CHANGED'; END IF;
    INSERT INTO aleph_recovery_step10.note_backup
      (slot, note_id, owner_id, title, content, source_created_at, content_sha256)
    VALUES (true, original.id, original.owner_id, original.title, original.content,
      original.created_at, expected_hash);
    INSERT INTO aleph_recovery_step10.recovery_audit
      (action, note_id, actor_id, before_sha256, after_sha256)
    VALUES ('backup_created', target_id, target_owner, expected_hash, expected_hash);
  END IF;
END;
$$;

-- No client chooses an owner or backup body. The API supplies its verified actor.
-- Writable public is excluded; temp comes last and every relation is qualified.
CREATE OR REPLACE FUNCTION public.aleph_step10_restore_note(
  p_note_id uuid, p_actor_id uuid, p_expected_sha256 text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '5s'
SET statement_timeout = '15s'
AS $$
DECLARE
  saved aleph_recovery_step10.note_backup%ROWTYPE;
  current_note public.vault_notes%ROWTYPE;
  backup_hash text;
  before_hash text;
  after_hash text;
  others_before text;
  others_after text;
  audit_before bigint;
  audit_after bigint;
  affected integer;
BEGIN
  SELECT * INTO saved FROM aleph_recovery_step10.note_backup WHERE slot FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'RESTORE_BACKUP_MISSING'; END IF;
  IF saved.note_id <> '__NOTE_ID__'::uuid OR saved.owner_id <> '__OWNER_ID__'::uuid THEN
    RAISE EXCEPTION 'RESTORE_BACKUP_IDENTITY_MISMATCH';
  END IF;
  IF p_note_id IS NULL OR p_actor_id IS NULL OR p_expected_sha256 IS NULL
     OR saved.note_id <> p_note_id OR saved.owner_id <> p_actor_id THEN
    RAISE EXCEPTION 'RESTORE_TARGET_DENIED';
  END IF;
  backup_hash := encode(sha256(convert_to(jsonb_build_object(
    'title', saved.title, 'content', saved.content)::text, 'UTF8')), 'hex');
  IF p_expected_sha256 <> '__CONTENT_SHA256__'
     OR p_expected_sha256 <> saved.content_sha256 OR backup_hash <> p_expected_sha256 THEN
    RAISE EXCEPTION 'RESTORE_BACKUP_HASH_MISMATCH';
  END IF;
  -- Briefly serialize memo writes while checking that unrelated rows stay equal.
  LOCK TABLE public.vault_notes IN SHARE ROW EXCLUSIVE MODE;
  SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object(
    'id', id, 'owner', owner_id, 'title', title, 'content', content,
    'created', extract(epoch FROM created_at)) ORDER BY id), '[]'::jsonb)::text, 'UTF8')), 'hex')
    INTO others_before FROM public.vault_notes WHERE id <> p_note_id;
  SELECT count(*) INTO audit_before FROM aleph_recovery_step10.recovery_audit;
  SELECT * INTO current_note FROM public.vault_notes WHERE id = p_note_id FOR UPDATE;
  IF FOUND THEN
    IF current_note.owner_id <> saved.owner_id THEN RAISE EXCEPTION 'RESTORE_OWNER_CHANGED'; END IF;
    before_hash := encode(sha256(convert_to(jsonb_build_object(
      'title', current_note.title, 'content', current_note.content)::text, 'UTF8')), 'hex');
    UPDATE public.vault_notes SET title = saved.title, content = saved.content
      WHERE id = saved.note_id AND owner_id = saved.owner_id;
    GET DIAGNOSTICS affected = ROW_COUNT;
  ELSE
    INSERT INTO public.vault_notes (id, owner_id, title, content, created_at)
      VALUES (saved.note_id, saved.owner_id, saved.title, saved.content, saved.source_created_at);
    GET DIAGNOSTICS affected = ROW_COUNT;
  END IF;
  IF affected <> 1 THEN RAISE EXCEPTION 'RESTORE_ROW_COUNT_MISMATCH'; END IF;
  SELECT * INTO current_note FROM public.vault_notes WHERE id = p_note_id;
  after_hash := encode(sha256(convert_to(jsonb_build_object(
    'title', current_note.title, 'content', current_note.content)::text, 'UTF8')), 'hex');
  IF current_note.owner_id <> saved.owner_id OR after_hash <> p_expected_sha256 THEN
    RAISE EXCEPTION 'RESTORE_VERIFICATION_FAILED';
  END IF;
  SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object(
    'id', id, 'owner', owner_id, 'title', title, 'content', content,
    'created', extract(epoch FROM created_at)) ORDER BY id), '[]'::jsonb)::text, 'UTF8')), 'hex')
    INTO others_after FROM public.vault_notes WHERE id <> p_note_id;
  IF others_before <> others_after THEN RAISE EXCEPTION 'RESTORE_OTHER_ROWS_CHANGED'; END IF;
  INSERT INTO aleph_recovery_step10.recovery_audit
    (action, note_id, actor_id, before_sha256, after_sha256)
  VALUES ('note_restored', p_note_id, p_actor_id, before_hash, after_hash);
  SELECT count(*) INTO audit_after FROM aleph_recovery_step10.recovery_audit;
  IF audit_after <> audit_before + 1 THEN RAISE EXCEPTION 'RESTORE_AUDIT_MISMATCH'; END IF;
  RETURN jsonb_build_object('schema', 'aleph.note-restore.v1', 'id', p_note_id,
    'restored', true, 'idMatches', true, 'ownerMatches', true, 'contentHashMatches', true,
    'contentSha256', after_hash, 'otherNotesUnchanged', true,
    'auditRowsBefore', audit_before, 'auditRowsAfter', audit_after);
END;
$$;
COMMENT ON FUNCTION public.aleph_step10_restore_note(uuid, uuid, text) IS 'aleph.step10.recovery.v1';
REVOKE ALL ON FUNCTION public.aleph_step10_restore_note(uuid, uuid, text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.aleph_step10_restore_note(uuid, uuid, text) TO service_role;

-- Verify effective permissions before committing setup.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF has_schema_privilege(r, 'aleph_recovery_step10', 'USAGE,CREATE')
       OR has_table_privilege(r, 'aleph_recovery_step10.note_backup', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_table_privilege(r, 'aleph_recovery_step10.recovery_audit', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
      RAISE EXCEPTION 'STEP10_PRIVATE_ACCESS_REMAINS';
    END IF;
    IF has_function_privilege(r, 'public.aleph_step10_restore_note(uuid,uuid,text)', 'EXECUTE')
       IS DISTINCT FROM (r = 'service_role') THEN
      RAISE EXCEPTION 'STEP10_RPC_PRIVILEGES_MISMATCH';
    END IF;
  END LOOP;
END;
$$;
NOTIFY pgrst, 'reload schema';
COMMIT;

SELECT jsonb_build_object(
  'schema', 'aleph.note-backup-ready.v1',
  'backupReady', true, 'noteId', saved.note_id,
  'idMatches', saved.note_id = '__NOTE_ID__'::uuid,
  'ownerMatches', saved.owner_id = '__OWNER_ID__'::uuid,
  'contentHashMatches', saved.content_sha256 = '__CONTENT_SHA256__'
    AND encode(sha256(convert_to(jsonb_build_object('title', saved.title,
      'content', saved.content)::text, 'UTF8')), 'hex') = saved.content_sha256,
  'contentSha256', saved.content_sha256,
  'liveMatchesBackup', EXISTS (SELECT 1 FROM public.vault_notes n
    WHERE n.id = saved.note_id AND n.owner_id = saved.owner_id
      AND encode(sha256(convert_to(jsonb_build_object('title', n.title,
        'content', n.content)::text, 'UTF8')), 'hex') = saved.content_sha256),
  'auditRows', (SELECT count(*) FROM aleph_recovery_step10.recovery_audit)
) AS backup_status FROM aleph_recovery_step10.note_backup saved WHERE slot;
