-- Execute this whole file as postgres in the EXISTING Supabase SQL Editor.
-- Adds a private summary audit and one server-only function. It never writes
-- existing notes, backups, device approvals, policies, or earlier audit rows.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '20s';
DO $$
BEGIN
  IF to_regclass('auth.sessions') IS NULL
     OR to_regclass('aleph_device_step11.devices') IS NULL
     OR to_regclass('aleph_device_step11.audit') IS NULL
     OR to_regclass('aleph_recovery_step10.note_backup') IS NULL
     OR to_regclass('aleph_recovery_step10.recovery_audit') IS NULL
     OR to_regclass('public.vault_notes') IS NULL THEN
    RAISE EXCEPTION 'OPERATIONS_PREREQUISITE_MISSING';
  END IF;
  IF (to_regnamespace('aleph_operations_step12') IS NOT NULL
      AND obj_description(to_regnamespace('aleph_operations_step12'),'pg_namespace')
        IS DISTINCT FROM 'aleph.step12.operations.v1')
     OR (to_regclass('aleph_operations_step12.snapshots') IS NOT NULL
      AND obj_description(to_regclass('aleph_operations_step12.snapshots'),'pg_class')
        IS DISTINCT FROM 'aleph.step12.operations.v1')
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proname='aleph_step12_operations_snapshot'
      AND obj_description(p.oid,'pg_proc') IS DISTINCT FROM 'aleph.step12.operations.v1') THEN
    RAISE EXCEPTION 'OPERATIONS_UNRELATED_OBJECT';
  END IF;
END;
$$;
CREATE SCHEMA IF NOT EXISTS aleph_operations_step12;
COMMENT ON SCHEMA aleph_operations_step12 IS 'aleph.step12.operations.v1';
REVOKE ALL ON SCHEMA aleph_operations_step12 FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE IF NOT EXISTS aleph_operations_step12.snapshots (
  request_id uuid PRIMARY KEY,
  actor_id uuid NOT NULL,
  checked_at timestamptz NOT NULL,
  record jsonb NOT NULL CHECK (record->>'schema'='aleph.operations.record.v1')
);
COMMENT ON TABLE aleph_operations_step12.snapshots IS 'aleph.step12.operations.v1';
ALTER TABLE aleph_operations_step12.snapshots ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE aleph_operations_step12.snapshots FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.aleph_step12_operations_snapshot(
  p_user_id uuid, p_session_id uuid, p_commit text, p_rule_ids text[]
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  device aleph_device_step11.devices%ROWTYPE;
  saved aleph_recovery_step10.note_backup%ROWTYPE;
  recovery jsonb;
  record jsonb;
  request_id uuid := gen_random_uuid();
  checked_at timestamptz := clock_timestamp();
  backup_hash text;
  live_matches boolean;
  revocations integer;
  last_revoked timestamptz;
  restores integer;
  last_restored timestamptz;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL
     OR p_commit IS NULL OR p_commit !~ '^[0-9a-f]{40}$'
     OR p_rule_ids IS DISTINCT FROM ARRAY['device_registered','step_up_required','resource_zone']::text[]
     OR NOT EXISTS (SELECT 1 FROM auth.sessions WHERE id=p_session_id AND user_id=p_user_id) THEN
    RAISE EXCEPTION 'OPERATIONS_INPUT_INVALID';
  END IF;
  SELECT * INTO device FROM aleph_device_step11.devices
    WHERE user_id=p_user_id AND session_id=p_session_id FOR SHARE;
  IF NOT FOUND OR device.status<>'approved' OR device.expires_at<=now() THEN
    RAISE EXCEPTION 'OPERATIONS_APPROVAL_REQUIRED';
  END IF;
  SELECT count(*)::integer,max(at) INTO revocations,last_revoked
    FROM aleph_device_step11.audit WHERE device_id=device.device_id AND action='revoked';

  -- Account-scoped: A never sees B's backup metadata, audit totals or memo body.
  SELECT * INTO saved FROM aleph_recovery_step10.note_backup
    WHERE slot AND owner_id=p_user_id FOR SHARE;
  recovery := jsonb_build_object('state','not_available_for_this_account',
    'version',NULL,'backedUpAt',NULL,'backupVerified',NULL,'liveMatchesBackup',NULL,
    'restoreEvents',NULL,'lastRestoredAt',NULL);
  IF FOUND THEN
    backup_hash := encode(sha256(convert_to(jsonb_build_object(
      'title',saved.title,'content',saved.content)::text,'UTF8')),'hex');
    SELECT EXISTS (SELECT 1 FROM public.vault_notes n
      WHERE n.id=saved.note_id AND n.owner_id=p_user_id
      AND encode(sha256(convert_to(jsonb_build_object(
        'title',n.title,'content',n.content)::text,'UTF8')),'hex')=saved.content_sha256)
      INTO live_matches;
    SELECT count(*)::integer,max(occurred_at) INTO restores,last_restored
      FROM aleph_recovery_step10.recovery_audit
      WHERE actor_id=p_user_id AND note_id=saved.note_id AND action='note_restored';
    recovery := jsonb_build_object('state','available','version',saved.content_sha256,
      'backedUpAt',saved.backed_up_at,
      'backupVerified',saved.note_id='ec10d0d2-ea65-42e8-97d3-2edc907e3943'::uuid
        AND saved.content_sha256='7312aaf08b8a099439939bb1b5e284a9887a3592bee31978986c74fa41341aa1'
        AND backup_hash=saved.content_sha256,
      'liveMatchesBackup',live_matches,'restoreEvents',restores,'lastRestoredAt',last_restored);
  END IF;
  record := jsonb_build_object('schema','aleph.operations.record.v1',
    'requestId',request_id,'checkedAt',checked_at,'commit',p_commit,
    'scope','current_login_session',
    'policy',jsonb_build_object('ruleIds',to_jsonb(p_rule_ids),'decisionTests','not_executed'),
    'detection',jsonb_build_object('state','not_executed','events',NULL,'proposals',NULL),
    'revocation',jsonb_build_object('scope','student_session_registry',
      'sessionStatus',device.status,'events',revocations,'lastRevokedAt',last_revoked,
      'engineExecution','not_executed'),
    'recovery',recovery,
    'officialTests',jsonb_build_object('total',41,'state','not_executed','passed',NULL));
  INSERT INTO aleph_operations_step12.snapshots(request_id,actor_id,checked_at,record)
    VALUES(request_id,p_user_id,checked_at,record);
  RETURN record;
END;
$$;
COMMENT ON FUNCTION public.aleph_step12_operations_snapshot(uuid,uuid,text,text[]) IS 'aleph.step12.operations.v1';
REVOKE ALL ON FUNCTION public.aleph_step12_operations_snapshot(uuid,uuid,text,text[])
  FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.aleph_step12_operations_snapshot(uuid,uuid,text,text[]) TO service_role;
DO $$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
    IF has_schema_privilege(role_name,'aleph_operations_step12','USAGE,CREATE')
       OR has_table_privilege(role_name,'aleph_operations_step12.snapshots',
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_function_privilege(role_name,
         'public.aleph_step12_operations_snapshot(uuid,uuid,text,text[])','EXECUTE')
          IS DISTINCT FROM (role_name='service_role') THEN
      RAISE EXCEPTION 'OPERATIONS_PRIVILEGE_UNSAFE';
    END IF;
  END LOOP;
END;
$$;
NOTIFY pgrst,'reload schema';
COMMIT;
SELECT jsonb_build_object('schema','aleph.operations-setup.v1','ready',true,
  'clientCanRead',has_function_privilege('authenticated',
    'public.aleph_step12_operations_snapshot(uuid,uuid,text,text[])','EXECUTE'),
  'serverCanRead',has_function_privilege('service_role',
    'public.aleph_step12_operations_snapshot(uuid,uuid,text,text[])','EXECUTE')) AS result;
