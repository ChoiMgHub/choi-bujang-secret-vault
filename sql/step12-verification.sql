-- Run the whole file as postgres after step12-operations.sql.
-- Adds only an account/session-scoped verification table and server RPC.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='20s';
DO $$
BEGIN
  IF to_regclass('aleph_operations_step12.snapshots') IS NULL
    OR obj_description(to_regnamespace('aleph_operations_step12'),'pg_namespace')
      IS DISTINCT FROM 'aleph.step12.operations.v1' THEN
    RAISE EXCEPTION 'VERIFICATION_PREREQUISITE_MISSING';
  END IF;
  IF (to_regclass('aleph_operations_step12.verification_runs') IS NOT NULL
    AND obj_description(to_regclass('aleph_operations_step12.verification_runs'),'pg_class')
      IS DISTINCT FROM 'aleph.step12.verification.v1')
    OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proname='aleph_step12_verification'
      AND obj_description(p.oid,'pg_proc') IS DISTINCT FROM 'aleph.step12.verification.v1') THEN
    RAISE EXCEPTION 'VERIFICATION_UNRELATED_OBJECT';
  END IF;
END;
$$;
CREATE TABLE IF NOT EXISTS aleph_operations_step12.verification_runs(
  run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL,
  session_id uuid NOT NULL,
  commit text NOT NULL CHECK(commit~'^[0-9a-f]{40}$'),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  rows jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(rows)='array' AND jsonb_array_length(rows)<=24)
);
COMMENT ON TABLE aleph_operations_step12.verification_runs IS 'aleph.step12.verification.v1';
ALTER TABLE aleph_operations_step12.verification_runs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE aleph_operations_step12.verification_runs FROM PUBLIC,anon,authenticated,service_role;
CREATE OR REPLACE FUNCTION public.aleph_step12_verification(
  p_user_id uuid,p_session_id uuid,p_commit text,p_mode text,
  p_run_id uuid DEFAULT NULL,p_item jsonb DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
SET lock_timeout='5s' SET statement_timeout='12s' AS $$
DECLARE
  saved aleph_operations_step12.verification_runs%ROWTYPE;
  device aleph_device_step11.devices%ROWTYPE;
  practice_account text;
  fixtures_ready boolean;
  known_cases text[]:=ARRAY['public_source','anonymous_notes','own_note','foreign_note','direct_database',
    'notice_read','notice_write','instructor_read','admin_write','restore_method','backup_snapshot',
    'approved_device','anonymous_operations','decider_allow','decider_deny','decider_step_up',
    'decider_recheck','detect_120','detect_121','detect_users','detect_slow'];
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL OR p_commit IS NULL OR p_commit!~'^[0-9a-f]{40}$'
    OR p_mode IS NULL OR p_mode NOT IN('start','read','append')
    OR NOT EXISTS(SELECT 1 FROM auth.sessions WHERE id=p_session_id AND user_id=p_user_id) THEN
    RAISE EXCEPTION 'VERIFICATION_INPUT_INVALID';
  END IF;
  SELECT * INTO device FROM aleph_device_step11.devices
    WHERE user_id=p_user_id AND session_id=p_session_id FOR SHARE;
  IF NOT FOUND OR device.status<>'approved' OR device.expires_at<=now() THEN
    RAISE EXCEPTION 'VERIFICATION_APPROVAL_REQUIRED';
  END IF;
  SELECT CASE lower(email) WHEN 'learner-a@example.com' THEN 'A'
    WHEN 'learner-b@example.com' THEN 'B' ELSE NULL END INTO practice_account
    FROM auth.users WHERE id=p_user_id;
  IF practice_account IS NULL THEN RAISE EXCEPTION 'VERIFICATION_PRACTICE_ACCOUNT_REQUIRED'; END IF;
  SELECT count(*)=2 INTO fixtures_ready FROM public.vault_notes n JOIN auth.users u ON u.id=n.owner_id
    WHERE (n.id='10000000-0000-4000-8000-000000000001'::uuid AND lower(u.email)='learner-a@example.com')
       OR (n.id='20000000-0000-4000-8000-000000000001'::uuid AND lower(u.email)='learner-b@example.com');
  IF p_mode='start' THEN
    IF p_run_id IS NOT NULL OR p_item IS NOT NULL THEN RAISE EXCEPTION 'VERIFICATION_INPUT_INVALID'; END IF;
    INSERT INTO aleph_operations_step12.verification_runs(actor_id,session_id,commit)
      VALUES(p_user_id,p_session_id,p_commit) RETURNING * INTO saved;
  ELSE
    IF p_mode='read' AND p_item IS NOT NULL THEN RAISE EXCEPTION 'VERIFICATION_INPUT_INVALID'; END IF;
    SELECT * INTO saved FROM aleph_operations_step12.verification_runs
      WHERE actor_id=p_user_id AND session_id=p_session_id AND commit=p_commit
        AND (p_run_id IS NULL OR run_id=p_run_id)
      ORDER BY started_at DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND AND (p_run_id IS NOT NULL OR p_mode='append') THEN
      RAISE EXCEPTION 'VERIFICATION_RUN_NOT_FOUND';
    END IF;
    IF p_mode='append' THEN
      IF p_run_id IS NULL OR p_item IS NULL OR jsonb_typeof(p_item)<>'object'
        OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(p_item) k)
          IS DISTINCT FROM ARRAY['actualResult','actualStatus','caseId','checkedAt','expectedResult',
            'expectedStatus','method','path','requestId','source','state']::text[]
        OR EXISTS(SELECT 1 FROM unnest(ARRAY['caseId','source','method','path',
          'expectedStatus','expectedResult','state']) k WHERE jsonb_typeof(p_item->k) IS DISTINCT FROM 'string')
        OR EXISTS(SELECT 1 FROM unnest(ARRAY['actualResult','requestId','checkedAt']) k
          WHERE jsonb_typeof(p_item->k) NOT IN('string','null'))
        OR NOT (p_item->>'caseId'=ANY(known_cases))
        OR p_item->>'source' NOT IN('live_api','student_fixture_api')
        OR p_item->>'method' NOT IN('GET','POST')
        OR p_item->>'state' NOT IN('passed','failed','error','not_applicable')
        OR length(p_item->>'path')>200 OR length(p_item->>'expectedStatus')>20
        OR length(p_item->>'expectedResult')>80 OR length(p_item->>'actualResult')>80
        OR (jsonb_typeof(p_item->'actualStatus') NOT IN('number','null'))
        OR (jsonb_typeof(p_item->'actualStatus')='number' AND
          (p_item->>'actualStatus')::integer NOT BETWEEN 100 AND 599)
        OR (p_item->>'requestId' IS NOT NULL AND
          (p_item->>'requestId'!~'^[-a-zA-Z0-9:]{1,200}$'))
        OR (p_item->>'checkedAt' IS NOT NULL AND
          (p_item->>'checkedAt'!~'^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$')) THEN
        RAISE EXCEPTION 'VERIFICATION_ROW_INVALID';
      END IF;
      IF p_item->>'state'='passed' AND (p_item->>'actualStatus' IS NULL
        OR p_item->>'requestId' IS NULL OR p_item->>'checkedAt' IS NULL) THEN
        RAISE EXCEPTION 'VERIFICATION_ROW_INVALID';
      END IF;
      -- First measured result is immutable for this run/case; a retry cannot
      -- silently rewrite a failed observation as a pass.
      IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(saved.rows) r WHERE r->>'caseId'=p_item->>'caseId') THEN
        UPDATE aleph_operations_step12.verification_runs SET rows=rows||jsonb_build_array(p_item)
          WHERE run_id=saved.run_id RETURNING * INTO saved;
      END IF;
    END IF;
  END IF;
  RETURN jsonb_build_object('schema','aleph.verification.record.v1','runId',saved.run_id,
    'startedAt',saved.started_at,'commit',p_commit,'account',practice_account,
    'fixtureNotesReady',fixtures_ready,'rows',coalesce(saved.rows,'[]'::jsonb));
END;
$$;
COMMENT ON FUNCTION public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb) IS 'aleph.step12.verification.v1';
REVOKE ALL ON FUNCTION public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb)
  FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb) TO service_role;
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
    IF has_table_privilege(r,'aleph_operations_step12.verification_runs',
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      OR has_function_privilege(r,'public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb)',
        'EXECUTE') IS DISTINCT FROM (r='service_role') THEN
      RAISE EXCEPTION 'VERIFICATION_PRIVILEGE_UNSAFE';
    END IF;
  END LOOP;
END;
$$;
NOTIFY pgrst,'reload schema';
COMMIT;
SELECT jsonb_build_object('schema','aleph.verification-setup.v1','ready',true,
  'clientCanRun',has_function_privilege('authenticated',
    'public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb)','EXECUTE'),
  'serverCanRun',has_function_privilege('service_role',
    'public.aleph_step12_verification(uuid,uuid,text,text,uuid,jsonb)','EXECUTE')) AS result;
