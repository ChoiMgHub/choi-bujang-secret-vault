-- Run the whole file in the EXISTING project's SQL Editor as postgres.
-- Adds only the stage-11 registry, audit, and two restricted functions.
-- Existing notes, accounts, stage-8/10 policies and audit rows are preserved.
BEGIN;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role' AND rolbypassrls)
     OR to_regclass('auth.sessions') IS NULL THEN
    RAISE EXCEPTION 'DEVICE_PREREQUISITE_MISSING';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='aleph_device_step11'
      AND obj_description(oid,'pg_namespace') IS DISTINCT FROM 'aleph.step11.v1') THEN
    RAISE EXCEPTION 'UNRELATED_DEVICE_SCHEMA';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proname IN ('aleph_step11_device_status','aleph_step11_review_device')
      AND obj_description(p.oid,'pg_proc') IS DISTINCT FROM 'aleph.step11.v1') THEN
    RAISE EXCEPTION 'UNRELATED_DEVICE_FUNCTION';
  END IF;
END;
$$;
CREATE SCHEMA IF NOT EXISTS aleph_device_step11;
COMMENT ON SCHEMA aleph_device_step11 IS 'aleph.step11.v1';
REVOKE ALL ON SCHEMA aleph_device_step11 FROM PUBLIC, anon, authenticated, service_role;

CREATE TABLE IF NOT EXISTS aleph_device_step11.devices (
  user_id uuid NOT NULL,
  session_id uuid NOT NULL,
  device_id text NOT NULL CHECK (device_id ~ '^[0-9a-f]{16}$'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','revoked')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  PRIMARY KEY (user_id,session_id),
  UNIQUE (user_id,device_id),
  CHECK ((status='pending' AND reviewed_at IS NULL) OR (status<>'pending' AND reviewed_at IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS aleph_device_step11.audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('requested','approved','revoked')),
  at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE aleph_device_step11.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE aleph_device_step11.audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA aleph_device_step11 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aleph_device_step11 FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.aleph_step11_device_status(
  p_user_id uuid, p_session_id uuid, p_request boolean DEFAULT false
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE saved aleph_device_step11.devices%ROWTYPE;
  device_code text;
  added integer;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL OR p_request IS NULL
     OR NOT EXISTS (SELECT 1 FROM auth.sessions WHERE id=p_session_id AND user_id=p_user_id) THEN
    RAISE EXCEPTION 'DEVICE_SESSION_INVALID';
  END IF;
  device_code := substr(encode(sha256(convert_to(p_user_id::text || ':' || p_session_id::text,'UTF8')),'hex'),1,16);
  IF p_request THEN
    -- Repeated requests never promote, reapprove, or renew a device.
    INSERT INTO aleph_device_step11.devices(user_id,session_id,device_id)
      VALUES(p_user_id,p_session_id,device_code) ON CONFLICT (user_id,session_id) DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    IF added=1 THEN
      INSERT INTO aleph_device_step11.audit(device_id,action) VALUES(device_code,'requested');
    END IF;
  END IF;
  SELECT * INTO saved FROM aleph_device_step11.devices WHERE user_id=p_user_id AND session_id=p_session_id;
  RETURN jsonb_build_object('schema','aleph.device-status.v1','deviceId',device_code,'status',
    CASE WHEN NOT FOUND THEN 'unrequested' WHEN saved.expires_at <= now() THEN 'expired' ELSE saved.status END);
END;
$$;
COMMENT ON FUNCTION public.aleph_step11_device_status(uuid,uuid,boolean) IS 'aleph.step11.v1';
REVOKE ALL ON FUNCTION public.aleph_step11_device_status(uuid,uuid,boolean) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.aleph_step11_device_status(uuid,uuid,boolean) TO service_role;

-- Administrator-only bootstrap/review. Neither browser nor app server can approve.
-- Run only after comparing the exact account and code shown in your own browser.
CREATE OR REPLACE FUNCTION public.aleph_step11_review_device(
  p_practice_email text, p_device_id text, p_approve boolean
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE saved aleph_device_step11.devices%ROWTYPE;
  actor uuid;
  next_status text;
BEGIN
  IF p_practice_email NOT IN ('learner-a@example.com','learner-b@example.com')
     OR p_device_id IS NULL OR p_device_id !~ '^[0-9a-f]{16}$' OR p_approve IS NULL THEN
    RAISE EXCEPTION 'DEVICE_REVIEW_INPUT_INVALID';
  END IF;
  SELECT id INTO STRICT actor FROM auth.users WHERE lower(email)=p_practice_email;
  SELECT * INTO STRICT saved FROM aleph_device_step11.devices
    WHERE user_id=actor AND device_id=p_device_id FOR UPDATE;
  IF NOT EXISTS (SELECT 1 FROM auth.sessions WHERE id=saved.session_id AND user_id=actor)
     OR saved.expires_at <= now() THEN RAISE EXCEPTION 'DEVICE_REVIEW_SESSION_EXPIRED'; END IF;
  -- A revoked approval cannot be brought back by another request.
  IF p_approve AND saved.status<>'pending' THEN RAISE EXCEPTION 'DEVICE_NOT_PENDING'; END IF;
  next_status := CASE WHEN p_approve THEN 'approved' ELSE 'revoked' END;
  UPDATE aleph_device_step11.devices SET status=next_status,reviewed_at=now()
    WHERE user_id=actor AND session_id=saved.session_id;
  INSERT INTO aleph_device_step11.audit(device_id,action) VALUES(saved.device_id,next_status);
  RETURN jsonb_build_object('schema','aleph.device-review.v1','deviceId',saved.device_id,
    'status',next_status,'auditPreserved',true);
END;
$$;
COMMENT ON FUNCTION public.aleph_step11_review_device(text,text,boolean) IS 'aleph.step11.v1';
REVOKE ALL ON FUNCTION public.aleph_step11_review_device(text,text,boolean) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.aleph_step11_review_device(text,text,boolean) TO postgres;

DO $$
DECLARE client_role text;
BEGIN
  FOREACH client_role IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF has_function_privilege(client_role,'public.aleph_step11_device_status(uuid,uuid,boolean)','EXECUTE')
       OR has_function_privilege(client_role,'public.aleph_step11_review_device(text,text,boolean)','EXECUTE')
       OR has_schema_privilege(client_role,'aleph_device_step11','USAGE') THEN
      RAISE EXCEPTION 'DEVICE_CLIENT_PRIVILEGE_UNSAFE';
    END IF;
  END LOOP;
  IF has_function_privilege('service_role','public.aleph_step11_review_device(text,text,boolean)','EXECUTE') THEN
    RAISE EXCEPTION 'DEVICE_SERVER_CANNOT_APPROVE';
  END IF;
END;
$$;
COMMIT;
SELECT jsonb_build_object('schema','aleph.device-setup.v1','ready',true,
  'clientCanApprove',has_function_privilege('authenticated','public.aleph_step11_review_device(text,text,boolean)','EXECUTE'),
  'serverCanApprove',has_function_privilege('service_role','public.aleph_step11_review_device(text,text,boolean)','EXECUTE'),
  'serverCanRequest',has_function_privilege('service_role','public.aleph_step11_device_status(uuid,uuid,boolean)','EXECUTE')) AS result;
