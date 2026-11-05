-- Run in the EXISTING Supabase project's SQL Editor.
-- Adds only three stage-8 tables and one explicitly public practice notice.
-- Does not modify vault_notes, existing Auth users, passwords or roles on those users.
BEGIN;

DO $$
DECLARE name text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role' AND rolbypassrls)
     OR NOT has_schema_privilege('service_role', 'public', 'USAGE') THEN
    RAISE EXCEPTION 'Server role is not ready; no changes committed.';
  END IF;
  FOREACH name IN ARRAY ARRAY['vault_notices', 'vault_instructor_materials', 'vault_resource_roles'] LOOP
    IF to_regclass('public.' || name) IS NOT NULL
       AND obj_description(to_regclass('public.' || name), 'pg_class') IS DISTINCT FROM 'aleph.step08.v1' THEN
      RAISE EXCEPTION 'Unrelated table % already exists; no changes committed.', name;
    END IF;
  END LOOP;
END;
$$;

CREATE TABLE IF NOT EXISTS public.vault_notices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
  body text NOT NULL CHECK (length(body) <= 10000),
  created_by uuid REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.vault_instructor_materials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users(id),
  title text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
  body text NOT NULL CHECK (length(body) <= 10000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.vault_resource_roles (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id),
  role text NOT NULL CHECK (role = 'instructor'),
  active boolean NOT NULL DEFAULT true
);
COMMENT ON TABLE public.vault_notices IS 'aleph.step08.v1';
COMMENT ON TABLE public.vault_instructor_materials IS 'aleph.step08.v1';
COMMENT ON TABLE public.vault_resource_roles IS 'aleph.step08.v1';

ALTER TABLE public.vault_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_instructor_materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_resource_roles ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.vault_notices, public.vault_instructor_materials,
  public.vault_resource_roles FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.vault_notices TO service_role;
GRANT SELECT ON public.vault_instructor_materials, public.vault_resource_roles TO service_role;

-- Public practice text; no private memo contents or real-person information.
INSERT INTO public.vault_notices(id, title, body)
VALUES ('80000000-0000-4000-8000-000000000001',
        '8단계 구역 읽기 확인용 공지',
        '민감정보가 없는 공개 실습용 공지입니다.')
ON CONFLICT (id) DO NOTHING;

DO $$
DECLARE name text; client_role text;
BEGIN
  FOREACH name IN ARRAY ARRAY['vault_notices', 'vault_instructor_materials', 'vault_resource_roles'] LOOP
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = to_regclass('public.' || name)) THEN
      RAISE EXCEPTION 'RLS missing; no changes committed.';
    END IF;
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
      IF has_table_privilege(client_role, 'public.' || name, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR has_any_column_privilege(client_role, 'public.' || name, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
        RAISE EXCEPTION 'Unexpected direct privilege on % for %; no changes committed.', name, client_role;
      END IF;
    END LOOP;
    IF NOT has_table_privilege('service_role', 'public.' || name, 'SELECT') THEN
      RAISE EXCEPTION 'Server read privilege missing; no changes committed.';
    END IF;
  END LOOP;
  IF NOT has_table_privilege('service_role', 'public.vault_notices', 'INSERT,UPDATE,DELETE')
     OR has_table_privilege('service_role', 'public.vault_resource_roles', 'INSERT,UPDATE,DELETE')
     OR has_table_privilege('service_role', 'public.vault_instructor_materials', 'INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'Server write privileges differ from the policy; no changes committed.';
  END IF;
END;
$$;
COMMIT;

-- Capture this final result: clients false x4; server writes only notices; RLS true.
SELECT names.table_name, roles.role_name,
  has_table_privilege(roles.role_name, 'public.' || names.table_name, 'SELECT') AS can_read,
  has_table_privilege(roles.role_name, 'public.' || names.table_name, 'INSERT') AS can_create,
  has_table_privilege(roles.role_name, 'public.' || names.table_name, 'UPDATE') AS can_update,
  has_table_privilege(roles.role_name, 'public.' || names.table_name, 'DELETE') AS can_delete,
  (SELECT relrowsecurity FROM pg_class WHERE oid = to_regclass('public.' || names.table_name)) AS rls_enabled
FROM (VALUES ('vault_notices'), ('vault_instructor_materials'), ('vault_resource_roles')) AS names(table_name)
CROSS JOIN (VALUES ('anon'), ('authenticated'), ('service_role')) AS roles(role_name)
ORDER BY names.table_name, roles.role_name;
