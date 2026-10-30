-- Stage 4 / making 3: review and run in the existing project's SQL Editor.
-- No note content, owner IDs, accounts, server keys or other tables are changed.
BEGIN;

-- BEFORE: explicit table grants and effective CRUD privileges.
SELECT 'before' AS phase, grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

SELECT 'before' AS phase, role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_read,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_create,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);

-- Do not silently replace unrelated policies on an unexpected database.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'vault_notes'
      AND policyname NOT IN (
        'aleph_vault_select_own', 'aleph_vault_insert_own',
        'aleph_vault_update_own', 'aleph_vault_delete_own'
      )
  ) THEN
    RAISE EXCEPTION 'Unexpected vault_notes policies: inspect pg_policies before changing them.';
  END IF;
END;
$$;

ALTER TABLE public.vault_notes ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.vault_notes FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.vault_notes TO authenticated;

DROP POLICY IF EXISTS aleph_vault_select_own ON public.vault_notes;
DROP POLICY IF EXISTS aleph_vault_insert_own ON public.vault_notes;
DROP POLICY IF EXISTS aleph_vault_update_own ON public.vault_notes;
DROP POLICY IF EXISTS aleph_vault_delete_own ON public.vault_notes;

CREATE POLICY aleph_vault_select_own ON public.vault_notes
  FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = owner_id);

CREATE POLICY aleph_vault_insert_own ON public.vault_notes
  FOR INSERT TO authenticated
  WITH CHECK ((SELECT auth.uid()) = owner_id);

CREATE POLICY aleph_vault_update_own ON public.vault_notes
  FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = owner_id)
  WITH CHECK ((SELECT auth.uid()) = owner_id);

CREATE POLICY aleph_vault_delete_own ON public.vault_notes
  FOR DELETE TO authenticated
  USING ((SELECT auth.uid()) = owner_id);

-- Fail and roll back instead of claiming success if inherited grants conflict.
DO $$
BEGIN
  IF has_table_privilege('anon', 'public.vault_notes',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR has_table_privilege('authenticated', 'public.vault_notes',
       'TRUNCATE,REFERENCES,TRIGGER') THEN
    RAISE EXCEPTION 'Unexpected effective privileges remain; no changes committed.';
  END IF;
  IF current_setting('server_version_num')::integer >= 170000 THEN
    IF has_table_privilege('anon', 'public.vault_notes', 'MAINTAIN')
       OR has_table_privilege('authenticated', 'public.vault_notes', 'MAINTAIN') THEN
      RAISE EXCEPTION 'Unexpected MAINTAIN privilege remains; no changes committed.';
    END IF;
  END IF;
  IF NOT has_schema_privilege('authenticated', 'public', 'USAGE') OR EXISTS (
    SELECT 1
    FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege_name)
    WHERE NOT has_table_privilege('authenticated', 'public.vault_notes', p.privilege_name)
       OR NOT has_table_privilege('service_role', 'public.vault_notes', p.privilege_name)
  ) THEN
    RAISE EXCEPTION 'Required authenticated/server privileges missing; no changes committed.';
  END IF;
END;
$$;

-- AFTER: compare actual grants and the four owner policies with BEFORE.
SELECT 'after' AS phase, grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

SELECT policyname, cmd, roles, qual AS existing_row_check,
  with_check AS resulting_row_check
FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'vault_notes'
ORDER BY policyname;

COMMIT;

-- Final result: anon false x4, authenticated true x4; RLS true, policies 4.
SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_read,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_create,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete,
  has_table_privilege(role_name, 'public.vault_notes',
    'TRUNCATE,REFERENCES,TRIGGER') AS has_extra_privileges,
  (SELECT relrowsecurity FROM pg_class
    WHERE oid = 'public.vault_notes'::regclass) AS rls_enabled,
  (SELECT COUNT(*) FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'vault_notes') AS policy_count
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);
