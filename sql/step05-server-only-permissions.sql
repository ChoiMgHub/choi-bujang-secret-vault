-- Step 5: review and run in the existing Supabase project's SQL Editor.
-- Only vault_notes grants change. Rows, owner IDs, Auth and RLS stay unchanged.
BEGIN;

-- Before: explicit grants and effective CRUD privileges.
SELECT 'before' AS phase, grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated', 'service_role')
ORDER BY grantee, privilege_type;

SELECT 'before' AS phase, role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_read,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_create,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated'), ('service_role')) AS roles(role_name);

-- Stop if the stage-4 table or server privileges are not ready.
DO $$
BEGIN
  IF NOT (SELECT relrowsecurity FROM pg_class
          WHERE oid = 'public.vault_notes'::regclass)
     OR NOT has_schema_privilege('service_role', 'public', 'USAGE')
     OR EXISTS (
       SELECT 1
       FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege_name)
       WHERE NOT has_table_privilege('service_role', 'public.vault_notes', p.privilege_name)
     ) THEN
    RAISE EXCEPTION 'Required RLS or server privileges missing; no changes committed.';
  END IF;
END;
$$;

-- Remove direct client access; do not grant it back in this stage.
REVOKE ALL ON TABLE public.vault_notes FROM PUBLIC, anon, authenticated;

-- Check effective permissions too: inherited or column grants must not remain.
-- Any failure aborts the transaction instead of committing a partial change.
DO $$
DECLARE
  client_role text;
BEGIN
  FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF has_table_privilege(client_role, 'public.vault_notes',
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_any_column_privilege(client_role, 'public.vault_notes',
         'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION 'Unexpected direct privileges remain for %; no changes committed.', client_role;
    END IF;
    IF current_setting('server_version_num')::integer >= 170000 THEN
      IF has_table_privilege(client_role, 'public.vault_notes', 'MAINTAIN') THEN
        RAISE EXCEPTION 'Unexpected MAINTAIN privilege remains; no changes committed.';
      END IF;
    END IF;
  END LOOP;
  IF NOT has_schema_privilege('service_role', 'public', 'USAGE') OR EXISTS (
    SELECT 1
    FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) AS p(privilege_name)
    WHERE NOT has_table_privilege('service_role', 'public.vault_notes', p.privilege_name)
  ) THEN
    RAISE EXCEPTION 'Server privileges would be lost; no changes committed.';
  END IF;
END;
$$;

-- After: ordinary roles should have no explicit table grants.
SELECT 'after' AS phase, grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated', 'service_role')
ORDER BY grantee, privilege_type;

COMMIT;

-- Final screen: anon/authenticated false x4; service_role true x4.
SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_read,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_create,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated'), ('service_role')) AS roles(role_name);
