-- Run in the existing Supabase project. This changes privileges, not memo contents.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.vault_notes TO service_role;

SELECT
  has_table_privilege('service_role', 'public.vault_notes', 'SELECT') AS server_can_read,
  has_table_privilege('service_role', 'public.vault_notes', 'INSERT') AS server_can_create,
  has_table_privilege('service_role', 'public.vault_notes', 'UPDATE') AS server_can_update,
  has_table_privilege('service_role', 'public.vault_notes', 'DELETE') AS server_can_delete,
  (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.vault_notes'::regclass) AS rls_enabled,
  has_table_privilege('anon', 'public.vault_notes', 'SELECT') AS anon_can_read,
  has_table_privilege('authenticated', 'public.vault_notes', 'SELECT') AS authenticated_can_read;
