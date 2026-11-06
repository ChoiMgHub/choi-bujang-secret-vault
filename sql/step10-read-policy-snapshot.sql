-- Step 10 preparation: one read-only SELECT of policy metadata only.
-- Run in the EXISTING project. No memo rows, Auth users, tokens or keys are read.
WITH targets AS (
  SELECT c.oid, c.relname, c.relowner, c.relacl,
         c.relrowsecurity, c.relforcerowsecurity
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND c.relname IN ('vault_notes', 'vault_notices',
                     'vault_instructor_materials', 'vault_resource_roles')
), snapshots AS (
  SELECT t.relname, jsonb_build_object(
    'table', t.relname,
    'rlsEnabled', t.relrowsecurity,
    'rlsForced', t.relforcerowsecurity,
    'policies', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'name', p.policyname, 'permissive', p.permissive,
        'roles', p.roles, 'command', p.cmd,
        'using', p.qual, 'check', p.with_check
      ) ORDER BY p.policyname)
      FROM pg_policies p
      WHERE p.schemaname = 'public' AND p.tablename = t.relname
    ), '[]'::jsonb),
    'grants', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_get_userbyid(a.grantee) END,
        'privilege', a.privilege_type, 'isGrantable', a.is_grantable
      ) ORDER BY a.grantee, a.privilege_type)
      FROM aclexplode(COALESCE(t.relacl, acldefault('r', t.relowner))) a
    ), '[]'::jsonb),
    'columnGrants', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'column', col.attname,
        'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_get_userbyid(a.grantee) END,
        'privilege', a.privilege_type, 'isGrantable', a.is_grantable
      ) ORDER BY col.attnum, a.grantee, a.privilege_type)
      FROM pg_attribute col
      CROSS JOIN LATERAL aclexplode(col.attacl) a
      WHERE col.attrelid = t.oid AND col.attnum > 0 AND NOT col.attisdropped
    ), '[]'::jsonb),
    'effectivePrivileges', (
      SELECT jsonb_agg(jsonb_build_object(
        'role', r.role_name,
        'select', has_table_privilege(r.role_name, t.oid, 'SELECT'),
        'insert', has_table_privilege(r.role_name, t.oid, 'INSERT'),
        'update', has_table_privilege(r.role_name, t.oid, 'UPDATE'),
        'delete', has_table_privilege(r.role_name, t.oid, 'DELETE'),
        'truncate', has_table_privilege(r.role_name, t.oid, 'TRUNCATE'),
        'references', has_table_privilege(r.role_name, t.oid, 'REFERENCES'),
        'trigger', has_table_privilege(r.role_name, t.oid, 'TRIGGER'),
        'maintain', CASE WHEN current_setting('server_version_num')::integer >= 170000
          THEN has_table_privilege(r.role_name, t.oid, 'MAINTAIN') ELSE false END,
        'columnSelect', has_any_column_privilege(r.role_name, t.oid, 'SELECT'),
        'columnInsert', has_any_column_privilege(r.role_name, t.oid, 'INSERT'),
        'columnUpdate', has_any_column_privilege(r.role_name, t.oid, 'UPDATE'),
        'columnReferences', has_any_column_privilege(r.role_name, t.oid, 'REFERENCES')
      ) ORDER BY r.role_name)
      FROM (VALUES ('anon'), ('authenticated'), ('service_role')) r(role_name)
    )
  ) AS value FROM targets t
)
SELECT jsonb_build_object(
  'schema', 'aleph.db-policy-snapshot.v1',
  'tables', COALESCE(jsonb_agg(value ORDER BY relname), '[]'::jsonb)
) AS policy_snapshot FROM snapshots;
