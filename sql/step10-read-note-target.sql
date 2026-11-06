-- Read-only identification of the one B practice note selected by the user.
-- Returns IDs and a content fingerprint, never the memo body or credentials.
-- Zero or multiple matches must be resolved before making or restoring a copy.
-- Replace <B_ACCOUNT_EMAIL> only in your private SQL Editor, not in Git.
SELECT jsonb_build_object(
  'schema', 'aleph.practice-note-target.v1',
  'matches', COUNT(*),
  'targets', COALESCE(jsonb_agg(jsonb_build_object(
    'id', n.id,
    'ownerId', n.owner_id,
    'contentSha256', encode(sha256(convert_to(
      jsonb_build_object('title', n.title, 'content', n.content)::text,
      'UTF8'
    )), 'hex')
  ) ORDER BY n.id), '[]'::jsonb)
) AS target_preview
FROM public.vault_notes n
JOIN auth.users u ON u.id = n.owner_id
WHERE u.email = '<B_ACCOUNT_EMAIL>'
  AND n.title = '방어전 9단계 테스트';
