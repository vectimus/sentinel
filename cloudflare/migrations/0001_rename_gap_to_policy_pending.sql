-- Migration: Rename coverage_status 'gap' → 'policy_pending'
--
-- Run with:
--   wrangler d1 execute vectimus-incidents --file=cloudflare/migrations/0001_rename_gap_to_policy_pending.sql
--   wrangler d1 execute vectimus-incidents --file=cloudflare/migrations/0001_rename_gap_to_policy_pending.sql --env production
--
-- This is a data-only migration. The coverage_status column is TEXT with no
-- CHECK constraint, so no DDL change is needed.

UPDATE incidents
SET coverage_status = 'policy_pending',
    updated_at = datetime('now')
WHERE coverage_status = 'gap';

-- Also update the trends table metric name for consistency
-- (gap_rate column stays as-is since it's a computed float — the name is
-- internal and renaming a column in SQLite requires recreating the table,
-- which is not worth the risk for an internal metric name)
