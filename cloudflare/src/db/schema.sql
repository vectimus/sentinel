-- Cloudflare D1 schema for vectimus-incidents
-- Run with: wrangler d1 execute vectimus-incidents --file=cloudflare/src/db/schema.sql

CREATE TABLE IF NOT EXISTS incidents (
  vtms_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  summary TEXT,
  discovered_at TEXT NOT NULL,
  incident_date TEXT,
  severity INTEGER NOT NULL,
  owasp_category TEXT,
  nist_ai_rmf TEXT,
  cis_controls TEXT,
  cve_ids TEXT,
  coverage_status TEXT NOT NULL,
  coverage_detail TEXT,
  existing_policy_ids TEXT,
  gap_description TEXT,
  tools_involved TEXT,
  sources TEXT,
  policy_pr_url TEXT,
  content_pr_url TEXT,
  policy_status TEXT DEFAULT 'na',
  content_status TEXT DEFAULT 'na',
  recommended_action TEXT,
  content_angle TEXT,
  replay_request TEXT,
  enforcement_scope TEXT DEFAULT 'full',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_key_created ON rate_limits (key, created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits (expires_at);

CREATE TABLE IF NOT EXISTS trends (
  date TEXT PRIMARY KEY,
  total_incidents INTEGER,
  incidents_30d INTEGER,
  incidents_by_category TEXT,
  incidents_by_severity TEXT,
  coverage_rate REAL,
  gap_rate REAL,
  policies_total INTEGER,
  rules_total INTEGER
);

CREATE TABLE IF NOT EXISTS content (
  id TEXT PRIMARY KEY,
  vtms_id TEXT REFERENCES incidents(vtms_id),
  content_type TEXT NOT NULL,
  title TEXT,
  slug TEXT,
  status TEXT DEFAULT 'draft',
  pr_url TEXT,
  published_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  pack TEXT NOT NULL,
  file TEXT NOT NULL,
  description TEXT,
  incident TEXT,
  category TEXT,
  controls TEXT,
  suggested_alternative TEXT,
  action_type TEXT,
  rule_count INTEGER DEFAULT 0,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
