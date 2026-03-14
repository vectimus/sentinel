CREATE TABLE IF NOT EXISTS incidents (
  vtms_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  summary TEXT,
  discovered_at TEXT NOT NULL,
  incident_date TEXT,
  severity INTEGER NOT NULL,
  owasp_category TEXT,
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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

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
