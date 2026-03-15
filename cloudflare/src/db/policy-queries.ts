/**
 * D1 query helpers for the Policies API.
 */

export interface PolicyRow {
  id: string;
  pack: string;
  file: string;
  description: string | null;
  incident: string | null;
  category: string | null;
  controls: string | null;
  suggested_alternative: string | null;
  action_type: string | null;
  rule_count: number;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyMetaRow {
  key: string;
  value: string;
}

export async function getPolicies(
  db: D1Database,
  params: { pack?: string; category?: string; action_type?: string }
): Promise<PolicyRow[]> {
  const conditions: string[] = [];
  const values: any[] = [];

  if (params.pack) {
    conditions.push("pack = ?");
    values.push(params.pack);
  }
  if (params.category) {
    conditions.push("category = ?");
    values.push(params.category);
  }
  if (params.action_type) {
    conditions.push("action_type = ?");
    values.push(params.action_type);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  const result = await db
    .prepare(`SELECT * FROM policies ${where} ORDER BY pack, id`)
    .bind(...values)
    .all<PolicyRow>();

  return result.results ?? [];
}

export async function getPolicyById(
  db: D1Database,
  id: string
): Promise<PolicyRow | null> {
  return db
    .prepare("SELECT * FROM policies WHERE id = ?")
    .bind(id)
    .first<PolicyRow>();
}

export async function getPolicyStats(
  db: D1Database
): Promise<{
  total_policies: number;
  total_rules: number;
  packs: Record<string, number>;
  version: string | null;
  synced_at: string | null;
}> {
  const [countResult, rulesResult, packsResult, versionMeta, syncMeta] =
    await Promise.all([
      db
        .prepare("SELECT COUNT(*) as cnt FROM policies")
        .first<{ cnt: number }>(),
      db
        .prepare("SELECT COALESCE(SUM(rule_count), 0) as total FROM policies")
        .first<{ total: number }>(),
      db
        .prepare(
          "SELECT pack, COUNT(*) as cnt FROM policies GROUP BY pack ORDER BY pack"
        )
        .all<{ pack: string; cnt: number }>(),
      db
        .prepare("SELECT value FROM policy_meta WHERE key = 'version'")
        .first<{ value: string }>(),
      db
        .prepare("SELECT value FROM policy_meta WHERE key = 'synced_at'")
        .first<{ value: string }>(),
    ]);

  const packs: Record<string, number> = {};
  for (const row of packsResult.results ?? []) {
    packs[row.pack] = row.cnt;
  }

  return {
    total_policies: countResult?.cnt ?? 0,
    total_rules: rulesResult?.total ?? 0,
    packs,
    version: versionMeta?.value ?? null,
    synced_at: syncMeta?.value ?? null,
  };
}

export async function upsertPolicy(
  db: D1Database,
  policy: PolicyRow
): Promise<void> {
  await db
    .prepare(
      `INSERT OR REPLACE INTO policies
       (id, pack, file, description, incident, category, controls, suggested_alternative, action_type, rule_count, source, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      policy.id,
      policy.pack,
      policy.file,
      policy.description,
      policy.incident,
      policy.category,
      policy.controls,
      policy.suggested_alternative,
      policy.action_type,
      policy.rule_count,
      policy.source,
      policy.created_at,
      policy.updated_at
    )
    .run();
}

export async function upsertPolicyMeta(
  db: D1Database,
  key: string,
  value: string
): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO policy_meta (key, value) VALUES (?, ?)"
    )
    .bind(key, value)
    .run();
}
