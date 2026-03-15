/**
 * D1 query helpers for the Vectimus API Worker.
 */

export interface Env {
  DB: D1Database;
}

export async function getIncidents(
  db: D1Database,
  params: {
    limit?: number;
    offset?: number;
    severity?: number;
    category?: string;
    status?: string;
    since?: string;
    until?: string;
    include_internal_gaps?: boolean;
  }
): Promise<{ incidents: any[]; total: number }> {
  const conditions: string[] = [];
  const values: any[] = [];

  // By default, exclude gap findings that are within Vectimus's enforcement
  // scope (these are internal product gaps awaiting policy work). Gaps with
  // enforcement_scope 'out_of_scope' are safe to show publicly — they indicate
  // limitations inherent to any tool-call governance product, not Vectimus
  // shortcomings. Pass include_internal_gaps=true for internal dashboards.
  if (!params.include_internal_gaps) {
    conditions.push(
      "(coverage_status != 'gap' OR enforcement_scope = 'out_of_scope')"
    );
  }

  if (params.severity) {
    conditions.push("severity = ?");
    values.push(params.severity);
  }
  if (params.category) {
    conditions.push("owasp_category = ?");
    values.push(params.category);
  }
  if (params.status) {
    conditions.push("coverage_status = ?");
    values.push(params.status);
  }
  if (params.since) {
    conditions.push("discovered_at >= ?");
    values.push(params.since);
  }
  if (params.until) {
    conditions.push("discovered_at <= ?");
    values.push(params.until);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = params.limit ?? 50;
  const offset = params.offset ?? 0;

  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM incidents ${where}`)
    .bind(...values)
    .first<{ total: number }>();

  const rows = await db
    .prepare(
      `SELECT * FROM incidents ${where} ORDER BY discovered_at DESC LIMIT ? OFFSET ?`
    )
    .bind(...values, limit, offset)
    .all();

  return {
    incidents: rows.results ?? [],
    total: countResult?.total ?? 0,
  };
}

export async function getIncidentById(
  db: D1Database,
  vtmsId: string
): Promise<any | null> {
  return db
    .prepare("SELECT * FROM incidents WHERE vtms_id = ?")
    .bind(vtmsId)
    .first();
}

export async function getLatestTrends(db: D1Database): Promise<any | null> {
  return db
    .prepare("SELECT * FROM trends ORDER BY date DESC LIMIT 1")
    .first();
}

export async function getTrendDeltas(
  db: D1Database
): Promise<{ d7: any; d30: any; d90: any }> {
  const now = new Date();
  const d7 = new Date(now.getTime() - 7 * 86400000).toISOString().split("T")[0];
  const d30 = new Date(now.getTime() - 30 * 86400000).toISOString().split("T")[0];
  const d90 = new Date(now.getTime() - 90 * 86400000).toISOString().split("T")[0];

  const [t7, t30, t90] = await Promise.all([
    db.prepare("SELECT * FROM trends WHERE date <= ? ORDER BY date DESC LIMIT 1").bind(d7).first(),
    db.prepare("SELECT * FROM trends WHERE date <= ? ORDER BY date DESC LIMIT 1").bind(d30).first(),
    db.prepare("SELECT * FROM trends WHERE date <= ? ORDER BY date DESC LIMIT 1").bind(d90).first(),
  ]);

  return { d7: t7, d30: t30, d90: t90 };
}

export async function getCoverageByCategory(db: D1Database): Promise<any[]> {
  const result = await db
    .prepare(
      `SELECT
        owasp_category,
        enforcement_scope,
        COUNT(*) as total,
        SUM(CASE WHEN coverage_status = 'covered' THEN 1 ELSE 0 END) as covered,
        SUM(CASE WHEN coverage_status = 'partial' THEN 1 ELSE 0 END) as partial,
        SUM(CASE WHEN coverage_status = 'gap' AND enforcement_scope = 'out_of_scope' THEN 1 ELSE 0 END) as gaps_out_of_scope
      FROM incidents
      WHERE coverage_status != 'gap' OR enforcement_scope = 'out_of_scope'
      GROUP BY owasp_category, enforcement_scope
      ORDER BY total DESC`
    )
    .all();

  return result.results ?? [];
}

export async function getFeed(
  db: D1Database,
  limit: number = 20
): Promise<any[]> {
  const result = await db
    .prepare(
      "SELECT vtms_id, title, summary, discovered_at, severity, owasp_category, coverage_status, enforcement_scope FROM incidents WHERE coverage_status != 'gap' OR enforcement_scope = 'out_of_scope' ORDER BY discovered_at DESC LIMIT ?"
    )
    .bind(limit)
    .all();

  return result.results ?? [];
}
