import {
  getPolicies,
  getPolicyById,
  getPolicyStats,
} from "../db/policy-queries";

export async function handlePolicies(
  request: Request,
  db: D1Database
): Promise<Response> {
  const url = new URL(request.url);

  // GET /api/policies/stats
  if (url.pathname === "/api/policies/stats") {
    const stats = await getPolicyStats(db);
    return Response.json(stats);
  }

  // GET /api/policies/:id
  const idMatch = url.pathname.match(/^\/api\/policies\/([^/]+)$/);
  if (idMatch && idMatch[1] !== "stats") {
    const policy = await getPolicyById(db, idMatch[1]);
    if (!policy) {
      return Response.json({ error: "Policy not found" }, { status: 404 });
    }
    return Response.json(policy);
  }

  // GET /api/policies
  if (url.pathname === "/api/policies") {
    const pack = url.searchParams.get("pack") ?? undefined;
    const category = url.searchParams.get("category") ?? undefined;
    const action_type = url.searchParams.get("action_type") ?? undefined;

    const policies = await getPolicies(db, { pack, category, action_type });
    const stats = await getPolicyStats(db);

    return Response.json({
      policies,
      total_policies: stats.total_policies,
      total_rules: stats.total_rules,
      packs: stats.packs,
      version: stats.version,
    });
  }

  return Response.json({ error: "Not found" }, { status: 404 });
}
