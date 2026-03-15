import { getIncidents, getIncidentById } from "../db/queries";

export async function handleIncidents(
  request: Request,
  db: D1Database
): Promise<Response> {
  const url = new URL(request.url);

  // GET /api/incidents/:vtms_id
  const idMatch = url.pathname.match(/^\/api\/incidents\/(VTMS-\d{4}-\d{4})$/);
  if (idMatch) {
    const incident = await getIncidentById(db, idMatch[1]);
    if (!incident) {
      return Response.json({ error: "Not found" }, { status: 404 });
    }
    return Response.json(incident);
  }

  // GET /api/incidents
  const params = {
    limit: Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 100),
    offset: Math.max(0, parseInt(url.searchParams.get("offset") ?? "0")),
    severity: url.searchParams.has("severity")
      ? parseInt(url.searchParams.get("severity")!)
      : undefined,
    category: url.searchParams.get("category") ?? undefined,
    status: url.searchParams.get("status") ?? undefined,
    since: url.searchParams.get("since") ?? undefined,
    until: url.searchParams.get("until") ?? undefined,
    include_internal_gaps: false,
  };

  const result = await getIncidents(db, params);
  return Response.json(result);
}
