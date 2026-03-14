import { getFeed } from "../db/queries";

export async function handleFeed(
  request: Request,
  db: D1Database
): Promise<Response> {
  const items = await getFeed(db);

  const feed = {
    version: "https://jsonfeed.org/version/1.1",
    title: "Vectimus Sentinel — Agentic AI Security Incidents",
    home_page_url: "https://vectimus.com/threats",
    feed_url: "https://api.vectimus.com/api/feed.json",
    description:
      "Real-time threat intelligence for agentic AI security incidents",
    items: items.map((item: any) => ({
      id: item.vtms_id,
      title: item.title,
      summary: item.summary,
      date_published: item.discovered_at,
      tags: [item.owasp_category, `severity-${item.severity}`],
      _vectimus: {
        vtms_id: item.vtms_id,
        severity: item.severity,
        coverage_status: item.coverage_status,
      },
    })),
  };

  return Response.json(feed);
}
