import { getLatestTrends, getTrendDeltas } from "../db/queries";

export async function handleTrends(
  request: Request,
  db: D1Database
): Promise<Response> {
  const [latest, deltas] = await Promise.all([
    getLatestTrends(db),
    getTrendDeltas(db),
  ]);

  return Response.json({
    current: latest,
    deltas,
  });
}
