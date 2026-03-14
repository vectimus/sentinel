import { getCoverageByCategory } from "../db/queries";

export async function handleCoverage(
  request: Request,
  db: D1Database
): Promise<Response> {
  const coverage = await getCoverageByCategory(db);
  return Response.json({ categories: coverage });
}
