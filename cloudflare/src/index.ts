/**
 * Vectimus API Worker
 *
 * Public API and dashboard for Vectimus Sentinel threat intelligence.
 * Reads from D1, serves JSON API and static dashboard.
 */

import { handleIncidents } from "./routes/incidents";
import { handleTrends } from "./routes/trends";
import { handleCoverage } from "./routes/coverage";
import { handleFeed } from "./routes/feed";

export interface Env {
  DB: D1Database;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://vectimus.com",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function corsResponse(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Only allow GET requests for API
    if (request.method !== "GET") {
      return corsResponse(
        Response.json({ error: "Method not allowed" }, { status: 405 })
      );
    }

    try {
      // API routes
      if (url.pathname.startsWith("/api/incidents")) {
        return corsResponse(await handleIncidents(request, env.DB));
      }

      if (url.pathname === "/api/trends") {
        return corsResponse(await handleTrends(request, env.DB));
      }

      if (url.pathname === "/api/coverage") {
        return corsResponse(await handleCoverage(request, env.DB));
      }

      if (url.pathname === "/api/feed.json") {
        return corsResponse(await handleFeed(request, env.DB));
      }

      // Health check
      if (url.pathname === "/api/health") {
        return corsResponse(Response.json({ status: "ok" }));
      }

      // Everything else falls through to static assets (dashboard)
      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error("Worker error:", error);
      return corsResponse(
        Response.json(
          { error: "Internal server error" },
          { status: 500 }
        )
      );
    }
  },
};
