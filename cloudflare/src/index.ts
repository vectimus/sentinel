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
import { handlePolicies } from "./routes/policies";

export interface Env {
  DB: D1Database;
  RATE_LIMITER: RateLimit;
}

const CORS_ORIGINS = [
  "https://vectimus.com",
  "https://www.vectimus.com",
];

function getCorsOrigin(request: Request): string {
  const origin = request.headers.get("Origin") ?? "";
  if (CORS_ORIGINS.includes(origin)) {
    return origin;
  }
  // Don't reflect an allowed origin for non-matching requests
  return "";
}

function corsHeaders(request: Request): Record<string, string> {
  const origin = getCorsOrigin(request);
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

function corsResponse(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(request))) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Simple per-IP rate limiting using D1 as backing store.
 * Allows 60 requests per minute per IP for API routes.
 */
async function checkRateLimit(
  request: Request,
  db: D1Database
): Promise<{ allowed: boolean; remaining: number }> {
  const ip =
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
    "unknown";

  const windowMs = 60_000;
  const maxRequests = 60;
  const now = Date.now();
  const windowStart = now - windowMs;
  const key = `rl:${ip}`;

  // Use a lightweight approach: count recent requests from this IP
  // stored in a simple rate_limits table
  try {
    // Clean old entries and count current window
    await db
      .prepare("DELETE FROM rate_limits WHERE expires_at < ?")
      .bind(now)
      .run();

    const count = await db
      .prepare("SELECT COUNT(*) as cnt FROM rate_limits WHERE key = ? AND created_at > ?")
      .bind(key, windowStart)
      .first<{ cnt: number }>();

    const current = count?.cnt ?? 0;

    if (current >= maxRequests) {
      return { allowed: false, remaining: 0 };
    }

    // Record this request
    await db
      .prepare("INSERT INTO rate_limits (key, created_at, expires_at) VALUES (?, ?, ?)")
      .bind(key, now, now + windowMs)
      .run();

    return { allowed: true, remaining: maxRequests - current - 1 };
  } catch {
    // If rate_limits table doesn't exist or any DB error, allow the request
    // Rate limiting is best-effort, not a hard gate
    return { allowed: true, remaining: maxRequests };
  }
}

function rateLimitHeaders(remaining: number): Record<string, string> {
  return {
    "X-RateLimit-Limit": "60",
    "X-RateLimit-Remaining": String(Math.max(0, remaining)),
    "X-RateLimit-Reset": String(Math.ceil(Date.now() / 60_000) * 60),
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Only allow GET requests for API
    if (request.method !== "GET") {
      return corsResponse(
        Response.json({ error: "Method not allowed" }, { status: 405 }),
        request
      );
    }

    // Rate limit API routes
    if (url.pathname.startsWith("/api/")) {
      const { allowed, remaining } = await checkRateLimit(request, env.DB);

      if (!allowed) {
        const resp = Response.json(
          { error: "Rate limit exceeded. 60 requests per minute." },
          { status: 429 }
        );
        const headers = new Headers(resp.headers);
        for (const [k, v] of Object.entries(rateLimitHeaders(remaining))) {
          headers.set(k, v);
        }
        headers.set("Retry-After", "60");
        for (const [k, v] of Object.entries(corsHeaders(request))) {
          headers.set(k, v);
        }
        return new Response(resp.body, { status: 429, headers });
      }

      try {
        let response: Response;

        if (url.pathname.startsWith("/api/policies")) {
          response = await handlePolicies(request, env.DB);
        } else if (url.pathname.startsWith("/api/incidents")) {
          response = await handleIncidents(request, env.DB);
        } else if (url.pathname === "/api/trends") {
          response = await handleTrends(request, env.DB);
        } else if (url.pathname === "/api/coverage") {
          response = await handleCoverage(request, env.DB);
        } else if (url.pathname === "/api/feed.json") {
          response = await handleFeed(request, env.DB);
        } else if (url.pathname === "/api/health") {
          response = Response.json({ status: "ok" });
        } else {
          response = Response.json({ error: "Not found" }, { status: 404 });
        }

        // Add rate limit and CORS headers
        const headers = new Headers(response.headers);
        for (const [k, v] of Object.entries(rateLimitHeaders(remaining))) {
          headers.set(k, v);
        }
        for (const [k, v] of Object.entries(corsHeaders(request))) {
          headers.set(k, v);
        }
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers,
        });
      } catch (error) {
        console.error("Worker error:", error);
        return corsResponse(
          Response.json({ error: "Internal server error" }, { status: 500 }),
          request
        );
      }
    }

    // Non-API routes (dashboard static assets)
    return new Response("Not found", { status: 404 });
  },
};
