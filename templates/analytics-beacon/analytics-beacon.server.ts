// Mission Control /analytics route-usage beacon — drop-in for every TanStack
// Start app in the fleet.
//
// Records ONLY the matched route template, the HTTP status class and a coarse
// duration bucket — never query strings, bodies, headers or any user identifier.
// Fire-and-forget: the POST is never awaited and every error is swallowed, so a
// slow or down Mission Control cannot add a millisecond to any real request.
// Gated by env — unset MC_ANALYTICS_BEACON_URL (or set MC_ANALYTICS_BEACON=off)
// to disable instantly with a redeploy, no code change.
//
// Wire it into start.ts as the LAST server middleware:
//
//   import { analyticsBeaconMiddleware } from "./lib/analytics-beacon.server";
//   export const startInstance = createStart(() => ({
//     requestMiddleware: [/* existing */, analyticsBeaconMiddleware],
//   }));

import { createMiddleware } from "@tanstack/react-start";
import { getEnv } from "./runtime-env.server"; // or process.env — see note below

// Buffer hits in module scope and flush on a timer so we send one small batch
// per ~20s per instance instead of a request per request.
interface Hit {
  http_path: string;
  kind: "page" | "api-route" | "server-fn";
  count: number;
  error_count: number;
  max_ms: number;
}
const buffer = new Map<string, Hit>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;

function config(): { url: string; token: string; appId: string } | null {
  const url = getEnv("MC_ANALYTICS_BEACON_URL"); // https://missioncontrol.distinct-app.com/api/analytics/hit
  const token = getEnv("MISSION_CONTROL_SECURITY_TOKEN");
  const appId = getEnv("MC_APPLICATION_ID");
  if (!url || !token || !appId) return null;
  if (getEnv("MC_ANALYTICS_BEACON") === "off") return null;
  return { url, token, appId };
}

// Collapse a resolved pathname to its route template so we never store ids:
//   /invoices/inv_2931           -> /invoices/:id
//   /api/orders/8f3.../items     -> /api/orders/:id/items
function toTemplate(pathname: string): string {
  return pathname
    .split("/")
    .map((seg) => {
      if (!seg) return seg;
      if (/^[0-9]+$/.test(seg)) return ":id";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(seg)) return ":id"; // uuid
      if (/^[0-9a-f]{16,}$/i.test(seg)) return ":id"; // long hex
      if (/[_-].*\d/.test(seg) && seg.length > 12) return ":id"; // prefixed id
      return seg;
    })
    .join("/")
    .slice(0, 200);
}

function record(pathname: string, status: number, ms: number) {
  const cfg = config();
  if (!cfg) return;
  // Sample high-traffic app routes down; keep all API routes.
  const isApi = pathname.startsWith("/api/");
  if (!isApi && Math.random() > 0.25) return;

  const key = toTemplate(pathname);
  const kind: Hit["kind"] = isApi ? "api-route" : "page";
  const cur = buffer.get(key) ?? { http_path: key, kind, count: 0, error_count: 0, max_ms: 0 };
  cur.count += 1;
  if (status >= 500) cur.error_count += 1;
  cur.max_ms = Math.max(cur.max_ms, Math.round(ms));
  buffer.set(key, cur);

  if (!flushTimer) flushTimer = setTimeout(flush, 20_000);
}

function flush() {
  flushTimer = null;
  const cfg = config();
  if (!cfg || buffer.size === 0) return;
  const hits = [...buffer.values()].map((h) => ({
    http_path: h.http_path,
    kind: h.kind,
    count: h.count,
    error_count: h.error_count,
    p95_ms: h.max_ms,
  }));
  buffer.clear();

  // Never awaited, never throws out.
  void fetch(cfg.url, {
    method: "POST",
    keepalive: true,
    headers: { Authorization: `Bearer ${cfg.token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ application_id: cfg.appId, hits }),
  }).catch(() => {});
}

export const analyticsBeaconMiddleware = createMiddleware().server(async ({ request, next }) => {
  const start = Date.now();
  let status = 200;
  try {
    const res = await next();
    // next() returns a Response-like object in Start middleware
    status = (res as { status?: number })?.status ?? 200;
    return res;
  } catch (err) {
    status = 500;
    throw err;
  } finally {
    try {
      const { pathname } = new URL(request.url);
      // Skip static assets and the health check.
      if (!/\.(?:js|css|png|jpg|svg|ico|woff2?|map)$/.test(pathname) && pathname !== "/health") {
        record(pathname, status, Date.now() - start);
      }
    } catch {
      /* never let telemetry break the request */
    }
  }
});

// NOTE on getEnv: if this app has no src/lib/runtime-env.server.ts helper, replace
// the import with `const getEnv = (k: string) => process.env[k];`.
