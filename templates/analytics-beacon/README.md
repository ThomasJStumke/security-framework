# Analytics route-usage beacon — fleet install

Feeds Mission Control's **/analytics** page the "which routes/functions are
actually hit" half (the static inventory half comes from the perf workflow).

## What it sends

Per ~20s per running instance, one batched POST to
`POST $MC_ANALYTICS_BEACON_URL` (`/api/analytics/hit`):

```json
{ "application_id": "flyer",
  "hits": [ { "http_path": "/invoices/:id", "kind": "page",
              "count": 42, "error_count": 0, "p95_ms": 180 } ] }
```

Route **templates** only — ids are collapsed to `:id` before anything leaves the
process. No query strings, no bodies, no user identifiers.

## Why it can't cause an outage

- The POST is `void fetch(...).catch(() => {})` — never awaited, never rethrown.
- All work is in a `finally` wrapped in its own `try/catch`.
- Disabled unless `MC_ANALYTICS_BEACON_URL` **and** `MISSION_CONTROL_SECURITY_TOKEN`
  **and** `MC_APPLICATION_ID` are all set; `MC_ANALYTICS_BEACON=off` kills it.
- App routes are sampled to 25%; only API routes are kept at 100%.

## Install

1. Copy `analytics-beacon.server.ts` to `src/lib/`.
2. If the app has no `src/lib/runtime-env.server.ts`, change its import to
   `const getEnv = (k: string) => process.env[k];`.
3. In `src/start.ts`, add it as the **last** `requestMiddleware`:

   ```ts
   import { analyticsBeaconMiddleware } from "./lib/analytics-beacon.server";
   export const startInstance = createStart(() => ({
     requestMiddleware: [errorMiddleware, csrfMiddleware, /* … */, analyticsBeaconMiddleware],
   }));
   ```

4. Set Vercel env (Production + Preview):
   - `MC_ANALYTICS_BEACON_URL` = `https://missioncontrol.distinct-app.com/api/analytics/hit`
   - `MC_APPLICATION_ID` = the app's id in Mission Control's `src/data/applications.ts`
   - `MISSION_CONTROL_SECURITY_TOKEN` — already set (security-scan ingest).

## Rollout order

`ease-rental` and `finance-friend` first (highest traffic; finance-friend also
validates the Cloudflare-Workers-types build). Confirm rows land in
`mc_app_route_usage` and no latency regression on the app, then copy the exact
same two-line change to the rest.
