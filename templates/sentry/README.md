# Sentry SDK — fleet install (TanStack Start + Vite)

Mission Control's **Performance → Errors** page provisions one Sentry project per
app and holds the on/off switch + issue counts. This is the client/server SDK
side that makes an app actually report.

## 1. Env vars (set on the app's Vercel project — Mission Control's
`provisionAll` action creates the project and returns the DSN)

| Var | Where | Value |
|---|---|---|
| `VITE_SENTRY_DSN` | Production + Preview | the project's public DSN |
| `SENTRY_ORG` | Production + Preview | `private-92b` |
| `SENTRY_PROJECT` | Production + Preview | `distinct-<app-id>` |
| `SENTRY_AUTH_TOKEN` | Production + Preview (secret) | release/sourcemap upload token |

## 2. Install

```
bun add @sentry/react @sentry/tanstackstart-react
```

## 3. `src/lib/sentry.client.ts`

```ts
import * as Sentry from "@sentry/react";

const dsn = import.meta.env.VITE_SENTRY_DSN as string | undefined;

if (dsn) {
  Sentry.init({
    dsn,
    environment: import.meta.env.MODE,
    tracesSampleRate: 0.1,
    replaysSessionSampleRate: 0,
    replaysOnErrorSampleRate: 0.1,
    integrations: [Sentry.browserTracingIntegration()],
  });
}
```

Import it once at the top of `src/router.tsx` (or the client entry) — guarded by
`if (dsn)` so an app with reporting toggled off (no DSN env) ships a no-op.

## 4. Server (Nitro) — `src/lib/sentry.server.ts`

```ts
import * as Sentry from "@sentry/tanstackstart-react";

if (process.env.SENTRY_DSN || process.env.VITE_SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN ?? process.env.VITE_SENTRY_DSN,
    tracesSampleRate: 0.1,
  });
}
```

Wrap the error middleware in `start.ts` with `Sentry.wrapStreamHandlerWithSentry`
(or add `Sentry.sentryGlobalServerMiddlewareHandler()` as the first
`requestMiddleware` entry).

## 5. The switch

Mission Control's toggle controls whether the cron **pulls** issue counts and is
the source of truth for "should this app report". To honour "off" fully, the
Vercel `VITE_SENTRY_DSN` var should be **removed** when an app is disabled — the
`if (dsn)` guards then make the SDK inert. The Errors page's per-app toggle calls
`PATCH /api/performance/sentry-config`; a follow-up will have that endpoint also
set/clear the Vercel env var via the Vercel API so the switch is fully
self-service. Until then, toggling off stops the counts and a maintainer clears
the env var.
