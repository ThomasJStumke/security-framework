# Performance scoring

Computed by `mc_recalculate_application_performance_state(_application_id)` in
Mission Control after every `POST /api/performance/runs` and after every
`performance-refresh` cron web-vitals pull.

## Score (0–100)

| Component | Weight | Source |
|---|---:|---|
| Lighthouse performance category | 40% | `lhci collect` median of N runs against `target-url` |
| Field Core Web Vitals pass | 40% | Vercel Speed Insights p75 — `good` 100 / `needs-improvement` 55 / `poor` 15; no field data yet ⇒ 100 (not penalised) |
| Bundle vs budget | 20% | size-limit total gzip ÷ `.size-limit.json` budget; 100 under budget, linear to 0 at 2× budget |

Minus 10 if there has been no `completed` run in the last 3 days (staleness).
Clamped to 0–100.

## Status band

`≥90` Excellent · `≥75` Good · `≥50` Attention Required · `≥25` High Risk · `<25` Critical

## Regression flag

Set when, versus the previous run: Lighthouse performance dropped ≥ 5 points, **or**
bundle gzip grew ≥ 10%.

## Core Web Vitals thresholds

LCP ≤ 2500 ms · INP ≤ 200 ms · CLS ≤ 0.1 (all p75, field).

## Playwright synthetic journey

`tests/perf.spec.ts` (or `e2e/perf.spec.ts`) — a scripted critical-path walk
(load → sign in → key screen). Per-step timings land on the app's Performance
detail page; the pass/fail status is informational, it does not feed the score.
