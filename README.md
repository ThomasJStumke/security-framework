# security-framework

Shared, centrally-maintained security scanning for every app under `ThomasJStumke`'s
personal GitHub account. One place to fix a scanner config instead of ~20.

## What lives here

- `.github/workflows/reusable-security-pr.yml` — fast PR/push checks: Gitleaks (working
  tree), Semgrep CE, Trivy, npm audit, optional Supabase static check. Fails the PR only
  on findings at or above `fail-on-severity` (default `high`).
- `.github/workflows/reusable-security-weekly.yml` — deep weekly scan: full-history
  Gitleaks, full Semgrep, Trivy, npm audit, Supabase static check, OWASP ZAP baseline
  (only if a scan URL is configured), Nuclei (deferred — see below).
- `scripts/normalize-and-submit.mjs` — turns every scanner's raw output into one common
  finding shape and POSTs it to Mission Control's `/api/security/scans`. Redacts secret
  values before they ever leave the runner.
- `scripts/supabase-check.mjs` — heuristic static linter over `supabase/migrations/*.sql`
  (missing RLS, missing per-command policies, `USING (true)`, `SECURITY DEFINER`
  functions, service-role key references in client code). **Not a substitute for manual
  RLS review** — see `security/CLAUDE_SECURITY_REVIEW.md` in each app repo for how to
  triage its output.
- `templates/security-pr.yml`, `templates/security-weekly.yml` — the two-file wrapper
  every app repo gets. They just call the reusable workflows above with that repo's
  `application-id`/`supabase-enabled` filled in — nothing else to maintain per-repo.
- `docs/security-scoring.md` — the 0–100 scoring formula Mission Control uses.

## How a repo adopts this (new app checklist)

1. Add `.github/workflows/security-pr.yml` and `.github/workflows/security-weekly.yml`
   from `templates/`, filling in `__APPLICATION_ID__` (must match the `application_id`
   Mission Control already uses for that app in `mc_repositories`/`mc_deployments`) and
   `__SUPABASE_ENABLED__`, and picking a `__CRON__` slot (see "Weekly schedule" below).
2. In the app repo's GitHub settings → Secrets and variables → Actions:
   - Secret `MISSION_CONTROL_SECURITY_TOKEN` — ask for the current value (shared across
     all repos, rotated centrally — see "Rotating the ingestion token" below).
   - Variable `MC_SECURITY_URL` — `https://missioncontrol.distinct-app.com/api/security/scans`.
   - Variable `SECURITY_SCAN_URL` (weekly only, optional) — a staging/preview URL if one
     exists. Omitting it just skips ZAP; source-code scans still run.
3. Open a PR — confirm the "Security (PR)" check appears and completes.
4. Nothing else. New findings show up in Mission Control's Security dashboard under this
   app automatically once the first scan lands.

## Weekly schedule

Each repo picks its own 5-field cron in its `security-weekly.yml`, spaced out so ~20
repos don't all hit Mission Control's ingestion endpoint in the same GitHub Actions
minute (which is a soft rate-limit/queueing concern more than a hard limit, but there's
no reason to bunch them). Suggested: stagger `0 2-4 * * 1` across repos, e.g.
`17 2 * * 1`, `23 2 * * 1`, `41 2 * * 1`, ... — see `docs/architecture.md` for the exact
per-repo table used in the rollout.

## Rotating the ingestion token

`MISSION_CONTROL_SECURITY_TOKEN` is one shared secret, not one per repo — it authenticates
"a GitHub Actions run from one of my repos" to Mission Control, nothing finer-grained
than that. To rotate: generate a new random value, update it via
`gh secret set MISSION_CONTROL_SECURITY_TOKEN --repo <owner>/<repo> --body <value>` for
every repo, then update the Cloudflare Worker secret on Mission Control
(`wrangler secret put MISSION_CONTROL_SECURITY_TOKEN`) to match. There's a short window
where old and new must both be accepted if you want zero dropped scans mid-rotation —
not implemented; for a solo-dev setup, a few minutes of scan downtime during rotation is
an acceptable trade-off.

## Running checks locally

```sh
# From inside any app repo:
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.18.4 detect --source=/repo --no-git

docker run --rm -v "$PWD:/src" semgrep/semgrep:1.78.0 semgrep scan --config p/security-audit --config p/secrets --config p/owasp-top-ten /src

docker run --rm -v "$PWD:/repo" aquasec/trivy:latest fs /repo

npm audit

# Supabase static check (needs Node, no install):
node /path/to/security-framework/scripts/supabase-check.mjs . ./supabase-check.json
```

No results are submitted anywhere by these local commands — submission only happens
inside the GitHub Actions workflow, and only if `MC_SECURITY_URL`/token are set.

## Why Semgrep uses community registry configs, not custom rules

`p/security-audit`, `p/secrets`, `p/owasp-top-ten` (and `p/typescript`, `p/react` in the
weekly run) are free, maintained-upstream rulesets covering the OWASP Top 10 class of
bugs across this codebase's actual stack. Writing and maintaining ~20 repos' worth of
custom Semgrep rules would directly work against "low maintenance" — only add a custom
rule here if a specific recurring false-negative shows up in practice.

## Nuclei — deferred, not wired up

Nuclei needs a vetted, non-destructive template subset and a real target list per app
to avoid noisy/risky scanning of production endpoints, and none of that exists yet. The
weekly reusable workflow has a placeholder job (`enable-nuclei: true`) that currently
just prints a message — flip it on only after templates and targets are chosen. Source
code and dependency scans do not depend on this and are fully live already.

## Severity gate on PRs

`fail-on-severity: high` (default) blocks the PR only when a Critical or High finding is
present. Medium/Low/Informational never block — they're visible in Mission Control but
don't interrupt shipping. Set `fail-on-severity: critical` per-repo if High findings are
too noisy for that app, or `none` to make the check fully advisory during initial rollout.
