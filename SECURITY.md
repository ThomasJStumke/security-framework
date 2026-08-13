# Security scanning — how this works

This is the canonical doc for the security platform across every app under
`ThomasJStumke`'s GitHub account. Each app repo has a short `SECURITY.md` stub that
links back here — this is the one place that gets updated when something changes.

## What runs on every pull request (and every push to `main`)

`.github/workflows/security-pr.yml` in the app repo calls this repo's
`reusable-security-pr.yml`, which runs, in parallel:

- **Gitleaks** — secret scan of the current working tree (not full history — that's
  the weekly job's job).
- **Semgrep CE** — static analysis using free community rulesets
  (`p/security-audit`, `p/secrets`, `p/owasp-top-ten`).
- **Trivy** — filesystem/dependency/config scan.
- **npm audit** — dependency CVEs (works even in bun-managed repos; a temporary
  lockfile is generated for the audit only, nothing is installed).
- **Supabase/RLS static check** — only if the app repo's workflow sets
  `supabase-enabled: true`.

All five feed into a normalize step that fingerprints/dedupes findings and submits
them to Mission Control. The PR check **fails only** if a Critical or High severity
finding is present (configurable per-repo via `fail-on-severity`). Medium/Low/
Informational findings never block a PR — they're visible in Mission Control instead.

Typical runtime: 1–2 minutes.

## What runs weekly

`.github/workflows/security-weekly.yml` calls `reusable-security-weekly.yml` on a
GitHub Actions cron (each repo picks its own time, staggered — see that repo's
workflow file). This is the deep pass:

- Gitleaks against **full git history**, not just the working tree.
- Semgrep with additional rulesets (`p/typescript`, `p/react`).
- Trivy, npm audit, Supabase check — same as PR but not diff-scoped.
- **OWASP ZAP baseline** — only if the repo has a `SECURITY_SCAN_URL` GitHub Actions
  variable set to a staging/preview URL. No ZAP run happens without one; source-code
  scans are unaffected either way.
- **Nuclei** — not implemented yet. See "Nuclei" in this repo's `README.md`.

The weekly job never fails the workflow on findings — it always reports, even if
every scanner found something. A scanner *erroring* (as opposed to finding
vulnerabilities) is tracked separately as scanner status "failed" in Mission Control,
distinct from "findings".

## Where results go

Every scan run POSTs a normalized JSON payload to
`https://missioncontrol.distinct-app.com/api/security/scans`, authenticated with a
shared bearer token. Mission Control stores it, deduplicates findings by fingerprint,
recalculates that app's security score, and the Security dashboard
(`missioncontrol.distinct-app.com/security`) picks it up from there. See
`docs/security-scoring.md` for the scoring formula.

If ingestion fails (network issue, Mission Control down, token misconfigured), the
scan step fails but the raw scanner outputs are still uploaded as GitHub Actions
artifacts on that run — nothing is silently lost, it's just not in the dashboard yet.

## Required secrets/variables (set per app repo)

| Name | Kind | Required? | Purpose |
|---|---|---|---|
| `MISSION_CONTROL_SECURITY_TOKEN` | Actions secret | Required | Authenticates this repo's scan submissions to Mission Control. Same value across all repos. |
| `MC_SECURITY_URL` | Actions variable | Required | `https://missioncontrol.distinct-app.com/api/security/scans` |
| `SECURITY_SCAN_URL` | Actions variable | Optional | Staging/preview URL for OWASP ZAP (weekly only). Omit to skip ZAP. |

## Configuring the staging URL for ZAP

`gh variable set SECURITY_SCAN_URL --repo <owner>/<repo> --body "https://staging.example.com"`

Use a staging/preview/test deployment, never production, per the baseline-only,
non-destructive scanning policy this framework follows.

## Running checks locally

See this repo's `README.md` → "Running checks locally" for the exact commands
(Docker-based, no global installs needed).

## Interpreting findings / false positives / triage

See `CLAUDE_SECURITY_REVIEW.md` in this repo — it's written as instructions for
Claude Code (or a human) doing triage: priority order, known false-positive patterns
for this specific fleet of apps, and what "done" looks like for a review pass.

To change a finding's status (accept the risk, mark false positive, mark fixed), open
it in Mission Control's Security dashboard (`/security/findings/<id>`) — there's no
CLI for this yet, it's a dashboard-only action.

## Adding a new application

1. Copy `templates/security-pr.yml` and `templates/security-weekly.yml` into the new
   repo's `.github/workflows/`, filling in `application-id` (pick a short slug; if this
   app also has a Mission Control-tracked entry in `src/data/applications.ts`, reuse
   that same id so the dashboard shows a friendly name instead of the raw slug),
   `supabase-enabled`, and a `cron` time (pick an unused minute in the 02:00–05:00 UTC
   Monday slot other repos use — see this repo's own workflow files for what's taken).
2. `gh secret set MISSION_CONTROL_SECURITY_TOKEN --repo <owner>/<repo> --body <token>`
   (ask for the current shared value).
3. `gh variable set MC_SECURITY_URL --repo <owner>/<repo> --body "https://missioncontrol.distinct-app.com/api/security/scans"`
4. Optionally `gh variable set SECURITY_SCAN_URL ...` if there's a staging URL.
5. Open any PR — confirm the "Security (PR)" check appears and passes/fails sensibly.
6. Done. No Mission Control-side configuration needed — the first scan submission
   creates that application's row automatically.
