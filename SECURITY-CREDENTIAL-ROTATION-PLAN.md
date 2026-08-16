# Distinct + DareToFish — Credential Rotation Plan

**Status:** Phase 2 (consolidation/cleanup) complete. Phase 3 (rotation) NOT started — awaiting explicit owner approval.
**Phase 2 completion date:** 2026-08-16
**Written by:** Claude (Sonnet 5), as the Phase 2 execution pass following the Phase 1 discovery audit.
**Git reference at time of writing:** this commit, in `ThomasJStumke/security-framework`, main branch.

This document is self-contained. A new Claude session (or a human) can resume Phase 3 from this file alone, without needing the Phase 1/Phase 2 conversation history. No secret values appear anywhere in this file — only names, locations, and consumers.

---

## 1. How the estate got here

Two prior passes:

1. **Phase 1 — Discovery** (2026-08-16, same day). A live-evidence audit across GitHub, Vercel, Cloudflare, R2, Supabase, Resend, and Mission Control's own database. Published as an artifact; not reproduced here. Its central finding: Mission Control's `mc_domains` and `mc_infrastructure_resources` tables described a pre-Vercel-migration snapshot of the estate — 16 of 17 domain rows and 15 of 17 Worker rows were stale.
2. **Phase 2 — Consolidate & clean up** (this pass, 2026-08-16). Re-verified every Phase 1 claim against live evidence immediately before acting on it, executed the safe/proven cleanup, and — critically — **found new evidence during re-verification that overturned two of Phase 1's own conclusions.** Both reversals are documented in §3 below. This is the reason Phase 2 re-checks everything itself rather than trusting Phase 1's table at face value, and Phase 3 must do the same.

---

## 2. Current verified estate state (as of 2026-08-16, end of Phase 2)

### Hosting
All 16 distinct-app.com production domains + daretofish.com are Vercel-hosted, confirmed by DNS. Two legitimate Cloudflare exceptions exist outside distinct-app.com:
- `underdog.stumke-fam.com` → Cloudflare Worker `tanstack-start-app` (genuinely required, own compute)
- `form-a-web.com` → Cloudflare Tunnel to a homelab node-server (DNS/proxy only)
- `trip.distinct-app.com` (drive-log) → Vercel origin, but DNS is Cloudflare-proxied (orange-cloud) for a known TLS exception — **preserve this DNS proxy**, it is not the same thing as the orphaned `thomasjstumke-drive-log` Worker object (see §3).

### Mission Control
`mc_domains` (16/16 correct) and `mc_infrastructure_resources` (9 rows, all matching live Cloudflare reality, 0 phantom rows, 0 duplicates) were reconciled against live evidence via direct SQL migrations against Supabase project `vjdpbelivlysjkhtjjcc`:
- `mc_domains_vercel_reconciliation_2026_08_16`
- `mc_infrastructure_resources_reconciliation_2026_08_16`

Mission Control's UI should now represent the current real infrastructure state. No historical `mc_security_events` / `mc_security_findings` rows were touched — only forward-looking infrastructure metadata.

### GitHub Actions secrets
- 9 confirmed-dead `CLOUDFLARE_API_TOKEN` secrets **deleted** (financial-overview-hub, quick-message-hub, distinct-app-showcase, logo-maker-genie, flyer-buddy, kauai-control-center, team-connect, swift-invoice, sales-pipeline-lite). Reconfirmed immediately before deletion: each repo's only workflow is `security-weekly.yml`, which does not reference Cloudflare in any form.
- `finance-friend`: `CLOUDFLARE_API_TOKEN` **deleted**, `deploy.yml` (the workflow that consumed it) **removed** from the repo. Commit: `ad8136a` on `ThomasJStumke/finance-friend` main. finance-friend now carries only `MISSION_CONTROL_SECURITY_TOKEN`.
- `unity-bridge-core`: `CLOUDFLARE_API_TOKEN` **preserved** — see §3, this was a Phase 1 classification reversal.
- `underdog-insights`: `CLOUDFLARE_API_TOKEN` **preserved** — genuinely required, serves `underdog.stumke-fam.com`.
- `MISSION_CONTROL_SECURITY_TOKEN` — verified present, untouched, in all 12 spot-checked repos plus presumed present in the remaining in-scope repos (not individually re-verified this pass; no reason to expect drift since Phase 1).

### Cloudflare Workers (7 live, confirmed via `workers_list`)
| Worker | Disposition this phase | Reason |
|---|---|---|
| `tanstack-start-app` | Keep | Serves underdog.stumke-fam.com, required |
| `thomasjstumke-finance-friend` | Deploy pipeline stopped, secret deleted. **Worker object itself NOT deleted** — no Worker-delete tool was available this session | Domain is Vercel-served, no cron/scheduled handler found in repo |
| `thomasjstumke-unity-bridge-core` | **Preserved — do not touch** | Carries a live hourly Cron Trigger wired to a real `scheduled()` handler; see §3 |
| `thomasjstumke-drive-log` | **Preserved — do not touch** | Explicit owner instruction: preserve until the trip.distinct-app.com TLS/proxy migration is independently verified |
| `thomasjstumke-educator-hub` | **Preserved — owner input required** | No custom domain anywhere, no deploy workflow, yet `modified_on` is recent (2026-08-15) — something outside GitHub Actions is deploying to it |
| `formaweb-grow-southafrica` | **Preserved — owner input required** | No deploy workflow in repo; this exact app has a documented DNS-record-vs-tunnel-ingress outage history. Do not touch without confirming the Tunnel serves 100% of traffic |
| `underdog-collective` | **Preserved — owner input required, see §3** | `modified_on` was 2026-08-16, the same day as this reconciliation — contradicts the "safe to decommission, dormant" read |

### R2
No changes. 4 buckets untouched: `daretofish`, `daretofish-private`, `daretofish-public`, `distinct-app` (shared, 9+ consumers). The shared `distinct-app` bucket credential remains a blast-radius item for a future scoping pass, not this one.

### Vercel
No env-var changes made — still no enumeration tool available this session. See §5 for the exact owner checklist (unchanged from Phase 1, still outstanding).

---

## 3. Two Phase 1 classifications that Phase 2 overturned

Read this section before touching anything Phase 1 called "safe." Phase 1 was DNS/deploy-workflow evidence only; Phase 2 went one level deeper (wrangler config, worker source, and Cloudflare's own `modified_on` timestamps) and found real facts Phase 1 missed.

**1. `unity-bridge-core` / `thomasjstumke-unity-bridge-core` — NOT a clean decommission.**
Phase 1 grouped this with `finance-friend` as "redeploys a Worker for a domain now served by Vercel, decommission after a route check." Phase 2 found:
- The repo's `wrangler.jsonc` defines `"triggers": { "crons": ["0 * * * *"] }`.
- `src/server.ts` exports a real `scheduled()` handler that calls `runScheduledSync()`.
- The repo's own `vercel.json` defines matching crons (`/api/cron/sync` hourly, `/api/cron/security-digest` daily), and `src/routes/api/cron/sync.ts` carries a code comment stating explicitly: *"Mirrors server.ts's scheduled() handler, which remains the entry point on Cloudflare... Same underlying runScheduledSync() either way."*

This is deliberate dual-path architecture, not leftover residue — the same sync job may currently be running twice an hour (once via Vercel Cron HTTP, once via the Worker's native Cron Trigger). Deleting the Worker would silently remove one of the two paths. Whether that's intended redundancy or an accidental double-run is an architecture question for the owner, not a cleanup decision. **Do not decommission this Worker or its `CLOUDFLARE_API_TOKEN`/deploy step until the owner decides which cron path is canonical.**

**2. `underdog-collective` — NOT dormant.**
Phase 1 called this "repo has zero workflows, superseded by underdog-insights, decommission immediately." Still true that the repo has zero GitHub workflows and hasn't been pushed to since 2026-07-09. But Cloudflare's live `workers_list` reports this Worker's `modified_on` as **2026-08-16** — the same calendar day this reconciliation ran, hours before it did. Something outside GitHub Actions (a manual `wrangler deploy`, a different CI system, or direct dashboard editing) is actively touching this Worker. **Do not decommission until the owner identifies that deploy path and confirms it's safe to stop.**

General lesson for Phase 3: **`modified_on` recency on the live Cloudflare resource is a stronger signal than "no workflow references it."** A dead GitHub Actions path does not prove a dead resource — check the resource's own last-modified timestamp before treating anything as safe to remove.

---

## 4. Credentials remaining that genuinely require rotation

**Zero.** As in Phase 1, nothing found in this pass was exposed in source, logs, or a public location. Two items remain blast-radius concerns worth planning as a future *design* change, not urgent rotations:
- The shared `distinct-app` R2 credential (used by 9+ apps) — candidate for per-app key issuance.
- The shared `distinct-app` Supabase project (`vjdpbelivlysjkhtjjcc`, serves 17 applications) — a standing architectural note from prior sessions, not newly found here.

Neither is an active exposure. Rotate only if/when the owner decides to do the underlying architecture change (splitting the shared bucket/project), at which point rotation is a side effect of that migration, not a standalone task.

---

## 5. Outstanding owner actions (nothing here was skippable by tooling, not by choice)

1. **Vercel environment-variable audit** — no enumeration tool was available in either phase. Checklist, unchanged from Phase 1:

   | Vercel project | Variable to check | Why | Expected action |
   |---|---|---|---|
   | financial-overview-hub, quick-message-hub, distinct-app-showcase, logo-maker-genie, flyer-buddy, kauai-control-center, team-connect, swift-invoice, sales-pipeline-lite | `CLOUDFLARE_API_TOKEN`, `WRANGLER_*`, any Worker-era API URL | These 9 apps just had their GitHub-side Cloudflare secret deleted as confirmed-dead; if a copy also exists in Vercel it's equally dead | Delete if present |
   | finance-friend | `CLOUDFLARE_API_TOKEN`, `WRANGLER_*` | Same app, GitHub-side secret + deploy step already removed this phase | Delete if present |
   | unity-bridge-core / mission-control | `CLOUDFLARE_API_TOKEN`, `WRANGLER_*` | **Do NOT delete GitHub-side per §3 — check but leave alone pending the cron decision** | Leave as-is until cron architecture decision is made |
   | All 23 projects | Any variable duplicated under a different name (two Supabase URLs, two R2 keys, etc.) across Production/Preview/Development | Config drift risk | Consolidate to one canonical name/value per concept |
   | All 23 projects | Every `VITE_*` / `NEXT_PUBLIC_*` variable | Scan for anything that looks like a service-role key, signing secret, or R2 secret key accidentally made client-visible | Move server-only, rotate if it was ever actually shipped to a client bundle |
   | All 23 projects | Any variable not grep-able in the corresponding repo's source | Dead config | Delete |

2. **Cloudflare Worker deletions requiring dashboard access** (no Worker-delete tool was available in this MCP session):
   - `thomasjstumke-finance-friend` — safe to delete now; deploy pipeline and secret are already gone, domain confirmed Vercel-served, no cron/scheduled handler exists in the repo.
   - Do **not** delete `thomasjstumke-unity-bridge-core`, `thomasjstumke-drive-log`, `thomasjstumke-educator-hub`, `formaweb-grow-southafrica`, or `underdog-collective` — each has an open owner-input item per §2/§3.

3. **`thomasjstumke-educator-hub`** — confirm whether this app is in active development or deprecated before any decision on its Worker.

4. **`formaweb-grow-southafrica`** — confirm the Cloudflare Tunnel serves 100% of `form-a-web.com` traffic before touching the orphaned Worker. This app has a known DNS-record-vs-Tunnel-ingress outage in its history — treat with extra care.

5. **`underdog-collective`** — identify what is deploying to this Worker outside GitHub Actions (manual CLI? separate CI? dashboard edits?) before deciding its fate.

6. **`unity-bridge-core`'s dual cron path** — decide whether the Vercel HTTP cron (`/api/cron/sync`) or the Cloudflare Worker's native Cron Trigger (or both, intentionally) should be the source of truth for the hourly infra/security sync. This decision determines whether `thomasjstumke-unity-bridge-core` and its `CLOUDFLARE_API_TOKEN` can ever be removed.

7. **Second Resend account** — confirm whether a separate Resend account/key exists for distinct-app.com outside the one MCP connection used in both audit passes (which only shows daretofish.com).

---

## 6. Recommended rotation order (for whenever owner decides to rotate — none is urgent today)

Only relevant once the owner-actions in §5 are closed out and/or a decision is made to proactively rotate as a hygiene measure, not because anything is known-exposed:

1. **Shared `distinct-app` R2 credential** — issue per-app scoped keys first, migrate each app's Vercel env var to its own key, confirm each app still uploads/reads correctly, *then* revoke the old shared key. Never revoke before every consumer has its replacement live.
2. **`CLOUDFLARE_API_TOKEN` for `underdog-insights`** (only remaining CF deploy secret expected to survive long-term, alongside `unity-bridge-core`'s pending its cron decision) — standard rotate-then-revoke: issue new token, update the GitHub secret, trigger one deploy to confirm success, then revoke the old token in the Cloudflare dashboard.
3. **`SUPABASE_SERVICE_ROLE_KEY` in `blue-baboons-compete`** — evaluate first whether the E2E teardown RPC can be scoped to a narrower role than full service-role; if yes, that's a privilege reduction to do *before* considering rotation of the existing key.
4. **`MISSION_CONTROL_SECURITY_TOKEN`** — only rotate if there's a specific reason (suspected exposure); it's a single ingestion token pattern across repos, verify whether all repos share one literal value or per-repo distinct values before deciding whether rotation is single-step or 23-step. Rotating this is the *daily security workflow's* dependency — coordinate the swap with the 21:00 SAST run so a mid-cycle rotation doesn't cause one day's ingestion to fail silently.

Dependencies between rotations: none of the above block each other — they can proceed independently and in any order the owner prefers. The R2 credential split is the only one with internal sequencing (issue-then-revoke, never revoke-then-issue).

---

## 7. What must NOT be deleted, under any future Phase 3 pass, without new evidence

- `thomasjstumke-unity-bridge-core` (Worker) and its `CLOUDFLARE_API_TOKEN` — active cron dependency, see §3.
- `thomasjstumke-drive-log` (Worker) — explicit standing owner instruction to preserve until the trip.distinct-app.com TLS/proxy migration is independently verified.
- The Cloudflare DNS proxy (orange-cloud) on `trip.distinct-app.com` — this is not the same thing as the drive-log Worker object above; it's the TLS exception itself.
- `thomasjstumke-educator-hub`, `formaweb-grow-southafrica`, `underdog-collective` (Workers) — each has unresolved owner-input items; treat `modified_on` recency as a hard stop signal, not a soft one.
- `tanstack-start-app` (Worker) — genuinely required, serves underdog.stumke-fam.com.
- All 4 R2 buckets.
- `MISSION_CONTROL_SECURITY_TOKEN` in any of the 23 in-scope repos — required by the daily 21:00 SAST / 19:00 UTC security workflow.
- The daily security workflow's single `cron: "0 19 * * *"` + `workflow_dispatch` trigger shape — do not restore push/PR/deployment triggers.
- Historical rows in `mc_security_events` / `mc_security_findings` — infrastructure metadata was corrected this phase, security history was not touched and must not be touched by a metadata cleanup.

---

## 8. Verification performed at the end of Phase 2

- All 10 spot-checked production domains (tracking, missioncontrol, daretofish, trip, form-a-web, underdog, financehub, logo, market, flyer) returned HTTP 200 after all changes.
- `finance-friend`'s `security-weekly.yml` reconfirmed present with its original daily-only trigger, untouched by this pass.
- `MISSION_CONTROL_SECURITY_TOKEN` reconfirmed present in all 12 spot-checked repos.
- `mc_domains` reconfirmed: 16/16 rows now `provider = 'vercel'` with real Vercel project IDs as `hosting_target` (daretofish.com was already correct).
- `mc_infrastructure_resources` reconfirmed: 9 rows total, all corresponding to real, live Cloudflare resources (7 Workers + 2 R2 bucket references), 0 phantom rows, 0 duplicates.
- Final `CLOUDFLARE_API_TOKEN` census across all 23 spot-checked repos: present in exactly 2 (`underdog-insights`, `unity-bridge-core`), both intentionally preserved.
