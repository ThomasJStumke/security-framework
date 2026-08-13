# Security score formula

Implemented in Mission Control as `mc_recalculate_application_security_state(app_id)`,
run after every scan ingestion. Score is 0–100, recomputed from **currently open**
findings only (status = `open` or `retest_required`) — `false_positive`, `accepted_risk`,
and `fixed` findings don't count against the score, so a triaged backlog isn't
indistinguishable from an unreviewed one.

## Base score

Start at 100. Subtract, per open finding:

| Severity | Points off |
|---|---|
| Critical | 25 |
| High | 10 |
| Medium | 3 |
| Low | 0.5 |
| Informational | 0.1 |

Floor at 0. This is intentionally steep for Critical/High — three open Critical findings
already floors the score, which is the point: this is not meant to average out.

## Freshness penalty

- If `last_successful_scan_at` is more than 10 days old (or null — never scanned): −10.
- If the most recent scan's `scanner_results` contains any entry with `status: "failed"`
  (the scanner itself errored, distinct from "ran clean and found nothing" or "ran and
  found issues"): −5 per failed scanner.

A stale or partially-broken scan pipeline should visibly cost score, not silently freeze
whatever the last good number was.

## Status label

| Score | Status |
|---|---|
| 90–100 | Excellent |
| 75–89 | Good |
| 50–74 | Attention Required |
| 25–49 | High Risk |
| 0–24 | Critical |

**Override:** any single open Critical finding caps the status at `High Risk` regardless
of numeric score (a lone Critical shouldn't hide behind an otherwise-clean 80). Any open
finding tagged `security_category = 'Tenant Isolation'` does the same — cross-tenant
access risk is treated as Critical-equivalent for status purposes even if a scanner
reported it at a lower raw severity.

## What is deliberately NOT in the formula (yet)

- CVSS score isn't separately weighted — severity bucket already reflects it, and mixing
  both would double-count.
- Finding *age* isn't weighted beyond the freshness penalty above (an open High from six
  months ago costs the same as one from yesterday). Revisit if stale-but-accepted
  findings start dragging scores down unfairly — the right fix there is triaging them to
  `accepted_risk`, not changing the formula.
