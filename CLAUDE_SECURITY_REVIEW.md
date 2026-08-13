# How Claude Code should interpret security scan reports

Copy or symlink this file into an app repo as `security/CLAUDE_SECURITY_REVIEW.md` (or
reference it directly from this shared repo) when asked to triage findings from the
security platform. It applies whether reading a normalized-payload.json artifact, the
Mission Control Security dashboard, or raw scanner output directly.

## Process

1. **Read the report(s)** — normalized findings (severity, scanner, file/line or
   endpoint, evidence) before touching any code.
2. **Inspect the affected code directly.** A finding's title/rule-id is a hypothesis,
   not a verdict — read the actual file/line, the calling context, and any
   authorization/RLS that runs before that code path.
3. **Correlate duplicates.** The same real bug is often flagged by more than one
   scanner (e.g. Semgrep's SQLi rule and Trivy's config scan both touching one file) or
   the same scanner across PR and weekly runs. Don't report it three times.
4. **Distinguish confirmed vs. potential.** State explicitly which findings you verified
   by reading the code vs. which are plausible-but-unverified from the report alone.
5. **Prioritize by realistic exploitability**, not raw severity number. A Critical
   Gitleaks hit on a real, live API key is more urgent than a Critical Semgrep SSRF
   match against a hardcoded, non-user-controlled URL.
6. **Explain business impact** in terms of this specific app (e.g. "an authenticated
   user of App X could read another business's invoices" beats "IDOR vulnerability").
7. **Recommend remediation** — concrete, minimal, scoped to the actual finding.
8. **Do not silently mass-fix.** Fixing one specific, confirmed, user-approved finding
   is fine. Rewriting a policy, auth flow, or dozen files because a scanner flagged
   something adjacent is not — surface it and let the human decide scope.

## Priority order when multiple findings compete for attention

1. Leaked secrets (Gitleaks — assume compromised the moment it's committed, even to a
   private repo; rotate first, discuss later)
2. Authentication bypass/weakness
3. Authorization bypass (a user doing something they shouldn't within their own account)
4. Tenant isolation / cross-business access (a user reaching *another* tenant's data —
   see `[[project_distinct_app_shared_crm_schema]]`-style shared-schema apps, where this
   is the single highest-value thing to get right)
5. Supabase RLS gaps (missing RLS, `USING (true)`, unreviewed `SECURITY DEFINER`)
6. API security (SSRF, injection, insecure deserialization, mass assignment)
7. Admin-only functionality reachable without an admin check
8. Payment-adjacent functionality (none of these apps process payments directly today —
   flag immediately if a finding suggests otherwise, that's a scope surprise)
9. File upload handling (path traversal, unrestricted type/size, R2/Storage bucket ACLs)
10. Sensitive information disclosure (PII in logs, verbose error messages, debug routes)
11. Dependency CVEs with a real, reachable code path (not just "package X is in the
    tree" — check whether the vulnerable function is actually called)
12. Lower-priority configuration/lint-adjacent findings

## Known false-positive patterns in this fleet

- `supabase-check.mjs` cannot see RLS policies applied outside migration files (e.g. via
  the Supabase dashboard directly). A "no RLS enabled" finding on a table that's
  genuinely locked down via a dashboard-applied policy is a false positive — verify
  against the live database (`supabase db query` or the readonly role, see project
  memory) before treating it as real.
- Semgrep's `p/security-audit` occasionally flags framework-idiomatic patterns in
  TanStack Start server functions (e.g. reading env vars) as "hardcoded secret" when
  it's actually just a variable named similarly to a secret. Read the line before
  escalating.
- Trivy dependency findings on `devDependencies` that never ship to production/the
  browser bundle are lower real-world risk than the same CVE in a runtime dependency —
  note this distinction rather than treating all Trivy Criticals identically.

## What "done" looks like for a triage pass

A short report: confirmed findings (with the specific fix, if you're asked to fix them),
likely false positives (with why), and anything that needs the human's judgment call
(accept the risk? fix now? track for later?) — not a diff that touched every file a
scanner mentioned.
