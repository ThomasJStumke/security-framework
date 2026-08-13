# Security scanning

This repo's automated security scanning (Gitleaks, Semgrep, Trivy, dependency audit,
Supabase/RLS check, OWASP ZAP) is defined in `.github/workflows/security-pr.yml` and
`.github/workflows/security-weekly.yml`, both of which call shared, centrally-maintained
reusable workflows in [ThomasJStumke/security-framework](https://github.com/ThomasJStumke/security-framework).

Results are visible in Mission Control's Security dashboard, not in this repo. For:
- what runs on PRs vs. weekly, and why
- required secrets/variables
- how to run any check locally
- how findings get triaged (including this fleet's known false-positive patterns)
- how to add security scanning to a brand new app

see [security-framework's SECURITY.md](https://github.com/ThomasJStumke/security-framework/blob/main/SECURITY.md).
