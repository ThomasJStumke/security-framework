#!/usr/bin/env node
// Normalizes raw scanner output (Gitleaks/Semgrep/Trivy/npm audit/Supabase check) into
// Mission Control's ingestion payload shape and POSTs it to /api/security/scans.
//
// Env vars (all required unless noted):
//   MC_SECURITY_URL             e.g. https://missioncontrol.distinct-app.com/api/security/scans
//   MISSION_CONTROL_SECURITY_TOKEN
//   MC_APPLICATION_ID           loose text id matching mc_repositories.application_id convention
//   REPO_OWNER, REPO_NAME
//   SCAN_TYPE                   pr | daily | weekly | manual
//   SCAN_STARTED_AT             ISO timestamp
//   COMMIT_SHA, BRANCH          (optional)
//   GITHUB_RUN_ID, GITHUB_RUN_URL (optional)
//   REPORTS_DIR                 directory containing raw scanner output (default: .security-reports)
//   SUPABASE_ENABLED, SCAN_URL, ENABLE_NUCLEI, ENABLE_NMAP (optional)
//     Used only to tell an *intentional* per-repo skip (Supabase check disabled, no
//     SECURITY_SCAN_URL configured, Nuclei/Nmap opted out) apart from a scanner that
//     was expected to run and didn't produce a report -- the latter becomes a
//     "failed" scanner_results entry plus a synthetic missing-security-control
//     finding, per the "security problem -> Mission Control finding, security
//     automation problem -> visible/flagged, never silently fewer findings" rule.
//
// Never sends raw secret values — Gitleaks matches/secrets are redacted before normalization.

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const REPORTS_DIR = process.env.REPORTS_DIR || ".security-reports";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];

function clampSeverity(s) {
  s = String(s || "").toLowerCase();
  if (SEVERITIES.includes(s)) return s;
  if (s === "error") return "high";
  if (s === "warning") return "medium";
  if (s === "info" || s === "unknown") return "informational";
  return "informational";
}

async function readJsonIfExists(file) {
  try {
    const raw = await readFile(file, "utf8");
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function fingerprint(parts) {
  // Stable identity for dedup — same tool, same rule, same location => same finding across runs.
  const key = parts.filter(Boolean).join("|");
  let hash = 0n;
  for (const ch of Buffer.from(key, "utf8")) {
    hash = (hash * 31n + BigInt(ch)) & 0xffffffffffffffffn;
  }
  return hash.toString(16).padStart(16, "0");
}

// ---- Gitleaks ----
function normalizeGitleaks(report) {
  if (!Array.isArray(report)) return { findings: [], status: "passed" };
  const findings = report.map((f) => ({
    scanner: "gitleaks",
    external_finding_id: f.Fingerprint || null,
    fingerprint: fingerprint(["gitleaks", f.RuleID, f.File, f.StartLine]),
    severity: "critical",
    original_severity: "leaked-secret",
    confidence: "high",
    title: `Potential secret: ${f.RuleID || f.Description || "unknown rule"}`,
    description: f.Description || "Gitleaks detected a pattern matching a known secret format.",
    security_category: "Secrets",
    cwe: "CWE-798",
    file_path: f.File,
    line_number: f.StartLine,
    evidence: "[redacted — never store raw secret values]",
    metadata: { rule_id: f.RuleID, commit: f.Commit, author: f.Author },
  }));
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- Semgrep ----
function normalizeSemgrep(report) {
  if (!report?.results) return { findings: [], status: "passed" };
  const findings = report.results.map((r) => {
    const meta = r.extra?.metadata || {};
    const sev = meta.severity || r.extra?.severity;
    return {
      scanner: "semgrep",
      external_finding_id: r.check_id,
      fingerprint: fingerprint(["semgrep", r.check_id, r.path, r.start?.line]),
      severity: clampSeverity(sev),
      original_severity: r.extra?.severity || null,
      confidence: meta.confidence || null,
      title: r.check_id,
      description: r.extra?.message || "",
      security_category: (meta.category || meta.owasp?.[0] || "Other"),
      cwe: Array.isArray(meta.cwe) ? meta.cwe[0] : meta.cwe || null,
      owasp_category: Array.isArray(meta.owasp) ? meta.owasp[0] : meta.owasp || null,
      file_path: r.path,
      line_number: r.start?.line,
      evidence: (r.extra?.lines || "").slice(0, 500),
      metadata: { references: meta.references || [] },
    };
  });
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- Trivy ----
function normalizeTrivy(report) {
  if (!report?.Results) return { findings: [], status: "passed" };
  const findings = [];
  for (const result of report.Results) {
    for (const v of result.Vulnerabilities || []) {
      findings.push({
        scanner: "trivy",
        external_finding_id: v.VulnerabilityID,
        fingerprint: fingerprint(["trivy", v.VulnerabilityID, v.PkgName, result.Target]),
        severity: clampSeverity(v.Severity),
        original_severity: v.Severity,
        title: `${v.VulnerabilityID}: ${v.PkgName}`,
        description: v.Title || v.Description || "",
        security_category: "Dependencies",
        cve: v.VulnerabilityID?.startsWith("CVE-") ? v.VulnerabilityID : null,
        cvss: v.CVSS?.nvd?.V3Score ?? v.CVSS?.redhat?.V3Score ?? null,
        package_name: v.PkgName,
        package_version: v.InstalledVersion,
        remediation: v.FixedVersion ? `Upgrade to ${v.FixedVersion}` : null,
        metadata: { target: result.Target, references: v.References || [] },
      });
    }
    for (const m of result.Misconfigurations || []) {
      findings.push({
        scanner: "trivy",
        external_finding_id: m.ID,
        fingerprint: fingerprint(["trivy-misconfig", m.ID, result.Target]),
        severity: clampSeverity(m.Severity),
        original_severity: m.Severity,
        title: m.Title,
        description: m.Description || "",
        security_category: "Configuration",
        remediation: m.Resolution || null,
        file_path: result.Target,
        metadata: {},
      });
    }
  }
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- npm / pnpm audit (both use the same `vulnerabilities` map shape) ----
function normalizeNpmAudit(report, scanner = "npm-audit") {
  const vulns = report?.vulnerabilities;
  if (!vulns) return { findings: [], status: "passed" };
  const findings = Object.entries(vulns).map(([name, v]) => ({
    scanner,
    external_finding_id: `${name}@${v.range}`,
    fingerprint: fingerprint([scanner, name, v.range]),
    severity: clampSeverity(v.severity),
    original_severity: v.severity,
    title: `Vulnerable dependency: ${name}`,
    description: (v.via || []).filter((x) => typeof x === "object").map((x) => x.title).join("; "),
    security_category: "Dependencies",
    package_name: name,
    package_version: v.range,
    remediation: v.fixAvailable ? "Fix available — run audit fix" : "No automatic fix available yet",
    metadata: {},
  }));
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- bun audit (`bun audit --json`: { [pkgName]: [{ id, url, title, severity,
// vulnerable_versions, cwe, cvss }] } -- NOT npm's { vulnerabilities: {...} } shape;
// each package name maps directly to an array of advisories) ----
function normalizeBunAudit(report) {
  if (!report || typeof report !== "object") return { findings: [], status: "passed" };
  const findings = [];
  for (const [name, advisories] of Object.entries(report)) {
    for (const a of advisories || []) {
      findings.push({
        scanner: "bun-audit",
        external_finding_id: String(a.id),
        fingerprint: fingerprint(["bun-audit", name, a.id]),
        severity: clampSeverity(a.severity),
        original_severity: a.severity,
        title: a.title || `Vulnerable dependency: ${name}`,
        description: a.title || "",
        security_category: "Dependencies",
        package_name: name,
        package_version: a.vulnerable_versions,
        remediation: "See advisory for a fixed version",
        metadata: { cwe: a.cwe, cvss: a.cvss, url: a.url },
      });
    }
  }
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- yarn audit (`yarn audit --json` emits newline-delimited JSON; each advisory line
// has type "auditAdvisory") ----
function normalizeYarnAudit(raw) {
  if (typeof raw !== "string") return { findings: [], status: "passed" };
  const findings = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    if (obj.type !== "auditAdvisory") continue;
    const d = obj.data?.advisory;
    if (!d) continue;
    findings.push({
      scanner: "yarn-audit",
      external_finding_id: String(d.id),
      fingerprint: fingerprint(["yarn-audit", d.module_name, d.id]),
      severity: clampSeverity(d.severity),
      original_severity: d.severity,
      title: `Vulnerable dependency: ${d.module_name}`,
      description: d.overview || d.title || "",
      security_category: "Dependencies",
      package_name: d.module_name,
      package_version: d.vulnerable_versions,
      remediation: d.patched_versions && d.patched_versions !== "<0.0.0" ? `Upgrade to ${d.patched_versions}` : "No automatic fix available yet",
      metadata: { cwe: d.cwe, cves: d.cves },
    });
  }
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- pip-audit (`pip-audit -f json`: { dependencies: [{ name, version, vulns: [...] }] }) ----
function normalizePipAudit(report) {
  const deps = report?.dependencies;
  if (!Array.isArray(deps)) return { findings: [], status: "passed" };
  const findings = [];
  for (const dep of deps) {
    for (const v of dep.vulns || []) {
      findings.push({
        scanner: "pip-audit",
        external_finding_id: v.id,
        fingerprint: fingerprint(["pip-audit", dep.name, v.id]),
        severity: "medium", // pip-audit (OSV-backed) doesn't emit a severity bucket directly
        original_severity: null,
        title: `Vulnerable dependency: ${dep.name} (${v.id})`,
        description: v.description || "",
        security_category: "Dependencies",
        package_name: dep.name,
        package_version: dep.version,
        remediation: v.fix_versions?.length ? `Upgrade to ${v.fix_versions.join(" or ")}` : "No automatic fix available yet",
        metadata: {},
      });
    }
  }
  return { findings, status: findings.length ? "findings" : "passed" };
}

// Dispatches the single `dependency-audit.json` artifact to the right normalizer based on
// the `dependency-audit.manager` marker file the workflow writes alongside it. Falls back
// to npm's shape (also what legacy `npm-audit.json` artifacts use) if the marker is missing.
async function normalizeDependencyAudit(reportsDir, manager) {
  const file = path.join(reportsDir, "dependency-audit.json");
  if (manager === "yarn") {
    const raw = await readFile(file, "utf8").catch(() => null);
    return normalizeYarnAudit(raw);
  }
  const parsed = await readJsonIfExists(file);
  if (manager === "pip-audit") return normalizePipAudit(parsed);
  if (manager === "pnpm") return normalizeNpmAudit(parsed, "pnpm-audit");
  if (manager === "bun") return normalizeBunAudit(parsed);
  return normalizeNpmAudit(parsed, "npm-audit");
}

// ---- Nuclei (`-jsonl` — one JSON object per line, one per matched template/host) ----
function normalizeNuclei(raw) {
  if (typeof raw !== "string") return { findings: [], status: "passed" };
  const severityMap = { critical: "critical", high: "high", medium: "medium", low: "low", info: "informational", unknown: "informational" };
  const findings = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    findings.push({
      scanner: "nuclei",
      external_finding_id: r["template-id"],
      fingerprint: fingerprint(["nuclei", r["template-id"], r["matched-at"]]),
      severity: severityMap[String(r.info?.severity || "").toLowerCase()] || "informational",
      original_severity: r.info?.severity || null,
      title: r.info?.name || r["template-id"],
      description: r.info?.description || "Scanner evidence requiring manual triage — Nuclei matches are not automatic proof of exploitability.",
      security_category: "Exposure/Misconfiguration",
      endpoint: r["matched-at"],
      evidence: (r["extracted-results"] || []).join(", ").slice(0, 500),
      remediation: r.info?.remediation || null,
      metadata: { tags: r.info?.tags || [], reference: r.info?.reference || [] },
    });
  }
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- Nmap (`-oX` XML output). No XML library dependency — the schema we need
// (open ports on the single scanned host) is simple enough for a targeted regex walk. ----
function normalizeNmap(raw, hostHint) {
  if (typeof raw !== "string" || !raw.trim()) return { findings: [], status: "passed" };
  const findings = [];
  const portRe = /<port protocol="(\w+)" portid="(\d+)">\s*<state state="(\w+)"[^/]*\/>(?:\s*<service name="([^"]*)"[^/]*\/>)?/g;
  let m;
  while ((m = portRe.exec(raw))) {
    const [, protocol, port, state, service] = m;
    if (state !== "open") continue; // filtered/closed ports are not exposure findings
    findings.push({
      scanner: "nmap",
      external_finding_id: `${protocol}/${port}`,
      fingerprint: fingerprint(["nmap", hostHint, protocol, port]),
      severity: "informational", // exposure evidence for triage, not a vulnerability by itself
      original_severity: null,
      title: `Open port ${port}/${protocol}${service ? ` (${service})` : ""} on ${hostHint || "target"}`,
      description: "Externally reachable open port detected by a conservative top-100-ports discovery scan. Confirm this is expected (e.g. 443 for the app itself) — anything unexpected should be investigated.",
      security_category: "Network Exposure",
      endpoint: hostHint || null,
      metadata: { protocol, port, service: service || null },
    });
  }
  // Weekly-only, all-informational severity — status here is descriptive (did the scan surface
  // ports to review), never a PR-blocking signal; the severity gate only runs in the PR workflow.
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- Supabase static check (already normalized by supabase-check.mjs) ----
function normalizeSupabase(report) {
  if (!Array.isArray(report?.findings)) return { findings: [], status: "passed" };
  return { findings: report.findings, status: report.findings.length ? "findings" : "passed" };
}

// ---- ZAP baseline ----
// ZAP's baseline spider follows every same- and cross-origin resource the page loads (fonts,
// analytics, OAuth providers, Supabase, etc), so `report.site` is an array of ALL of those
// hosts, each with their own (usually empty) `alerts` -- not just the scanned target. The
// target's own entry can land at any index. Match it by hostname against SCAN_URL rather than
// assuming site[0]; falling back to site[0] silently reported an unrelated third-party host's
// (typically clean) results as if they were the target's own scan.
function normalizeZap(report) {
  const sites = report?.site;
  if (!Array.isArray(sites) || sites.length === 0) return { findings: [], status: "passed" };
  let targetSite = sites[0];
  const scanUrl = process.env.SCAN_URL;
  if (scanUrl) {
    try {
      const targetHost = new URL(scanUrl).hostname;
      // Exact hostname match only. A substring/`.includes()` check on `@name` is unsafe here --
      // e.g. targetHost "daretofish.com" is a substring of "cdn.daretofish.com", so a subdomain
      // entry earlier in the array would falsely win over the real (exact) match.
      targetSite =
        sites.find((s) => s["@host"] === targetHost) ??
        sites.find((s) => {
          try {
            return new URL(s["@name"]).hostname === targetHost;
          } catch {
            return false;
          }
        }) ??
        targetSite;
    } catch {
      // malformed SCAN_URL -- fall back to site[0] below rather than throwing
    }
  }
  const alerts = targetSite?.alerts;
  if (!Array.isArray(alerts)) return { findings: [], status: "passed" };
  const riskMap = { 3: "high", 2: "medium", 1: "low", 0: "informational" };
  const findings = alerts.map((a) => ({
    scanner: "zap",
    external_finding_id: a.pluginid,
    fingerprint: fingerprint(["zap", a.pluginid, a.instances?.[0]?.uri]),
    severity: riskMap[a.riskcode] || "informational",
    original_severity: a.riskdesc,
    confidence: a.confidence,
    title: a.alert || a.name,
    description: a.desc,
    security_category: "API Security",
    cwe: a.cweid ? `CWE-${a.cweid}` : null,
    owasp_category: a.wascid ? `WASC-${a.wascid}` : null,
    endpoint: a.instances?.[0]?.uri,
    evidence: (a.instances?.[0]?.evidence || "").slice(0, 500),
    remediation: a.solution,
    metadata: { reference: a.reference },
  }));
  return { findings, status: findings.length ? "findings" : "passed" };
}

// A scanner/control expected to have produced a report but didn't (job crashed,
// tool failed to install, timed out, etc.) becomes both a "failed" scanner_results
// entry AND a real, deduplicated Mission Control finding -- so it's visible next to
// actual vulnerabilities instead of just silently reducing the finding count.
function missingControlFinding(scannerName, appId) {
  return {
    fingerprint: fingerprint(["missing-control", appId, scannerName]),
    scanner: "security-framework",
    severity: "high",
    title: `Security control missing or failed to execute: ${scannerName}`,
    description: `The ${scannerName} scanner was expected to run in this scan but produced no report. This means a security control gap, not zero findings -- normalize-and-submit.mjs found the scanner enabled/expected but its report file was absent from the uploaded artifacts.`,
    remediation: `Inspect the "${scannerName}" job in the most recent security-framework run for this repo (install failure, timeout, Docker/registry issue, or a workflow-config problem) and re-run once fixed.`,
    security_category: "Infrastructure",
    metadata: { kind: "missing-control", scanner: scannerName },
  };
}

async function main() {
  const files = await readdir(REPORTS_DIR).catch(() => []);
  const scannerResults = [];
  let allFindings = [];
  const appId = process.env.MC_APPLICATION_ID || process.env.REPO_NAME || "unknown";
  const scanUrlConfigured = Boolean(process.env.SCAN_URL);
  const supabaseEnabled = process.env.SUPABASE_ENABLED === "true";
  const nucleiEnabled = process.env.ENABLE_NUCLEI !== "false"; // reusable workflow defaults to true
  const nmapEnabled = process.env.ENABLE_NMAP === "true"; // reusable workflow defaults to false
  const codeUnchanged = process.env.CODE_UNCHANGED === "true"; // source/dependency scanners were deliberately skipped this run

  function recordMissing(scannerName) {
    scannerResults.push({ scanner: scannerName, status: "failed", duration_ms: null });
    allFindings.push(missingControlFinding(scannerName, appId));
  }

  // Trivy's Docker-image scan (only present when the repo has a Dockerfile) reuses the same
  // normalizeTrivy shape but is a distinct scanner-result entry from the filesystem scan, and
  // is legitimately absent for repos with no Dockerfile -- excluded from missing-control checks.
  const specs = [
    { file: "gitleaks.json", name: "gitleaks", normalize: normalizeGitleaks, alwaysExpected: true, skippable: true },
    { file: "semgrep.json", name: "semgrep", normalize: normalizeSemgrep, alwaysExpected: true, skippable: true },
    { file: "trivy.json", name: "trivy", normalize: normalizeTrivy, alwaysExpected: true, skippable: true },
    { file: "trivy-image.json", name: "trivy-image", normalize: normalizeTrivy, alwaysExpected: false, skippable: true },
    { file: "npm-audit.json", name: "npm-audit", normalize: normalizeNpmAudit, alwaysExpected: false, skippable: true },
    { file: "supabase-check.json", name: "supabase", normalize: normalizeSupabase, alwaysExpected: false, expectedIf: () => supabaseEnabled, skippable: true },
    { file: "zap-baseline.json", name: "zap", normalize: normalizeZap, alwaysExpected: false, expectedIf: () => scanUrlConfigured },
  ];

  for (const spec of specs) {
    const failedMarker = files.includes(`${spec.name}.failed`);
    if (failedMarker) {
      recordMissing(spec.name);
      continue;
    }
    if (!files.includes(spec.file)) {
      // Deliberately skipped because a prior successful daily scan already covered
      // this exact commit (see check-previous-scan) -- not a missing-control gap.
      // Existing findings from this scanner simply aren't resubmitted; the ingest
      // endpoint only upserts what's present in a payload, it never deletes/closes
      // findings absent from one, so their state (open/fixed/accepted_risk/etc) is
      // untouched rather than duplicated or wiped.
      if (spec.skippable && codeUnchanged) continue;
      const expected = spec.alwaysExpected || (spec.expectedIf && spec.expectedIf());
      if (expected) recordMissing(spec.name);
      continue;
    }
    const raw = await readJsonIfExists(path.join(REPORTS_DIR, spec.file));
    const { findings, status } = spec.normalize(raw);
    scannerResults.push({ scanner: spec.name, status });
    allFindings.push(...findings);
  }

  // dependency-audit.json needs its manager marker to pick the right normalizer (npm/pnpm
  // share a shape; yarn is line-delimited; pip-audit is its own OSV-derived shape). Always
  // expected -- every repo in this fleet has a lockfile of some kind.
  if (files.includes("dependency-audit.json")) {
    const manager = (await readFile(path.join(REPORTS_DIR, "dependency-audit.manager"), "utf8").catch(() => "npm")).trim();
    const scannerName = { npm: "npm-audit", pnpm: "pnpm-audit", yarn: "yarn-audit", bun: "bun-audit", "pip-audit": "pip-audit" }[manager] || "npm-audit";
    if (files.includes(`${scannerName}.failed`)) {
      recordMissing(scannerName);
    } else {
      const { findings, status } = await normalizeDependencyAudit(REPORTS_DIR, manager);
      scannerResults.push({ scanner: scannerName, status });
      allFindings.push(...findings);
    }
  } else if (!codeUnchanged) {
    recordMissing("dependency-audit");
  }

  if (files.includes("nuclei.jsonl")) {
    const raw = await readFile(path.join(REPORTS_DIR, "nuclei.jsonl"), "utf8").catch(() => "");
    const { findings, status } = normalizeNuclei(raw);
    scannerResults.push({ scanner: "nuclei", status });
    allFindings.push(...findings);
  } else if (scanUrlConfigured && nucleiEnabled) {
    recordMissing("nuclei");
  }

  if (files.includes("nmap.xml")) {
    const raw = await readFile(path.join(REPORTS_DIR, "nmap.xml"), "utf8").catch(() => "");
    let hostHint = null;
    try {
      hostHint = process.env.SCAN_URL ? new URL(process.env.SCAN_URL).hostname : null;
    } catch {
      hostHint = null;
    }
    const { findings, status } = normalizeNmap(raw, hostHint);
    scannerResults.push({ scanner: "nmap", status });
    allFindings.push(...findings);
  } else if (scanUrlConfigured && nmapEnabled) {
    recordMissing("nmap");
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of allFindings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const payload = {
    repository: { owner: process.env.REPO_OWNER, name: process.env.REPO_NAME, provider: "github" },
    application_id: process.env.MC_APPLICATION_ID || process.env.REPO_NAME,
    environment: process.env.SCAN_ENVIRONMENT || "ci",
    scan_type: process.env.SCAN_TYPE || "manual",
    commit_sha: process.env.COMMIT_SHA || null,
    branch: process.env.BRANCH || null,
    github_run_id: process.env.GITHUB_RUN_ID || null,
    github_run_url: process.env.GITHUB_RUN_URL || null,
    started_at: process.env.SCAN_STARTED_AT || new Date(0).toISOString(),
    completed_at: new Date().toISOString(),
    scanner_results: scannerResults,
    counts,
    findings: allFindings,
  };

  const outFile = path.join(REPORTS_DIR, "normalized-payload.json");
  await import("node:fs/promises").then((fs) => fs.writeFile(outFile, JSON.stringify(payload, null, 2)));
  console.log(`Normalized ${allFindings.length} findings from ${scannerResults.length} scanners -> ${outFile}`);
  console.log(`Counts: ${JSON.stringify(counts)}`);

  const url = process.env.MC_SECURITY_URL;
  const token = process.env.MISSION_CONTROL_SECURITY_TOKEN;
  if (!url || !token) {
    console.log("MC_SECURITY_URL or MISSION_CONTROL_SECURITY_TOKEN not set — skipping submission (normalized report still saved as an artifact).");
    return;
  }

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(60_000),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    console.error(`Mission Control ingestion failed: ${res.status} ${body.slice(0, 1000)}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Submitted to Mission Control: ${res.status}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
