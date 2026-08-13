#!/usr/bin/env node
// Normalizes raw scanner output (Gitleaks/Semgrep/Trivy/npm audit/Supabase check) into
// Mission Control's ingestion payload shape and POSTs it to /api/security/scans.
//
// Env vars (all required unless noted):
//   MC_SECURITY_URL             e.g. https://missioncontrol.distinct-app.com/api/security/scans
//   MISSION_CONTROL_SECURITY_TOKEN
//   MC_APPLICATION_ID           loose text id matching mc_repositories.application_id convention
//   REPO_OWNER, REPO_NAME
//   SCAN_TYPE                   pr | weekly | manual
//   SCAN_STARTED_AT             ISO timestamp
//   COMMIT_SHA, BRANCH          (optional)
//   GITHUB_RUN_ID, GITHUB_RUN_URL (optional)
//   REPORTS_DIR                 directory containing raw scanner output (default: .security-reports)
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

// ---- npm audit ----
function normalizeNpmAudit(report) {
  const vulns = report?.vulnerabilities;
  if (!vulns) return { findings: [], status: "passed" };
  const findings = Object.entries(vulns).map(([name, v]) => ({
    scanner: "npm-audit",
    external_finding_id: `${name}@${v.range}`,
    fingerprint: fingerprint(["npm-audit", name, v.range]),
    severity: clampSeverity(v.severity),
    original_severity: v.severity,
    title: `Vulnerable dependency: ${name}`,
    description: (v.via || []).filter((x) => typeof x === "object").map((x) => x.title).join("; "),
    security_category: "Dependencies",
    package_name: name,
    package_version: v.range,
    remediation: v.fixAvailable ? "Fix available — run npm audit fix" : "No automatic fix available yet",
    metadata: {},
  }));
  return { findings, status: findings.length ? "findings" : "passed" };
}

// ---- Supabase static check (already normalized by supabase-check.mjs) ----
function normalizeSupabase(report) {
  if (!Array.isArray(report?.findings)) return { findings: [], status: "passed" };
  return { findings: report.findings, status: report.findings.length ? "findings" : "passed" };
}

// ---- ZAP baseline ----
function normalizeZap(report) {
  const alerts = report?.site?.[0]?.alerts;
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

async function main() {
  const files = await readdir(REPORTS_DIR).catch(() => []);
  const scannerResults = [];
  let allFindings = [];

  const specs = [
    { file: "gitleaks.json", name: "gitleaks", normalize: normalizeGitleaks },
    { file: "semgrep.json", name: "semgrep", normalize: normalizeSemgrep },
    { file: "trivy.json", name: "trivy", normalize: normalizeTrivy },
    { file: "npm-audit.json", name: "npm-audit", normalize: normalizeNpmAudit },
    { file: "supabase-check.json", name: "supabase", normalize: normalizeSupabase },
    { file: "zap-baseline.json", name: "zap", normalize: normalizeZap },
  ];

  for (const spec of specs) {
    if (!files.includes(spec.file)) continue;
    const raw = await readJsonIfExists(path.join(REPORTS_DIR, spec.file));
    const failedMarker = files.includes(`${spec.name}.failed`);
    if (failedMarker) {
      scannerResults.push({ scanner: spec.name, status: "failed", duration_ms: null });
      continue;
    }
    const { findings, status } = normalize(spec, raw);
    scannerResults.push({ scanner: spec.name, status });
    allFindings.push(...findings);
  }

  function normalize(spec, raw) {
    return spec.normalize(raw);
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
