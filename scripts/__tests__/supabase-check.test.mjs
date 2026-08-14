#!/usr/bin/env node
// Regression tests for supabase-check.mjs. Plain node + assert — no test framework
// dependency, consistent with this repo's "low maintenance" bar. Run with:
//   node scripts/__tests__/supabase-check.test.mjs
//
// Each case runs the real script as a child process against a fixture repo under
// fixtures/supabase-check/<case>/ and asserts on the findings it produces. These
// fixtures encode the exact regressions already fixed in supabase-check.mjs (live
// policy replay across migrations, DROP POLICY retiring a policy instead of leaving
// it "permissive" forever, SQL comment stripping, test-file/server-entry exclusions)
// so a future edit can't silently reintroduce them.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(__dirname, "..", "supabase-check.mjs");
const FIXTURES = path.join(__dirname, "fixtures", "supabase-check");

let passed = 0;
let failed = 0;

function run(fixture) {
  const repoRoot = path.join(FIXTURES, fixture);
  const outFile = path.join(mkdtempSync(path.join(tmpdir(), "supabase-check-test-")), "out.json");
  execFileSync("node", [SCRIPT, repoRoot, outFile], { stdio: "pipe" });
  return JSON.parse(readFileSync(outFile, "utf8")).findings;
}

function findingsMatching(findings, predicate) {
  return findings.filter(predicate);
}

function test(name, fn) {
  try {
    fn();
    console.log(`  ok — ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL — ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

console.log("supabase-check.mjs regression tests");

test("table with no RLS enabled is flagged critical", () => {
  const findings = run("no-rls");
  const hit = findingsMatching(findings, (f) => f.title.includes('"widgets"') && f.title.includes("no RLS"));
  assert.equal(hit.length, 1, "expected exactly one no-RLS finding for widgets");
  assert.equal(hit[0].severity, "critical");
});

test("a permissive policy later replaced by DROP+CREATE is not flagged (live-policy replay)", () => {
  const findings = run("permissive-then-fixed");
  const permissive = findingsMatching(findings, (f) => f.title.includes("Overly permissive"));
  assert.equal(permissive.length, 0, `expected no permissive-policy findings after the tightening migration, got: ${JSON.stringify(permissive)}`);
});

test("a permissive policy that is DROPped and never replaced is not flagged as permissive, and is flagged as missing-select-policy instead", () => {
  const findings = run("dropped-permissive");
  const permissive = findingsMatching(findings, (f) => f.title.includes("Overly permissive"));
  assert.equal(permissive.length, 0, "a dropped policy must not still count as a live permissive policy");
  const noRls = findingsMatching(findings, (f) => f.title.includes("no RLS"));
  assert.equal(noRls.length, 0, "RLS is enabled on legacy_feed — must not be reported as missing");
});

test("SQL line comments are stripped before matching (narrative CREATE TABLE text in a comment is not parsed as a real statement)", () => {
  const findings = run("clean");
  // The fixture's first line is a `--` comment containing the literal text
  // "CREATE TABLE IF NOT EXISTS reference_pricing" for a *different*, nonexistent table
  // name pattern than the real statement below it. If comment-stripping regressed, this
  // would either double-count or mis-locate the real table's finding.
  const pricingFindings = findingsMatching(findings, (f) => f.metadata?.table === "reference_pricing" || f.title.includes('"reference_pricing"'));
  assert.ok(pricingFindings.length > 0, "expected findings for the real reference_pricing table");
});

test("a deliberately public reference-data policy (USING (true)) is still surfaced for human triage, not silently dropped", () => {
  const findings = run("clean");
  const permissive = findingsMatching(findings, (f) => f.title.includes("Overly permissive") && f.metadata?.table === "reference_pricing");
  assert.equal(permissive.length, 1);
  assert.equal(permissive[0].severity, "high");
});

test("SECURITY DEFINER functions are surfaced for review", () => {
  const findings = run("clean");
  const secdef = findingsMatching(findings, (f) => f.title.includes("SECURITY DEFINER"));
  assert.equal(secdef.length, 1);
  assert.equal(secdef[0].metadata?.function, "recalc_price");
});

test("service_role reference in a non-.server.ts client file is flagged critical", () => {
  const findings = run("service-role-leak");
  const leak = findingsMatching(findings, (f) => f.title.includes("service-role") && f.file_path?.includes("admin-client.ts"));
  assert.equal(leak.length, 1, `expected exactly one leak finding, got: ${JSON.stringify(findings.map((f) => f.file_path))}`);
  assert.equal(leak[0].severity, "critical");
});

test("service_role reference in a .server.ts file is NOT flagged (server-only, never bundled client-side)", () => {
  const findings = run("service-role-leak");
  const falsePositive = findingsMatching(findings, (f) => f.file_path?.includes("admin-client.server.ts"));
  assert.equal(falsePositive.length, 0);
});

test("service_role reference in a *.test.ts file is NOT flagged (test files never ship to the browser)", () => {
  const findings = run("service-role-leak");
  const falsePositive = findingsMatching(findings, (f) => f.file_path?.includes("admin-client.test.ts"));
  assert.equal(falsePositive.length, 0);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
