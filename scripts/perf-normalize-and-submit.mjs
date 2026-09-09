#!/usr/bin/env node
// Normalizes Lighthouse CI / size-limit / Knip / Playwright output into Mission
// Control's performance-run payload and POSTs it to /api/performance/runs, then
// POSTs the code inventory to /api/analytics/inventory.
//
// Env (required unless noted):
//   MC_PERFORMANCE_URL           e.g. https://missioncontrol.distinct-app.com/api/performance/runs
//   MISSION_CONTROL_SECURITY_TOKEN
//   MC_APPLICATION_ID
//   REPO_OWNER, REPO_NAME
//   PERF_REPORTS_DIR             default .perf-reports
//   TARGET_URL                   (optional) the URL Lighthouse ran against
//   COMMIT_SHA, BRANCH, GITHUB_RUN_ID, GITHUB_RUN_URL (optional)
//   PERF_STARTED_AT              ISO timestamp (optional)

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const DIR = process.env.PERF_REPORTS_DIR || ".perf-reports";
const RUNS_URL = process.env.MC_PERFORMANCE_URL;
const INVENTORY_URL = RUNS_URL ? RUNS_URL.replace(/\/api\/performance\/runs$/, "/api/analytics/inventory") : "";
const TOKEN = process.env.MISSION_CONTROL_SECURITY_TOKEN;
const APP_ID = process.env.MC_APPLICATION_ID;

async function readJson(file) {
  try {
    return JSON.parse(await readFile(path.join(DIR, file), "utf8"));
  } catch {
    return null;
  }
}

async function readLhci() {
  // @lhci/cli writes one or more lhr-*.json + a manifest.json into .lighthouseci/
  const lhciDir = ".lighthouseci";
  let files = [];
  try {
    files = (await readdir(lhciDir)).filter((f) => /^lhr-.*\.json$/.test(f));
  } catch {
    return null;
  }
  if (!files.length) return null;
  const runs = [];
  for (const f of files) {
    try {
      runs.push(JSON.parse(await readFile(path.join(lhciDir, f), "utf8")));
    } catch {
      /* skip */
    }
  }
  if (!runs.length) return null;
  const median = (arr) => {
    const s = [...arr].filter((n) => typeof n === "number").sort((a, b) => a - b);
    return s.length ? s[Math.floor(s.length / 2)] : null;
  };
  const cat = (r, k) => Math.round((r.categories?.[k]?.score ?? 0) * 100);
  const audit = (r, k) => r.audits?.[k]?.numericValue ?? null;
  return {
    performance: median(runs.map((r) => cat(r, "performance"))),
    accessibility: median(runs.map((r) => cat(r, "accessibility"))),
    best_practices: median(runs.map((r) => cat(r, "best-practices"))),
    seo: median(runs.map((r) => cat(r, "seo"))),
    lcp_ms: Math.round(median(runs.map((r) => audit(r, "largest-contentful-paint"))) ?? 0) || null,
    tbt_ms: Math.round(median(runs.map((r) => audit(r, "total-blocking-time"))) ?? 0) || null,
    cls: median(runs.map((r) => audit(r, "cumulative-layout-shift"))),
    fcp_ms: Math.round(median(runs.map((r) => audit(r, "first-contentful-paint"))) ?? 0) || null,
    si_ms: Math.round(median(runs.map((r) => audit(r, "speed-index"))) ?? 0) || null,
  };
}

function parseSizeLimit(raw, prev) {
  if (!Array.isArray(raw) || !raw.length) return null;
  const total = raw.reduce((s, e) => s + (e.size ?? 0), 0);
  const budget = raw.reduce((s, e) => s + (e.sizeLimit ?? e.limit ?? 0), 0) || null;
  let delta = null;
  if (Array.isArray(prev) && prev.length) {
    const prevTotal = prev.reduce((s, e) => s + (e.size ?? 0), 0);
    delta = total - prevTotal;
  }
  return { bytes_gzip: total, budget_bytes: budget, delta_bytes: delta };
}

function parseKnip(raw) {
  if (!raw) return null;
  const count = (key) =>
    (raw.issues ?? []).reduce((s, i) => s + (Array.isArray(i[key]) ? i[key].length : 0), 0);
  return {
    unused_files: Array.isArray(raw.files) ? raw.files.length : count("files"),
    unused_exports: count("exports"),
    unused_deps:
      (Array.isArray(raw.dependencies) ? raw.dependencies.length : 0) + count("dependencies"),
    unused_types: count("types"),
  };
}

function parsePlaywright(raw) {
  if (!raw) return null;
  const steps = [];
  let status = "passed";
  const walkSuite = (suite) => {
    for (const spec of suite.specs ?? []) {
      for (const test of spec.tests ?? []) {
        const result = test.results?.[test.results.length - 1];
        const st = result?.status === "passed" ? "passed" : result?.status === "skipped" ? "skipped" : "failed";
        if (st === "failed") status = "failed";
        steps.push({ name: spec.title, status: st, duration_ms: result?.duration ?? null });
      }
    }
    for (const child of suite.suites ?? []) walkSuite(child);
  };
  for (const s of raw.suites ?? []) walkSuite(s);
  if (!steps.length) return null;
  return {
    status,
    duration_ms: steps.reduce((s, x) => s + (x.duration_ms ?? 0), 0),
    steps,
  };
}

async function post(url, body) {
  if (!url || !TOKEN) {
    console.log(`Skipping POST to ${url || "(no url)"} — missing url or token.`);
    return;
  }
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    console.error(`POST ${url} -> ${res.status}: ${await res.text()}`);
    process.exitCode = 1;
  } else {
    console.log(`POST ${url} -> ${res.status}`);
  }
}

async function main() {
  if (!APP_ID) {
    console.error("MC_APPLICATION_ID is required.");
    process.exit(1);
  }

  const lighthouse = await readLhci();
  const sizeRaw = await readJson("size-limit.json");
  const sizePrev = await readJson("size-limit.prev.json");
  const knipRaw = await readJson("knip.json");
  const pwRaw = await readJson("playwright-report.json");
  const inventory = await readJson("inventory.json");

  const anyMissing = [lighthouse, sizeRaw, knipRaw].some((x) => x == null);

  const payload = {
    repository:
      process.env.REPO_OWNER && process.env.REPO_NAME
        ? { owner: process.env.REPO_OWNER, name: process.env.REPO_NAME, provider: "github" }
        : null,
    application_id: APP_ID,
    environment: process.env.TARGET_URL ? "production" : "ci",
    target_url: process.env.TARGET_URL || null,
    commit_sha: process.env.COMMIT_SHA || null,
    branch: process.env.BRANCH || null,
    github_run_id: process.env.GITHUB_RUN_ID || null,
    github_run_url: process.env.GITHUB_RUN_URL || null,
    status: anyMissing ? "partial" : "completed",
    started_at: process.env.PERF_STARTED_AT || new Date().toISOString(),
    completed_at: new Date().toISOString(),
    lighthouse,
    bundle: parseSizeLimit(sizeRaw, sizePrev),
    knip: parseKnip(knipRaw),
    playwright: parsePlaywright(pwRaw),
    metadata: {},
  };

  await post(RUNS_URL, payload);

  if (inventory?.symbols?.length) {
    await post(INVENTORY_URL, {
      repository: payload.repository,
      application_id: APP_ID,
      commit_sha: payload.commit_sha,
      symbols: inventory.symbols,
    });
  }
}

main();
