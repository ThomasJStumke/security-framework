#!/usr/bin/env node
// Static code inventory for Mission Control's /analytics page.
//
// Walks a repo's src/ tree and emits one record per page/route/api-route and per
// exported function/hook/component, tagged with the URL path where it can be
// worked out from the file location (TanStack Start / Next-style route files).
// Zero dependencies — plain fs + light source scanning. Knip's JSON output (if
// present at $KNIP_JSON) is folded in to mark unreferenced exports as dead.
//
// Env:
//   REPO_DIR      repo root (default: cwd)
//   KNIP_JSON     path to `knip --reporter json` output (optional)
//   OUT           output file (default: .perf-reports/inventory.json)
//
// Output: { symbols: [ { symbol_path, kind, name, file_path, http_path,
//                        is_referenced, is_dead } ] }

import { readFile, readdir, writeFile, mkdir, stat } from "node:fs/promises";
import path from "node:path";

const REPO_DIR = process.env.REPO_DIR || process.cwd();
const OUT = process.env.OUT || ".perf-reports/inventory.json";
const SRC = path.join(REPO_DIR, "src");

const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx"]);
const IGNORE_DIR = new Set(["node_modules", ".git", "dist", "build", ".output", "coverage", "__tests__"]);

async function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".") continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (IGNORE_DIR.has(e.name)) continue;
      out.push(...(await walk(full)));
    } else if (CODE_EXT.has(path.extname(e.name)) && !/\.(test|spec|d)\.[tj]sx?$/.test(e.name)) {
      out.push(full);
    }
  }
  return out;
}

// Derive a URL path from a routes-directory file path, TanStack-Start-style:
//   src/routes/_authenticated/performance.index.tsx  -> /performance
//   src/routes/_authenticated/performance.$id.tsx    -> /performance/$id
//   src/routes/api/analytics/hit.ts                  -> /api/analytics/hit
//   src/pages/dashboard.tsx (Next pages)             -> /dashboard
function httpPathFor(rel) {
  let m = rel.match(/^src\/routes\/(.+)\.[tj]sx?$/);
  let isApi = false;
  if (!m) {
    m = rel.match(/^src\/pages\/(.+)\.[tj]sx?$/);
    if (!m) {
      m = rel.match(/^(?:src\/)?app\/(.+)\/(?:page|route)\.[tj]sx?$/);
      if (!m) return null;
    }
  }
  let p = m[1];
  if (p.startsWith("api/")) isApi = true;
  p = p
    .replace(/(^|\/)_[^/.]+/g, "") // pathless layout segments (_authenticated)
    .replace(/\.route$/, "")
    .replace(/\.index$/, "")
    .replace(/\/index$/, "")
    .replace(/\./g, "/"); // TanStack flat-route dots -> slashes
  p = "/" + p.replace(/^\/+/, "").replace(/\/+$/, "");
  if (p === "/") p = isApi ? "/api" : "/";
  return { httpPath: p, isApi };
}

function kindForRoute(rel, isApi) {
  if (isApi) return "api-route";
  return "page";
}

// Very light export scan — good enough for an inventory, not a compiler.
function scanExports(src) {
  const found = [];
  const patterns = [
    { re: /export\s+(?:async\s+)?function\s+([A-Za-z0-9_]+)/g, kind: "function" },
    { re: /export\s+const\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(/g, kind: "function" },
    { re: /export\s+const\s+([A-Za-z0-9_]+)\s*=\s*(?:React\.)?(?:forwardRef|memo)\s*\(/g, kind: "component" },
  ];
  for (const { re, kind } of patterns) {
    let mm;
    while ((mm = re.exec(src))) {
      const name = mm[1];
      let k = kind;
      if (/^use[A-Z]/.test(name)) k = "hook";
      else if (/^[A-Z]/.test(name) && kind === "function") k = "component";
      found.push({ name, kind: k });
    }
  }
  // de-dup by name
  const seen = new Set();
  return found.filter((f) => (seen.has(f.name) ? false : seen.add(f.name)));
}

async function loadKnipDead() {
  const p = process.env.KNIP_JSON;
  if (!p) return { files: new Set(), exports: new Map() };
  try {
    const raw = JSON.parse(await readFile(p, "utf8"));
    const files = new Set((raw.files ?? []).map((f) => f.replace(/^\.\//, "")));
    const exports = new Map();
    for (const issue of raw.issues ?? []) {
      const file = (issue.file ?? "").replace(/^\.\//, "");
      const names = [
        ...(issue.exports ?? []).map((e) => e.name ?? e),
        ...(issue.types ?? []).map((e) => e.name ?? e),
      ];
      if (names.length) exports.set(file, new Set(names));
    }
    return { files, exports };
  } catch {
    return { files: new Set(), exports: new Map() };
  }
}

async function main() {
  try {
    await stat(SRC);
  } catch {
    console.error(`No src/ directory at ${SRC} — emitting empty inventory.`);
    await mkdir(path.dirname(path.join(REPO_DIR, OUT)), { recursive: true });
    await writeFile(path.join(REPO_DIR, OUT), JSON.stringify({ symbols: [] }, null, 2));
    return;
  }

  const dead = await loadKnipDead();
  const files = await walk(SRC);
  const symbols = [];

  for (const abs of files) {
    const rel = path.relative(REPO_DIR, abs).split(path.sep).join("/");
    let src = "";
    try {
      src = await readFile(abs, "utf8");
    } catch {
      continue;
    }

    const routeInfo = httpPathFor(rel);
    const fileIsDead = dead.files.has(rel);
    const deadExports = dead.exports.get(rel) ?? new Set();

    if (routeInfo) {
      symbols.push({
        symbol_path: rel,
        kind: kindForRoute(rel, routeInfo.isApi),
        name: routeInfo.httpPath,
        file_path: rel,
        http_path: routeInfo.httpPath,
        is_referenced: !fileIsDead,
        is_dead: fileIsDead,
      });
    }

    for (const ex of scanExports(src)) {
      // Skip the route component itself — already represented by the route row.
      if (routeInfo && (ex.name === "Route" || ex.name === "loader" || ex.name === "action")) continue;
      symbols.push({
        symbol_path: `${rel}#${ex.name}`,
        kind: ex.kind,
        name: ex.name,
        file_path: rel,
        http_path: null,
        is_referenced: !fileIsDead && !deadExports.has(ex.name),
        is_dead: fileIsDead || deadExports.has(ex.name),
      });
    }
  }

  await mkdir(path.dirname(path.join(REPO_DIR, OUT)), { recursive: true });
  await writeFile(path.join(REPO_DIR, OUT), JSON.stringify({ symbols }, null, 2));
  console.log(`Inventory: ${symbols.length} symbols (${symbols.filter((s) => s.is_dead).length} dead) -> ${OUT}`);
}

main();
