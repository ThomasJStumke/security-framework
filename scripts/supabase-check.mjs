#!/usr/bin/env node
// Best-effort static Supabase/RLS review. Reads supabase/migrations/*.sql and src/**
// looking for the most common RLS/service-role mistakes. This is a heuristic linter,
// not a live database connection — it cannot see policies applied outside migration
// files (e.g. via the dashboard) and can misparse unusual SQL. Findings should be
// triaged by a human, not treated as ground truth. See security/CLAUDE_SECURITY_REVIEW.md.
//
// Usage: node supabase-check.mjs <repo-root> <output-file>

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const repoRoot = process.argv[2] || ".";
const outFile = process.argv[3] || ".security-reports/supabase-check.json";

async function walk(dir, filter, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) await walk(full, filter, out);
    else if (filter(e.name)) out.push(full);
  }
  return out;
}

function fingerprint(parts) {
  const key = parts.filter(Boolean).join("|");
  let hash = 0n;
  for (const ch of Buffer.from(key, "utf8")) hash = (hash * 31n + BigInt(ch)) & 0xffffffffffffffffn;
  return hash.toString(16).padStart(16, "0");
}

// Strips `--` line comments before any SQL is regex-matched. Without this, narrative
// comment text like "...CREATE TABLE IF NOT EXISTS never actually ran..." gets misread
// as a real CREATE TABLE statement. Best-effort: doesn't account for `--` inside a
// string literal, which is rare enough in migration SQL to accept.
function stripSqlComments(sql) {
  return sql
    .split("\n")
    .map((line) => {
      const idx = line.indexOf("--");
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join("\n");
}

async function main() {
  const findings = [];
  const migrationsDir = path.join(repoRoot, "supabase", "migrations");
  const sqlFiles = await walk(migrationsDir, (n) => n.endsWith(".sql"));

  if (sqlFiles.length === 0) {
    await writeOut([]);
    return;
  }

  const tablesCreated = new Map(); // table -> file
  const rlsEnabled = new Set();
  const policiesByTable = new Map(); // table -> Set of commands ('select'|'insert'|'update'|'delete'|'all')
  const securityDefinerFns = [];

  for (const file of sqlFiles) {
    const sql = stripSqlComments(await readFile(file, "utf8"));
    const rel = path.relative(repoRoot, file);

    for (const m of sql.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?["`]?(\w+)["`]?/gi)) {
      tablesCreated.set(m[1], rel);
    }
    for (const m of sql.matchAll(/alter\s+table\s+(?:public\.)?["`]?(\w+)["`]?\s+enable\s+row\s+level\s+security/gi)) {
      rlsEnabled.add(m[1]);
    }
    for (const m of sql.matchAll(/create\s+policy\s+.+?\s+on\s+(?:public\.)?["`]?(\w+)["`]?([\s\S]*?);/gi)) {
      const table = m[1];
      const body = m[2].toLowerCase();
      const cmdMatch = body.match(/for\s+(select|insert|update|delete|all)/);
      const cmd = cmdMatch ? cmdMatch[1] : "all";
      if (!policiesByTable.has(table)) policiesByTable.set(table, new Set());
      policiesByTable.get(table).add(cmd);

      if (/using\s*\(\s*true\s*\)/.test(body) || /with\s+check\s*\(\s*true\s*\)/.test(body)) {
        findings.push({
          scanner: "supabase-check",
          fingerprint: fingerprint(["supabase-permissive-policy", table, cmd, rel]),
          severity: "high",
          title: `Overly permissive RLS policy on "${table}"`,
          description: `A policy on "${table}" uses USING (true) or WITH CHECK (true) for ${cmd.toUpperCase()}, allowing any authenticated (or anonymous, depending on role grants) request through with no row-level restriction.`,
          security_category: "Supabase/RLS",
          file_path: rel,
          remediation: "Confirm this table is genuinely intended to be fully public for this operation. If not, scope the policy to the owning user/organization/tenant.",
          metadata: { table, command: cmd },
        });
      }
    }
    for (const m of sql.matchAll(/create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?["`]?(\w+)["`]?[\s\S]{0,500}?security\s+definer/gi)) {
      securityDefinerFns.push({ name: m[1], file: rel });
    }
  }

  for (const [table, file] of tablesCreated) {
    if (!rlsEnabled.has(table)) {
      findings.push({
        scanner: "supabase-check",
        fingerprint: fingerprint(["supabase-no-rls", table]),
        severity: "critical",
        title: `Table "${table}" has no RLS enabled`,
        description: `No "ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY" was found across scanned migrations. If this table is reachable by the anon or authenticated Postgres role, its rows may be fully readable/writable by any client holding the anon key.`,
        security_category: "Supabase/RLS",
        file_path: file,
        remediation: "Enable RLS and add explicit policies, or confirm this table is intentionally service-role-only and never exposed to PostgREST/the browser.",
        metadata: { table },
      });
      continue;
    }
    const cmds = policiesByTable.get(table) || new Set();
    if (cmds.size === 0) {
      findings.push({
        scanner: "supabase-check",
        fingerprint: fingerprint(["supabase-rls-no-policies", table]),
        severity: "high",
        title: `Table "${table}" has RLS enabled but no policies found`,
        description: `RLS is enabled on "${table}" but no CREATE POLICY statement was found in scanned migrations, which — unless policies were added outside migrations — means all access is denied by default (fail-closed) or the table is genuinely unreachable.`,
        security_category: "Supabase/RLS",
        file_path: file,
        remediation: "If this table should be readable/writable, add explicit policies. If access is intentionally service-role only, no action needed — verify manually.",
        metadata: { table },
      });
    } else if (!cmds.has("all")) {
      for (const cmd of ["select", "insert", "update", "delete"]) {
        if (!cmds.has(cmd)) {
          findings.push({
            scanner: "supabase-check",
            fingerprint: fingerprint(["supabase-missing-policy", table, cmd]),
            severity: "informational",
            title: `Table "${table}" has no ${cmd.toUpperCase()} policy`,
            description: `RLS is enabled and other commands have policies, but no ${cmd.toUpperCase()} policy was found — that operation is denied by default for non-service-role clients. This may be intentional.`,
            security_category: "Supabase/RLS",
            file_path: file,
            metadata: { table, command: cmd },
          });
        }
      }
    }
  }

  for (const fn of securityDefinerFns) {
    findings.push({
      scanner: "supabase-check",
      fingerprint: fingerprint(["supabase-security-definer", fn.name]),
      severity: "informational",
      title: `Review SECURITY DEFINER function "${fn.name}"`,
      description: "SECURITY DEFINER functions run with the privileges of their owner (often bypassing RLS). Confirm this function validates auth.uid()/tenant scoping internally rather than trusting caller-supplied IDs.",
      security_category: "Supabase/RLS",
      file_path: fn.file,
      metadata: { function: fn.name },
    });
  }

  // Client-side service-role exposure check — scan non-.server.ts/.server.tsx source files.
  // Excludes test files (never shipped to the browser, and commonly reference "service_role"
  // in mock SQL/descriptions when testing that a bypass is blocked) and known framework
  // server-entry filenames that don't follow the *.server.ts convention but are never
  // bundled client-side either (e.g. TanStack Start's src/server.ts SSR bootstrap).
  const FRAMEWORK_SERVER_ENTRY_PATHS = new Set(["src/server.ts", "src/server.tsx", "src/start.ts", "src/start.tsx"]);
  const isTestFile = (relPath) => /\.(test|spec)\.[jt]sx?$/.test(relPath) || /(^|\/)__tests__\//.test(relPath);
  const srcDir = path.join(repoRoot, "src");
  const clientFiles = await walk(
    srcDir,
    (n) => (n.endsWith(".ts") || n.endsWith(".tsx") || n.endsWith(".js") || n.endsWith(".jsx")) && !n.includes(".server."),
  );
  for (const file of clientFiles) {
    const rel = path.relative(repoRoot, file).replace(/\\/g, "/");
    if (isTestFile(rel) || FRAMEWORK_SERVER_ENTRY_PATHS.has(rel)) continue;
    const content = await readFile(file, "utf8").catch(() => "");
    if (/service_role/i.test(content) || /SUPABASE_SERVICE_ROLE_KEY/.test(content)) {
      findings.push({
        scanner: "supabase-check",
        fingerprint: fingerprint(["supabase-service-role-in-client", path.relative(repoRoot, file)]),
        severity: "critical",
        title: "Possible service-role key reference in client-side code",
        description: `"${path.relative(repoRoot, file)}" is not a *.server.ts file but references "service_role" or SUPABASE_SERVICE_ROLE_KEY. If this file ships to the browser, the service-role key (which bypasses RLS entirely) could be exposed.`,
        security_category: "Secrets",
        cwe: "CWE-798",
        file_path: path.relative(repoRoot, file),
        remediation: "Move service-role usage into a *.server.ts file / server-only module that never bundles into client JS.",
        metadata: {},
      });
    }
  }

  await writeOut(findings);

  async function writeOut(list) {
    const fs = await import("node:fs/promises");
    await fs.mkdir(path.dirname(outFile), { recursive: true });
    await fs.writeFile(outFile, JSON.stringify({ findings: list }, null, 2));
    console.log(`Supabase static check: ${list.length} findings -> ${outFile}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
