#!/usr/bin/env node
// Zero-dependency stand-in for `size-limit --json`, used when a repo has a .size-limit.json but does not
// depend on size-limit itself (size-limit only resolves its plugins from the project's own node_modules, so
// `npx size-limit` cannot work in a repo that never installed it). Reads the same file format:
//   [{ "name": "...", "path": "dist/client/assets/*.js", "limit": "3 MB", "gzip": true }]
// and prints size-limit's JSON shape: [{ "name", "size", "sizeLimit" }] (bytes). `gzip: true` is the default.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { join, relative } from "node:path";

const UNITS = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 };
export function parseLimit(v) {
  if (typeof v === "number") return v;
  const m = String(v ?? "")
    .trim()
    .match(/^([\d.]+)\s*([a-z]+)?$/i);
  if (!m) return null;
  return Math.round(Number(m[1]) * (UNITS[(m[2] ?? "b").toLowerCase()] ?? 1));
}

export function globToRegExp(glob) {
  const g = glob.replace(/^\.\//, "");
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*" && g[i + 1] === "*") {
      re += ".*";
      i++;
      if (g[i + 1] === "/") i++;
    } else if (c === "*") re += "[^/]*";
    else re += c.replace(/[.+^${}()|[\]\\?]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

function walk(dir, out = []) {
  let names = [];
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of names) {
    if (name === "node_modules" || name === ".git") continue;
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue; // broken symlink etc.
    }
    if (st.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

// Directory part of a glob before its first wildcard -- the only place worth walking.
function staticBase(glob) {
  const g = glob.replace(/^\.\//, "");
  const cut = g.search(/[*?[{]/);
  const head = cut === -1 ? g : g.slice(0, cut);
  return head.includes("/") ? head.slice(0, head.lastIndexOf("/")) || "." : cut === -1 ? g : ".";
}

export function measure(entries, root = ".") {
  return entries.map((e) => {
    const paths = Array.isArray(e.path) ? e.path : [e.path];
    const matched = new Set();
    for (const p of paths) {
      const re = globToRegExp(p);
      const base = staticBase(p);
      const start = join(root, base);
      let st;
      try {
        st = statSync(start);
      } catch {
        continue;
      }
      const candidates = st.isDirectory() ? walk(start) : [start];
      for (const f of candidates) {
        if (re.test(relative(root, f).split("\\").join("/"))) matched.add(f);
      }
    }
    let size = 0;
    for (const f of matched) {
      const buf = readFileSync(f);
      size += e.gzip === false ? buf.length : gzipSync(buf).length;
    }
    return { name: e.name ?? paths.join(","), size, sizeLimit: parseLimit(e.limit), files: matched.size };
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cfg = JSON.parse(readFileSync(".size-limit.json", "utf8"));
  const out = measure(Array.isArray(cfg) ? cfg : []);
  process.stdout.write(JSON.stringify(out));
}
