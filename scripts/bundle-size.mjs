// Fallback bundle measurement for apps with no size-limit config: the gzip size of the JS and CSS
// the build produced (what a browser downloads). Writes the same shape size-limit does:
// [{ "name": ..., "size": <bytes> }]. Prints "[]" when there is no build output.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";

const CANDIDATES = [".output/public", "dist/client", "build/client", ".vercel/output/static", "dist", "build", "out"];
const dir = CANDIDATES.find((d) => existsSync(d) && statSync(d).isDirectory());
if (!dir) {
  process.stdout.write("[]");
  process.exit(0);
}
let total = 0;
let files = 0;
const walk = (d) => {
  for (const name of readdirSync(d)) {
    const p = path.join(d, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.(m?js|css)$/.test(name) && !/\.map$/.test(name)) {
      total += gzipSync(readFileSync(p)).length;
      files += 1;
    }
  }
};
walk(dir);
process.stdout.write(JSON.stringify(files ? [{ name: `${dir} (gzip, ${files} files)`, size: total }] : []));
