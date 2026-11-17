import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { build } from "vite";

const root = path.resolve(process.argv[2]);
const outDir = mkdtempSync(path.join(os.tmpdir(), "mscqr-osv-browser-probe-"));
try {
  await build({ root, logLevel: "silent", build: { outDir, emptyOutDir: true, write: true } });
  const files = readdirSync(outDir, { recursive: true }).filter(file => /\.(?:js|mjs|cjs|html|css)$/.test(file)).sort();
  if (!files.length) throw new Error("No executable browser output");
  const hash = createHash("sha256");
  for (const file of files) hash.update(file).update(readFileSync(path.join(outDir, file)));
  process.stdout.write(JSON.stringify({ outputSha256: hash.digest("hex"), fileCount: files.length }));
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
