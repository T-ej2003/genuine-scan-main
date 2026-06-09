import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const baselinePath = path.join(repoRoot, ".security", "lint-debt-baseline.json");

const ensurePath = () => {
  const segments = String(process.env.PATH || "")
    .split(":")
    .filter(Boolean);
  for (const entry of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]) {
    if (!segments.includes(entry)) segments.unshift(entry);
  }
  return segments.join(":");
};

const eslint = spawnSync("npx", ["eslint", ".", "-f", "json"], {
  cwd: repoRoot,
  encoding: "utf8",
  maxBuffer: 128 * 1024 * 1024,
  env: {
    ...process.env,
    PATH: ensurePath(),
  },
});

const raw = String(eslint.stdout || "").trim();
if (!raw) {
  console.error("lint:baseline failed: eslint produced no JSON output.");
  process.exit(1);
}

let entries;
try {
  entries = JSON.parse(raw);
} catch (error) {
  console.error(`lint:baseline failed: could not parse eslint JSON (${error?.message || error}).`);
  process.exit(1);
}

const totals = entries.reduce(
  (acc, entry) => {
    acc.errors += Number(entry.errorCount || 0);
    acc.warnings += Number(entry.warningCount || 0);
    acc.files += 1;
    return acc;
  },
  { errors: 0, warnings: 0, files: 0 }
);

const baseline = {
  recordedAt: new Date().toISOString(),
  errors: totals.errors,
  warnings: totals.warnings,
  files: totals.files,
  command: "npx eslint . -f json",
  note: "MSCQR lint debt ratchet baseline. Lower this file only after intentional cleanup; do not raise it to hide new debt.",
};

mkdirSync(path.dirname(baselinePath), { recursive: true });
writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
console.log(`lint baseline recorded: ${totals.errors} errors, ${totals.warnings} warnings across ${totals.files} files`);
