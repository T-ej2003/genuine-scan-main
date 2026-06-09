import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

const readBaseline = () => {
  try {
    const parsed = JSON.parse(readFileSync(baselinePath, "utf8"));
    const errors = Number(parsed.errors);
    const warnings = Number(parsed.warnings);
    if (!Number.isFinite(errors) || !Number.isFinite(warnings)) throw new Error("baseline counts missing");
    return { errors, warnings, raw: parsed };
  } catch (error) {
    console.error(`lint:ratchet failed: unable to read ${baselinePath} (${error?.message || error}).`);
    console.error("Run npm run lint:baseline after reviewing current debt, then commit the baseline intentionally.");
    process.exit(1);
  }
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
  console.error("lint:ratchet failed: eslint produced no JSON output.");
  process.exit(1);
}

let entries;
try {
  entries = JSON.parse(raw);
} catch (error) {
  console.error(`lint:ratchet failed: could not parse eslint JSON (${error?.message || error}).`);
  process.exit(1);
}

const totals = entries.reduce(
  (acc, entry) => {
    acc.errors += Number(entry.errorCount || 0);
    acc.warnings += Number(entry.warningCount || 0);
    return acc;
  },
  { errors: 0, warnings: 0 }
);

const baseline = readBaseline();
const errorDelta = totals.errors - baseline.errors;
const warningDelta = totals.warnings - baseline.warnings;

if (errorDelta > 0 || warningDelta > 0) {
  console.error("lint:ratchet failed: lint debt increased above baseline.");
  console.error(`baseline: ${baseline.errors} errors, ${baseline.warnings} warnings`);
  console.error(`current:  ${totals.errors} errors, ${totals.warnings} warnings`);
  console.error(`delta:    ${errorDelta >= 0 ? "+" : ""}${errorDelta} errors, ${warningDelta >= 0 ? "+" : ""}${warningDelta} warnings`);
  console.error("Keep touched files lint-clean or intentionally reduce the baseline after cleanup.");
  process.exit(1);
}

console.log(
  `lint:ratchet passed: ${totals.errors} errors, ${totals.warnings} warnings (baseline ${baseline.errors}/${baseline.warnings})`
);
