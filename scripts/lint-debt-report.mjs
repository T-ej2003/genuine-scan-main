import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = process.cwd();
const baselinePath = path.join(repoRoot, ".security", "lint-debt-baseline.json");
const artifactDir = path.join(repoRoot, "audit-artifacts");
const reportPath = path.join(artifactDir, "lint-debt-report.json");
const issueTemplatePath = path.join(artifactDir, "lint-debt-issue-template.md");

const ensurePath = () => {
  const segments = String(process.env.PATH || "")
    .split(":")
    .filter(Boolean);
  for (const entry of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]) {
    if (!segments.includes(entry)) segments.unshift(entry);
  }
  return segments.join(":");
};

const eslintResult = spawnSync("npx", ["eslint", ".", "-f", "json"], {
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
  env: {
    ...process.env,
    PATH: ensurePath(),
  },
});

const raw = String(eslintResult.stdout || "").trim();
if (!raw) {
  throw new Error("lint debt report failed: eslint produced no JSON output.");
}

let entries;
try {
  entries = JSON.parse(raw);
} catch (error) {
  throw new Error(`lint debt report failed: could not parse eslint json (${error?.message || error}).`);
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

let baseline = { errors: totals.errors, warnings: totals.warnings, recordedAt: null };
try {
  baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
} catch {
  // Keep current totals as baseline fallback.
}

const delta = {
  errors: totals.errors - Number(baseline.errors || 0),
  warnings: totals.warnings - Number(baseline.warnings || 0),
};

const report = {
  generatedAt: new Date().toISOString(),
  baseline,
  totals,
  delta,
  lintExitCode: eslintResult.status ?? null,
};

mkdirSync(artifactDir, { recursive: true });
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

const issueTemplate = [
  "# Lint Debt Delta Report",
  "",
  `Generated at: ${report.generatedAt}`,
  "",
  "## Current totals",
  `- Files scanned: ${totals.files}`,
  `- Errors: ${totals.errors}`,
  `- Warnings: ${totals.warnings}`,
  "",
  "## Baseline comparison",
  `- Baseline errors: ${baseline.errors}`,
  `- Baseline warnings: ${baseline.warnings}`,
  `- Error delta: ${delta.errors >= 0 ? "+" : ""}${delta.errors}`,
  `- Warning delta: ${delta.warnings >= 0 ? "+" : ""}${delta.warnings}`,
  "",
  "## Action",
  "- Do not allow lint debt to increase on release-candidate branches.",
  "- If delta is positive, create follow-up fixes in the next hardening sprint.",
].join("\n");

writeFileSync(issueTemplatePath, `${issueTemplate}\n`, "utf8");
console.log(`Lint debt report written: ${reportPath}`);
console.log(`Lint debt issue template written: ${issueTemplatePath}`);
