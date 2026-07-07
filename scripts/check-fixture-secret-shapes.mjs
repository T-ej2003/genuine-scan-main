import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const recursiveTargets = [
  path.join("backend", "tests"),
  "e2e",
  path.join("scripts", "tests"),
  "documents",
  path.join(".github", "workflows"),
];

const allowedExtensions = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".md", ".json", ".yml", ".yaml"]);
const skippedDirectories = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  "playwright-report",
  "test-results",
  "generated-docx",
]);
const skippedFiles = new Set(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]);
const legacyBaselineFindings = [
  {
    file: path.join("backend", "tests", "stagingRlsValidationSeedScript.test.js"),
    line: 67,
  },
];

const escapeRegExp = (value) => String(value).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");

const serviceSchemes = [
  ["post", "gres", "ql"].join(""),
  ["post", "gres"].join(""),
  ["redis"].join(""),
  ["smtp"].join(""),
  ["smtps"].join(""),
  ["http"].join(""),
  ["https"].join(""),
];

const quoteChars = `\\s"'${String.fromCharCode(96)}`;
const schemePattern = `(?:${serviceSchemes.map(escapeRegExp).join("|")})`;
const authoritySeparator = `${":".repeat(1)}${"/".repeat(2)}`;
const userPart = `[^${quoteChars}/@:]+`;
const secretPart = `[^${quoteChars}/@]+`;
const credentialedServiceUrlPattern = new RegExp(
  `\\b${schemePattern}${escapeRegExp(authoritySeparator)}${userPart}:${secretPart}@`,
  "gi"
);

const walk = (dir) => {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (skippedDirectories.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walk(fullPath));
      continue;
    }

    if (!entry.isFile()) continue;
    if (skippedFiles.has(entry.name)) continue;
    if (!allowedExtensions.has(path.extname(entry.name).toLowerCase())) continue;
    results.push(fullPath);
  }
  return results;
};

const filesToScan = [];
for (const relativeDir of recursiveTargets) {
  const fullDir = path.join(repoRoot, relativeDir);
  if (!existsSync(fullDir) || !statSync(fullDir).isDirectory()) continue;
  filesToScan.push(...walk(fullDir));
}

const findings = [];
let legacyBaselineFindingCount = 0;

const isLegacyBaselineFinding = (relativePath, line) =>
  legacyBaselineFindings.some((entry) => entry.file === relativePath && entry.line === line);

for (const filePath of filesToScan) {
  const relativePath = path.relative(repoRoot, filePath);
  const contents = readFileSync(filePath, "utf8");
  credentialedServiceUrlPattern.lastIndex = 0;

  let match = credentialedServiceUrlPattern.exec(contents);
  while (match) {
    const line = contents.slice(0, match.index).split("\n").length;
    if (isLegacyBaselineFinding(relativePath, line)) {
      legacyBaselineFindingCount += 1;
      match = credentialedServiceUrlPattern.exec(contents);
      continue;
    }

    findings.push({
      file: relativePath,
      line,
    });
    match = credentialedServiceUrlPattern.exec(contents);
  }
}

if (findings.length > 0) {
  console.error("Fixture secret-shape guard failed: complete credentialed service URLs are not allowed.");
  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line}`);
  }
  process.exit(1);
}

const baselineSuffix = legacyBaselineFindingCount > 0 ? `; ${legacyBaselineFindingCount} legacy baseline finding(s) ignored` : "";
console.log(`Fixture secret-shape guard passed for ${filesToScan.length} file(s)${baselineSuffix}.`);
