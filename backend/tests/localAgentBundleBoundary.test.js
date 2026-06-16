const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const srcRoot = path.join(repoRoot, "src");
const entry = path.join(srcRoot, "local-print-agent", "index.ts");

const forbiddenSpecifiers = [
  "@prisma/client",
  ".prisma",
  "../services/printPayloadService",
  "./services/printPayloadService",
];

const forbiddenPathFragments = [
  `${path.sep}src${path.sep}controllers${path.sep}`,
  `${path.sep}src${path.sep}config${path.sep}database`,
  `${path.sep}src${path.sep}services${path.sep}printPayloadService`,
];

const importPattern =
  /(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']|require\(\s*["']([^"']+)["']\s*\)/g;

const resolveLocalModule = (fromFile, specifier) => {
  if (!specifier.startsWith(".")) return null;
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.mjs`,
    path.join(base, "index.ts"),
    path.join(base, "index.tsx"),
    path.join(base, "index.js"),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile()) || null;
};

const assertAllowedImport = (fromFile, specifier, resolvedFile, violations) => {
  if (forbiddenSpecifiers.some((forbidden) => specifier === forbidden || specifier.includes(forbidden))) {
    violations.push(`${path.relative(repoRoot, fromFile)} imports forbidden ${specifier}`);
  }
  if (resolvedFile && forbiddenPathFragments.some((fragment) => resolvedFile.includes(fragment))) {
    violations.push(`${path.relative(repoRoot, fromFile)} reaches forbidden ${path.relative(repoRoot, resolvedFile)}`);
  }
};

const walk = (file, seen, violations) => {
  const normalized = path.resolve(file);
  if (seen.has(normalized)) return;
  seen.add(normalized);

  const source = fs.readFileSync(normalized, "utf8");
  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] || match[2] || "";
    const resolved = resolveLocalModule(normalized, specifier);
    assertAllowedImport(normalized, specifier, resolved, violations);
    if (resolved && resolved.startsWith(srcRoot)) {
      walk(resolved, seen, violations);
    }
  }
};

const violations = [];
walk(entry, new Set(), violations);

if (violations.length > 0) {
  console.error("Local print agent bundle boundary violations:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}

console.log("local agent bundle boundary test passed");
