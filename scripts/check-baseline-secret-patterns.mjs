import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const explicitTargets = [
  "docker-compose.yml",
  "docker-compose.local.yml",
  ".env.example",
  path.join("backend", ".env.example"),
  "README.md",
];

const recursiveTargets = [".github/workflows", "docs"];

const filesToScan = new Set();

for (const relativePath of explicitTargets) {
  const fullPath = path.join(repoRoot, relativePath);
  if (existsSync(fullPath)) filesToScan.add(fullPath);
}

const walk = (dir) => {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if ([".git", "node_modules", "dist", "coverage"].includes(entry.name)) continue;
      results.push(...walk(fullPath));
      continue;
    }
    if (entry.isFile()) results.push(fullPath);
  }
  return results;
};

for (const relativeDir of recursiveTargets) {
  const fullDir = path.join(repoRoot, relativeDir);
  if (!existsSync(fullDir) || !statSync(fullDir).isDirectory()) continue;
  for (const filePath of walk(fullDir)) filesToScan.add(filePath);
}

const rules = [
  {
    name: "Legacy MinIO fallback literal",
    regex: /\bmscqrminiochange\b|\bmscqrminio\b/g,
    message: "Legacy MinIO/object-storage fallback literals are forbidden in tracked baseline files.",
  },
  {
    name: "Fallback default on MinIO root env",
    regex: /\$\{MINIO_ROOT_(?:USER|PASSWORD):-[^}]+\}/g,
    message: "MINIO_ROOT_* must use required env forms, not fallback defaults.",
  },
  {
    name: "Fallback default on object storage credential env",
    regex: /\$\{OBJECT_STORAGE_(?:ACCESS_KEY|SECRET_KEY):-[^}]+\}/g,
    message: "OBJECT_STORAGE_* credentials must use required env forms, not fallback defaults.",
  },
];

const findings = [];

for (const filePath of filesToScan) {
  const contents = readFileSync(filePath, "utf8");
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    let match = rule.regex.exec(contents);
    while (match) {
      const line = contents.slice(0, match.index).split("\n").length;
      findings.push({
        file: path.relative(repoRoot, filePath),
        line,
        rule: rule.name,
        message: rule.message,
      });
      match = rule.regex.exec(contents);
    }
  }
}

if (findings.length > 0) {
  console.error("Baseline secret-pattern guard failed:");
  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line} [${finding.rule}] ${finding.message}`);
  }
  process.exit(1);
}

console.log("Baseline secret-pattern guard passed.");
