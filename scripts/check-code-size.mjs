import fs from "node:fs";
import path from "node:path";

import { DEFAULT_BUDGETS, LEGACY_FILE_BUDGETS } from "./code-quality/size-budget-config.mjs";

const ROOT = process.cwd();

const WALK_ROOTS = ["src", "backend/src", "scripts"];

const walk = (directory) => {
  const absoluteDirectory = path.join(ROOT, directory);
  if (!fs.existsSync(absoluteDirectory)) return [];

  const result = [];
  for (const entry of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
    const absolutePath = path.join(absoluteDirectory, entry.name);
    const relativePath = path.relative(ROOT, absolutePath).replaceAll(path.sep, "/");
    if (entry.isDirectory()) {
      result.push(...walk(relativePath));
      continue;
    }
    result.push(relativePath);
  }
  return result;
};

const countLines = (filePath) => {
  const content = fs.readFileSync(path.join(ROOT, filePath), "utf8");
  return content.split("\n").length;
};

const resolveBudget = (filePath) => {
  if (LEGACY_FILE_BUDGETS[filePath]) return LEGACY_FILE_BUDGETS[filePath];
  return DEFAULT_BUDGETS.find((budget) => budget.match(filePath)) || null;
};

const filesToCheck = Array.from(new Set(WALK_ROOTS.flatMap(walk))).sort();

const violations = [];
const checked = [];

for (const filePath of filesToCheck) {
  const budget = resolveBudget(filePath);
  if (!budget) continue;

  const lines = countLines(filePath);
  checked.push({ filePath, lines, budget });
  if (lines > budget.maxLines) {
    violations.push({ filePath, lines, budget });
  }
}

if (violations.length > 0) {
  console.error("Code-size budget failures:");
  for (const violation of violations) {
    const reasonSuffix = violation.budget.reason ? ` [reason: ${violation.budget.reason}]` : "";
    console.error(
      `- ${violation.filePath}: ${violation.lines} lines exceeds ${violation.budget.maxLines} (${violation.budget.label})${reasonSuffix}`
    );
  }
  process.exit(1);
}

console.log(`Code-size budgets passed for ${checked.length} tracked files.`);
