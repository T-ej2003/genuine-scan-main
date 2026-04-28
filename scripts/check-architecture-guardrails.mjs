import fs from "node:fs";
import path from "node:path";

import { DEFAULT_BUDGETS } from "./code-quality/size-budget-config.mjs";

const ROOT = process.cwd();
const NOTES_PATH = path.join(ROOT, "documents/architecture/threshold-migration-notes.json");
const REQUIRED_NOTE_FIELDS = ["summary", "nextStep", "targetMaxLines"];
const WALK_ROOTS = ["backend/src/controllers", "src/pages", "src/features"];

const readJson = (filePath) => JSON.parse(fs.readFileSync(filePath, "utf8"));

const countLines = (filePath) =>
  fs.readFileSync(path.join(ROOT, filePath), "utf8").split("\n").length;

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
    if (/\.(ts|tsx)$/.test(relativePath)) {
      result.push(relativePath);
    }
  }
  return result;
};

const architectureBudgets = DEFAULT_BUDGETS.filter((budget) => budget.label === "Controller" || budget.label === "Page");
const notes = readJson(NOTES_PATH);
const filesToCheck = Array.from(new Set(WALK_ROOTS.flatMap(walk))).sort();
const trackedOversizedFiles = [];
const missingNotes = [];
const invalidNotes = [];
const staleNotes = [];

for (const filePath of filesToCheck) {
  const budget = architectureBudgets.find((entry) => entry.match(filePath));
  if (!budget) continue;

  const lines = countLines(filePath);
  if (lines <= budget.maxLines) continue;

  trackedOversizedFiles.push({ filePath, lines, budget });
  const note = notes[filePath];
  if (!note) {
    missingNotes.push({ filePath, lines, budget });
    continue;
  }

  const missingFields = REQUIRED_NOTE_FIELDS.filter((field) => {
    if (!(field in note)) return true;
    if (field === "targetMaxLines") return !Number.isInteger(note[field]) || note[field] <= 0;
    return typeof note[field] !== "string" || note[field].trim().length === 0;
  });

  if (missingFields.length > 0) {
    invalidNotes.push({ filePath, missingFields });
  }
}

for (const [filePath, note] of Object.entries(notes)) {
  if (!filesToCheck.includes(filePath)) {
    staleNotes.push({ filePath, reason: "file no longer matches a tracked controller/page path" });
    continue;
  }

  const budget = architectureBudgets.find((entry) => entry.match(filePath));
  if (!budget) {
    staleNotes.push({ filePath, reason: "file is no longer governed by the controller/page thresholds" });
    continue;
  }

  const lines = countLines(filePath);
  if (lines <= budget.maxLines) {
    staleNotes.push({ filePath, reason: `file is back under the default ${budget.label.toLowerCase()} threshold` });
  }

  if (note.targetMaxLines > budget.maxLines) {
    invalidNotes.push({
      filePath,
      missingFields: [`targetMaxLines must be <= ${budget.maxLines} to represent an actual reduction target`],
    });
  }
}

if (missingNotes.length > 0 || invalidNotes.length > 0) {
  console.error("Architecture guardrail failures:");

  for (const violation of missingNotes) {
    console.error(
      `- ${violation.filePath}: ${violation.lines} lines exceeds the default ${violation.budget.label.toLowerCase()} threshold (${violation.budget.maxLines}) without an explicit migration note in documents/architecture/threshold-migration-notes.json`
    );
  }

  for (const violation of invalidNotes) {
    console.error(`- ${violation.filePath}: invalid migration note (${violation.missingFields.join("; ")})`);
  }

  process.exit(1);
}

console.log(
  `Architecture guardrails passed for ${trackedOversizedFiles.length} oversized controller/page files with explicit migration notes.`
);

if (staleNotes.length > 0) {
  console.warn("Stale migration notes detected:");
  for (const note of staleNotes) {
    console.warn(`- ${note.filePath}: ${note.reason}`);
  }
}
