import { execFileSync } from "node:child_process";

const allowedConventionalMarkdown = new Set([
  "README.md",
  "SECURITY.md",
  ".github/PULL_REQUEST_TEMPLATE.md",
]);

const trackedDocuments = execFileSync("git", ["ls-files", "*.md", "*.docx"], {
  encoding: "utf8",
})
  .split("\n")
  .map((entry) => entry.trim())
  .filter(Boolean);

const misplaced = trackedDocuments.filter((filePath) => {
  if (filePath.startsWith("documents/")) return false;
  return !allowedConventionalMarkdown.has(filePath);
});

if (misplaced.length > 0) {
  console.error("Documents organization guardrail failed:");
  for (const filePath of misplaced) {
    console.error(`- ${filePath} must live under documents/ or be an approved repository convention file.`);
  }
  process.exit(1);
}

console.log(
  `Documents organization guardrail passed for ${trackedDocuments.length} tracked Markdown/DOCX file(s).`,
);
