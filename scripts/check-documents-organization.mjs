import { execFileSync } from "node:child_process";

const allowedConventionalMarkdown = new Set([
  "README.md",
  "SECURITY.md",
  ".github/PULL_REQUEST_TEMPLATE.md",
  "playbooks/aws-cleanup/README.md",
  "infra/aws/terraform/production-green-stage-a/README.md",
  "infra/aws/terraform/production-green-stage-b/README.md",
  "infra/aws/terraform/production-green-stage-b-image-publisher/README.md",
  "infra/aws/terraform/production-green-stage-b-publisher-bootstrap/README.md",
  "infra/aws/terraform/production-initial-activation-policy-reconciler/README.md",
]);

const allowedDocumentationPrefixes = [
  "tools/aws-webapp-cost-optimizer/",
];

const allowedConventionalMarkdownPatterns = [
  /^infra\/terraform\/.+\/README\.md$/,
];

const trackedDocuments = execFileSync("git", ["ls-files", "*.md", "*.docx"], {
  encoding: "utf8",
})
  .split("\n")
  .map((entry) => entry.trim())
  .filter(Boolean);

const misplaced = trackedDocuments.filter((filePath) => {
  if (filePath.startsWith("documents/")) return false;
  if (allowedConventionalMarkdown.has(filePath)) return false;
  if (allowedConventionalMarkdownPatterns.some((pattern) => pattern.test(filePath))) return false;
  return !allowedDocumentationPrefixes.some((prefix) => filePath.startsWith(prefix));
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
