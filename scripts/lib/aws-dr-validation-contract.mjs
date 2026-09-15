import yaml from "js-yaml";

const watchedPrefixes = ["documents/ops/", "scripts/", "ops/deploy/", "ops/aws/", ".github/workflows/"];
const watchedPaths = new Set(["backend/Dockerfile", "package.json", "package-lock.json"]);
const guardrailStepName = "Validate DR guardrails";
const canonicalGuardrailProgram = [
  'if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then',
  "npm run verify:guardrails:source",
  "else",
  "npm run verify:guardrails",
  "fi",
];

export function isDrRelevantPath(filePath) {
  return typeof filePath === "string" && (watchedPaths.has(filePath) || watchedPrefixes.some((prefix) => filePath.startsWith(prefix)));
}

export function isDrRelevantChange({ filename, previous_filename: previousFilename }) {
  return isDrRelevantPath(filename) || isDrRelevantPath(previousFilename);
}

function executableLines(lines) {
  return lines
    .map((line) => line.trim().replace(/\s+/g, " "))
    .filter((line) => line && !line.startsWith("#"));
}

export function extractGuardrailRunBlock(workflowSource) {
  const steps = yaml.load(workflowSource)?.jobs?.validate?.steps;
  const step = Array.isArray(steps) && steps.find(({ name }) => name === guardrailStepName);
  return typeof step?.run === "string" ? step.run : null;
}

export function guardrailRunBlockIsCanonical(runBlock) {
  return JSON.stringify(executableLines(String(runBlock || "").split(/\r?\n/))) === JSON.stringify(canonicalGuardrailProgram);
}
