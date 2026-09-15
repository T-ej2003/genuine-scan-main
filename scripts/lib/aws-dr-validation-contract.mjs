const watchedPrefixes = ["documents/ops/", "scripts/", "ops/deploy/", "ops/aws/", ".github/workflows/"];
const watchedPaths = new Set(["backend/Dockerfile", "package.json", "package-lock.json"]);

export function isDrRelevantPath(filePath) {
  return typeof filePath === "string" && (watchedPaths.has(filePath) || watchedPrefixes.some((prefix) => filePath.startsWith(prefix)));
}

export function isDrRelevantChange({ filename, previous_filename: previousFilename }) {
  return isDrRelevantPath(filename) || isDrRelevantPath(previousFilename);
}

export function hasExactShellCommand(source, command) {
  return source.split(/\r?\n/).some((line) => line.trim().replace(/\s+/g, " ") === command);
}

export function hasGuardrailBranches(source) {
  return /if \[ "\$GITHUB_EVENT_NAME" = "pull_request" \]; then\s+npm run verify:guardrails:source\s+else\s+npm run verify:guardrails\s+/m.test(source);
}
