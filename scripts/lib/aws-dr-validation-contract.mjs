const watchedPrefixes = ["documents/ops/", "scripts/", "ops/deploy/", "ops/aws/", ".github/workflows/"];
const watchedPaths = new Set(["backend/Dockerfile", "package.json", "package-lock.json"]);

export function isDrRelevantPath(filePath) {
  return typeof filePath === "string" && (watchedPaths.has(filePath) || watchedPrefixes.some((prefix) => filePath.startsWith(prefix)));
}

export function isDrRelevantChange({ filename, previous_filename: previousFilename }) {
  return isDrRelevantPath(filename) || isDrRelevantPath(previousFilename);
}

function guardrailBranchLines(source) {
  const lines = source.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === 'if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then');
  if (start < 0) return null;

  const otherwise = lines.findIndex((line, index) => index > start && line.trim() === "else");
  const end = lines.findIndex((line, index) => index > otherwise && line.trim() === "fi");
  if (otherwise < 0 || end < 0) return null;

  return { pullRequest: lines.slice(start + 1, otherwise), dispatch: lines.slice(otherwise + 1, end) };
}

function executableLines(lines) {
  return lines
    .map((line) => line.trim().replace(/\s+/g, " "))
    .filter((line) => line && !line.startsWith("#"));
}

function hasOnlyExactGuardrailCommand(lines, command) {
  const commands = executableLines(lines);
  return commands.length === 1 && commands[0] === command;
}

export function guardrailBranchCommandsAreExact(source) {
  const branches = guardrailBranchLines(source);
  return {
    pullRequest: branches ? hasOnlyExactGuardrailCommand(branches.pullRequest, "npm run verify:guardrails:source") : false,
    dispatch: branches ? hasOnlyExactGuardrailCommand(branches.dispatch, "npm run verify:guardrails") : false,
  };
}
