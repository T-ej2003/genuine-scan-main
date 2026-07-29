const REQUIRED_VARS = ["SMOKE_BASE_URL", "SMOKE_API_BASE_URL"];
const REQUIRED_SECRETS = ["SMOKE_LOGIN_EMAIL", "SMOKE_LOGIN_PASSWORD"];
export const KNOWN_BLUE_LOGIN_SKIP_REASON = "known-blue-production-auth-http-500-production-green-lineage";

// This is deliberately an exact, reviewable pre-cutover Stage B allowlist, not
// a PR-number or branch-name exception. Any file outside it keeps login blocking.
const PRE_CUTOVER_STAGE_B_FILES = new Set([
  ".github/workflows/production-green-stage-b-images.yml",
  ".github/workflows/release-candidate-gate.yml",
  "backend/Dockerfile",
  "backend/scripts/full-rls-green-executor-core.mjs",
  "backend/scripts/production-full-rls-green-executor.mjs",
  "backend/scripts/production-green-application-canary.mjs",
  "backend/scripts/production-green-canary-provision.mjs",
  "backend/scripts/production-rls-approval.mjs",
  "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_CONTROL_PLANE.md",
  "documents/security/rls-program/production-full-rls-executor-contract.json",
  "package.json",
  "scripts/aws/apply-production-full-rls-release.mjs",
  "scripts/aws/package-production-green-stage-b-broker.mjs",
  "scripts/aws/production-green-stage-b-contract.mjs",
  "scripts/aws/production-green-stage-b-task-definitions.mjs",
  "scripts/aws/publish-ecs-images.sh",
  "scripts/aws/stage-b-image-bindings.mjs",
  "scripts/aws/stage-b-release-gate.mjs",
  "scripts/check-known-blue-staging-smoke-exception.mjs",
  "scripts/lib/staging-smoke-config-core.mjs",
  "scripts/rls/lib/clean-room-source-contract.mjs",
  "scripts/tests/production-full-rls-release.test.mjs",
  "scripts/tests/production-green-stage-b-control-plane.test.mjs",
  "scripts/tests/production-green-stage-b-image-bindings.test.mjs",
  "scripts/tests/stage-b-release-gate.test.mjs",
  "scripts/tests/staging-smoke-config.test.mjs",
]);
const PRE_CUTOVER_STAGE_B_PREFIXES = [
  "documents/security/rls-program/generated/",
  "infra/aws/terraform/lambda/production-rls-approval-broker/",
  "infra/aws/terraform/production-green-stage-b/",
  "scripts/rls/sql/generated/",
];
const BLUE_OR_RUNTIME_PREFIXES = [
  "frontend/", "src/", "backend/src/", "infra/aws/terraform/production-green-stage-a/",
  "infra/aws/terraform/main.tf", "infra/aws/terraform/production-rls-green.tf",
  ".github/workflows/release-gate.yml", "infra/aws/terraform/production-green-stage-a",
];
const DEPENDENCY_FILE_PATHS = new Set([
  "bun.lockb",
  "npm-shrinkwrap.json",
  "package-lock.json",
  "package.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "backend/npm-shrinkwrap.json",
  "backend/package-lock.json",
  "backend/package.json",
  "backend/pnpm-lock.yaml",
  "backend/yarn.lock",
]);

export const readConfigValue = (env, key) => String(env[key] || "").trim();

export const parseChangedFiles = (value) =>
  String(value || "")
    .split(/\r?\n|,/)
    .map((entry) => entry.trim())
    .filter(Boolean);

export const isDependabotActor = (actor) => {
  const normalized = String(actor || "").trim().toLowerCase();
  return normalized === "dependabot[bot]";
};

export const isDependencyManifestFile = (filePath) => {
  const normalized = String(filePath || "").trim().replace(/\\/g, "/");
  if (!normalized || normalized.includes("\0")) return false;
  return DEPENDENCY_FILE_PATHS.has(normalized);
};

export const isDependencyOnlyChangeSet = (changedFiles) => {
  if (!Array.isArray(changedFiles) || changedFiles.length === 0) return false;
  return changedFiles.every(isDependencyManifestFile);
};

export const collectStagingSmokeConfig = (env = process.env) => {
  const read = (key) => readConfigValue(env, key);
  const missing = [];

  for (const key of REQUIRED_VARS) {
    if (!read(key)) missing.push({ key, type: "var" });
  }

  for (const key of REQUIRED_SECRETS) {
    if (!read(key)) missing.push({ key, type: "secret" });
  }

  const hasVerifyFlow = Boolean(read("SMOKE_VERIFY_CODE"));

  const batchPrintEndpoint = read("SMOKE_BATCH_PRINT_ENDPOINT");
  const batchPrintPayload = read("SMOKE_BATCH_PRINT_PAYLOAD_JSON");
  const hasBatchPrintFlow = Boolean(batchPrintEndpoint && batchPrintPayload);
  if (batchPrintEndpoint || batchPrintPayload) {
    if (!batchPrintEndpoint) missing.push({ key: "SMOKE_BATCH_PRINT_ENDPOINT", type: "var" });
    if (!batchPrintPayload) missing.push({ key: "SMOKE_BATCH_PRINT_PAYLOAD_JSON", type: "var" });
  }

  const incidentEndpoint = read("SMOKE_INCIDENT_ENDPOINT");
  const incidentPayload = read("SMOKE_INCIDENT_PAYLOAD_JSON");
  const hasIncidentFlow = Boolean(incidentEndpoint && incidentPayload);
  if (incidentEndpoint || incidentPayload) {
    if (!incidentEndpoint) missing.push({ key: "SMOKE_INCIDENT_ENDPOINT", type: "var" });
    if (!incidentPayload) missing.push({ key: "SMOKE_INCIDENT_PAYLOAD_JSON", type: "var" });
  }

  const evidenceUrl = read("SMOKE_EVIDENCE_URL");
  const evidencePath = read("SMOKE_EVIDENCE_PATH");
  const hasEvidenceFlow = Boolean(evidenceUrl || evidencePath);
  if (evidenceUrl && evidencePath) {
    missing.push({ key: "only one of SMOKE_EVIDENCE_URL or SMOKE_EVIDENCE_PATH", type: "var" });
  }

  const hasStepUpFlow = Boolean(
    read("SMOKE_STEP_UP_PASSWORD") ||
    read("SMOKE_ADMIN_STEP_UP_CODE") ||
    read("SMOKE_ADMIN_MFA_CODE") ||
    read("SMOKE_ADMIN_MFA_SECRET")
  );

  const configuredOptionalFlows = [
    hasVerifyFlow ? "verify" : null,
    hasBatchPrintFlow ? "batch-print" : null,
    hasIncidentFlow ? "incident" : null,
    hasEvidenceFlow ? "evidence" : null,
    hasStepUpFlow ? "step-up-or-mfa" : null,
  ].filter(Boolean);

  return {
    missing,
    configuredOptionalFlows,
  };
};

export const evaluateDependabotSmokeSkip = ({ env = process.env, missing = [] } = {}) => {
  const actor = readConfigValue(env, "GITHUB_ACTOR");
  const eventName = readConfigValue(env, "GITHUB_EVENT_NAME");
  const allowSkip = /^(1|true|yes|on)$/i.test(readConfigValue(env, "ALLOW_DEPENDABOT_DEPENDENCY_SMOKE_SKIP"));
  const changedFiles = parseChangedFiles(env.STAGING_SMOKE_CHANGED_FILES);
  const dependencyOnly = isDependencyOnlyChangeSet(changedFiles);
  const missingLoginSecrets = missing.filter(
    (item) => item.type === "secret" && REQUIRED_SECRETS.includes(item.key)
  );
  const missingOnlyLoginSecrets =
    missing.length > 0 && missing.length === missingLoginSecrets.length;

  const shouldSkip =
    allowSkip &&
    eventName === "pull_request" &&
    isDependabotActor(actor) &&
    dependencyOnly &&
    missingOnlyLoginSecrets;

  return {
    shouldSkip,
    actor,
    eventName,
    dependencyOnly,
    changedFiles,
    missingOnlyLoginSecrets,
    missingLoginSecrets: missingLoginSecrets.map((item) => item.key),
  };
};

export const evaluateKnownBlueLoginSkip = ({
  env = process.env,
  readyHealthPassed = false,
  liveHealthPassed = false,
  failureStage = "",
  status = null,
  smokeExitCode = 0,
} = {}) => {
  const changedFiles = parseChangedFiles(env.STAGING_SMOKE_CHANGED_FILES);
  const blueOrRuntimeChange = changedFiles.some((file) => BLUE_OR_RUNTIME_PREFIXES.some((prefix) => file === prefix || file.startsWith(prefix)));
  const stageBPreCutoverScope =
    changedFiles.length > 0 &&
    !blueOrRuntimeChange &&
    changedFiles.every((file) => PRE_CUTOVER_STAGE_B_FILES.has(file) || PRE_CUTOVER_STAGE_B_PREFIXES.some((prefix) => file.startsWith(prefix)));
  const activationScope = !blueOrRuntimeChange && stageBPreCutoverScope;
  const shouldSkip =
    readConfigValue(env, "KNOWN_BLUE_ENDPOINT_MISMATCH") === KNOWN_BLUE_LOGIN_SKIP_REASON &&
    readConfigValue(env, "GITHUB_EVENT_NAME") === "pull_request" &&
    readConfigValue(env, "GITHUB_REPOSITORY") === "T-ej2003/genuine-scan-main" &&
    readConfigValue(env, "SMOKE_BASE_URL") === "https://www.mscqr.com" &&
    readConfigValue(env, "SMOKE_API_BASE_URL") === "https://www.mscqr.com/api" &&
    activationScope &&
    readyHealthPassed &&
    liveHealthPassed &&
    failureStage === "login" &&
    status === 500 &&
    Number.isInteger(smokeExitCode) &&
    smokeExitCode > 0;

  return {
    shouldSkip,
    reasonCode: shouldSkip ? KNOWN_BLUE_LOGIN_SKIP_REASON : null,
    activationScope,
    stageBPreCutoverScope,
    blueOrRuntimeChange,
    changedFiles,
  };
};
