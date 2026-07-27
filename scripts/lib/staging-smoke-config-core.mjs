const REQUIRED_VARS = ["SMOKE_BASE_URL", "SMOKE_API_BASE_URL"];
const REQUIRED_SECRETS = ["SMOKE_LOGIN_EMAIL", "SMOKE_LOGIN_PASSWORD"];
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
