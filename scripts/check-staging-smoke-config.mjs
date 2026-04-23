const read = (key) => String(process.env[key] || "").trim();

const missing = [];

const requireVar = (key) => {
  if (!read(key)) missing.push({ key, type: "var" });
};

const requireSecret = (key) => {
  if (!read(key)) missing.push({ key, type: "secret" });
};

// Minimum required for a useful smoke run
requireVar("SMOKE_BASE_URL");
requireSecret("SMOKE_LOGIN_EMAIL");
requireSecret("SMOKE_LOGIN_PASSWORD");

// Optional grouped flows
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
  read("SMOKE_ADMIN_MFA_CODE")
);

if (missing.length > 0) {
  console.error("Staging smoke configuration is incomplete.");
  for (const item of missing) {
    console.error(`- missing ${item.type}: ${item.key}`);
  }
  process.exit(1);
}

console.log("Staging smoke configuration check passed.");
console.log("Validated required keys: SMOKE_BASE_URL, SMOKE_LOGIN_EMAIL, SMOKE_LOGIN_PASSWORD");

const configuredOptionalFlows = [
  hasVerifyFlow ? "verify" : null,
  hasBatchPrintFlow ? "batch-print" : null,
  hasIncidentFlow ? "incident" : null,
  hasEvidenceFlow ? "evidence" : null,
  hasStepUpFlow ? "step-up-or-mfa" : null,
].filter(Boolean);

console.log(
  configuredOptionalFlows.length > 0
    ? `Configured optional flows: ${configuredOptionalFlows.join(", ")}`
    : "Configured optional flows: none"
);