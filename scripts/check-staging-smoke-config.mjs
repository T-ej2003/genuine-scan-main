const read = (key) => String(process.env[key] || "").trim();

const missing = [];

const requireVar = (key) => {
  if (!read(key)) missing.push({ key, type: "var" });
};

const requireSecret = (key) => {
  if (!read(key)) missing.push({ key, type: "secret" });
};

// Only hard-require the minimum needed for a useful smoke run
requireVar("SMOKE_BASE_URL");
requireSecret("SMOKE_LOGIN_EMAIL");
requireSecret("SMOKE_LOGIN_PASSWORD");

// Optional verify flow
const verifyCode = read("SMOKE_VERIFY_CODE");

// Optional batch print flow
const batchPrintEndpoint = read("SMOKE_BATCH_PRINT_ENDPOINT");
const batchPrintPayload = read("SMOKE_BATCH_PRINT_PAYLOAD_JSON");
if (batchPrintEndpoint || batchPrintPayload) {
  if (!batchPrintEndpoint) missing.push({ key: "SMOKE_BATCH_PRINT_ENDPOINT", type: "var" });
  if (!batchPrintPayload) missing.push({ key: "SMOKE_BATCH_PRINT_PAYLOAD_JSON", type: "var" });
}

// Optional incident flow
const incidentEndpoint = read("SMOKE_INCIDENT_ENDPOINT");
const incidentPayload = read("SMOKE_INCIDENT_PAYLOAD_JSON");
if (incidentEndpoint || incidentPayload) {
  if (!incidentEndpoint) missing.push({ key: "SMOKE_INCIDENT_ENDPOINT", type: "var" });
  if (!incidentPayload) missing.push({ key: "SMOKE_INCIDENT_PAYLOAD_JSON", type: "var" });
}

// Optional evidence retrieval flow
const evidenceUrl = read("SMOKE_EVIDENCE_URL");
const evidencePath = read("SMOKE_EVIDENCE_PATH");
if (evidenceUrl && evidencePath) {
  missing.push({ key: "only one of SMOKE_EVIDENCE_URL or SMOKE_EVIDENCE_PATH", type: "var" });
}

// Optional step-up / MFA
const stepUpPassword = read("SMOKE_STEP_UP_PASSWORD");
const stepUpCode = read("SMOKE_ADMIN_STEP_UP_CODE");
const mfaCode = read("SMOKE_ADMIN_MFA_CODE");

if (missing.length > 0) {
  console.error("Staging smoke configuration is incomplete.");
  for (const item of missing) {
    console.error(`- missing ${item.type}: ${item.key}`);
  }
  process.exit(1);
}

const configuredOptionalCount = [
  verifyCode,
  batchPrintEndpoint,
  batchPrintPayload,
  incidentEndpoint,
  incidentPayload,
  evidenceUrl,
  evidencePath,
  stepUpPassword,
  stepUpCode,
  mfaCode,
].filter(Boolean).length;

console.log("Staging smoke configuration check passed.");
console.log(`Validated required keys: SMOKE_BASE_URL, SMOKE_LOGIN_EMAIL, SMOKE_LOGIN_PASSWORD`);
console.log(`Configured optional inputs: ${configuredOptionalCount}`);