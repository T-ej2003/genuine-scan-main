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
// If set, the smoke runner will use it. If not, it should skip.
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
// These should not be hard-required because some staging accounts may not need them.
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

console.log("Staging smoke configuration check passed.");
console.log(
  JSON.stringify(
    {
      required: {
        SMOKE_BASE_URL: Boolean(read("SMOKE_BASE_URL")),
        SMOKE_LOGIN_EMAIL: Boolean(read("SMOKE_LOGIN_EMAIL")),
        SMOKE_LOGIN_PASSWORD: Boolean(read("SMOKE_LOGIN_PASSWORD")),
      },
      optional: {
        SMOKE_VERIFY_CODE: Boolean(verifyCode),
        SMOKE_BATCH_PRINT_ENDPOINT: Boolean(batchPrintEndpoint),
        SMOKE_BATCH_PRINT_PAYLOAD_JSON: Boolean(batchPrintPayload),
        SMOKE_INCIDENT_ENDPOINT: Boolean(incidentEndpoint),
        SMOKE_INCIDENT_PAYLOAD_JSON: Boolean(incidentPayload),
        SMOKE_EVIDENCE_URL: Boolean(evidenceUrl),
        SMOKE_EVIDENCE_PATH: Boolean(evidencePath),
        SMOKE_STEP_UP_PASSWORD: Boolean(stepUpPassword),
        SMOKE_ADMIN_STEP_UP_CODE: Boolean(stepUpCode),
        SMOKE_ADMIN_MFA_CODE: Boolean(mfaCode),
      },
    },
    null,
    2
  )
);