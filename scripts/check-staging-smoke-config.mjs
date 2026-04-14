const required = [
  { key: "SMOKE_BASE_URL", type: "var" },
  { key: "SMOKE_LOGIN_EMAIL", type: "secret" },
  { key: "SMOKE_LOGIN_PASSWORD", type: "secret" },
  { key: "SMOKE_VERIFY_CODE", type: "var" },
  { key: "SMOKE_BATCH_PRINT_ENDPOINT", type: "var" },
  { key: "SMOKE_BATCH_PRINT_PAYLOAD_JSON", type: "var" },
  { key: "SMOKE_INCIDENT_ENDPOINT", type: "var" },
  { key: "SMOKE_INCIDENT_PAYLOAD_JSON", type: "var" },
];

const read = (key) => String(process.env[key] || "").trim();
const missing = [];

for (const item of required) {
  if (!read(item.key)) {
    missing.push(item);
  }
}

const evidenceUrl = read("SMOKE_EVIDENCE_URL");
const evidencePath = read("SMOKE_EVIDENCE_PATH");
if (!evidenceUrl && !evidencePath) {
  missing.push({ key: "SMOKE_EVIDENCE_URL or SMOKE_EVIDENCE_PATH", type: "var" });
}

const stepUpPassword = read("SMOKE_STEP_UP_PASSWORD");
const stepUpCode = read("SMOKE_ADMIN_STEP_UP_CODE");
const mfaCode = read("SMOKE_ADMIN_MFA_CODE");
if (!stepUpPassword && !stepUpCode && !mfaCode) {
  missing.push({ key: "SMOKE_STEP_UP_PASSWORD or SMOKE_ADMIN_STEP_UP_CODE or SMOKE_ADMIN_MFA_CODE", type: "secret" });
}

if (missing.length > 0) {
  console.error("Staging smoke configuration is incomplete.");
  for (const item of missing) {
    console.error(`- missing ${item.type}: ${item.key}`);
  }
  process.exit(1);
}

console.log("Staging smoke configuration check passed.");

