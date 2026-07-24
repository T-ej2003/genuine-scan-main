const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const service = readFileSync(path.join(__dirname,
  "../src/services/customerVerificationSessionService.ts"), "utf8");
const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");
const sql = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicVerificationFunctions.sql"), "utf8");

assert.doesNotMatch(service, /prisma\.(?:customerVerificationSession|customerTrustIntake|verificationDecision)/);
assert.match(service, /hashToken\(raw\)/);
assert.match(service, /hashToken\(proofToken\)/);
assert.match(repository, /app_public\.start_verification_session/);
assert.match(repository, /app_public\.read_verification_session/);
assert.match(repository, /app_public\.write_verification_session/);
assert.match(sql, /"proofBindingTokenHash" IS DISTINCT FROM p_session_proof_hash/);
assert.match(sql, /"proofBindingExpiresAt"<=p_checked_at/);
assert.match(sql, /require_customer_auth_session\([\s\S]*customer-verification-session/);
assert.match(sql, /"customerUserId" IS DISTINCT FROM customer\."customerUserId"/);
assert.match(sql, /PUBLIC_VERIFICATION_INTAKE_REQUIRED/);
assert.doesNotMatch(sql, /p_customer_user_id\s*=\s*metadata|app\.user_id/);

console.log("customer verification session capability contract passed");
