import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
const source = readFileSync("scripts/security/production-rotation-state-inventory.mjs", "utf8");
test("rotation inventory is bounded read-only metadata and never selects secret values", () => {
  assert.match(source, /SET TRANSACTION READ ONLY/); assert.match(source, /SET LOCAL ROLE/);
  for (const forbidden of ["tokenHash", "proofBindingTokenHash", "DATABASE_URL.*console", "secretValue"]) assert.doesNotMatch(source, new RegExp(forbidden, "i"));
  for (const name of ["refreshSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification", "qrArtifacts", "artifactRecords", "oauthState"]) assert.match(source, new RegExp(name));
});
