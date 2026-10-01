import assert from "node:assert/strict";
import test from "node:test";
import { validateVictoriaRecoveryResult } from "../aws/victoria-recovery-result.mjs";

const sourceSha = "a".repeat(40), nonce = "00000000-0000-4000-8000-000000000000";
const valid = () => ({ operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", sourceSha, authorizationNonce: nonce,
  status: "complete", reason: "FAILED_ONBOARDING_PRUNE_COMPLETE", temporaryAuthorityCleanup: true,
  result: { operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", targetEmail: "victoria@mscqr.com",
    targetDatabase: "mscqr_production", pruneComplete: true, reason: "FAILED_ONBOARDING_PRUNE_COMPLETE" } });

test("canonical executor envelope validates nested successful recovery result", () => {
  assert.deepEqual(validateVictoriaRecoveryResult(valid(), { sourceSha, nonce }), {
    operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", targetEmail: "victoria@mscqr.com",
    targetDatabase: "mscqr_production", status: "complete", pruneComplete: true,
    temporaryAuthorityCleanup: true, reason: "FAILED_ONBOARDING_PRUNE_COMPLETE",
  });
});

test("malformed, mismatched, or incomplete executor results fail closed", () => {
  const mutations = [
    (v) => { delete v.result; },
    (v) => { v.result = { ...v.result, targetEmail: "other@example.com" }; },
    (v) => { v.result = { ...v.result, targetDatabase: "other_database" }; },
    (v) => { v.result = { ...v.result, operation: "OTHER_OPERATION" }; },
    (v) => { v.result = { ...v.result, pruneComplete: false }; },
    (v) => { v.temporaryAuthorityCleanup = false; },
    (v) => { v.status = "stopped"; },
    (v) => { v.sourceSha = "b".repeat(40); },
    (v) => { v.authorizationNonce = "00000000-0000-4000-8000-000000000001"; },
    (v) => { v.targetEmail = "victoria@mscqr.com"; },
  ];
  for (const mutate of mutations) assert.throws(() => validateVictoriaRecoveryResult(mutate(valid()), { sourceSha, nonce }), /VICTORIA_RECOVERY_RESULT_INVALID/);
  assert.throws(() => validateVictoriaRecoveryResult(valid(), { sourceSha: "b".repeat(40), nonce }), /VICTORIA_RECOVERY_RESULT_INVALID/);
  assert.throws(() => validateVictoriaRecoveryResult(valid(), { sourceSha, nonce: "00000000-0000-4000-8000-000000000001" }), /VICTORIA_RECOVERY_RESULT_INVALID/);
});
