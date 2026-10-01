import assert from "node:assert/strict";
import test from "node:test";
import { validateVictoriaRecoveryBrokerCleanup, validateVictoriaRecoveryBrokerLaunch, validateVictoriaRecoveryResult } from "../aws/victoria-recovery-result.mjs";

const sourceSha = "a".repeat(40), nonce = "00000000-0000-4000-8000-000000000000";
const valid = () => ({ operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", sourceSha, authorizationNonce: nonce,
  status: "complete", reason: "FAILED_ONBOARDING_PRUNED", temporaryAuthorityCleanup: true,
  result: { operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", targetEmail: "victoria@mscqr.com",
    targetDatabase: "mscqr_production", userExists: false, activeAccountExists: false, emailVerified: false,
    validUnusedInvite: false, auditHistoryPreserved: true, auditHistoryDeleted: 0,
    pruneComplete: true, reason: "FAILED_ONBOARDING_PRUNED" } });

test("canonical executor envelope validates nested successful recovery result", () => {
  assert.deepEqual(validateVictoriaRecoveryResult(valid(), { sourceSha, nonce }), {
    operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", targetEmail: "victoria@mscqr.com",
    targetDatabase: "mscqr_production", status: "complete", pruneComplete: true,
    temporaryAuthorityCleanup: true, reason: "FAILED_ONBOARDING_PRUNED",
  });
});

test("already-clean repeat execution is a deterministic successful terminal state", () => {
  const value = valid();
  value.reason = "FAILED_ONBOARDING_ALREADY_CLEAN";
  value.result.reason = "FAILED_ONBOARDING_ALREADY_CLEAN";
  assert.equal(validateVictoriaRecoveryResult(value, { sourceSha, nonce }).pruneComplete, true);
});

test("malformed, mismatched, or incomplete executor results fail closed", () => {
  const mutations = [
    (v) => { delete v.result; },
    (v) => { v.result = { ...v.result, targetEmail: "other@example.com" }; },
    (v) => { v.result = { ...v.result, targetDatabase: "other_database" }; },
    (v) => { v.result = { ...v.result, operation: "OTHER_OPERATION" }; },
    (v) => { v.result = { ...v.result, pruneComplete: false }; },
    (v) => { v.result = { ...v.result, userExists: true }; },
    (v) => { v.result = { ...v.result, validUnusedInvite: true }; },
    (v) => { v.result = { ...v.result, activeAccountExists: true }; },
    (v) => { v.result = { ...v.result, emailVerified: true }; },
    (v) => { v.result = { ...v.result, auditHistoryPreserved: false }; },
    (v) => { v.reason = "OTHER"; },
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

test("broker launch and cleanup boundaries share exact schemas", () => {
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/01234567-89ab-cdef-0123-456789abcdef";
  const launch = { operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", sourceSha, nonce, taskArn };
  const cleanup = { operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", sourceSha, nonce,
    networkAuthorityRevoked: true, taskStopped: true };
  assert.equal(validateVictoriaRecoveryBrokerLaunch(launch, { sourceSha, nonce }).taskArn, taskArn);
  assert.equal(validateVictoriaRecoveryBrokerCleanup(cleanup, { sourceSha, nonce }).taskStopped, true);
  for (const invalid of [{ ...launch, nonce: "00000000-0000-4000-8000-000000000001" },
    { ...launch, taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/other/id" }, { ...launch, extra: true }]) {
    assert.throws(() => validateVictoriaRecoveryBrokerLaunch(invalid, { sourceSha, nonce }));
  }
  for (const invalid of [{ ...cleanup, sourceSha: "b".repeat(40) }, { ...cleanup, taskStopped: false },
    { ...cleanup, networkAuthorityRevoked: false }, { ...cleanup, extra: true }]) {
    assert.throws(() => validateVictoriaRecoveryBrokerCleanup(invalid, { sourceSha, nonce }));
  }
});
