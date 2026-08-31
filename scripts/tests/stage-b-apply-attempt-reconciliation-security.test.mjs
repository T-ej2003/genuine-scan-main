import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  HISTORICAL_STAGE_B_V2_INCIDENT,
  STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF,
  assertHistoricalStageBV2Incident,
  assertStageBApplyAttemptReconciliationEligibility,
  assertStageBApplyAttemptReservation,
  assertStageBApplyAttemptTransition,
  classifyStageBApplyAttemptReconciliationState,
  classifyStageBReservationAwsResult,
  createStageBApplyAttemptReconciliationArtifact,
  createStageBApplyAttemptReconciliationAuthorization,
  createStageBApplyAttemptReconciliationClaim,
  createStageBApplyAttemptReservation,
  createStageBApplyAttemptSuccessorReservation,
  createStageBApplyAttemptTransition,
  stageBApplyAttemptReconciliationSha256,
} from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const digest = (value) => value.repeat(64);
const predecessorSource = "b".repeat(40);
const successorSource = "c".repeat(40);
const now = new Date("2026-08-30T04:03:00.000Z");
const exactV2 = () => ({ schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 });
const reservation = () => createStageBApplyAttemptReservation({ sourceSha: predecessorSource, planSha256: digest("a"), savedPlanSha256: digest("b"), stateLineage: "lineage", stateSerial: 102, stateSha256: digest("c"), workspace: "default", backendIdentitySha256: digest("d"), executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:00:00.000Z" });
const intent = (value) => createStageBApplyAttemptTransition(value, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null } });
const spawnUncertain = (value) => createStageBApplyAttemptTransition(value, { status: "APPLY_SPAWN_UNCERTAIN", operationResult: { classification: "APPLY_SPAWN_UNCERTAIN", readback: "EXACT" }, applyMayHaveOccurred: true, applyStarted: { status: "REACHABLE", evidenceSha256: digest("e") }, applyResult: { status: "PENDING", evidenceSha256: null } });
const approval = ({ sourceSha = successorSource, actor = "operator", reviewer = "reviewer", preventSelfReview = true, observedAt = now.toISOString() } = {}) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: preventSelfReview, reviewers: [{ type: "User", reviewer: { id: 7, login: reviewer } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: actor, actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: reviewer }, observedAt });
const artifact = (initial = reservation(), transitions = [intent(initial)], generatedAt = now.toISOString()) => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: initial, historicalTransitions: transitions, successorSourceSha: successorSource, generatedAt, now });
const authorized = (value) => {
  const reconciliationArtifact = value || artifact(); const reconciliationArtifactSha256 = stageBApplyAttemptReconciliationSha256(reconciliationArtifact, { now });
  const authorization = createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: approval(), reconciliationArtifact, reconciliationArtifactSha256, successorSourceSha: successorSource, approvedBy: "reviewer", approverRole: "independent-production-reviewer", verificationRef: "review-1", now });
  return { reconciliationArtifact, reconciliationArtifactSha256, authorization };
};
const claimedTransitions = ({ reconciliationArtifact, reconciliationArtifactSha256, authorization }) => {
  const transitions = reconciliationArtifact.predecessorTransitions;
  return [...transitions, createStageBApplyAttemptReconciliationClaim({ reservation: reconciliationArtifact.predecessorReservation, transitions, reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256: authorization.authorizationSha256, successorSourceSha: successorSource, now })];
};

test("the exact historical v2 incident is parseable but permanently non-retryable", () => {
  const historical = exactV2();
  assert.doesNotThrow(() => assertHistoricalStageBV2Incident(historical));
  assert.equal(classifyStageBApplyAttemptReconciliationState(historical).status, "HISTORICAL_V2_INSUFFICIENT_DURABLE_EVIDENCE");
  assert.throws(() => assertHistoricalStageBV2Incident({ ...historical, planSha256: digest("f") }), /exact reviewed incident/);
  for (const suppliedEvidence of [{ observedAt: now.toISOString(), evidenceSource: [{ kind: "local" }, { kind: "remote" }] }, { currentStateSha256: HISTORICAL_STAGE_B_V2_INCIDENT.stateSha256, providerMutationObserved: false }, { approvedBy: "reviewer", signedCurrentObservation: digest("1") }]) {
    assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: historical, successorSourceSha: successorSource, generatedAt: now.toISOString(), now, ...suppliedEvidence }), /permanently non-retryable/);
    assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: historical, transitions: [], reconciliationArtifact: {}, reconciliationArtifactSha256: digest("2"), authorization: {}, authorizationSha256: digest("3"), successorSourceSha: successorSource, now, ...suppliedEvidence }), /permanently non-retryable/);
  }
});

test("v3 preserves the pre-spawn boundary and makes post-spawn states terminal", () => {
  const initial = reservation(); const beforeSpawn = intent(initial); const uncertain = spawnUncertain(beforeSpawn);
  assert.equal(beforeSpawn.applyMayHaveOccurred, false);
  assert.equal(uncertain.applyMayHaveOccurred, true);
  assert.equal(artifact(initial, [beforeSpawn]).bridgeType, "V3_APPLY_INTENT_PRE_TERRAFORM");
  assert.throws(() => artifact(initial, [beforeSpawn, uncertain]), /pre-spawn/);
  const applied = createStageBApplyAttemptTransition(uncertain, { status: "APPLIED", operationResult: { classification: "APPLY_RESULT_COMMITTED", readback: "EXACT" }, applyStarted: uncertain.applyStarted, applyResult: { status: "SUCCEEDED", evidenceSha256: digest("4") } });
  assert.throws(() => createStageBApplyAttemptTransition(applied, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null } }), /monotonic/);
});

test("future reconciliation trusts only canonical S3 history, not caller descriptors", () => {
  const source = readFileSync(new URL("../aws/stage-b-apply-attempt-reconciliation-contract.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /evidenceSource|authenticatedBy|terraformProcessStarted|providerSideMutationEvidence/);
  const initial = reservation(); const beforeSpawn = intent(initial);
  const first = artifact(initial, [beforeSpawn]);
  const second = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: initial, historicalTransitions: [beforeSpawn], successorSourceSha: successorSource, generatedAt: now.toISOString(), now, evidenceSource: [{ kind: "caller-text", sha256: digest("7") }] });
  assert.deepEqual(second, first);
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: { ...initial, planSha256: digest("8") }, historicalTransitions: [beforeSpawn], successorSourceSha: successorSource, generatedAt: now.toISOString(), now }), /transition|predecessor/);
});

test("reconciliation freshness and protected approval are rechecked at successor preparation", () => {
  const initial = reservation(); const beforeSpawn = intent(initial);
  assert.doesNotThrow(() => artifact(initial, [beforeSpawn], "2026-08-30T03:03:00.001Z"));
  for (const generatedAt of ["2026-not-a-date", "2026-08-30T03:03:00.000Z", "2026-08-30T04:04:00.001Z"]) assert.throws(() => artifact(initial, [beforeSpawn], generatedAt), /malformed|stale\/expired|future/);
  const binding = authorized(artifact(initial, [beforeSpawn]));
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: initial, transitions: claimedTransitions(binding), reconciliationArtifact: binding.reconciliationArtifact, reconciliationArtifactSha256: binding.reconciliationArtifactSha256, authorization: binding.authorization, authorizationSha256: binding.authorization.authorizationSha256, successorSourceSha: successorSource, now: new Date("2026-08-30T04:33:00.001Z") }), /stale or malformed/);
});

test("actual review is independent, source-bound, and cannot be fabricated", () => {
  const current = artifact(); const currentSha = stageBApplyAttemptReconciliationSha256(current, { now });
  for (const invalidApproval of [approval({ actor: "operator", reviewer: "operator", preventSelfReview: true }), approval({ preventSelfReview: false })]) assert.throws(() => createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: invalidApproval, reconciliationArtifact: current, reconciliationArtifactSha256: currentSha, successorSourceSha: successorSource, approvedBy: invalidApproval.actualApproval.userLogin, approverRole: "independent-production-reviewer", verificationRef: "review-1", now }), /self-approved|self-review prevention|distinct actual/);
  const binding = authorized(current); const transitions = claimedTransitions(binding);
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: binding.reconciliationArtifact.predecessorReservation, transitions, reconciliationArtifact: binding.reconciliationArtifact, reconciliationArtifactSha256: binding.reconciliationArtifactSha256, authorization: binding.authorization, authorizationSha256: binding.authorization.authorizationSha256, successorSourceSha: successorSource, now }));
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: binding.reconciliationArtifact.predecessorReservation, transitions, reconciliationArtifact: binding.reconciliationArtifact, reconciliationArtifactSha256: binding.reconciliationArtifactSha256, authorization: binding.authorization, authorizationSha256: binding.authorization.authorizationSha256, successorSourceSha: "d".repeat(40), now }), /identity|source/);
});

test("successor preparation is append-only and cannot execute the deployment", () => {
  const binding = authorized(); const { reconciliationArtifact, reconciliationArtifactSha256, authorization } = binding; const transitions = claimedTransitions(binding);
  const successor = createStageBApplyAttemptSuccessorReservation({ currentReservation: reconciliationArtifact.predecessorReservation, currentTransitions: transitions, reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256: authorization.authorizationSha256, executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:04:00.000Z", now });
  assert.equal(successor.predecessorAttemptId, reconciliationArtifact.predecessor.reservationIdentity);
  assert.notEqual(successor.attemptId, successor.predecessorAttemptId);
  assert.equal(successor.sourceSha, successorSource);
  assert.throws(() => createStageBApplyAttemptSuccessorReservation({ currentReservation: { ...reconciliationArtifact.predecessorReservation, stateSerial: 103 }, currentTransitions: transitions, reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256: authorization.authorizationSha256, executionPrincipal: "principal", now }), /monotonic|predecessor changed/);
});

test("reservation result classifications and malformed state remain fail-closed", () => {
  assert.equal(classifyStageBReservationAwsResult({ status: 0 }).classification, "CONDITIONAL_CREATE_COMMITTED");
  for (const [stderr, expected] of [["PreconditionFailed (412)", "OCCUPIED"], ["ConditionalRequestConflict (409)", "CONCURRENT_CONFLICT"], ["AccessDenied", "AUTHORIZATION_FAILURE"], ["network timeout", "TRANSPORT_FAILURE"], ["ServiceUnavailable", "SERVICE_FAILURE"], ["unclassified", "UNKNOWN_RESULT"]]) assert.equal(classifyStageBReservationAwsResult({ status: 1, stderr }).classification, expected);
  assert.throws(() => assertStageBApplyAttemptReservation({ schemaVersion: 3 }), /schema/);
  const beforeSpawn = intent(reservation());
  assert.throws(() => assertStageBApplyAttemptReservation({ ...beforeSpawn, applyMayHaveOccurred: true }), /prove Terraform remains unreachable/);
});
