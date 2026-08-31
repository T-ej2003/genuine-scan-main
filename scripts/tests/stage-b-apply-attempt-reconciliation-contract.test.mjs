import assert from "node:assert/strict";
import test from "node:test";
import { HISTORICAL_STAGE_B_V2_INCIDENT, STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, assertStageBApplyAttemptReconciliationEligibility, assertStageBApplyAttemptReservation, assertStageBApplyAttemptTransition, classifyStageBApplyAttemptReconciliationState, createStageBApplyAttemptReconciliationArtifact, createStageBApplyAttemptReconciliationAuthorization, createStageBApplyAttemptReservation, createStageBApplyAttemptTransition, stageBApplyAttemptReconciliationSha256 } from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const sha = (value) => value.repeat(64);
const sourceSha = "c".repeat(40);
const now = new Date("2026-08-30T04:03:00.000Z");
const reservation = () => createStageBApplyAttemptReservation({ sourceSha, planSha256: sha("a"), savedPlanSha256: sha("b"), stateLineage: "lineage", stateSerial: 102, stateSha256: sha("c"), workspace: "default", backendIdentitySha256: sha("d"), executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:00:00.000Z" });
const intent = (value) => createStageBApplyAttemptTransition(value, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null } });
const approval = ({ source = sourceSha, selfReview = false } = {}) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: !selfReview, reviewers: [{ type: "User", reviewer: { id: 7, login: selfReview ? "operator" : "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: source, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: selfReview ? "operator" : "reviewer" }, observedAt: now.toISOString() });

test("v3 records a recoverable pre-spawn intent and permanently blocks post-spawn uncertainty", () => {
  const initial = reservation(); const beforeSpawn = intent(initial);
  assert.doesNotThrow(() => assertStageBApplyAttemptTransition(initial, beforeSpawn));
  assert.equal(beforeSpawn.applyMayHaveOccurred, false);
  assert.equal(classifyStageBApplyAttemptReconciliationState(initial).status, "V3_RESERVED_BEFORE_APPLY_CANDIDATE");
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: initial, historicalTransitions: [beforeSpawn], successorSourceSha: "e".repeat(40), generatedAt: now.toISOString(), now });
  assert.equal(artifact.bridgeType, "V3_APPLY_INTENT_PRE_TERRAFORM");
  const spawnUncertain = createStageBApplyAttemptTransition(beforeSpawn, { status: "APPLY_SPAWN_UNCERTAIN", operationResult: { classification: "APPLY_SPAWN_UNCERTAIN", readback: "EXACT" }, applyStarted: { status: "REACHABLE", evidenceSha256: sha("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: initial, historicalTransitions: [beforeSpawn, spawnUncertain], successorSourceSha: "e".repeat(40), generatedAt: now.toISOString(), now }), /pre-spawn/);
});

test("the historical v2 incident remains immutable evidence but cannot be auto-reconciled from a typed observation", () => {
  const historical = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: "default", backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  assert.equal(classifyStageBApplyAttemptReconciliationState(historical).status, "HISTORICAL_V2_INSUFFICIENT_DURABLE_EVIDENCE");
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: historical, successorSourceSha: sourceSha, generatedAt: now.toISOString(), now }), /durable independent/);
});

test("successor eligibility requires exact v3 history and an actual distinct reviewer", () => {
  const initial = reservation(); const beforeSpawn = intent(initial); const successor = "e".repeat(40);
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: initial, historicalTransitions: [beforeSpawn], successorSourceSha: successor, generatedAt: now.toISOString(), now }); const artifactSha = stageBApplyAttemptReconciliationSha256(artifact, { now });
  const authorization = createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: approval({ source: successor }), reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha, successorSourceSha: successor, approvedBy: "reviewer", approverRole: "independent-production-reviewer", verificationRef: "review-1", now });
  assert.equal(assertStageBApplyAttemptReconciliationEligibility({ reservation: initial, transitions: [beforeSpawn], reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha, authorization, authorizationSha256: authorization.authorizationSha256, successorSourceSha: successor, now }).status, "RECOVERABLE");
  assert.throws(() => createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: approval({ source: successor, selfReview: true }), reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha, successorSourceSha: successor, approvedBy: "operator", approverRole: "independent-production-reviewer", verificationRef: "review-1", now }), /self-review|distinct actual/);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: initial, transitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha, authorization, authorizationSha256: authorization.authorizationSha256, successorSourceSha: successor, now }), /predecessor changed/);
});

test("malformed pre-spawn and post-spawn transitions fail closed", () => {
  const initial = reservation(); const beforeSpawn = intent(initial);
  assert.throws(() => assertStageBApplyAttemptReservation({ ...beforeSpawn, applyMayHaveOccurred: true }), /prove Terraform remains unreachable/);
  assert.throws(() => createStageBApplyAttemptTransition(beforeSpawn, { status: "APPLIED", operationResult: { classification: "APPLY_RESULT_COMMITTED", readback: "EXACT" }, applyStarted: { status: "REACHABLE", evidenceSha256: sha("2") }, applyResult: { status: "SUCCEEDED", evidenceSha256: sha("3") } }), /authorized/);
});
