import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  STAGE_B_APPLY_ATTEMPT_RECONCILIATION_REASON,
  STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF,
  HISTORICAL_STAGE_B_V2_INCIDENT,
  assertHistoricalStageBV2Incident,
  assertStageBApplyAttemptReconciliationAuthorization,
  assertStageBApplyAttemptReconciliationEligibility,
  assertStageBApplyAttemptReconciliationArtifact,
  classifyStageBApplyAttemptReconciliationState,
  assertStageBApplyAttemptReservation,
  assertStageBApplyAttemptTransition,
  classifyStageBReservationAwsResult,
  createStageBApplyAttemptReconciliationArtifact as createRawReconciliationArtifact,
  createStageBApplyAttemptReconciliationAuthorization as createRawReconciliationAuthorization,
  createStageBApplyAttemptReservation,
  createStageBApplyAttemptSuccessorReservation,
  createStageBApplyAttemptTransition,
  stageBApplyAttemptReconciliationSha256 as rawReconciliationSha256,
  stageBApplyAttemptSuccessorIdentity,
} from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const sourceSha = "c".repeat(40);
const digest = (letter) => letter.repeat(64);
const NOW = new Date("2026-08-30T04:03:00.000Z");
const createStageBApplyAttemptReconciliationArtifact = (value) => createRawReconciliationArtifact({ ...value, generatedAt: NOW.toISOString(), now: NOW });
const stageBApplyAttemptReconciliationSha256 = (value) => rawReconciliationSha256(value, { now: NOW });
const createStageBApplyAttemptReconciliationAuthorization = (value) => createRawReconciliationAuthorization({ ...value, now: NOW });
const v3 = () => createStageBApplyAttemptReservation({
  sourceSha,
  planSha256: digest("a"),
  savedPlanSha256: digest("b"),
  stateLineage: HISTORICAL_STAGE_B_V2_INCIDENT.stateLineage,
  stateSerial: HISTORICAL_STAGE_B_V2_INCIDENT.stateSerial,
  stateSha256: HISTORICAL_STAGE_B_V2_INCIDENT.stateSha256,
  workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace,
  backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256,
  executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
  createdAt: "2026-08-30T04:00:00.000Z",
});
const observation = () => ({
  reservationIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity,
  sourceSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha,
  planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256,
  savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256,
  stateLineage: HISTORICAL_STAGE_B_V2_INCIDENT.stateLineage,
  stateSerial: HISTORICAL_STAGE_B_V2_INCIDENT.stateSerial,
  stateSha256: HISTORICAL_STAGE_B_V2_INCIDENT.stateSha256,
  workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace,
  backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256,
  applyEntrypointReached: false,
  terraformProcessStarted: false,
  providerSideMutationEvidence: "NONE",
  infrastructureMutationDetected: false,
  localReservationMarkerCreated: false,
  observedAt: "2026-08-30T04:02:00.000Z",
  evidenceSource: [{ domain: "LOCAL_EXECUTION", kind: "orchestrator-result", sha256: digest("d"), authenticatedBy: "release-deployer" }, { domain: "REMOTE_STATE_AND_INFRASTRUCTURE", kind: "state-and-reference-read", sha256: digest("e"), authenticatedBy: "independent-checker" }],
});
const approval = (artifact, { approvalSourceSha = sourceSha, ...overrides } = {}) => createStageBApplyAttemptReconciliationAuthorization({
  protectedEnvironmentApprovalEvidence: createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] },
    repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: approvalSourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF,
    eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "reviewer" }, observedAt: "2026-08-30T04:03:00.000Z",
  }),
  reconciliationArtifact: artifact,
  reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact),
  successorSourceSha: approvalSourceSha,
  approvedBy: "reviewer",
  approverRole: "independent-production-reviewer",
  verificationRef: "incident-review-1",
  ...overrides,
});

const historicalReservation = () => ({ schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 });

test("future reservations carry owner, exact tuple, structured result, and explicit pre-apply state", () => {
  const reservation = v3();
  assert.doesNotThrow(() => assertStageBApplyAttemptReservation(reservation));
  assert.equal(reservation.status, "RESERVED");
  assert.equal(reservation.applyMayHaveOccurred, false);
  assert.equal(reservation.applyStarted.status, "NOT_STARTED");
  assert.equal(reservation.operationResult.classification, "CONDITIONAL_CREATE_COMMITTED");
  assert.notEqual(reservation.attemptId, stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId: reservation.attemptId, reconciliationArtifactSha256: digest("f"), sourceSha, planSha256: reservation.planSha256, savedPlanSha256: reservation.savedPlanSha256, stateLineage: reservation.stateLineage, stateSerial: reservation.stateSerial, stateSha256: reservation.stateSha256, workspace: reservation.workspace, backendIdentitySha256: reservation.backendIdentitySha256 }));
});

test("reservation state transitions are append-only and ambiguous states are terminal until reconciliation", () => {
  const reserved = v3();
  const applying = createStageBApplyAttemptTransition(reserved, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyStarted: { status: "INTENT_RECORDED", evidenceSha256: digest("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  const unknown = createStageBApplyAttemptTransition(applying, { status: "UNKNOWN", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "UNKNOWN", evidenceSha256: digest("2") }, applyResult: { status: "UNKNOWN", evidenceSha256: digest("3") } });
  assert.equal(unknown.sequence, 2);
  assert.doesNotThrow(() => assertStageBApplyAttemptTransition(applying, unknown));
  assert.throws(() => createStageBApplyAttemptTransition(unknown, { status: "APPLY_INTENT_RECORDED", operationResult: unknown.operationResult, applyStarted: unknown.applyStarted, applyResult: unknown.applyResult }), /reservation|monotonic|authorized/);
  assert.throws(() => createStageBApplyAttemptTransition(reserved, { status: "APPLIED", operationResult: unknown.operationResult, applyStarted: unknown.applyStarted, applyResult: { status: "SUCCEEDED", evidenceSha256: digest("4") } }), /successful|authorized/);
});

test("AWS reservation outcomes remain distinguishable without persisting command output", () => {
  assert.equal(classifyStageBReservationAwsResult({ status: 0, stdout: "ok", stderr: "" }).classification, "CONDITIONAL_CREATE_COMMITTED");
  assert.equal(classifyStageBReservationAwsResult({ status: 1, stdout: "", stderr: "PreconditionFailed (412)" }).classification, "OCCUPIED");
  assert.equal(classifyStageBReservationAwsResult({ status: 1, stdout: "", stderr: "AccessDenied" }).classification, "AUTHORIZATION_FAILURE");
  assert.equal(classifyStageBReservationAwsResult({ status: 1, stdout: "", stderr: "connection timeout" }).classification, "TRANSPORT_FAILURE");
  assert.equal(classifyStageBReservationAwsResult({ status: 1, stdout: "", stderr: "ServiceUnavailable" }).classification, "SERVICE_FAILURE");
  assert.equal(classifyStageBReservationAwsResult({ status: 1, stdout: "", stderr: "other" }).classification, "UNKNOWN_RESULT");
});

test("only the exact historical schema-v2 incident enters the explicit bridge", () => {
  assert.throws(() => assertStageBApplyAttemptReservation({ schemaVersion: 2 }, { allowHistoricalV2: true }), /schema/);
  assert.throws(() => assertStageBApplyAttemptReservation({ ...HISTORICAL_STAGE_B_V2_INCIDENT, schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt" }, { allowHistoricalV2: true }), /schema/);
  const exact = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  assert.doesNotThrow(() => assertHistoricalStageBV2Incident(exact));
  assert.throws(() => assertHistoricalStageBV2Incident({ ...exact, planSha256: digest("9") }), /exact reviewed incident/);
});

test("historical reconciliation requires fresh independent evidence and fresh protected approval", () => {
  const reservation = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationArtifact(artifact, { successorSourceSha: sourceSha, now: NOW }));
  const auth = approval(artifact);
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationAuthorization(auth, { successorSourceSha: sourceSha, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), now: NOW }));
  assert.deepEqual(assertStageBApplyAttemptReconciliationEligibility({ reservation, transitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization: auth, authorizationSha256: auth.authorizationSha256, successorSourceSha: sourceSha, now: NOW }), { status: "RECOVERABLE", successorAttemptId: auth.successorAttemptId, maximumTerraformApplies: 1 });
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), applyEntrypointReached: true }, successorSourceSha: sourceSha }), /pre-Terraform/);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation, transitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization: null, authorizationSha256: null, successorSourceSha: sourceSha, now: NOW }), /authorization/);
});

test("reconciliation observations use strict, bounded, independently authenticated time evidence", () => {
  const reservation = historicalReservation();
  assert.doesNotThrow(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha }));
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), observedAt: "2026-not-a-date" }, successorSourceSha: sourceSha }), /timestamp is malformed/);
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), observedAt: "2026-08-30T03:03:00.000Z" }, successorSourceSha: sourceSha }), /stale\/expired/);
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), observedAt: "2026-08-30T04:04:01.000Z" }, successorSourceSha: sourceSha }), /future/);
  const boundary = { ...observation(), observedAt: "2026-08-30T03:03:00.001Z" };
  assert.doesNotThrow(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: boundary, successorSourceSha: sourceSha }));
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  const auth = approval(artifact);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation, transitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization: auth, authorizationSha256: auth.authorizationSha256, successorSourceSha: sourceSha, now: new Date("2026-08-30T05:02:00.000Z") }), /stale\/expired/);
});

test("reconciliation evidence requires the two distinct execution and remote-state domains", () => {
  const reservation = historicalReservation();
  const duplicate = observation();
  duplicate.evidenceSource = [duplicate.evidenceSource[0], { ...duplicate.evidenceSource[0], domain: "REMOTE_STATE_AND_INFRASTRUCTURE" }];
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: duplicate, successorSourceSha: sourceSha }), /independent/);
  const sameAuthenticator = observation(); sameAuthenticator.evidenceSource[1] = { ...sameAuthenticator.evidenceSource[1], authenticatedBy: sameAuthenticator.evidenceSource[0].authenticatedBy };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: sameAuthenticator, successorSourceSha: sourceSha }), /independent/);
  const sameDigest = observation(); sameDigest.evidenceSource[1] = { ...sameDigest.evidenceSource[1], sha256: sameDigest.evidenceSource[0].sha256 };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: sameDigest, successorSourceSha: sourceSha }), /independent/);
});

test("v3 reserved attempts have an explicit pre-spawn recovery candidate while apply intent remains indeterminate", () => {
  const reserved = v3();
  const intent = createStageBApplyAttemptTransition(reserved, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyStarted: { status: "INTENT_RECORDED", evidenceSha256: digest("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  const genericObservation = { ...observation(), reservationIdentity: reserved.attemptId, sourceSha: reserved.sourceSha, planSha256: reserved.planSha256, savedPlanSha256: reserved.savedPlanSha256, stateLineage: reserved.stateLineage, stateSerial: reserved.stateSerial, stateSha256: reserved.stateSha256, workspace: reserved.workspace, backendIdentitySha256: reserved.backendIdentitySha256 };
  assert.doesNotThrow(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reserved, observation: genericObservation, successorSourceSha: "d".repeat(40) }));
  const successorSourceSha = "d".repeat(40);
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reserved, historicalTransitions: [intent], observation: { ...genericObservation, localReservationMarkerCreated: true }, successorSourceSha });
  assert.equal(artifact.bridgeType, "V3_APPLY_INTENT_PRE_TERRAFORM");
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: historicalReservation(), observation: { ...observation(), localReservationMarkerCreated: true }, successorSourceSha }), /pre-Terraform/);
  const authorization = approval(artifact, { approvalSourceSha: successorSourceSha });
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: reserved, transitions: [intent], reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization, authorizationSha256: authorization.authorizationSha256, successorSourceSha, now: NOW }));
  const unknown = createStageBApplyAttemptTransition(intent, { status: "UNKNOWN", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "UNKNOWN", evidenceSha256: digest("2") }, applyResult: { status: "UNKNOWN", evidenceSha256: digest("3") } });
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reserved, historicalTransitions: [intent, unknown], observation: genericObservation, successorSourceSha }), /pre-spawn reservation or apply intent/);
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: intent, observation: genericObservation, successorSourceSha: "d".repeat(40) }), /indeterminate|reservation/);
  assert.deepEqual(classifyStageBApplyAttemptReconciliationState(intent), { status: "INDETERMINATE_NO_AUTOMATIC_SUCCESSOR", automaticSuccessorAllowed: false });
});

test("age, unchanged serial, or missing local marker cannot create reconciliation evidence", () => {
  const bad = { ...observation(), evidenceSource: [] };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: { schemaVersion: 2 }, observation: bad, successorSourceSha: sourceSha }), /schema|exact reviewed incident/);
  const reservation = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), evidenceSource: [{ domain: "LOCAL_EXECUTION", kind: "age", sha256: digest("d"), authenticatedBy: "operator" }] }, successorSourceSha: sourceSha }), /independently/);
});

test("transition tuple, predecessor, and successor identities are immutable and distinct", () => {
  const reserved = v3();
  const applying = createStageBApplyAttemptTransition(reserved, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyStarted: { status: "INTENT_RECORDED", evidenceSha256: digest("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  assert.throws(() => assertStageBApplyAttemptTransition(applying, { ...applying, sequence: 2, sourceSha: "d".repeat(40) }), /monotonic/);
  const unknown = createStageBApplyAttemptTransition(applying, { status: "UNKNOWN", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "UNKNOWN", evidenceSha256: digest("2") }, applyResult: { status: "UNKNOWN", evidenceSha256: digest("3") } });
  assert.throws(() => createStageBApplyAttemptTransition(unknown, { status: "ABORTED_BEFORE_APPLY", operationResult: unknown.operationResult, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null }, applyMayHaveOccurred: false }), /monotonic|authorized|ABORTED/);
  const binding = { artifactSha256: digest("4"), authorizationSha256: digest("5"), successorAttemptId: digest("6") };
  const aborted = createStageBApplyAttemptTransition(reserved, { status: "ABORTED_BEFORE_APPLY", operationResult: { classification: "CONDITIONAL_CREATE_COMMITTED", readback: "EXACT" }, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null }, applyMayHaveOccurred: false, reconciliationBinding: binding });
  assert.doesNotThrow(() => assertStageBApplyAttemptReservation(aborted));
  assert.notEqual(stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId: reserved.attemptId, reconciliationArtifactSha256: digest("7"), sourceSha, planSha256: reserved.planSha256, savedPlanSha256: reserved.savedPlanSha256, stateLineage: reserved.stateLineage, stateSerial: reserved.stateSerial, stateSha256: reserved.stateSha256, workspace: reserved.workspace, backendIdentitySha256: reserved.backendIdentitySha256 }), reserved.attemptId);
});

test("reconciliation authorization cannot substitute its predecessor or expose material", () => {
  const reservation = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  const auth = approval(artifact);
  const forged = { ...auth, predecessor: { ...auth.predecessor, planSha256: digest("8") } };
  assert.throws(() => assertStageBApplyAttemptReconciliationAuthorization(forged, { successorSourceSha: sourceSha, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), now: NOW }), /predecessor binding|hash/);
  assert.equal(JSON.stringify(artifact).includes("secretValue"), false);
  assert.equal(JSON.stringify(artifact).includes("SecretString"), false);
  assert.equal(JSON.stringify(auth).includes("SecretString"), false);
});

test("successor preparation rechecks the complete current predecessor history and approval freshness", () => {
  const predecessor = historicalReservation();
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: predecessor, observation: observation(), successorSourceSha: sourceSha });
  const artifactSha256 = stageBApplyAttemptReconciliationSha256(artifact);
  const auth = approval(artifact);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: predecessor, transitions: [{ schemaVersion: 3 }], reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha256, authorization: auth, authorizationSha256: auth.authorizationSha256, successorSourceSha: sourceSha, now: NOW }), /transitions|schema/);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation: predecessor, transitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha256, authorization: auth, authorizationSha256: auth.authorizationSha256, successorSourceSha: sourceSha, now: new Date("2026-08-30T04:33:00.001Z") }), /stale or malformed/);
});

test("the historical bridge binds every incident tuple field and creates a new successor identity", () => {
  const reservation = historicalReservation();
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  const artifactSha256 = stageBApplyAttemptReconciliationSha256(artifact);
  const auth = approval(artifact);
  const successor = createStageBApplyAttemptSuccessorReservation({ currentReservation: reservation, currentTransitions: [], reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha256, authorization: auth, authorizationSha256: auth.authorizationSha256, executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:05:00.000Z", now: NOW });
  assert.equal(successor.predecessorAttemptId, HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity);
  assert.equal(successor.sourceSha, sourceSha);
  assert.notEqual(successor.attemptId, HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity);
  for (const [field, replacement] of Object.entries({ sourceSha: "d".repeat(40), planSha256: digest("9"), savedPlanSha256: digest("8"), stateLineage: "other-lineage", stateSerial: 103, stateSha256: digest("7"), workspace: "other", backendIdentitySha256: digest("6"), createdAt: "2026-08-30T03:38:40.213Z" })) {
    assert.throws(() => assertHistoricalStageBV2Incident({ ...reservation, [field]: replacement }), /schema|exact reviewed incident/);
  }
});

test("reconciliation source contains no reservation bypass or destructive retry seam", () => {
  const source = readFileSync(new URL("../aws/stage-b-apply-attempt-reconciliation.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /(?:--force|--ignore-reservation|--delete-reservation|--retry-anyway|delete-object|terraform\s+apply|PutSecretValue|UpdateSecretVersionStage)/i);
  assert.match(source, /SUCCESSOR_READY_BUT_NOT_EXECUTED/);
});
