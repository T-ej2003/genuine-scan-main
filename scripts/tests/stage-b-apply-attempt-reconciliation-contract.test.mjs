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
  assertStageBApplyAttemptReservation,
  assertStageBApplyAttemptTransition,
  classifyStageBReservationAwsResult,
  createStageBApplyAttemptReconciliationArtifact,
  createStageBApplyAttemptReconciliationAuthorization,
  createStageBApplyAttemptReservation,
  createStageBApplyAttemptSuccessorReservation,
  createStageBApplyAttemptTransition,
  stageBApplyAttemptReconciliationSha256,
  stageBApplyAttemptSuccessorIdentity,
} from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const sourceSha = "c".repeat(40);
const digest = (letter) => letter.repeat(64);
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
  evidenceSource: [{ kind: "orchestrator-result", sha256: digest("d"), authenticatedBy: "release-deployer" }, { kind: "state-and-reference-read", sha256: digest("e"), authenticatedBy: "independent-checker" }],
});
const approval = (artifact, overrides = {}) => createStageBApplyAttemptReconciliationAuthorization({
  protectedEnvironmentApprovalEvidence: createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] },
    repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF,
    eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "reviewer" }, observedAt: "2026-08-30T04:03:00.000Z",
  }),
  reconciliationArtifact: artifact,
  reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact),
  successorSourceSha: sourceSha,
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
  const applying = createStageBApplyAttemptTransition(reserved, { status: "APPLYING", operationResult: { classification: "CONDITIONAL_CREATE_COMMITTED", readback: "EXACT" }, applyStarted: { status: "REACHABLE", evidenceSha256: digest("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  const unknown = createStageBApplyAttemptTransition(applying, { status: "UNKNOWN", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "UNKNOWN", evidenceSha256: digest("2") }, applyResult: { status: "UNKNOWN", evidenceSha256: digest("3") } });
  assert.equal(unknown.sequence, 2);
  assert.doesNotThrow(() => assertStageBApplyAttemptTransition(applying, unknown));
  assert.throws(() => createStageBApplyAttemptTransition(unknown, { status: "APPLYING", operationResult: unknown.operationResult, applyStarted: unknown.applyStarted, applyResult: unknown.applyResult }), /reservation|monotonic|authorized/);
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
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationArtifact(artifact, { successorSourceSha: sourceSha }));
  const auth = approval(artifact);
  assert.doesNotThrow(() => assertStageBApplyAttemptReconciliationAuthorization(auth, { successorSourceSha: sourceSha, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact) }));
  assert.deepEqual(assertStageBApplyAttemptReconciliationEligibility({ reservation, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization: auth, authorizationSha256: auth.authorizationSha256, successorSourceSha: sourceSha }), { status: "RECOVERABLE", successorAttemptId: auth.successorAttemptId, maximumTerraformApplies: 1 });
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), applyEntrypointReached: true }, successorSourceSha: sourceSha }), /pre-Terraform/);
  assert.throws(() => assertStageBApplyAttemptReconciliationEligibility({ reservation, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact), authorization: null, authorizationSha256: null, successorSourceSha: sourceSha }), /authorization/);
});

test("age, unchanged serial, or missing local marker cannot create reconciliation evidence", () => {
  const bad = { ...observation(), evidenceSource: [] };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: { schemaVersion: 2 }, observation: bad, successorSourceSha: sourceSha }), /schema|exact reviewed incident/);
  const reservation = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  assert.throws(() => createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: { ...observation(), evidenceSource: [{ kind: "age", sha256: digest("d"), authenticatedBy: "operator" }] }, successorSourceSha: sourceSha }), /independently/);
});

test("transition tuple, predecessor, and successor identities are immutable and distinct", () => {
  const reserved = v3();
  const applying = createStageBApplyAttemptTransition(reserved, { status: "APPLYING", operationResult: { classification: "APPLY_ENTRYPOINT_REACHED", readback: "EXACT" }, applyStarted: { status: "REACHABLE", evidenceSha256: digest("1") }, applyResult: { status: "PENDING", evidenceSha256: null } });
  assert.throws(() => assertStageBApplyAttemptTransition(applying, { ...applying, sequence: 2, sourceSha: "d".repeat(40) }), /monotonic/);
  const unknown = createStageBApplyAttemptTransition(applying, { status: "UNKNOWN", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "UNKNOWN", evidenceSha256: digest("2") }, applyResult: { status: "UNKNOWN", evidenceSha256: digest("3") } });
  assert.throws(() => createStageBApplyAttemptTransition(unknown, { status: "ABORTED_BEFORE_APPLY", operationResult: unknown.operationResult, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null }, applyMayHaveOccurred: false }), /reconciliation|bind/);
  const binding = { artifactSha256: digest("4"), authorizationSha256: digest("5"), successorAttemptId: digest("6") };
  const aborted = createStageBApplyAttemptTransition(unknown, { status: "ABORTED_BEFORE_APPLY", operationResult: { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" }, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null }, applyMayHaveOccurred: false, reconciliationBinding: binding });
  assert.doesNotThrow(() => assertStageBApplyAttemptReservation(aborted));
  assert.notEqual(stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId: reserved.attemptId, reconciliationArtifactSha256: digest("7"), sourceSha, planSha256: reserved.planSha256, savedPlanSha256: reserved.savedPlanSha256, stateLineage: reserved.stateLineage, stateSerial: reserved.stateSerial, stateSha256: reserved.stateSha256, workspace: reserved.workspace, backendIdentitySha256: reserved.backendIdentitySha256 }), reserved.attemptId);
});

test("reconciliation authorization cannot substitute its predecessor or expose material", () => {
  const reservation = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  const auth = approval(artifact);
  const forged = { ...auth, predecessor: { ...auth.predecessor, planSha256: digest("8") } };
  assert.throws(() => assertStageBApplyAttemptReconciliationAuthorization(forged, { successorSourceSha: sourceSha, reconciliationArtifact: artifact, reconciliationArtifactSha256: stageBApplyAttemptReconciliationSha256(artifact) }), /predecessor binding|hash/);
  assert.equal(JSON.stringify(artifact).includes("secretValue"), false);
  assert.equal(JSON.stringify(artifact).includes("SecretString"), false);
  assert.equal(JSON.stringify(auth).includes("SecretString"), false);
});

test("the historical bridge binds every incident tuple field and creates a new successor identity", () => {
  const reservation = historicalReservation();
  const artifact = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: reservation, observation: observation(), successorSourceSha: sourceSha });
  const artifactSha256 = stageBApplyAttemptReconciliationSha256(artifact);
  const auth = approval(artifact);
  const successor = createStageBApplyAttemptSuccessorReservation({ reconciliationArtifact: artifact, reconciliationArtifactSha256: artifactSha256, authorization: auth, authorizationSha256: auth.authorizationSha256, executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:05:00.000Z" });
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
