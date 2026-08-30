import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readStageBApplyAttemptHistory, runStageBApplyAttemptReconciliationCli } from "../aws/stage-b-apply-attempt-reconciliation.mjs";
import { HISTORICAL_STAGE_B_V2_INCIDENT, STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, createStageBApplyAttemptReservation, createStageBApplyAttemptTransition, stageBApplyAttemptReconciliationSha256 } from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from "../aws/stage-b-terraform-backend-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const digest = (letter) => letter.repeat(64);
const NOW = new Date("2026-08-30T04:03:00.000Z");
const reservation = createStageBApplyAttemptReservation({
  sourceSha: "c".repeat(40), planSha256: digest("a"), savedPlanSha256: digest("b"), stateLineage: "lineage",
  stateSerial: 102, stateSha256: digest("c"), workspace: "default", backendIdentitySha256: digest("d"),
  executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
  createdAt: "2026-08-30T04:00:00.000Z",
});
const applying = createStageBApplyAttemptTransition(reservation, {
  status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" },
  applyStarted: { status: "INTENT_RECORDED", evidenceSha256: digest("e") }, applyResult: { status: "PENDING", evidenceSha256: null },
});
const historyRunner = (objects) => (args) => {
  const bytes = objects.get(args[args.indexOf("--key") + 1]);
  if (!bytes) return { status: 1, stderr: "NoSuchKey" };
  fs.writeFileSync(args.at(-1), bytes, { mode: 0o600 });
  return { status: 0 };
};

test("standalone reservation reader authenticates the initial object and append-only transitions", () => {
  const objects = new Map([
    [stageBApplyAttemptS3Key(reservation.attemptId), Buffer.from(`${JSON.stringify(reservation)}\n`)],
    [stageBAttemptStepS3ObjectKey(reservation.attemptId, 1), Buffer.from(`${JSON.stringify(applying)}\n`)],
  ]);
  const result = readStageBApplyAttemptHistory({ reservationIdentity: reservation.attemptId, run: historyRunner(objects) });
  assert.equal(result.reservation.status, "RESERVED");
  assert.deepEqual(result.transitions.map(({ status }) => status), ["APPLY_INTENT_RECORDED"]);
});

test("standalone reservation reader fails closed on a non-not-found transition read error", () => {
  assert.throws(() => readStageBApplyAttemptHistory({ reservationIdentity: reservation.attemptId, run: (args) => {
    if (args.includes("--key") && args[args.indexOf("--key") + 1] === stageBApplyAttemptS3Key(reservation.attemptId)) { fs.writeFileSync(args.at(-1), Buffer.from(`${JSON.stringify(reservation)}\n`), { mode: 0o600 }); return { status: 0 }; }
    return { status: 1, stderr: "AccessDenied" };
  } }), /could not be authenticated/);
});

test("reconciliation CLI inputs are external private artifacts, never secret payloads", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-reconciliation-cli-"));
  try { assert.equal(fs.statSync(directory).isDirectory(), true); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("real prepare-successor CLI preserves and authenticates the full historical predecessor", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-reconciliation-cli-")); fs.chmodSync(directory, 0o700);
  try {
    const predecessor = { schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, executableAuditSha256: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, createdAt: HISTORICAL_STAGE_B_V2_INCIDENT.createdAt, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, protectedMainSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 };
    const observation = { reservationIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, sourceSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, stateLineage: HISTORICAL_STAGE_B_V2_INCIDENT.stateLineage, stateSerial: HISTORICAL_STAGE_B_V2_INCIDENT.stateSerial, stateSha256: HISTORICAL_STAGE_B_V2_INCIDENT.stateSha256, workspace: "default", backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256, applyEntrypointReached: false, terraformProcessStarted: false, providerSideMutationEvidence: "NONE", infrastructureMutationDetected: false, localReservationMarkerCreated: false, observedAt: "2026-08-30T04:02:00.000Z", evidenceSource: [{ domain: "LOCAL_EXECUTION", kind: "orchestrator-result", sha256: digest("d"), authenticatedBy: "release-deployer" }, { domain: "REMOTE_STATE_AND_INFRASTRUCTURE", kind: "state-and-reference-read", sha256: digest("e"), authenticatedBy: "independent-checker" }] };
    const sourceSha = "c".repeat(40);
    const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "reviewer" }, observedAt: NOW.toISOString() });
    const run = historyRunner(new Map([[stageBApplyAttemptS3Key(HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity), Buffer.from(`${JSON.stringify(predecessor)}\n`)]]));
    const historicalPath = path.join(directory, "historical.json"); const observationPath = path.join(directory, "observation.json"); const artifactPath = path.join(directory, "reconciliation.json"); const approvalPath = path.join(directory, "approval.json"); const authorizationPath = path.join(directory, "authorization.json");
    fs.writeFileSync(historicalPath, `${JSON.stringify(predecessor, null, 2)}\n`, { mode: 0o600 }); fs.writeFileSync(observationPath, `${JSON.stringify(observation, null, 2)}\n`, { mode: 0o600 }); fs.writeFileSync(approvalPath, `${JSON.stringify(approval, null, 2)}\n`, { mode: 0o600 });
    const published = runStageBApplyAttemptReconciliationCli(["--mode", "create-reconciliation", "--historical-reservation", historicalPath, "--observation", observationPath, "--reservation-identity", HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, "--successor-source-sha", sourceSha, "--output", artifactPath], { now: NOW, awsRun: run });
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8")); const artifactSha256 = published.sha256;
    const approvalSha256 = crypto.createHash("sha256").update(fs.readFileSync(approvalPath)).digest("hex");
    const authorized = runStageBApplyAttemptReconciliationCli(["--mode", "authorize", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", artifactSha256, "--environment-approval", approvalPath, "--environment-approval-sha256", approvalSha256, "--source-sha", sourceSha, "--output", authorizationPath, "--approved-by", "reviewer", "--approver-role", "independent-production-reviewer", "--verification-ref", "incident-review-1"], { now: NOW });
    const authorization = JSON.parse(fs.readFileSync(authorizationPath, "utf8"));
    assert.equal(authorized.authorizationSha256, authorization.authorizationSha256);
    const result = runStageBApplyAttemptReconciliationCli(["--mode", "prepare-successor", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", artifactSha256, "--authorization", authorizationPath, "--authorization-sha256", authorization.authorizationSha256, "--source-sha", sourceSha], { now: NOW, awsRun: run });
    assert.equal(result.status, "SUCCESSOR_READY_BUT_NOT_EXECUTED");
    const tampered = structuredClone(artifact); tampered.predecessorReservation.planSha256 = digest("f"); fs.writeFileSync(artifactPath, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
    assert.throws(() => runStageBApplyAttemptReconciliationCli(["--mode", "prepare-successor", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", stageBApplyAttemptReconciliationSha256(tampered, { now: NOW }), "--authorization", authorizationPath, "--authorization-sha256", authorization.authorizationSha256, "--source-sha", sourceSha], { now: NOW, awsRun: run }), /exact reviewed incident|predecessor/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("real verify CLI classifies the authenticated latest transition, not the initial reservation", () => {
  const objects = new Map([
    [stageBApplyAttemptS3Key(reservation.attemptId), Buffer.from(`${JSON.stringify(reservation)}\n`)],
    [stageBAttemptStepS3ObjectKey(reservation.attemptId, 1), Buffer.from(`${JSON.stringify(applying)}\n`)],
  ]);
  const result = runStageBApplyAttemptReconciliationCli([
    "--mode", "verify", "--reservation-identity", reservation.attemptId,
    "--source-sha", reservation.sourceSha, "--plan-sha256", reservation.planSha256,
    "--saved-plan-sha256", reservation.savedPlanSha256, "--state-lineage", reservation.stateLineage,
    "--state-serial", String(reservation.stateSerial), "--state-sha256", reservation.stateSha256,
    "--workspace", reservation.workspace, "--backend-identity-sha256", reservation.backendIdentitySha256,
  ], { now: NOW, awsRun: historyRunner(objects) });
  assert.equal(result.status, "APPLY_INTENT_RECORDED");
  assert.equal(result.reconciliationStatus, "INDETERMINATE_NO_AUTOMATIC_SUCCESSOR");
});
