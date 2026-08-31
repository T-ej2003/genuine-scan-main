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
import { createProductionGithubCommandRunner } from "../aws/production-credential-source-contract.mjs";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";

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
  applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null },
});
const spawnUncertain = (value) => createStageBApplyAttemptTransition(value, {
  status: "APPLY_SPAWN_UNCERTAIN", operationResult: { classification: "APPLY_SPAWN_UNCERTAIN", readback: "EXACT" },
  applyMayHaveOccurred: true, applyStarted: { status: "REACHABLE", evidenceSha256: digest("e") }, applyResult: { status: "PENDING", evidenceSha256: null },
});
const historyRunner = (objects) => (args) => {
  const key = args[args.indexOf("--key") + 1];
  if (args[0] === "s3api" && args[1] === "put-object") {
    if (objects.has(key)) return { status: 1, stderr: "PreconditionFailed (412)" };
    objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1]));
    return { status: 0 };
  }
  const bytes = objects.get(key);
  if (!bytes) return { status: 1, stderr: "NoSuchKey" };
  fs.writeFileSync(args.at(-1), bytes, { mode: 0o600 });
  return { status: 0 };
};
const canonicalGithubRunner = (authorization, sourceSha) => {
  const archive = Buffer.from("authenticated-authorization-archive");
  const execute = (command, args) => {
    if (command === "gh" && args[1].endsWith("/actions/runs/99")) return JSON.stringify({ id: 99, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/authorize-production-green-stage-b-apply-attempt-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } });
    if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 91, name: "stage-b-apply-attempt-reconciliation-authorization", expired: false, workflow_run: { id: 99, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}` }] }]);
    if (command === "gh" && args[1].endsWith("/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(authorization);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  return createProductionGithubCommandRunner({ env: { GH_TOKEN: "fixture-github-token" }, exec: execute });
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

test("real prepare-successor CLI authenticates a canonical v3 pre-spawn predecessor", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-reconciliation-cli-")); fs.chmodSync(directory, 0o700);
  try {
    const sourceSha = "c".repeat(40);
    const predecessor = createStageBApplyAttemptReservation({ sourceSha: "b".repeat(40), planSha256: digest("a"), savedPlanSha256: digest("b"), stateLineage: "lineage", stateSerial: 102, stateSha256: digest("c"), workspace: "default", backendIdentitySha256: digest("d"), executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:00:00.000Z" });
    const beforeSpawn = createStageBApplyAttemptTransition(predecessor, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null } });
    const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "reviewer" }, observedAt: NOW.toISOString() });
    const objects = new Map([[stageBApplyAttemptS3Key(predecessor.attemptId), Buffer.from(`${JSON.stringify(predecessor)}\n`)], [stageBAttemptStepS3ObjectKey(predecessor.attemptId, 1), Buffer.from(`${JSON.stringify(beforeSpawn)}\n`)]]);
    const canonicalRun = historyRunner(objects); let ambiguousClaimWrite = true; let claimWrites = 0;
    const run = (args) => {
      if (args[0] === "s3api" && args[1] === "put-object" && ambiguousClaimWrite) {
        claimWrites += 1;
        ambiguousClaimWrite = false;
        const key = args[args.indexOf("--key") + 1];
        objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1]));
        return { status: 1, stderr: "network timeout" };
      }
      return canonicalRun(args);
    };
    const historicalPath = path.join(directory, "historical.json"); const artifactPath = path.join(directory, "reconciliation.json"); const approvalPath = path.join(directory, "approval.json"); const authorizationPath = path.join(directory, "authorization.json");
    fs.writeFileSync(historicalPath, `${JSON.stringify(predecessor, null, 2)}\n`, { mode: 0o600 }); fs.writeFileSync(approvalPath, `${JSON.stringify(approval, null, 2)}\n`, { mode: 0o600 });
    const published = runStageBApplyAttemptReconciliationCli(["--mode", "create-reconciliation", "--historical-reservation", historicalPath, "--reservation-identity", predecessor.attemptId, "--successor-source-sha", sourceSha, "--output", artifactPath], { now: NOW, awsRun: run });
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8")); const artifactSha256 = published.sha256;
    const approvalSha256 = crypto.createHash("sha256").update(fs.readFileSync(approvalPath)).digest("hex");
    const authorized = runStageBApplyAttemptReconciliationCli(["--mode", "authorize", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", artifactSha256, "--environment-approval", approvalPath, "--environment-approval-sha256", approvalSha256, "--source-sha", sourceSha, "--output", authorizationPath, "--approved-by", "reviewer", "--approver-role", "independent-production-reviewer", "--verification-ref", "incident-review-1"], { now: NOW });
    const authorization = JSON.parse(fs.readFileSync(authorizationPath, "utf8"));
    assert.equal(authorized.authorizationSha256, authorization.authorizationSha256);
    const prepareArgs = ["--mode", "prepare-successor", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", artifactSha256, "--authorization", authorizationPath, "--authorization-sha256", authorization.authorizationSha256, "--source-sha", sourceSha, "--authorization-workflow-run-id", "99", "--authorization-workflow-run-attempt", "1"];
    assert.throws(() => runStageBApplyAttemptReconciliationCli(prepareArgs.slice(0, -4), { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(authorization, sourceSha) }), /workflow-run-id/);
    const forged = structuredClone(authorization); forged.approvedBy = "fabricator"; const { authorizationSha256: ignored, ...forgedBody } = forged; forged.authorizationSha256 = crypto.createHash("sha256").update(canonicalJson(forgedBody)).digest("hex"); fs.writeFileSync(authorizationPath, `${JSON.stringify(forged, null, 2)}\n`, { mode: 0o600 });
    assert.throws(() => runStageBApplyAttemptReconciliationCli(prepareArgs.map((value) => value === authorization.authorizationSha256 ? forged.authorizationSha256 : value), { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(authorization, sourceSha) }), /does not match the authenticated workflow artifact/);
    assert.equal(claimWrites, 0);
    fs.writeFileSync(authorizationPath, `${JSON.stringify(authorization, null, 2)}\n`, { mode: 0o600 });
    const result = runStageBApplyAttemptReconciliationCli(prepareArgs, { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(authorization, sourceSha) });
    assert.equal(result.status, "SUCCESSOR_READY_BUT_NOT_EXECUTED");
    assert.equal(JSON.parse(objects.get(stageBAttemptStepS3ObjectKey(predecessor.attemptId, 2))).status, "ABORTED_BEFORE_APPLY");
    assert.equal(ambiguousClaimWrite, false);
    assert.equal(runStageBApplyAttemptReconciliationCli(prepareArgs, { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(authorization, sourceSha) }).status, "SUCCESSOR_READY_BUT_NOT_EXECUTED");
    const tampered = structuredClone(artifact); tampered.predecessorReservation.planSha256 = digest("f"); fs.writeFileSync(artifactPath, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
    assert.throws(() => runStageBApplyAttemptReconciliationCli(["--mode", "prepare-successor", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", stageBApplyAttemptReconciliationSha256(tampered, { now: NOW }), "--authorization", authorizationPath, "--authorization-sha256", authorization.authorizationSha256, "--source-sha", sourceSha, "--authorization-workflow-run-id", "99", "--authorization-workflow-run-attempt", "1"], { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(authorization, sourceSha) }), /monotonic|predecessor|workflow|artifact/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("original continuation winning the same next slot prevents successor readiness", () => {
  const sourceSha = "c".repeat(40); const predecessor = createStageBApplyAttemptReservation({ sourceSha: "b".repeat(40), planSha256: digest("a"), savedPlanSha256: digest("b"), stateLineage: "lineage", stateSerial: 102, stateSha256: digest("c"), workspace: "default", backendIdentitySha256: digest("d"), executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", createdAt: "2026-08-30T04:00:00.000Z" }); const beforeSpawn = createStageBApplyAttemptTransition(predecessor, { status: "APPLY_INTENT_RECORDED", operationResult: { classification: "APPLY_INTENT_RECORDED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null } });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-reconciliation-race-")); fs.chmodSync(directory, 0o700);
  try {
    const objects = new Map([[stageBApplyAttemptS3Key(predecessor.attemptId), Buffer.from(`${JSON.stringify(predecessor)}\n`)], [stageBAttemptStepS3ObjectKey(predecessor.attemptId, 1), Buffer.from(`${JSON.stringify(beforeSpawn)}\n`)]]);
    const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 42, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "reviewer" }, observedAt: NOW.toISOString() });
    const historicalPath = path.join(directory, "historical.json"); const artifactPath = path.join(directory, "reconciliation.json"); const approvalPath = path.join(directory, "approval.json"); const authorizationPath = path.join(directory, "authorization.json"); fs.writeFileSync(historicalPath, `${JSON.stringify(predecessor)}\n`, { mode: 0o600 }); fs.writeFileSync(approvalPath, `${JSON.stringify(approval)}\n`, { mode: 0o600 });
    const publish = runStageBApplyAttemptReconciliationCli(["--mode", "create-reconciliation", "--historical-reservation", historicalPath, "--reservation-identity", predecessor.attemptId, "--successor-source-sha", sourceSha, "--output", artifactPath], { now: NOW, awsRun: historyRunner(objects) }); const approvalSha = crypto.createHash("sha256").update(fs.readFileSync(approvalPath)).digest("hex"); runStageBApplyAttemptReconciliationCli(["--mode", "authorize", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", publish.sha256, "--environment-approval", approvalPath, "--environment-approval-sha256", approvalSha, "--source-sha", sourceSha, "--output", authorizationPath, "--approved-by", "reviewer", "--approver-role", "independent-production-reviewer", "--verification-ref", "race-review"], { now: NOW });
    let originalWon = false; const run = (args) => {
      if (args[0] === "s3api" && args[1] === "put-object" && !originalWon) { originalWon = true; objects.set(stageBAttemptStepS3ObjectKey(predecessor.attemptId, 2), Buffer.from(`${JSON.stringify(spawnUncertain(beforeSpawn))}\n`)); return { status: 1, stderr: "PreconditionFailed (412)" }; }
      return historyRunner(objects)(args);
    };
    assert.throws(() => runStageBApplyAttemptReconciliationCli(["--mode", "prepare-successor", "--reconciliation-artifact", artifactPath, "--reconciliation-artifact-sha256", publish.sha256, "--authorization", authorizationPath, "--authorization-sha256", JSON.parse(fs.readFileSync(authorizationPath)).authorizationSha256, "--source-sha", sourceSha, "--authorization-workflow-run-id", "99", "--authorization-workflow-run-attempt", "1"], { now: NOW, awsRun: run, githubRun: canonicalGithubRunner(JSON.parse(fs.readFileSync(authorizationPath)), sourceSha) }), /claim was not acquired/);
    assert.equal(JSON.parse(objects.get(stageBAttemptStepS3ObjectKey(predecessor.attemptId, 2))).status, "APPLY_SPAWN_UNCERTAIN");
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
