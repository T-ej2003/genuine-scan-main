#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND, stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from "./stage-b-terraform-backend-contract.mjs";
import { assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { reserveStageBApplyAttemptTransition } from "../apply-production-green-stage-b.mjs";
import { assertHistoricalStageBV2Incident, assertStageBApplyAttemptReconciliationArtifact, assertStageBApplyAttemptReconciliationAuthorization, assertStageBApplyAttemptReconciliationEligibility, assertStageBApplyAttemptReservation, assertStageBApplyAttemptTransition, classifyStageBApplyAttemptReconciliationState, createStageBApplyAttemptReconciliationArtifact, createStageBApplyAttemptReconciliationAuthorization, createStageBApplyAttemptReconciliationClaim, stageBApplyAttemptReconciliationSha256, STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF } from "./stage-b-apply-attempt-reconciliation-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const readJsonFile = (filePath, label) => { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label }); return { value: JSON.parse(captured.bytes.toString("utf8")), bytes: captured.bytes, sha256: captured.sha256 }; };

export function readStageBApplyAttemptReservation({ reservationIdentity, run } = {}) {
  if (!/^[a-f0-9]{64}$/.test(reservationIdentity || "")) throw new Error("Stage B reservation identity must be a SHA256.");
  if (typeof run !== "function") throw new Error("Stage B reservation verification requires an explicit AWS command runner.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-reservation-")); const file = path.join(directory, "reservation.json");
  try {
    const result = run(["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", stageBApplyAttemptS3Key(reservationIdentity), "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager", file]);
    if (result?.status !== 0 || !fs.existsSync(file)) throw new Error("Stage B apply reservation could not be read from the canonical backend.");
    const bytes = fs.readFileSync(file); const reservation = JSON.parse(bytes.toString("utf8"));
    return Object.freeze({ reservation, bytes, sha256: sha256(bytes), key: stageBApplyAttemptS3Key(reservationIdentity) });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function readStageBApplyAttemptHistory({ reservationIdentity, run, maxTransitions = 3 } = {}) {
  const initial = readStageBApplyAttemptReservation({ reservationIdentity, run });
  if (initial.reservation.schemaVersion === 2) return Object.freeze({ ...initial, transitions: [], latestReservation: initial.reservation });
  assertStageBApplyAttemptReservation(initial.reservation);
  const transitions = [];
  for (let sequence = 1; sequence <= maxTransitions; sequence += 1) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-transition-")); const file = path.join(directory, "transition.json");
    try {
      let result;
      try { result = run(["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", stageBAttemptStepS3ObjectKey(reservationIdentity, sequence), "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager", file]); } catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error?.message || ""}\n${error?.stderr || ""}`)) result = { status: 1, stderr: "NoSuchKey" }; else throw error; }
      if (result?.status !== 0) { if (/NoSuchKey|NotFound|404/i.test(`${result?.stderr || ""}\n${result?.stdout || ""}`)) break; throw new Error("Stage B apply-attempt transition could not be authenticated."); }
      if (!fs.existsSync(file)) throw new Error("Stage B apply-attempt transition readback is missing.");
      const bytes = fs.readFileSync(file); const transition = JSON.parse(bytes.toString("utf8"));
      assertStageBApplyAttemptTransition(transitions.at(-1) || initial.reservation, transition);
      transitions.push(transition);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
  return Object.freeze({ ...initial, transitions, latestReservation: transitions.at(-1) || initial.reservation });
}

export function resolveStageBApplyAttemptReconciliationAuthorization({ workflowRunId, workflowRunAttempt, sourceSha, reconciliationArtifact, reconciliationArtifactSha256, run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }), githubRun = createProductionGithubCommandRunner() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Stage B reconciliation authorization workflow coordinates are invalid.");
  const workflow = JSON.parse(githubRun("gh", ["api", `repos/T-ej2003/genuine-scan-main/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== "T-ej2003/genuine-scan-main" || workflow.head_repository?.full_name !== "T-ej2003/genuine-scan-main" || workflow.path !== ".github/workflows/authorize-production-green-stage-b-apply-attempt-reconciliation.yml" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Stage B reconciliation authorization workflow provenance is not authentic.");
  const pages = JSON.parse(githubRun("gh", ["api", `repos/T-ej2003/genuine-scan-main/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"])); const artifacts = Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : [];
  const matches = artifacts.filter((artifact) => artifact.name === "stage-b-apply-attempt-reconciliation-authorization" && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id) || matches[0].id < 1) throw new Error("Stage B reconciliation authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-reconciliation-authorization-")); const archive = path.join(directory, "authorization.zip");
  try {
    const archiveBytes = Buffer.from(githubRun("gh", ["api", `repos/T-ej2003/genuine-scan-main/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 }));
    if (`sha256:${sha256(archiveBytes)}` !== matches[0].digest) throw new Error("Stage B reconciliation authorization archive digest is invalid.");
    fs.writeFileSync(archive, archiveBytes, { mode: 0o600, flag: "wx" });
    const entries = String(githubRun("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (JSON.stringify(entries) !== JSON.stringify(["authorization.json"])) throw new Error("Stage B reconciliation authorization archive contents are not exact.");
    const authorization = JSON.parse(Buffer.from(githubRun("unzip", ["-p", archive, "authorization.json"])).toString("utf8"));
    assertStageBApplyAttemptReconciliationAuthorization(authorization, { successorSourceSha: sourceSha, reconciliationArtifact, reconciliationArtifactSha256 });
    const evidence = authorization.protectedEnvironmentApprovalEvidence;
    if (evidence.workflowRunId !== String(workflow.id) || evidence.workflowRunAttempt !== String(workflow.run_attempt) || evidence.executionActor?.toLowerCase() !== String(workflow.actor?.login || "").toLowerCase()) throw new Error("Stage B reconciliation authorization is not bound to the authenticated workflow execution.");
    return Object.freeze({ workflow, artifact: matches[0], authorization, authorizationArtifactDigest: matches[0].digest });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function produceStageBApplyAttemptReconciliationAuthorization({ reconciliationArtifactPath, reconciliationArtifactSha256, environmentApprovalPath, environmentApprovalSha256, sourceSha, outputPath, approvedBy, approverRole, verificationRef, now = new Date() } = {}) {
  const reconciliation = readJsonFile(reconciliationArtifactPath, "Stage B reconciliation artifact");
  if (stageBApplyAttemptReconciliationSha256(reconciliation.value, { now }) !== reconciliationArtifactSha256) throw new Error("Stage B reconciliation artifact changed after authentication.");
  const approval = readJsonFile(environmentApprovalPath, "Stage B reconciliation environment approval");
  if (approval.sha256 !== environmentApprovalSha256) throw new Error("Stage B reconciliation environment approval changed after authentication.");
  assertProductionEnvironmentApprovalIdentity(approval.value, { sourceSha, repository: "T-ej2003/genuine-scan-main" });
  const authorization = createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: approval.value, reconciliationArtifact: reconciliation.value, reconciliationArtifactSha256, successorSourceSha: sourceSha, approvedBy, approverRole, verificationRef, now });
  const output = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot: root, label: "Stage B apply-attempt reconciliation authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage B apply-attempt reconciliation authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Stage B apply-attempt reconciliation authorization" });
  return { status: "published", outputPath: output, authorizationSha256: authorization.authorizationSha256 };
}

export function runStageBApplyAttemptReconciliationCli(argv = process.argv.slice(2), { now = new Date(), awsRun: suppliedAwsRun, reserveTransition = reserveStageBApplyAttemptTransition } = {}) {
  const mode = required(argv, "--mode");
  const awsRun = suppliedAwsRun || ((args) => {
    const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
    try { return { status: 0, stdout: releaseRun(args) }; } catch (error) { return { status: error.status ?? 1, stdout: error.stdout?.toString?.() || "", stderr: error.stderr?.toString?.() || error.message || "" }; }
  });
  if (mode === "reconciliation-sha256") {
    const reconciliation = readJsonFile(required(argv, "--reconciliation-artifact"), "Stage B reconciliation artifact");
    return { sha256: stageBApplyAttemptReconciliationSha256(reconciliation.value, { now }) };
  }
  if (mode === "verify") {
    const reservationIdentity = required(argv, "--reservation-identity"); const expected = { sourceSha: required(argv, "--source-sha"), planSha256: required(argv, "--plan-sha256"), savedPlanSha256: required(argv, "--saved-plan-sha256"), stateLineage: required(argv, "--state-lineage"), stateSerial: Number(required(argv, "--state-serial")), stateSha256: required(argv, "--state-sha256"), workspace: required(argv, "--workspace"), backendIdentitySha256: required(argv, "--backend-identity-sha256") };
    const result = readStageBApplyAttemptHistory({ reservationIdentity, run: awsRun });
    if (result.reservation.schemaVersion === 2) { assertHistoricalStageBV2Incident(result.reservation); if (reservationIdentity !== result.reservation.artifactSetIdentity) throw new Error("Historical Stage B reservation identity mismatch."); }
    else { const { sourceSha, ...v3Expected } = expected; assertStageBApplyAttemptReservation(result.reservation, { expected: { ...v3Expected, sourceSha } }); }
    return { status: result.latestReservation.status || result.latestReservation.phase, reconciliationStatus: classifyStageBApplyAttemptReconciliationState(result.latestReservation).status, reservationIdentity, sha256: result.sha256 };
  }
  if (mode === "prepare-successor") {
    const reconciliation = readJsonFile(required(argv, "--reconciliation-artifact"), "Stage B reconciliation artifact"); const authorization = readJsonFile(required(argv, "--authorization"), "Stage B reconciliation authorization"); const sourceSha = required(argv, "--source-sha"); const reconciliationArtifactSha256 = required(argv, "--reconciliation-artifact-sha256");
    if (stageBApplyAttemptReconciliationSha256(reconciliation.value, { now }) !== reconciliationArtifactSha256 || authorization.value.authorizationSha256 !== required(argv, "--authorization-sha256")) throw new Error("Stage B successor inputs changed after authentication.");
    const history = readStageBApplyAttemptHistory({ reservationIdentity: reconciliation.value.predecessor.reservationIdentity, run: awsRun });
    const existingClaim = history.transitions.at(-1)?.status === "ABORTED_BEFORE_APPLY" ? history.transitions.at(-1) : null;
    const predecessorTransitions = existingClaim ? history.transitions.slice(0, -1) : history.transitions;
    const claim = createStageBApplyAttemptReconciliationClaim({ reservation: history.reservation, transitions: predecessorTransitions, reconciliationArtifact: reconciliation.value, reconciliationArtifactSha256, authorization: authorization.value, authorizationSha256: authorization.value.authorizationSha256, successorSourceSha: sourceSha, now });
    let claimError;
    if (!existingClaim || canonicalJson(existingClaim) !== canonicalJson(claim)) {
      const claimBytes = Buffer.from(`${JSON.stringify(claim, null, 2)}\n`);
      try { reserveTransition({ attemptId: claim.attemptId, sequence: claim.sequence, bytes: claimBytes, privateDirectory: os.tmpdir(), run: awsRun }); } catch (error) { claimError = error; }
    }
    const claimedHistory = readStageBApplyAttemptHistory({ reservationIdentity: claim.attemptId, run: awsRun });
    let result;
    try { result = assertStageBApplyAttemptReconciliationEligibility({ reservation: claimedHistory.reservation, transitions: claimedHistory.transitions, reconciliationArtifact: reconciliation.value, reconciliationArtifactSha256, authorization: authorization.value, authorizationSha256: authorization.value.authorizationSha256, successorSourceSha: sourceSha, now }); }
    catch (error) { throw new Error("Stage B reconciliation claim was not acquired; successor is unreachable.", { cause: claimError || error }); }
    return { ...result, sourceSha, status: "SUCCESSOR_READY_BUT_NOT_EXECUTED" };
  }
  if (mode === "create-reconciliation") {
    const historical = readJsonFile(required(argv, "--historical-reservation")); const reservationIdentity = required(argv, "--reservation-identity"); const history = readStageBApplyAttemptHistory({ reservationIdentity, run: awsRun });
    if (canonicalJson(historical.value) !== canonicalJson(history.reservation)) throw new Error("Stage B reconciliation historical reservation differs from canonical backend readback.");
    const result = createStageBApplyAttemptReconciliationArtifact({ historicalReservation: history.reservation, historicalTransitions: history.transitions, successorSourceSha: required(argv, "--successor-source-sha"), generatedAt: now.toISOString(), now });
    const output = assertStageBArtifactPath({ artifactPath: required(argv, "--output"), repositoryRoot: root, label: "Stage B apply-attempt reconciliation artifact", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage B apply-attempt reconciliation directory" });
    writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "Stage B apply-attempt reconciliation artifact" });
    return { status: "published", outputPath: output, sha256: stageBApplyAttemptReconciliationSha256(result, { now }) };
  }
  if (mode === "authorize") {
    return produceStageBApplyAttemptReconciliationAuthorization({ reconciliationArtifactPath: required(argv, "--reconciliation-artifact"), reconciliationArtifactSha256: required(argv, "--reconciliation-artifact-sha256"), environmentApprovalPath: required(argv, "--environment-approval"), environmentApprovalSha256: required(argv, "--environment-approval-sha256"), sourceSha: required(argv, "--source-sha"), outputPath: required(argv, "--output"), approvedBy: required(argv, "--approved-by"), approverRole: required(argv, "--approver-role"), verificationRef: required(argv, "--verification-ref"), now });
  }
  throw new Error("Unknown Stage B apply-attempt reconciliation mode.");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runStageBApplyAttemptReconciliationCli(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
