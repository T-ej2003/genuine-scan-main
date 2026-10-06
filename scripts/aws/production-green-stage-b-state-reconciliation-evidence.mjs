import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { STAGE_B_STATE_RECONCILIATION as CONTRACT, STAGE_B_STATE_RECONCILIATION_MODES, assertStageBOutputOnlyReconciliationResult, assertStageBStateReconciliationAuthorization, assertStageBStateReconciliationPreparation } from "./production-green-stage-b-state-reconciliation.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const RUN_ID = /^[1-9][0-9]*$/;
const HEX = /^[a-f0-9]{64}$/;
const authenticated = new WeakSet();
const fileBytes = (run, args, options) => Buffer.from(run("gh", args, options));
const json = (bytes, label) => { try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error(`${label} is malformed.`); } };
const timestamp = (value, label) => { const date = new Date(value); if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} is invalid.`); return date; };

function assertRun(run, { runId, attempt, workflowPath, sourceSha, completedBefore } = {}) {
  if (!RUN_ID.test(String(runId || "")) || String(run.id) !== String(runId) || String(run.run_attempt) !== String(attempt) || String(attempt) !== "1"
    || run.path !== workflowPath || run.head_sha !== sourceSha || run.event !== "workflow_dispatch" || run.status !== "completed" || run.conclusion !== "success"
    || !Number.isSafeInteger(run.repository?.id) || run.repository?.full_name !== CONTRACT.repository) throw new Error("Stage B reconciliation workflow provenance is invalid.");
  const createdAt = timestamp(run.created_at, "Stage B workflow creation time");
  const startedAt = timestamp(run.run_started_at, "Stage B workflow start time");
  const completedAt = timestamp(run.updated_at, "Stage B workflow completion time");
  if (createdAt > startedAt || startedAt > completedAt || completedBefore && completedAt > completedBefore) throw new Error("Stage B reconciliation workflow order is invalid.");
  return Object.freeze({ createdAt, startedAt, completedAt, repositoryId: run.repository.id });
}

function runJson(githubRun, runId) { return json(fileBytes(githubRun, ["api", `repos/${CONTRACT.repository}/actions/runs/${runId}`]), "Stage B workflow run"); }

function exactArtifact(githubRun, { runId, runAttempt, sourceSha, runMetadata, name, expectedId, expectedDigest }) {
  const listed = json(fileBytes(githubRun, ["api", `repos/${CONTRACT.repository}/actions/runs/${runId}/artifacts`]), "Stage B workflow artifact listing");
  const matches = (listed.artifacts || []).filter((entry) => entry.name === name && entry.expired === false && String(entry.workflow_run?.id) === String(runId)
    && entry.workflow_run?.head_sha === sourceSha && entry.workflow_run?.repository_id === runMetadata.repositoryId
    && Number.isSafeInteger(entry.id) && /^sha256:[a-f0-9]{64}$/.test(entry.digest || ""));
  if (matches.length !== 1 || expectedId !== undefined && String(matches[0].id) !== String(expectedId) || expectedDigest !== undefined && matches[0].digest !== expectedDigest) throw new Error(`Stage B ${name} artifact identity is invalid.`);
  const archive = fileBytes(githubRun, ["api", `repos/${CONTRACT.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 });
  if (`sha256:${sha256(archive)}` !== matches[0].digest) throw new Error(`Stage B ${name} artifact archive digest is invalid.`);
  return Object.freeze({ metadata: matches[0], archive });
}

function listZip(run, archivePath) { return String(run("unzip", ["-Z1", archivePath])).trim().split("\n").filter(Boolean); }
function unzip(run, archivePath, member) { return Buffer.from(run("unzip", ["-p", archivePath, member], { encoding: null, maxBuffer: 64 * 1024 * 1024 })); }
function deepFreeze(value) { if (!value || typeof value !== "object" || Object.isFrozen(value)) return value; Object.values(value).forEach(deepFreeze); return Object.freeze(value); }

export function resolveStageBStateReconciliationEvidence({ currentProtectedMainSha, preparationRunId, preparationRunAttempt = "1", authorizationRunId, authorizationRunAttempt = "1", executionRunId, executionRunAttempt = "1", expectedResultSha256, expectedResultArtifactId, expectedResultArtifactDigest, githubRun = createProductionGithubCommandRunner(), unzipRun = githubRun, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  if (!/^[a-f0-9]{40}$/.test(currentProtectedMainSha || "") || !HEX.test(expectedResultSha256 || "") || !/^sha256:[a-f0-9]{64}$/.test(expectedResultArtifactDigest || "")) throw new Error("Stage B reconciliation evidence references are incomplete.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-reconciliation-proof-")); fs.chmodSync(directory, 0o700);
  try {
    const preparationRun = runJson(githubRun, preparationRunId);
    const preparationMeta = assertRun(preparationRun, { runId: preparationRunId, attempt: preparationRunAttempt, workflowPath: ".github/workflows/prepare-production-green-stage-b-state-reconciliation.yml", sourceSha: preparationRun.head_sha });
    const prepArtifact = exactArtifact(githubRun, { runId: preparationRunId, runAttempt: preparationRunAttempt, sourceSha: preparationRun.head_sha, runMetadata: preparationMeta, name: "production-green-stage-b-state-reconciliation-preparation" });
    const prepArchive = path.join(directory, "stage-b-reconciliation-preparation.zip"); fs.writeFileSync(prepArchive, prepArtifact.archive, { mode: 0o600 });
    if (!equal(listZip(unzipRun, prepArchive), ["preparation-bundle.zip"])) throw new Error("Stage B preparation artifact contents are not exact.");
    const bundle = unzip(unzipRun, prepArchive, "preparation-bundle.zip"); const bundlePath = path.join(directory, "preparation-bundle.zip"); fs.writeFileSync(bundlePath, bundle, { mode: 0o600 });
    if (!equal(listZip(unzipRun, bundlePath).sort(), ["preparation.json", "prerequisite-bundle.zip", "refresh.tfplan", "release-preflight.json"].sort())) throw new Error("Stage B preparation bundle contents are not exact.");
    const preparationBytes = unzip(unzipRun, bundlePath, "preparation.json"); const preparation = json(preparationBytes, "Stage B reconciliation preparation");
    const planBytes = unzip(unzipRun, bundlePath, "refresh.tfplan");
    if (sha256(preparationBytes) !== sha256(Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`)) || sha256(planBytes) !== preparation.refreshOnlyPlanSha256) throw new Error("Stage B preparation or saved-plan bytes changed.");
    const sourceSha = preparation.sourceSha;
    const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha, now: preparationMeta.completedAt });
    if (prepared.reconciliationMode !== STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY) throw new Error("FinalApplyWrite successor composition requires OUTPUT_ONLY reconciliation.");
    if (gitRun(["merge-base", "--is-ancestor", sourceSha, currentProtectedMainSha]) !== "") throw new Error("Stage B reconciliation source is not an ancestor of exact protected main.");

    const authorizationRun = runJson(githubRun, authorizationRunId);
    const authorizationMeta = assertRun(authorizationRun, { runId: authorizationRunId, attempt: authorizationRunAttempt, workflowPath: ".github/workflows/authorize-production-green-stage-b-state-reconciliation.yml", sourceSha, completedBefore: undefined });
    if (preparationRun.repository.id !== authorizationRun.repository?.id || preparationMeta.completedAt > authorizationMeta.createdAt) throw new Error("Stage B preparation and authorization workflow order/provenance is invalid.");
    assertStageBStateReconciliationPreparation(prepared, { sourceSha, now: authorizationMeta.createdAt });
    const authArtifact = exactArtifact(githubRun, { runId: authorizationRunId, runAttempt: authorizationRunAttempt, sourceSha, runMetadata: authorizationMeta, name: "production-green-stage-b-state-reconciliation-authorization" });
    const authArchive = path.join(directory, "stage-b-reconciliation-authorization.zip"); fs.writeFileSync(authArchive, authArtifact.archive, { mode: 0o600 });
    if (!equal(listZip(unzipRun, authArchive), ["authorization.json"])) throw new Error("Stage B authorization artifact contents are not exact.");
    const authorizationBytes = unzip(unzipRun, authArchive, "authorization.json"); const authorization = json(authorizationBytes, "Stage B reconciliation authorization");
    if (authorization.protectedEnvironmentApprovalEvidence?.workflowRunId !== String(authorizationRunId) || authorization.protectedEnvironmentApprovalEvidence?.workflowRunAttempt !== String(authorizationRunAttempt)) throw new Error("Stage B environment approval is not bound to the authenticated authorization run.");

    const executionRun = runJson(githubRun, executionRunId);
    const executionMeta = assertRun(executionRun, { runId: executionRunId, attempt: executionRunAttempt, workflowPath: CONTRACT.executionWorkflowPath, sourceSha });
    if (authorizationRun.repository.id !== executionRun.repository?.id || authorizationMeta.completedAt > executionMeta.startedAt) throw new Error("Stage B authorization and execution workflow order/provenance is invalid.");
    const checkedAuthorization = assertStageBStateReconciliationAuthorization(authorization, { preparation: prepared, sourceSha, now: executionMeta.startedAt });
    const resultArtifact = exactArtifact(githubRun, { runId: executionRunId, runAttempt: executionRunAttempt, sourceSha, runMetadata: executionMeta, name: "production-green-stage-b-state-reconciliation-result", expectedId: expectedResultArtifactId, expectedDigest: expectedResultArtifactDigest });
    const resultArchive = path.join(directory, "stage-b-reconciliation-result.zip"); fs.writeFileSync(resultArchive, resultArtifact.archive, { mode: 0o600 });
    if (!equal(listZip(unzipRun, resultArchive), ["result.json"])) throw new Error("Stage B result artifact contents are not exact.");
    const resultBytes = unzip(unzipRun, resultArchive, "result.json");
    if (sha256(resultBytes) !== expectedResultSha256) throw new Error("Stage B reconciliation result byte SHA256 is invalid.");
    const result = json(resultBytes, "Stage B reconciliation result");
    const proof = assertStageBOutputOnlyReconciliationResult(result, { preparation: prepared, authorization: checkedAuthorization, sourceSha, now: executionMeta.startedAt });
    if (preparationRun.repository.id !== executionRun.repository?.id || prepArtifact.metadata.workflow_run?.head_sha !== sourceSha) throw new Error("Stage B reconciliation evidence crosses repository/source identities.");
    const authenticatedProof = deepFreeze({ ...proof, artifactProvenance: { preparationRunId: String(preparationRunId), authorizationRunId: String(authorizationRunId), executionRunId: String(executionRunId), resultArtifactId: String(resultArtifact.metadata.id), resultArtifactDigest: resultArtifact.metadata.digest, resultByteSha256: expectedResultSha256, currentProtectedMainSha } });
    authenticated.add(authenticatedProof);
    return authenticatedProof;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function assertAuthenticatedStageBOutputOnlySuccessor(proof, { currentProtectedMainSha, historicalState, liveState, liveStateSha256, historicalBoundImages, expectedBoundImages } = {}) {
  if (!authenticated.has(proof)) throw new Error("Stage B reconciliation successor evidence was not authenticated from canonical workflow artifacts.");
  const prepared = proof.preparation; const result = proof.result;
  if (proof.artifactProvenance.currentProtectedMainSha !== currentProtectedMainSha || proof.sourceSha !== prepared.sourceSha || !historicalState || !liveState
    || !equal(result.predecessorState, historicalState) || !equal(result.successorState, { lineage: liveState.lineage, serial: liveState.serial, stateSha256: liveStateSha256 })
    || !equal(prepared.boundImagesTransition.before, historicalBoundImages) || !equal(prepared.boundImagesTransition.after, expectedBoundImages)
    || !equal(prepared.outputOnlyEvidence.boundImages, historicalBoundImages)) throw new Error("Stage B reconciliation result does not authenticate this exact historical-to-live successor chain.");
  return Object.freeze({ sourceSha: proof.sourceSha, predecessorState: result.predecessorState, successorState: result.successorState, savedPlanSha256: proof.savedPlanSha256, boundImagesTransitionSha256: result.boundImagesTransitionSha256, resultByteSha256: proof.artifactProvenance.resultByteSha256 });
}
