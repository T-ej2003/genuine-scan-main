import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { assertHistoricalFinalApplyWriteV16Successor, HISTORICAL_FINAL_APPLY_WRITE_V16, readHistoricalFinalApplyWriteV16Artifacts, buildNormalActivationPolicy, NORMAL_ACTIVATION } from "../aws/production-normal-backend-activation.mjs";
import { stageBBoundImagesFromBindingReport } from "../aws/generate-production-green-stage-b-tfvars.mjs";
import { assertAuthenticatedStageBOutputOnlySuccessor, resolveStageBStateReconciliationEvidence } from "../aws/production-green-stage-b-state-reconciliation-evidence.mjs";
import { STAGE_B_STATE_RECONCILIATION as CONTRACT, STAGE_B_STATE_RECONCILIATION_MODES, assertStageBOutputOnlyReconciliationResult, createStageBStateReconciliationAuthorization, createStageBStateReconciliationPreparation, stageBStateReconciliationSha256 } from "../aws/production-green-stage-b-state-reconciliation.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const sourceSha = "35b6a77c16d7f6651759c0354b98ef1f17560a44";
const imageReleaseSha = HISTORICAL_FINAL_APPLY_WRITE_V16.imageReleaseSha;
const historicalDirectory = "scripts/tests/fixtures/historical-final-apply-write-v16";
const timestamp = { prepCreated: "2026-10-06T10:00:00.000Z", prepStarted: "2026-10-06T10:00:10.000Z", prepCompleted: "2026-10-06T10:03:00.000Z", authCreated: "2026-10-06T10:04:00.000Z", authStarted: "2026-10-06T10:04:05.000Z", authCompleted: "2026-10-06T10:05:00.000Z", executeCreated: "2026-10-06T10:06:00.000Z", executeStarted: "2026-10-06T10:06:10.000Z", executeCompleted: "2026-10-06T10:08:00.000Z" };
const digest = "a".repeat(64);
const imagesForAddress = (images, address) => address.includes('["backend"]') ? images.backend : address.includes('["worker"]') ? images.worker : address.includes('["canary"]') ? images.canary : address.includes('["read_only_canary"]') ? images.read_only_canary : images.executor;
const closure = { runtimeTfvarsSha256: digest, runtimeBindingSha256: digest, runtimeMaterializationSha256: digest, relocationContractSha256: digest, prerequisiteManifestSha256: digest, brokerPackageSha256: digest, brokerManifestSha256: digest, stageAInputSha256: digest, stageAStateBackupSha256: digest, prerequisiteProducerWorkflowRunId: "37502590000", prerequisiteProducerWorkflowRunAttempt: "1", prerequisiteBundleArtifactId: "11430950000", prerequisiteBundleArtifactDigest: `sha256:${digest}` };
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function createFixture({ predecessorSerial = HISTORICAL_FINAL_APPLY_WRITE_V16.stateSerial, successorSerial = predecessorSerial + 1 } = {}) {
  const historicalReport = JSON.parse(fs.readFileSync(path.join(historicalDirectory, "refresh-report.json"), "utf8"));
  const bindingReport = JSON.parse(fs.readFileSync(path.join(historicalDirectory, "stage-b-tfvars-binding.json"), "utf8"));
  const before = historicalReport.outputChanges.find(({ name }) => name === "bound_images").before;
  const after = stageBBoundImagesFromBindingReport(bindingReport);
  const taskDefinitionArns = Object.fromEntries(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family], index) => [address, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 20}`]));
  const registeredSuccessors = Object.fromEntries(Object.entries(taskDefinitionArns).map(([address, arn]) => [address, { arn, image: imagesForAddress(after, address) }]));
  const predecessorState = { lineage: HISTORICAL_FINAL_APPLY_WRITE_V16.stateLineage, serial: predecessorSerial, stateSha256: predecessorSerial === HISTORICAL_FINAL_APPLY_WRITE_V16.stateSerial ? HISTORICAL_FINAL_APPLY_WRITE_V16.stateSha256 : "c".repeat(64) };
  const outputEvidenceBody = { stateIdentity: predecessorState, boundImages: before, taskDefinitionArns, registeredSuccessors };
  const outputOnlyEvidence = { ...outputEvidenceBody, evidenceSha256: stageBStateReconciliationSha256(outputEvidenceBody) };
  const binding = { images: Object.fromEntries(Object.entries(after).map(([name, imageReference]) => [name === "read_only_canary" ? "readOnlyCanary" : name, { terraformVariable: `${name}_image`, imageReference }])) };
  const plan = { format_version: "1.2", terraform_version: "1.15.8", variables: { tooling_sha: { value: sourceSha } }, errored: false, complete: true, applyable: true, resource_changes: [], resource_drift: [], output_changes: { bound_images: { actions: ["update"], before, after, after_unknown: false, before_sensitive: false, after_sensitive: false } } };
  const planBytes = Buffer.from("canonical authenticated output-only refresh plan fixture");
  const preparation = createStageBStateReconciliationPreparation({ sourceSha, ticketId: "CHG-20261006-0001", stateIdentity: predecessorState, tfvarsSha256: digest, bindingSha256: digest, bindingReport: binding, terraformConfiguration: fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8"), preflightSha256: digest, ...closure, planBytes, planJson: plan, reconciliationMode: STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY, outputOnlyEvidence, createdAt: timestamp.prepCreated });
  const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 8, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: "production", sourceSha, workflowRef: `${CONTRACT.repository}/${CONTRACT.authorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: "202", workflowRunAttempt: "1", executionActor: "operator", observedAt: timestamp.authCreated, actualApproval: { state: "approved", environmentId: 7, environmentName: "production", userId: 8, userLogin: "reviewer" } });
  const authorization = createStageBStateReconciliationAuthorization({ preparation, approval, now: new Date(timestamp.authCreated) });
  const successorState = { lineage: predecessorState.lineage, serial: successorSerial, stateSha256: "b".repeat(64) };
  const successorEvidenceBody = { stateIdentity: successorState, boundImages: after, taskDefinitionArns, registeredSuccessors };
  const result = { schemaVersion: 2, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_RESULT", reconciliationMode: "OUTPUT_ONLY", status: "complete", sourceSha, authorizationSha256: authorization.authorizationSha256, predecessorState, successorState, successorEvidenceSha256: stageBStateReconciliationSha256(successorEvidenceBody), outputAllowlist: ["bound_images"], boundImagesTransitionSha256: preparation.boundImagesTransition.transitionSha256, remoteResourceMutationCount: 0, terraformStateMutationCount: 1 };
  const files = {
    "preparation-bundle.zip": Buffer.from("nested prep archive"),
    "preparation.json": Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`),
    "refresh.tfplan": planBytes,
    "prerequisite-bundle.zip": Buffer.from("prerequisite archive"),
    "release-preflight.json": Buffer.from("{}\n"),
    "authorization.json": Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`),
    "result.json": Buffer.from(`${JSON.stringify(result, null, 2)}\n`),
  };
  const archives = new Map([["preparation", Buffer.from("preparation archive")], ["authorization", Buffer.from("authorization archive")], ["result", Buffer.from("result archive")]]);
  const artifactIds = { preparation: 301, authorization: 302, result: 303 };
  const artifactNames = { preparation: "production-green-stage-b-state-reconciliation-preparation", authorization: "production-green-stage-b-state-reconciliation-authorization", result: "production-green-stage-b-state-reconciliation-result" };
  const artifactDigest = Object.fromEntries([...archives].map(([key, value]) => [key, `sha256:${sha(value)}`]));
  const runIds = { preparation: "201", authorization: "202", execution: "203" };
  const runPaths = { preparation: ".github/workflows/prepare-production-green-stage-b-state-reconciliation.yml", authorization: ".github/workflows/authorize-production-green-stage-b-state-reconciliation.yml", execution: CONTRACT.executionWorkflowPath };
  const runTimes = { preparation: [timestamp.prepCreated, timestamp.prepStarted, timestamp.prepCompleted], authorization: [timestamp.authCreated, timestamp.authStarted, timestamp.authCompleted], execution: [timestamp.executeCreated, timestamp.executeStarted, timestamp.executeCompleted] };
  const runs = Object.fromEntries(Object.entries(runIds).map(([key, id]) => [id, { id: Number(id), run_attempt: 1, path: runPaths[key], head_sha: sourceSha, event: "workflow_dispatch", status: "completed", conclusion: "success", repository: { id: 99, full_name: CONTRACT.repository }, ...Object.fromEntries(["created_at", "run_started_at", "updated_at"].map((field, index) => [field, runTimes[key][index]])) }]));
  const githubRun = (command, args, options = {}) => {
    assert.equal(command, "gh"); assert.equal(args[0], "api"); const endpoint = args[1];
    const runMatch = /actions\/runs\/(\d+)$/.exec(endpoint); if (runMatch) return JSON.stringify(runs[runMatch[1]]);
    const artifactRunMatch = /actions\/runs\/(\d+)\/artifacts$/.exec(endpoint);
    if (artifactRunMatch) { const runKey = Object.keys(runIds).find((name) => runIds[name] === artifactRunMatch[1]); const key = runKey === "execution" ? "result" : runKey; return JSON.stringify({ artifacts: [{ id: artifactIds[key], name: artifactNames[key], expired: false, digest: artifactDigest[key], workflow_run: { id: Number(artifactRunMatch[1]), head_sha: sourceSha, repository_id: 99 } }] }); }
    const artifactMatch = /actions\/artifacts\/(\d+)\/zip$/.exec(endpoint); if (artifactMatch) { const key = Object.keys(artifactIds).find((name) => artifactIds[name] === Number(artifactMatch[1])); return options.encoding === null ? archives.get(key) : archives.get(key).toString(); }
    throw new Error(`Unexpected GitHub API endpoint ${endpoint}`);
  };
  const unzipRun = (command, args, options = {}) => {
    const archiveName = path.basename(args[args[0] === "-Z1" ? 1 : 1]);
    const key = archiveName === "preparation-bundle.zip" ? "bundle" : archiveName.includes("preparation") ? "preparation" : archiveName.includes("authorization") ? "authorization" : archiveName.includes("result") ? "result" : "bundle";
    if (args[0] === "-Z1") return key === "preparation" ? "preparation-bundle.zip\n" : key === "bundle" ? "preparation.json\nprerequisite-bundle.zip\nrefresh.tfplan\nrelease-preflight.json\n" : key === "authorization" ? "authorization.json\n" : "result.json\n";
    const member = args[2];
    const value = key === "bundle" ? files[member] : member === "preparation-bundle.zip" ? files[member] : files[member];
    return options.encoding === null ? value : value.toString();
  };
  const historicalTmp = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-compose-history-")); fs.chmodSync(historicalTmp, 0o700);
  const reportPath = path.join(historicalTmp, "refresh-report.json"); const bindingPath = path.join(historicalTmp, "binding.json");
  fs.copyFileSync(path.join(historicalDirectory, "refresh-report.json"), reportPath); fs.copyFileSync(path.join(historicalDirectory, "stage-b-tfvars-binding.json"), bindingPath); fs.chmodSync(reportPath, 0o600); fs.chmodSync(bindingPath, 0o600);
  const historicalArtifacts = readHistoricalFinalApplyWriteV16Artifacts({ refreshReportPath: reportPath, refreshReportSha256: HISTORICAL_FINAL_APPLY_WRITE_V16.refreshReportSha256, bindingReportPath: bindingPath, bindingReportSha256: HISTORICAL_FINAL_APPLY_WRITE_V16.bindingReportSha256 });
  const artifacts = { files, archives, artifactIds, artifactNames, artifactDigest, runIds, runPaths, runTimes, runs, githubRun, unzipRun, preparation, authorization, result, historicalArtifacts, reportPath, bindingPath, historicalTmp, before, after, predecessorState, successorState };
  return artifacts;
}

function resolve(fixture) {
  return resolveStageBStateReconciliationEvidence({ currentProtectedMainSha: sourceSha, preparationRunId: fixture.runIds.preparation, authorizationRunId: fixture.runIds.authorization, executionRunId: fixture.runIds.execution, expectedResultSha256: sha(fixture.files["result.json"]), expectedResultArtifactId: fixture.artifactIds.result, expectedResultArtifactDigest: fixture.artifactDigest.result, githubRun: fixture.githubRun, unzipRun: fixture.unzipRun, gitRun: () => "" });
}

test("authenticated OUTPUT_ONLY run artifacts compose the historical serial 115 predecessor to the exact live successor", (t) => {
  const f = createFixture(); t.after(() => fs.rmSync(f.historicalTmp, { recursive: true, force: true }));
  const proof = resolve(f);
  const sourcePolicy = JSON.parse(execFileSync("git", ["show", `${HISTORICAL_FINAL_APPLY_WRITE_V16.sourcePolicyCommit}:${NORMAL_ACTIVATION.policyPath}`], { encoding: "utf8" }));
  const before = { document: buildNormalActivationPolicy(HISTORICAL_FINAL_APPLY_WRITE_V16.activationTargetArn, sourcePolicy), defaultVersionId: "v16" };
  const versions = HISTORICAL_FINAL_APPLY_WRITE_V16.versionIds.map((VersionId, index) => ({ VersionId, IsDefaultVersion: VersionId === "v16", CreateDate: new Date(Date.UTC(2026, 7, 12 + index)).toISOString() }));
  const authenticated = { before, versions, sourceSha, imageReleaseSha, sourceArn: HISTORICAL_FINAL_APPLY_WRITE_V16.sourceArn, targetArn: HISTORICAL_FINAL_APPLY_WRITE_V16.targetArn, state: { lineage: f.successorState.lineage, serial: f.successorState.serial }, stateSha256: f.successorState.stateSha256 };
  assert.equal(assertHistoricalFinalApplyWriteV16Successor({ authenticated, supplemental: { artifacts: f.historicalArtifacts, protectedMainAncestorAuthenticated: true, reconciliationEvidence: proof } }), true);
  for (const mutate of [
    (v) => { v.state.serial = 117; },
    (v) => { v.state.lineage = "00000000-0000-0000-0000-000000000000"; },
    (v) => { v.stateSha256 = "c".repeat(64); },
    (v) => { v.sourceSha = "f".repeat(40); },
  ]) { const changed = structuredClone(authenticated); mutate(changed); assert.throws(() => assertHistoricalFinalApplyWriteV16Successor({ authenticated: changed, supplemental: { artifacts: f.historicalArtifacts, protectedMainAncestorAuthenticated: true, reconciliationEvidence: proof } })); }
  assert.throws(() => assertHistoricalFinalApplyWriteV16Successor({ authenticated: { ...authenticated, state: { ...authenticated.state, serial: 116 } }, supplemental: { artifacts: f.historicalArtifacts, protectedMainAncestorAuthenticated: true } }), /Historical|supplemental/);
  assert.throws(() => assertHistoricalFinalApplyWriteV16Successor({ authenticated, supplemental: { artifacts: f.historicalArtifacts, protectedMainAncestorAuthenticated: true, reconciliationEvidence: proof, state: { serial: 115 }, stateSha256: HISTORICAL_FINAL_APPLY_WRITE_V16.stateSha256, lineage: HISTORICAL_FINAL_APPLY_WRITE_V16.stateLineage, sourceSha: HISTORICAL_FINAL_APPLY_WRITE_V16.minimumProtectedMainSha } }), /evidence fields are not exact/);
  assert.throws(() => assertHistoricalFinalApplyWriteV16Successor({ authenticated, supplemental: { artifacts: f.historicalArtifacts, protectedMainAncestorAuthenticated: true, reconciliationEvidence: structuredClone(proof) } }), /authenticated from canonical workflow artifacts/);
});

test("the authenticated-successor primitive accepts generic evidence-derived serial transitions", (t) => {
  const f = createFixture({ predecessorSerial: 41, successorSerial: 42 }); t.after(() => fs.rmSync(f.historicalTmp, { recursive: true, force: true }));
  const proof = resolve(f);
  assert.deepEqual(assertAuthenticatedStageBOutputOnlySuccessor(proof, { currentProtectedMainSha: sourceSha, historicalState: f.predecessorState, liveState: f.successorState, liveStateSha256: f.successorState.stateSha256, historicalBoundImages: f.before, expectedBoundImages: f.after }).successorState, f.successorState);
});

test("canonical artifact authentication rejects mismatched runs, altered receipt bytes, and failed or cross-source execution", (t) => {
  const f = createFixture(); t.after(() => fs.rmSync(f.historicalTmp, { recursive: true, force: true }));
  assert.doesNotThrow(() => resolve(f));
  const expectReject = (changes) => { const value = createFixture(); t.after(() => fs.rmSync(value.historicalTmp, { recursive: true, force: true })); changes(value); assert.throws(() => resolve(value)); };
  expectReject((v) => { v.runs[v.runIds.execution].conclusion = "failure"; });
  expectReject((v) => { v.runs[v.runIds.execution].head_sha = "f".repeat(40); });
  expectReject((v) => { v.runIds.authorization = "299"; });
  expectReject((v) => { v.artifactDigest.result = `sha256:${"0".repeat(64)}`; });
  expectReject((v) => { v.files["result.json"] = Buffer.from(`${JSON.stringify({ ...v.result, status: "state-write-outcome-ambiguous" }, null, 2)}\n`); });
  expectReject((v) => { v.result.authorizationSha256 = "0".repeat(64); v.files["result.json"] = Buffer.from(`${JSON.stringify(v.result, null, 2)}\n`); });
});

test("canonical result validator rejects wrong predecessor, successor, source, authorization, plan, status, and output semantics", (t) => {
  const f = createFixture(); t.after(() => fs.rmSync(f.historicalTmp, { recursive: true, force: true }));
  const check = (result = f.result, preparation = f.preparation, authorization = f.authorization, expectedSource = sourceSha) => assertStageBOutputOnlyReconciliationResult(result, { preparation, authorization, sourceSha: expectedSource, now: new Date(timestamp.executeStarted) });
  assert.doesNotThrow(() => check());
  for (const mutate of [
    (value) => { value.predecessorState.stateSha256 = "0".repeat(64); },
    (value) => { value.predecessorState.serial += 1; },
    (value) => { value.predecessorState.lineage = "wrong"; },
    (value) => { value.successorState.stateSha256 = "0".repeat(64); },
    (value) => { value.successorState.serial += 1; },
    (value) => { value.successorState.lineage = "wrong"; },
    (value) => { value.sourceSha = "f".repeat(40); },
    (value) => { value.authorizationSha256 = "0".repeat(64); },
    (value) => { value.boundImagesTransitionSha256 = "0".repeat(64); },
    (value) => { value.outputAllowlist = []; },
    (value) => { value.status = "state-write-outcome-ambiguous"; },
    (value) => { value.terraformStateMutationCount = 0; },
    (value) => { value.remoteResourceMutationCount = 1; },
    (value) => { value.extra = true; },
  ]) { const result = structuredClone(f.result); mutate(result); assert.throws(() => check(result)); }
  assert.throws(() => check(f.result, f.preparation, f.authorization, "e".repeat(40)));
  const wrongAuthorization = structuredClone(f.authorization); wrongAuthorization.authorizationSha256 = "f".repeat(64); assert.throws(() => check(f.result, f.preparation, wrongAuthorization));
  const wrongPreparation = structuredClone(f.preparation); wrongPreparation.refreshOnlyPlanSha256 = "f".repeat(64); assert.throws(() => check(f.result, wrongPreparation, f.authorization));
  const resourceChangingPreparation = structuredClone(f.preparation); resourceChangingPreparation.planSemantics.resourceStateChangeCount = 1; const { preparationSha256, ...preparationBody } = resourceChangingPreparation; resourceChangingPreparation.preparationSha256 = stageBStateReconciliationSha256(preparationBody);
  const resourceChangingAuthorization = createStageBStateReconciliationAuthorization({ preparation: resourceChangingPreparation, approval: f.authorization.protectedEnvironmentApprovalEvidence, now: new Date(timestamp.authCreated) });
  assert.throws(() => check(f.result, resourceChangingPreparation, resourceChangingAuthorization), /resourceStateChangeCount|result/);
});
