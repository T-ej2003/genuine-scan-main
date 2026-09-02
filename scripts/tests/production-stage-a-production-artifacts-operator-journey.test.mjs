import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, createStageAProductionArtifactsReconciliationPrepareEvidence, STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY } from "../aws/production-stage-a-control-plane.mjs";
import { createStageAProductionArtifactsRecoveryAuthorization, createStageAProductionArtifactsRecoveryCompletionEvidence, createStageAProductionArtifactsReconciliationAuthorization, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { runStageAProductionArtifactsRecovery } from "../aws/run-production-stage-a-production-artifacts-recovery.mjs";
import { runStageAProductionArtifactsReconciliation, runStageAProductionArtifactsReconciliationCli } from "../aws/run-production-stage-a-production-artifacts-reconciliation.mjs";

const sourceSha = "a".repeat(40); const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837"; const stateSha256 = "b".repeat(64);
const state = { lineage, serial: 35, stateSha256 };
const rootIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
const releaseIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" });
const environment = { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] };
const approval = (workflowRef, runId) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: runId, workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const source = () => ({ headSha: sourceSha });

const policyResource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
const refreshPlan = (savedPolicy) => ({ complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: policyResource(buildStageAProductionArtifactsBucketPolicyPredecessor()), after: policyResource(savedPolicy), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }] });

test("the production CLI composes prepare then execute without re-planning", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-cli-")); const terraformDataDir = path.join(directory, "terraform-data"); const refreshOnlyPlanPath = path.join(directory, "prepared.tfplan"); const prepareEvidencePath = path.join(directory, "prepare.json");
  let state = { lineage, serial: 35, stateSha256 }; let createPlans = 0; let readPlans = 0; let applies = 0; let terminal = "";
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "201"), verificationRef: "cli" });
  const completionEvidence = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recoveryAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => "c2lnbmF0dXJl" });
  const planBytes = Buffer.from("prepared-refresh-only-plan"); const savedPlanSha256 = createHash("sha256").update(planBytes).digest("hex"); const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: planBytes.length, planPath: refreshOnlyPlanPath, preState: state, plan: refreshPlan(buildStageAProductionArtifactsBucketPolicy()) };
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(buildStageAProductionArtifactsBucketPolicy()) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const adapter = { readStateIdentity: async () => ({ ...state }), createSavedRefreshOnlyPlan: async () => { createPlans += 1; fs.writeFileSync(refreshOnlyPlanPath, planBytes, { mode: 0o600 }); return saved; }, readSavedRefreshOnlyPlan: async () => { readPlans += 1; return saved.plan; }, applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36, stateSha256: "e".repeat(64) }; }, readProductionArtifactsPolicy: async () => buildStageAProductionArtifactsBucketPolicy() };
  const journal = { readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completionEvidence)) }), reserve: (identity) => ({ reservation: identity }), finalize: ({ status }) => { terminal = status; } };
  let reconciliationAuthorization;
  const resolveAuthorization = ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? { authorization: recoveryAuthorization } : { authorization: reconciliationAuthorization };
  const common = { releaseRun, adapter, journal, verifySignature: () => true, readProtectedSource: source, resolveAuthorization };
  try {
    await runStageAProductionArtifactsReconciliationCli(["--production", "--prepare", "--source-sha", sourceSha, "--terraform-data-dir", terraformDataDir, "--refresh-only-plan", refreshOnlyPlanPath, "--prepare-evidence", prepareEvidencePath, "--recovery-authorization-workflow-run-id", "201", "--recovery-authorization-workflow-run-attempt", "1"], common);
    const prepareEvidence = JSON.parse(fs.readFileSync(prepareEvidencePath, "utf8"));
    reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "202"), verificationRef: "cli", verifyRecoveryCompletionEvidence: () => true });
    const result = await runStageAProductionArtifactsReconciliationCli(["--production", "--execute", "--source-sha", sourceSha, "--terraform-data-dir", terraformDataDir, "--refresh-only-plan", refreshOnlyPlanPath, "--prepare-evidence", prepareEvidencePath, "--recovery-authorization-workflow-run-id", "201", "--recovery-authorization-workflow-run-attempt", "1", "--reconciliation-authorization-workflow-run-id", "202", "--reconciliation-authorization-workflow-run-attempt", "1"], { ...common });
    assert.equal(result.applied, true); assert.equal(createPlans, 1); assert.equal(readPlans, 1); assert.equal(applies, 1); assert.equal(terminal, "COMPLETED");
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("real Stage-A recovery and reconciliation runner composition reaches one state-only apply", async () => {
  let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let puts = 0; let applies = 0; let persistedAttempt; let persistedCompletion; let terminal;
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "101"), verificationRef: "manual" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { livePolicy = buildStageAProductionArtifactsBucketPolicy(); puts += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const recoveryJournal = { readRecoveryAttempt: () => persistedAttempt && { bytes: persistedAttempt }, writeRecoveryAttempt: ({ bytes }) => { persistedAttempt = bytes; return { key: "attempt", sha256: "a".repeat(64) }; } };
  const completionJournal = { readRecoveryCompletion: () => persistedCompletion && { bytes: persistedCompletion }, writeRecoveryCompletion: ({ bytes }) => { persistedCompletion = bytes; return { key: "completion", sha256: "c".repeat(64) }; } };
  const recovery = await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "101", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, readProtectedSource: source, resolveAuthorization: () => ({ authorization: recoveryAuthorization }), journal: completionJournal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true });
  assert.equal(recovery.putBucketPolicyCount, 1); assert.equal(puts, 1);
  const completionEvidence = JSON.parse(persistedCompletion); const recoveryArtifact = { authorization: recoveryAuthorization };
  const savedPlanSha256 = "d".repeat(64);
  const resource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
  const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: 1, planPath: "/tmp/stage-a-refresh.tfplan", preState: state, plan: { complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: "aws_s3_bucket_policy", name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(buildStageAProductionArtifactsBucketPolicyPredecessor()), after: resource(livePolicy), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }] } };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState: state, recoveryCompletion: completionEvidence.completion, saved });
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "102"), verificationRef: "manual", verifyRecoveryCompletionEvidence: () => true });
  const adapter = { readStateIdentity: async () => ({ ...state }), createSavedRefreshOnlyPlan: async () => saved, applySavedRefreshOnlyPlan: async () => { applies += 1; state.serial = 36; state.stateSha256 = "e".repeat(64); }, readProductionArtifactsPolicy: async () => livePolicy };
  const result = await runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: "101", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "102", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, readProtectedSource: source, verifySignature: () => true, preparedEvidence: prepareEvidence, saved, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryArtifact : { authorization: reconciliationAuthorization }, journal: { readRecoveryCompletion: () => ({ bytes: persistedCompletion }), reserve: (identity) => ({ reservation: identity }), finalize: ({ status }) => { terminal = status; } } });
  assert.equal(result.applied, true); assert.equal(applies, 1); assert.equal(terminal, "COMPLETED");
  await assert.rejects(() => runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: "101", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "102", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, readProtectedSource: source, verifySignature: () => false, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryArtifact : { authorization: reconciliationAuthorization }, journal: { readRecoveryCompletion: () => ({ bytes: persistedCompletion }), reserve: () => { throw new Error("must not reserve"); }, finalize: () => {} } }), /authorization|signature/);
});

test("recovery resumes exact desired policy only from its signed immutable attempt", async () => {
  let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let puts = 0; let attemptBytes; let completionBytes; let signCalls = 0; let loseCompletionResponse = true;
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "201"), verificationRef: "resume" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { livePolicy = buildStageAProductionArtifactsBucketPolicy(); puts += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const recoveryJournal = { readRecoveryAttempt: () => attemptBytes && { bytes: attemptBytes }, writeRecoveryAttempt: ({ bytes }) => { attemptBytes = bytes; return { key: "attempt" }; } };
  const journal = { readRecoveryCompletion: () => completionBytes && { bytes: completionBytes }, writeRecoveryCompletion: ({ bytes }) => { completionBytes = bytes; if (loseCompletionResponse) { loseCompletionResponse = false; throw new Error("injected after completion write"); } return { key: "completion", sha256: "c".repeat(64) }; } };
  const input = { sourceSha, workflowRunId: "201", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, verify: () => true };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, sign: () => { signCalls += 1; if (signCalls === 2) throw new Error("injected after policy write"); return Buffer.from("signature").toString("base64"); } }), /injected after policy write/);
  assert.equal(puts, 1); assert.ok(attemptBytes); assert.equal(completionBytes, undefined);
  const resumed = await runStageAProductionArtifactsRecovery({ ...input, sign: () => Buffer.from("signature").toString("base64") });
  assert.equal(resumed.resumed, true); assert.equal(resumed.putBucketPolicyCount, 0); assert.equal(puts, 1);
  const complete = await runStageAProductionArtifactsRecovery({ ...input, sign: () => { throw new Error("must not sign"); } });
  assert.equal(complete.alreadyComplete, true); assert.equal(complete.putBucketPolicyCount, 0); assert.equal(puts, 1);
  completionBytes = undefined; attemptBytes = undefined;
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, sign: () => Buffer.from("signature").toString("base64") }), /lacks the immutable signed pre-write attempt/);
  assert.equal(puts, 1);
});

test("root recovery rejects every non-clean protected checkout before AWS", async () => {
  for (const message of ["tracked modifications", "staged modification", "untracked file", "wrong protected main"]) {
    let awsCalls = 0;
    const run = () => { awsCalls += 1; throw new Error("must not call AWS"); };
    const journal = { readRecoveryCompletion() {}, writeRecoveryCompletion() {}, readRecoveryAttempt() {}, writeRecoveryAttempt() {} };
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, rootRun: run, releaseRun: run, readStateIdentity: async () => state, resolveAuthorization: () => { throw new Error("must not resolve authorization"); }, journal, sign: () => "signature", verify: () => true, readProtectedSource: () => { throw new Error(message); } }), new RegExp(message));
    assert.equal(awsCalls, 0);
  }
});

test("root recovery rejects a changed Terraform state before PutBucketPolicy", async () => {
  const cases = ["serial", "lineage", "bytes"];
  for (const [index, label] of cases.entries()) {
    const baselineState = { lineage, serial: 35, stateSha256 };
    const alteredState = label === "serial" ? { ...baselineState, serial: 36 } : label === "lineage" ? { ...baselineState, lineage: "other-lineage" } : { ...baselineState, stateSha256: "d".repeat(64) };
    let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let stateReads = 0; let puts = 0;
    const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: baselineState, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, `30${index + 1}`), verificationRef: `state-race-${label}` });
    const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
    const rootRun = (args) => {
      if (args[1] === "get-caller-identity") return rootIdentity;
      if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
      if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
      if (args[1] === "put-bucket-policy") { puts += 1; livePolicy = buildStageAProductionArtifactsBucketPolicy(); return ""; }
      throw new Error(`unexpected root ${args[1]}`);
    };
    const recoveryJournal = { readRecoveryAttempt: () => null, writeRecoveryAttempt: () => ({ key: "attempt" }) };
    const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => ({ key: "completion" }) };
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: `30${index + 1}`, workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => { stateReads += 1; return stateReads === 1 ? baselineState : alteredState; }, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true }), /state changed before the policy write/, label);
    assert.equal(puts, 0, label);
  }
});

test("root recovery performs no networked work between final state CAS and policy write", async () => {
  const calls = []; let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let stateReads = 0;
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "304"), verificationRef: "adjacency" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { calls.push("put-policy"); livePolicy = buildStageAProductionArtifactsBucketPolicy(); return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const recoveryJournal = { readRecoveryAttempt: () => null, writeRecoveryAttempt: () => ({ key: "attempt" }) };
  const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => ({ key: "completion" }) };
  await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "304", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => { calls.push("state"); stateReads += 1; return state; }, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true });
  assert.equal(calls.at(-2), "state");
  assert.equal(calls.at(-1), "put-policy");
});
