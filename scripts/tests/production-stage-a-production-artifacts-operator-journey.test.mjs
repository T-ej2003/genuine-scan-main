import assert from "node:assert/strict";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY } from "../aws/production-stage-a-control-plane.mjs";
import { createStageAProductionArtifactsRecoveryAuthorization, createStageAProductionArtifactsReconciliationAuthorization, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { runStageAProductionArtifactsRecovery } from "../aws/run-production-stage-a-production-artifacts-recovery.mjs";
import { runStageAProductionArtifactsReconciliation } from "../aws/run-production-stage-a-production-artifacts-reconciliation.mjs";

const sourceSha = "a".repeat(40); const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837"; const stateSha256 = "b".repeat(64);
const state = { lineage, serial: 35, stateSha256 };
const rootIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
const releaseIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" });
const environment = { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] };
const approval = (workflowRef, runId) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: runId, workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const source = () => ({ headSha: sourceSha });

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
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "102"), verificationRef: "manual", verifyRecoveryCompletionEvidence: () => true });
  const resource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
  const saved = { sourceSha, refreshOnly: true, savedPlanSha256, planPath: "/tmp/stage-a-refresh.tfplan", preState: state, plan: { complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: "aws_s3_bucket_policy", name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(buildStageAProductionArtifactsBucketPolicyPredecessor()), after: resource(livePolicy), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }] } };
  const adapter = { readStateIdentity: async () => ({ ...state }), createSavedRefreshOnlyPlan: async () => saved, applySavedRefreshOnlyPlan: async () => { applies += 1; state.serial = 36; state.stateSha256 = "e".repeat(64); }, readProductionArtifactsPolicy: async () => livePolicy };
  const result = await runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: "101", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "102", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, readProtectedSource: source, verifySignature: () => true, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryArtifact : { authorization: reconciliationAuthorization }, journal: { readRecoveryCompletion: () => ({ bytes: persistedCompletion }), reserve: (identity) => ({ reservation: identity }), finalize: ({ status }) => { terminal = status; } } });
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
