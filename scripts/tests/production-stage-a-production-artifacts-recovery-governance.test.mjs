import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import {
  assertStageAProductionArtifactsRecoveryAttemptEvidence,
  assertStageAProductionArtifactsRecoveryCompletionEvidence,
  createStageAProductionArtifactsRecoveryAttemptEvidence,
  createStageAProductionArtifactsRecoveryAuthorization,
  createStageAProductionArtifactsRecoveryCompletionEvidence,
  createStageAProductionArtifactsReconciliationAuthorization,
  assertStageAProductionArtifactsRecoverySourceCompatibility,
  resolveStageAProductionArtifactsAuthorizationArtifact,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION,
  STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF,
  STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF,
} from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, createStageAProductionArtifactsReconciliationPrepareEvidence } from "../aws/production-stage-a-control-plane.mjs";
import { STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "../aws/production-stage-a-production-artifacts-journal.mjs";

const sourceSha = "a".repeat(40);
const preState = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 35, stateSha256: "b".repeat(64) };
const environment = Object.freeze({ id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] });
const approval = (workflowRef, approvedSourceSha = sourceSha) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha: approvedSourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const sign = () => Buffer.from("signature").toString("base64");
const verify = () => true;

const githubRun = ({ operation, authorization, id = 123, attempt = 1, actor = "operator", headSha = sourceSha, workflowPath } = {}) => {
  const archiveBytes = Buffer.from(`authorization-${operation}`);
  const artifactName = operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT : STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT;
  const workflow = { id, run_attempt: attempt, repository: { full_name: "T-ej2003/genuine-scan-main", id: 9001 }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: workflowPath || (operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? ".github/workflows/authorize-production-stage-a-production-artifacts-recovery.yml" : ".github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml"), event: "workflow_dispatch", head_sha: headSha, status: "completed", conclusion: "success", actor: { login: actor } };
  const digest = `sha256:${createHash("sha256").update(archiveBytes).digest("hex")}`;
  return (command, args) => {
    if (command === "gh" && /\/actions\/runs\/[0-9]+$/.test(args[1] || "")) return JSON.stringify(workflow);
    if (command === "gh" && /\/actions\/runs\/[0-9]+\/artifacts$/.test(args[1] || "")) return JSON.stringify([{ artifacts: [{ name: artifactName, expired: false, workflow_run: { id, head_sha: sourceSha, repository_id: workflow.repository.id }, digest, id: 7 }] }]);
    if (command === "gh" && args[1]?.endsWith("/zip")) return archiveBytes;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(authorization);
    throw new Error(`unexpected resolver command: ${command} ${args.join(" ")}`);
  };
};

function reconciliationAuthorization() {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manual" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const saved = { refreshOnly: true, savedPlanSha256: "c".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.8" };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState, recoveryCompletion: completion.completion, saved });
  return createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: completion, prepareEvidence, savedPlanSha256: saved.savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF), verificationRef: "manual", verifyRecoveryCompletionEvidence: verify });
}

test("authorization resolvers accept numeric GitHub workflow identities with canonical string evidence", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manual" });
  const resolvedRecovery = resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, authorization: recovery }) });
  assert.equal(resolvedRecovery.authorization.authorizationSha256, recovery.authorizationSha256);
  const reconciliation = reconciliationAuthorization();
  const resolvedReconciliation = resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, authorization: reconciliation }) });
  assert.equal(resolvedReconciliation.authorization.authorizationSha256, reconciliation.authorizationSha256);
});

test("authorization resolvers reject mismatched workflow identity and provenance", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manual" });
  const resolve = (overrides = {}) => resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, authorization: recovery, ...overrides }) });
  assert.throws(() => resolve({ id: 124 }), /provenance/);
  assert.throws(() => resolve({ attempt: 2 }), /provenance/);
  assert.throws(() => resolve({ actor: "other" }), /approval evidence/);
  assert.throws(() => resolve({ headSha: "f".repeat(40) }), /provenance/);
  assert.throws(() => resolve({ workflowPath: ".github/workflows/other.yml" }), /provenance/);
});

test("recovery completion and reconciliation authorization are independently bound", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef), verificationRef: "manual" });
  const attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization: recovery, sign });
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryAttemptEvidence(attempt, { authorization: recovery, verify }));
  for (const changed of [{ ...attempt, sourceSha: "f".repeat(40) }, { ...attempt, preStateSha256: "f".repeat(64) }, { ...attempt, signature: { ...attempt.signature, signatureBase64: "forged" } }]) assert.throws(() => assertStageAProductionArtifactsRecoveryAttemptEvidence(changed, { authorization: recovery, verify: () => false }), /binding|hash|signature/);
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryCompletionEvidence(completion, { authorization: recovery, verify }));
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState, recoveryCompletion: completion.completion, saved: { refreshOnly: true, savedPlanSha256: "c".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.8" } });
  const reconciliation = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: completion, prepareEvidence, savedPlanSha256: "c".repeat(64), protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef), verificationRef: "manual", verifyRecoveryCompletionEvidence: verify });
  assert.equal(reconciliation.recoveryCompletionSha256, completion.completionEvidenceSha256);
  assert.throws(() => createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: { ...completion, signature: { ...completion.signature, signatureBase64: "forged" } }, prepareEvidence, savedPlanSha256: "c".repeat(64), protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef), verificationRef: "manual", verifyRecoveryCompletionEvidence: () => false }), /hash|signature/);
});

test("descendant reconciliation preserves the historical recovery source and completion", () => {
  const successorSourceSha = "b".repeat(40);
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "historical" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const saved = { refreshOnly: true, savedPlanSha256: "c".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.8" };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha: successorSourceSha, preState, recoveryCompletion: completion.completion, saved });
  const proveDescendant = ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === successorSourceSha;
  const reconciliation = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha: successorSourceSha, recoverySourceSha: sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: completion, prepareEvidence, savedPlanSha256: saved.savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF, successorSourceSha), verificationRef: "successor", verifyRecoveryCompletionEvidence: verify, proveDescendant });
  assert.equal(reconciliation.recoverySourceSha, sourceSha);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: successorSourceSha, recoverySourceSha: sourceSha, proveDescendant }));
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "f".repeat(40), recoverySourceSha: sourceSha, proveDescendant }), /descendant/);
});
