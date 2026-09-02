import assert from "node:assert/strict";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import {
  assertStageAProductionArtifactsRecoveryAttemptEvidence,
  assertStageAProductionArtifactsRecoveryCompletionEvidence,
  createStageAProductionArtifactsRecoveryAttemptEvidence,
  createStageAProductionArtifactsRecoveryAuthorization,
  createStageAProductionArtifactsRecoveryCompletionEvidence,
  createStageAProductionArtifactsReconciliationAuthorization,
} from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, createStageAProductionArtifactsReconciliationPrepareEvidence } from "../aws/production-stage-a-control-plane.mjs";

const sourceSha = "a".repeat(40);
const preState = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 35, stateSha256: "b".repeat(64) };
const environment = Object.freeze({ id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] });
const approval = (workflowRef) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const sign = () => Buffer.from("signature").toString("base64");
const verify = () => true;

test("recovery completion and reconciliation authorization are independently bound", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef), verificationRef: "manual" });
  const attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization: recovery, sign });
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryAttemptEvidence(attempt, { authorization: recovery, verify }));
  for (const changed of [{ ...attempt, sourceSha: "f".repeat(40) }, { ...attempt, preStateSha256: "f".repeat(64) }, { ...attempt, signature: { ...attempt.signature, signatureBase64: "forged" } }]) assert.throws(() => assertStageAProductionArtifactsRecoveryAttemptEvidence(changed, { authorization: recovery, verify: () => false }), /binding|hash|signature/);
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryCompletionEvidence(completion, { authorization: recovery, verify }));
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState, recoveryCompletion: completion.completion, saved: { refreshOnly: true, savedPlanSha256: "c".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan" } });
  const reconciliation = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: completion, prepareEvidence, savedPlanSha256: "c".repeat(64), protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef), verificationRef: "manual", verifyRecoveryCompletionEvidence: verify });
  assert.equal(reconciliation.recoveryCompletionSha256, completion.completionEvidenceSha256);
  assert.throws(() => createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: { ...completion, signature: { ...completion.signature, signatureBase64: "forged" } }, prepareEvidence, savedPlanSha256: "c".repeat(64), protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef), verificationRef: "manual", verifyRecoveryCompletionEvidence: () => false }), /hash|signature/);
});
