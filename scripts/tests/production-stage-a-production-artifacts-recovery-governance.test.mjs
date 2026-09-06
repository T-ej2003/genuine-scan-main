import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import {
  assertStageAProductionArtifactsRecoveryAttemptEvidence,
  assertStageAProductionArtifactsRecoveryAuthorization,
  assertStageAProductionArtifactsRecoveryCompletionEvidence,
  assertStageAProductionArtifactsContinuationRebindAuthorization,
  createStageAProductionArtifactsRecoveryAttemptEvidence,
  createStageAProductionArtifactsRecoveryAuthorization as createRecoveryAuthorization,
  createStageAProductionArtifactsRecoveryCompletionEvidence,
  createStageAProductionArtifactsContinuationRebindAuthorization,
  createStageAProductionArtifactsReconciliationAuthorization,
  assertStageAProductionArtifactsRecoverySourceCompatibility,
  resolveStageAProductionArtifactsAuthorizationArtifact,
  STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION_ARTIFACT,
  STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION,
  STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF,
  STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT,
  STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF,
  STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF,
  stageAProductionArtifactsGovernedExecutableManifest,
  stageAProductionArtifactsGovernedExecutableManifestSha256,
} from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation, createStageAProductionArtifactsReconciliationPrepareEvidence, currentStageAProductionArtifactsBucketPolicyTransition, stageAProductionArtifactsPolicySha256 } from "../aws/production-stage-a-control-plane.mjs";
import { STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "../aws/production-stage-a-production-artifacts-journal.mjs";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { authorizeStageAProductionArtifactsReconciliation } from "../aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs";
import { authorizeStageAProductionArtifactsRecovery } from "../aws/authorize-production-stage-a-production-artifacts-recovery.mjs";

const sourceSha = "a".repeat(40);
const preState = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 35, stateSha256: "b".repeat(64) };
const environment = Object.freeze({ id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] });
const approval = (workflowRef, approvedSourceSha = sourceSha) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha: approvedSourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const policyApproval = ({ preventSelfReview, executionActor = "operator", actualReviewer = "reviewer", configuredReviewer = actualReviewer, actual = true } = {}) => createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: preventSelfReview, reviewers: [{ type: "User", reviewer: { id: 2, login: configuredReviewer } }] }] },
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor, observedAt: "2026-09-02T00:00:00.000Z",
  ...(actual ? { actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: actualReviewer } } : {}),
});
const sign = () => Buffer.from("signature").toString("base64");
const verify = () => true;
const governedExecutableManifestSha256 = "9".repeat(64);
const historicalTransition = Object.freeze({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()), desiredPolicySha256: stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicy()) });
const createStageAProductionArtifactsRecoveryAuthorization = (input) => createRecoveryAuthorization({ ...input, governedExecutableManifestSha256, transition: historicalTransition });
const unchangedGovernedSource = () => governedExecutableManifestSha256;
const rebindApproval = (authorization, protectedEnvironmentApprovalEvidence) => {
  const { authorizationSha256, ...existing } = authorization;
  const body = { ...existing, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256 };
  return { ...body, authorizationSha256: createHash("sha256").update(canonicalJson(body)).digest("hex") };
};

test("fresh recovery authorization binds the exact deployed-to-reservation policy transition", () => {
  const authorization = createRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "reservation-transition", governedExecutableManifestSha256 });
  assert.equal(authorization.predecessorPolicySha256, stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicy()));
  assert.equal(authorization.desiredPolicySha256, stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation()));
  assert.equal(authorization.expectedLivePolicySha256, authorization.predecessorPolicySha256);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha, preState }));
});

test("production recovery authorizer remains on the reservation-bearing transition until reconciler migration", () => {
  const transition = currentStageAProductionArtifactsBucketPolicyTransition();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-current-authorizer-"));
  const source = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const approvalPath = path.join(directory, "approval.json"); const outputPath = path.join(directory, "authorization.json");
  fs.writeFileSync(approvalPath, JSON.stringify(approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF, source)));
  try {
    authorizeStageAProductionArtifactsRecovery(["--source-sha", source, "--state-lineage", preState.lineage, "--state-serial", String(preState.serial), "--state-sha256", preState.stateSha256, "--verification-ref", "current-transition", "--environment-approval", approvalPath, "--output", outputPath]);
    const authorization = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(authorization.predecessorPolicySha256, transition.predecessorPolicySha256);
    assert.equal(authorization.desiredPolicySha256, transition.desiredPolicySha256);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

const githubRun = ({ operation, authorization, id = 123, attempt = 1, actor = "operator", headSha = sourceSha, workflowPath } = {}) => {
  const archiveBytes = Buffer.from(`authorization-${operation}`);
  const rebind = operation === STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION;
  const artifactName = operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT : rebind ? STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION_ARTIFACT : STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT;
  const workflow = { id, run_attempt: attempt, repository: { full_name: "T-ej2003/genuine-scan-main", id: 9001 }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: workflowPath || (operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? ".github/workflows/authorize-production-stage-a-production-artifacts-recovery.yml" : rebind ? ".github/workflows/authorize-production-stage-a-production-artifacts-continuation-rebind.yml" : ".github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml"), event: "workflow_dispatch", head_sha: headSha, status: "completed", conclusion: "success", actor: { login: actor } };
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

test("continuation rebind pins one externally approved source and governed manifest", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "historical" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const reviewedSourceSha = "c".repeat(40); const manifest = "d".repeat(64);
  const rebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery, recoveryCompletion: completion, reviewedContinuationSourceSha: reviewedSourceSha, reviewedGovernedExecutableManifestSha256: manifest, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, reviewedSourceSha), verificationRef: "reviewed-chain" });
  const check = (value = rebind, source = reviewedSourceSha, completionValue = completion, manifestValue = () => manifest) => assertStageAProductionArtifactsContinuationRebindAuthorization(value, { historicalRecoveryAuthorization: recovery, recoveryCompletion: completionValue, sourceSha: source, readGovernedExecutableManifestSha256: manifestValue });
  assert.doesNotThrow(() => check());
  assert.throws(() => check(rebind, "e".repeat(40)), /binding/);
  assert.throws(() => check(rebind, reviewedSourceSha, completion, () => "e".repeat(64)), /binding/);
  assert.throws(() => check({ ...rebind, recoveryCompletionSha256: "e".repeat(64) }), /binding|hash/);
  assert.throws(() => check({ ...rebind, operation: "OTHER" }), /binding|hash/);
});

test("advanced reconciliation authorization consumes and binds the exact continuation rebind", () => {
  const reviewedSourceSha = "c".repeat(40); const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "historical" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const saved = { refreshOnly: true, savedPlanSha256: "d".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.8" };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha: reviewedSourceSha, preState, recoveryCompletion: completion.completion, saved });
  const rebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery, recoveryCompletion: completion, reviewedContinuationSourceSha: reviewedSourceSha, reviewedGovernedExecutableManifestSha256: governedExecutableManifestSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, reviewedSourceSha), verificationRef: "reviewed" });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-rebind-authorizer-"));
  const preparePath = path.join(directory, "prepare.json"); const approvalPath = path.join(directory, "approval.json"); const outputPath = path.join(directory, "authorization.json");
  fs.writeFileSync(preparePath, JSON.stringify(prepareEvidence)); fs.writeFileSync(approvalPath, JSON.stringify(approval(STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF, reviewedSourceSha)));
  const resolveAuthorization = ({ operation, workflowRunId, workflowRunAttempt, sourceSha: resolvedSourceSha }) => {
    if (operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION) { assert.equal(workflowRunId, "201"); assert.equal(workflowRunAttempt, "1"); assert.equal(resolvedSourceSha, sourceSha); return { authorization: recovery }; }
    assert.equal(operation, "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_CONTINUATION_REBIND"); assert.equal(workflowRunId, "202"); assert.equal(workflowRunAttempt, "1"); assert.equal(resolvedSourceSha, reviewedSourceSha); return { authorization: rebind };
  };
  const args = ["--source-sha", reviewedSourceSha, "--recovery-source-sha", sourceSha, "--state-lineage", preState.lineage, "--state-serial", String(preState.serial), "--state-sha256", preState.stateSha256, "--saved-plan-sha256", saved.savedPlanSha256, "--prepare-evidence", preparePath, "--verification-ref", "reviewed", "--recovery-authorization-workflow-run-id", "201", "--recovery-authorization-workflow-run-attempt", "1", "--continuation-rebind-workflow-run-id", "202", "--continuation-rebind-workflow-run-attempt", "1", "--environment-approval", approvalPath, "--output", outputPath];
  try {
    authorizeStageAProductionArtifactsReconciliation(args, { verifyRecoveryCompletionEvidence: verify, resolveAuthorization, journal: { readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completion)) }) }, proveSourceDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === reviewedSourceSha, readGovernedExecutableManifestSha256: unchangedGovernedSource });
    assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).continuationRebindAuthorizationSha256, rebind.authorizationSha256);
    fs.rmSync(outputPath);
    assert.throws(() => authorizeStageAProductionArtifactsReconciliation(args.filter((value) => value !== "--continuation-rebind-workflow-run-id" && value !== "202"), { verifyRecoveryCompletionEvidence: verify, resolveAuthorization, journal: { readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completion)) }) }, proveSourceDescendant: () => true, readGovernedExecutableManifestSha256: unchangedGovernedSource }), /continuation-rebind-workflow-run-id/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("Stage A recovery approval follows the authenticated GitHub self-review policy", () => {
  for (const protectedEnvironmentApprovalEvidence of [
    policyApproval({ preventSelfReview: false, executionActor: "T-ej2003", actualReviewer: "T-ej2003" }),
    policyApproval({ preventSelfReview: false }),
    policyApproval({ preventSelfReview: true }),
  ]) {
    const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence, verificationRef: "policy-matrix" });
    assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha, preState }));
  }

  const selfReviewBlocked = policyApproval({ preventSelfReview: true, executionActor: "T-ej2003", actualReviewer: "T-ej2003" });
  assert.throws(() => createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: selfReviewBlocked, verificationRef: "policy-matrix" }), /self-approved|prevents self-review/);
  const selfReviewAllowedAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: policyApproval({ preventSelfReview: false, executionActor: "T-ej2003", actualReviewer: "T-ej2003" }), verificationRef: "policy-matrix" });
  assert.throws(() => assertStageAProductionArtifactsRecoveryAuthorization(rebindApproval(selfReviewAllowedAuthorization, selfReviewBlocked), { sourceSha, preState }), /self-approved|prevents self-review/);
  const resolved = resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, authorization: selfReviewAllowedAuthorization, actor: "T-ej2003" }), readGovernedExecutableManifestSha256: unchangedGovernedSource });
  assert.equal(resolved.authorization.authorizationSha256, selfReviewAllowedAuthorization.authorizationSha256);
});

test("Stage A recovery approval keeps reviewer, evidence, provenance, and hash checks fail closed", () => {
  assert.throws(() => createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: policyApproval({ preventSelfReview: false, actualReviewer: "outsider", configuredReviewer: "reviewer" }), verificationRef: "policy-negative" }), /configured production environment reviewer/);
  assert.throws(() => createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: policyApproval({ preventSelfReview: false, actual: false }), verificationRef: "policy-negative" }), /actual protected-environment approval/);
  const valid = policyApproval({ preventSelfReview: false });
  for (const changed of [
    { ...valid, actualApproval: { ...valid.actualApproval, userLogin: "tampered" } },
    { ...valid, environment: "staging" },
    { ...valid, sourceSha: "f".repeat(40) },
    { ...valid, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF },
  ]) assert.throws(() => createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: changed, verificationRef: "policy-negative" }), /schema|hash|identity|workflow|approval/);
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: valid, verificationRef: "policy-negative" });
  assert.throws(() => assertStageAProductionArtifactsRecoveryAuthorization({ ...authorization, preStateSerial: authorization.preStateSerial + 1 }, { sourceSha, preState }), /binding|hash/);
  assert.throws(() => policyApproval({ preventSelfReview: undefined }), /policy/);
  assert.throws(() => createProductionEnvironmentApprovalEvidence({ environmentConfig: { ...environment, can_admins_bypass: true }, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z" }), /administrator bypass/);
});

test("authorization resolvers accept numeric GitHub workflow identities with canonical string evidence", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manual" });
  const resolvedRecovery = resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, authorization: recovery }), readGovernedExecutableManifestSha256: unchangedGovernedSource });
  assert.equal(resolvedRecovery.authorization.authorizationSha256, recovery.authorizationSha256);
  const reconciliation = reconciliationAuthorization();
  const resolvedReconciliation = resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, authorization: reconciliation }) });
  assert.equal(resolvedReconciliation.authorization.authorizationSha256, reconciliation.authorizationSha256);
  const rebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery, recoveryCompletion: createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign }), reviewedContinuationSourceSha: sourceSha, reviewedGovernedExecutableManifestSha256: governedExecutableManifestSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF), verificationRef: "manual" });
  const rebindRunner = githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, authorization: rebind });
  assert.equal(resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, githubRun: rebindRunner, readGovernedExecutableManifestSha256: unchangedGovernedSource }).authorization.authorizationSha256, rebind.authorizationSha256);
  assert.throws(() => resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "124", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, githubRun: rebindRunner }), /provenance/);
  assert.throws(() => resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "2", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, githubRun: rebindRunner }), /provenance/);
});

test("authorization resolvers reject mismatched workflow identity and provenance", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manual" });
  const resolve = (overrides = {}) => resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, githubRun: githubRun({ operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, authorization: recovery, ...overrides }), readGovernedExecutableManifestSha256: unchangedGovernedSource });
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

test("descendant continuation rejects a changed closed-world recovery contract", () => {
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "compatibility" });
  assert.throws(() => assertStageAProductionArtifactsRecoveryAuthorization(recovery, { sourceSha, preState, expectedContinuationCompatibilitySha256: "f".repeat(64) }), /binding/);
});

test("descendant continuation binds the complete governed Git-object manifest", () => {
  const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const manifest = stageAProductionArtifactsGovernedExecutableManifest(head);
  const paths = manifest.files.map(({ path }) => path);
  const requiredFamilies = [
    "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
    "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs",
    "scripts/aws/authorize-production-stage-a-production-artifacts-continuation-rebind.mjs",
    "scripts/aws/production-stage-a-production-artifacts-recovery-governance.mjs",
    "scripts/aws/production-stage-a-production-artifacts-journal.mjs",
    "scripts/aws/production-stage-a-control-plane.mjs",
    "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs",
    "scripts/aws/production-root-attestation-key.mjs",
    "infra/aws/terraform/production-green-stage-a/main.tf",
    "infra/aws/terraform/production-green-stage-a/.terraform.lock.hcl",
  ];
  for (const file of requiredFamilies) assert.ok(paths.includes(file), `${file} must be governed`);
  assert.equal(paths.some((file) => file.endsWith("README.md") || file.includes("scripts/tests/")), false);

  const historical = stageAProductionArtifactsGovernedExecutableManifestSha256(head);
  const digest = (files) => createHash("sha256").update(canonicalJson({ schemaVersion: manifest.schemaVersion, files })).digest("hex");
  const changedDigest = (file) => {
    const files = manifest.files.map((entry) => entry.path === file ? { ...entry, sha256: "f".repeat(64) } : entry);
    return digest(files);
  };
  const rebindAuthorizer = "scripts/aws/authorize-production-stage-a-production-artifacts-continuation-rebind.mjs";
  const rebindAuthorizerObject = execFileSync("git", ["rev-parse", `${head}:${rebindAuthorizer}`], { encoding: "utf8" }).trim();
  const rebindAuthorizerMutation = stageAProductionArtifactsGovernedExecutableManifestSha256(head, {
    git: (args) => {
      const bytes = Buffer.from(execFileSync("git", args, { encoding: null }));
      return args[0] === "cat-file" && args[2] === rebindAuthorizerObject ? Buffer.concat([bytes, Buffer.from("\n// test mutation\n")]) : bytes;
    },
  });
  assert.notEqual(rebindAuthorizerMutation, historical, "changing the continuation-rebind authorizer must change the governed manifest");
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "manifest-bound-authorizer" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const rebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery, recoveryCompletion: completion, reviewedContinuationSourceSha: head, reviewedGovernedExecutableManifestSha256: historical, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, head), verificationRef: "manifest-bound-authorizer" });
  assert.throws(() => assertStageAProductionArtifactsContinuationRebindAuthorization(rebind, { historicalRecoveryAuthorization: recovery, recoveryCompletion: completion, sourceSha: head, readGovernedExecutableManifestSha256: () => rebindAuthorizerMutation }), /binding/);
  const proveDescendant = () => true;
  for (const { path: file } of manifest.files) {
    assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "b".repeat(40), recoverySourceSha: "a".repeat(40), proveDescendant, readGovernedExecutableManifestSha256: (sha) => sha.startsWith("a") ? historical : changedDigest(file) }), /governed executable source/, file);
  }
  for (const changed of [digest(manifest.files.slice(1)), digest([...manifest.files, { path: "infra/aws/terraform/production-green-stage-a/new.tf", sha256: "f".repeat(64) }])]) {
    assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "b".repeat(40), recoverySourceSha: "a".repeat(40), proveDescendant, readGovernedExecutableManifestSha256: (sha) => sha.startsWith("a") ? historical : changed }), /governed executable source/);
  }
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "b".repeat(40), recoverySourceSha: "a".repeat(40), proveDescendant, historicalGovernedExecutableManifestSha256: "0".repeat(64), readGovernedExecutableManifestSha256: () => historical }), /governed executable source/);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "b".repeat(40), recoverySourceSha: "a".repeat(40), proveDescendant, readGovernedExecutableManifestSha256: () => historical }));
});

test("descendant reconciliation preserves the historical recovery source and completion", () => {
  const successorSourceSha = "b".repeat(40);
  const recovery = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF), verificationRef: "historical" });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recovery, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign });
  const saved = { refreshOnly: true, savedPlanSha256: "c".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.8" };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha: successorSourceSha, preState, recoveryCompletion: completion.completion, saved });
  const proveDescendant = ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === successorSourceSha;
  const continuationRebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery, recoveryCompletion: completion, reviewedContinuationSourceSha: successorSourceSha, reviewedGovernedExecutableManifestSha256: governedExecutableManifestSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, successorSourceSha), verificationRef: "successor" });
  const reconciliation = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha: successorSourceSha, recoverySourceSha: sourceSha, preState, recoveryAuthorization: recovery, recoveryCompletion: completion, continuationRebindAuthorization: continuationRebind, prepareEvidence, savedPlanSha256: saved.savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF, successorSourceSha), verificationRef: "successor", verifyRecoveryCompletionEvidence: verify, proveDescendant, readGovernedExecutableManifestSha256: unchangedGovernedSource });
  assert.equal(reconciliation.recoverySourceSha, sourceSha);
  assert.equal(reconciliation.continuationRebindAuthorizationSha256, continuationRebind.authorizationSha256);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: successorSourceSha, recoverySourceSha: sourceSha, proveDescendant, readGovernedExecutableManifestSha256: unchangedGovernedSource }));
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: "f".repeat(40), recoverySourceSha: sourceSha, proveDescendant }), /descendant/);
});
