import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation, createStageAProductionArtifactsReconciliationPrepareEvidence, STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY, stageAProductionArtifactsPolicySha256 } from "../aws/production-stage-a-control-plane.mjs";
import { createStageAProductionArtifactsRecoveryAuthorization as createRecoveryAuthorization, createStageAProductionArtifactsRecoveryAttemptEvidence, createStageAProductionArtifactsRecoveryCompletionEvidence, createStageAProductionArtifactsContinuationRebindAuthorization, createStageAProductionArtifactsReconciliationAuthorization, STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";
import { assertStageAProductionArtifactsJournalRetention, runStageAProductionArtifactsRecovery } from "../aws/run-production-stage-a-production-artifacts-recovery.mjs";
import { createStageAProductionArtifactsJournalResult, createStageAProductionArtifactsPostApplyEvidence, createStageAProductionArtifactsReservation, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "../aws/production-stage-a-production-artifacts-journal.mjs";
import { assertStageAProductionArtifactsReconciliationPrivateArtifactPath, runStageAProductionArtifactsReconciliation as runReconciliation, runStageAProductionArtifactsReconciliationCli } from "../aws/run-production-stage-a-production-artifacts-reconciliation.mjs";

const sourceSha = "a".repeat(40); const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837"; const stateSha256 = "b".repeat(64);
const governedExecutableManifestSha256 = "9".repeat(64);
const historicalTransition = Object.freeze({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()), desiredPolicySha256: stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicy()) });
const createStageAProductionArtifactsRecoveryAuthorization = (input) => createRecoveryAuthorization({ ...input, governedExecutableManifestSha256, transition: historicalTransition });
const unchangedGovernedSource = () => governedExecutableManifestSha256;
const state = { lineage, serial: 35, stateSha256 };
const fixtureId = (prefix) => `${prefix}-${"0".repeat(8)}`;
const stageAVars = { TF_VAR_aws_region: "eu-west-2", TF_VAR_vpc_id: fixtureId("vpc"), TF_VAR_private_subnet_ids: JSON.stringify([fixtureId("subnet")]), TF_VAR_runtime_endpoint_security_group_ids: JSON.stringify([fixtureId("sg")]), TF_VAR_database_runtime_security_group_ids: JSON.stringify([fixtureId("sg")]), TF_VAR_s3_prefix_list_id: fixtureId("pl"), TF_VAR_vpc_dns_resolver_cidr: "10.0.0.2/32", TF_VAR_checker_principal_arns: '["arn:aws:iam::368992683803:role/mscqr-production-independent-checker"]', TF_VAR_release_role_arn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", TF_VAR_receipt_bucket_arn: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an" };
const terraformStateLock = { acquire: async () => {}, release: async () => {} };
const runStageAProductionArtifactsReconciliation = (input) => runReconciliation({ terraformStateLock, ...input });
const rootIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
const releaseIdentity = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" });
const environment = { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] };
const approval = (workflowRef, runId, approvedSourceSha = sourceSha) => createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha: approvedSourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: runId, workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-02T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const source = () => ({ headSha: sourceSha });

const policyResource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
const refreshPlan = (savedPolicy) => ({ complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: policyResource(buildStageAProductionArtifactsBucketPolicyPredecessor()), after: policyResource(savedPolicy), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }] });
const stateSnapshot = (identity, policy = identity.serial === 35 ? buildStageAProductionArtifactsBucketPolicyPredecessor() : buildStageAProductionArtifactsBucketPolicy()) => ({ ...identity, state: { version: 4, lineage: identity.lineage, serial: identity.serial, resources: [{ mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider: 'provider["registry.terraform.io/hashicorp/aws"]', instances: [{ schema_version: 0, attributes: policyResource(policy) }] }] } });

test("production reconciliation artifacts require one private direct-child directory", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-private-")); const dataDir = path.join(directory, "terraform-data"); fs.mkdirSync(dataDir, { mode: 0o700 });
  try {
    assert.equal(assertStageAProductionArtifactsReconciliationPrivateArtifactPath(path.join(dataDir, "refresh.tfplan"), { terraformDataDir: dataDir, allowExisting: false }), path.join(dataDir, "refresh.tfplan"));
    for (const candidate of [path.join(directory, "refresh.tfplan"), path.join(directory, "sibling", "refresh.tfplan"), path.join(process.cwd(), "refresh.tfplan"), path.join(dataDir, "nested", "refresh.tfplan")]) assert.throws(() => assertStageAProductionArtifactsReconciliationPrivateArtifactPath(candidate, { terraformDataDir: dataDir, allowExisting: false }), /direct child|outside the repository/);
    const nestedTarget = path.join(directory, "nested-target"); fs.mkdirSync(nestedTarget); fs.symlinkSync(nestedTarget, path.join(dataDir, "nested"), "dir"); assert.throws(() => assertStageAProductionArtifactsReconciliationPrivateArtifactPath(path.join(dataDir, "nested", "refresh.tfplan"), { terraformDataDir: dataDir, allowExisting: false }), /direct child/);
    const planLink = path.join(dataDir, "plan-link"); fs.symlinkSync(path.join(directory, "target"), planLink); assert.throws(() => assertStageAProductionArtifactsReconciliationPrivateArtifactPath(planLink, { terraformDataDir: dataDir, allowExisting: false }), /symlink/);
    fs.chmodSync(dataDir, 0o755); assert.throws(() => assertStageAProductionArtifactsReconciliationPrivateArtifactPath(path.join(dataDir, "refresh.tfplan"), { terraformDataDir: dataDir, allowExisting: false }), /mode 0700/); fs.chmodSync(dataDir, 0o700);
    const rootLink = path.join(directory, "root-link"); fs.symlinkSync(dataDir, rootLink, "dir"); assert.throws(() => assertStageAProductionArtifactsReconciliationPrivateArtifactPath(path.join(rootLink, "refresh.tfplan"), { terraformDataDir: rootLink, allowExisting: false }), /non-symlink directory/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("the production CLI composes prepare then execute without re-planning", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-cli-")); const terraformDataDir = path.join(directory, "terraform-data"); const refreshOnlyPlanPath = path.join(terraformDataDir, "prepared.tfplan"); const prepareEvidencePath = path.join(terraformDataDir, "prepare.json");
  let state = { lineage, serial: 35, stateSha256 }; let createPlans = 0; let readPlans = 0; let applies = 0; let terminal = "";
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "201"), verificationRef: "cli" });
  const completionEvidence = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recoveryAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => "c2lnbmF0dXJl" });
  const planBytes = Buffer.from("prepared-refresh-only-plan"); const savedPlanSha256 = createHash("sha256").update(planBytes).digest("hex"); const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: planBytes.length, planPath: refreshOnlyPlanPath, preState: state, terraformVersion: "1.15.8", plan: refreshPlan(buildStageAProductionArtifactsBucketPolicy()) };
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(buildStageAProductionArtifactsBucketPolicy()) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => args[1] === "get-caller-identity" ? rootIdentity : (() => { throw new Error(`unexpected root ${args[1]}`); })();
  const adapter = { readStateIdentity: async () => ({ ...state }), readStateSnapshot: async () => stateSnapshot(state), createSavedRefreshOnlyPlan: async () => { createPlans += 1; fs.writeFileSync(refreshOnlyPlanPath, planBytes, { mode: 0o600 }); return saved; }, readSavedRefreshOnlyPlan: async () => { readPlans += 1; return saved.plan; }, applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36, stateSha256: "e".repeat(64) }; }, readProductionArtifactsPolicy: async () => buildStageAProductionArtifactsBucketPolicy() };
  const journal = { readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completionEvidence)) }), readReservation: () => null, readPostApplyEvidence: () => null, readResult: () => null, reserve: (identity) => ({ reservation: identity }), writePostApplyEvidence: () => ({}), finalize: ({ status }) => { terminal = status; } };
  let reconciliationAuthorization;
  const resolveAuthorization = ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? { authorization: recoveryAuthorization } : { authorization: reconciliationAuthorization };
  const common = { releaseRun, rootRun, adapter, terraformStateLock, journal, rootJournal: journal, verifySignature: () => true, readProtectedSource: source, resolveAuthorization };
  try {
    await runStageAProductionArtifactsReconciliationCli(["--production", "--prepare", "--source-sha", sourceSha, "--terraform-data-dir", terraformDataDir, "--refresh-only-plan", refreshOnlyPlanPath, "--prepare-evidence", prepareEvidencePath, "--recovery-authorization-workflow-run-id", "201", "--recovery-authorization-workflow-run-attempt", "1"], { ...common, terraformInputEnvironment: stageAVars });
    assert.equal(fs.statSync(terraformDataDir).mode & 0o777, 0o700); assert.equal(fs.statSync(refreshOnlyPlanPath).mode & 0o777, 0o600); assert.equal(fs.statSync(prepareEvidencePath).mode & 0o777, 0o600);
    const prepareEvidence = JSON.parse(fs.readFileSync(prepareEvidencePath, "utf8"));
    reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "202"), verificationRef: "cli", verifyRecoveryCompletionEvidence: () => true });
    const result = await runStageAProductionArtifactsReconciliationCli(["--production", "--execute", "--source-sha", sourceSha, "--root-profile", "root", "--terraform-data-dir", terraformDataDir, "--refresh-only-plan", refreshOnlyPlanPath, "--prepare-evidence", prepareEvidencePath, "--recovery-authorization-workflow-run-id", "201", "--recovery-authorization-workflow-run-attempt", "1", "--reconciliation-authorization-workflow-run-id", "202", "--reconciliation-authorization-workflow-run-attempt", "1"], { ...common, terraformInputEnvironment: stageAVars });
    assert.equal(result.applied, true); assert.equal(createPlans, 1); assert.equal(readPlans, 1); assert.equal(applies, 1); assert.equal(terminal, "COMPLETED");
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("reconciliation uses the authenticated root exact-key reader only for release journal access denial", async () => {
  const before = { ...state }; const after = { ...state, serial: 36, stateSha256: "e".repeat(64) }; let currentState = { ...before }; let applies = 0;
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: before, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "611"), verificationRef: "root-journal" });
  const completionEvidence = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recoveryAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => "c2lnbmF0dXJl" });
  const savedPlanSha256 = "d".repeat(64); const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: 1, planPath: "/tmp/root-journal.tfplan", preState: before, terraformVersion: "1.15.8", plan: refreshPlan(buildStageAProductionArtifactsBucketPolicy()) };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState: before, recoveryCompletion: completionEvidence.completion, saved });
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: before, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "612"), verificationRef: "root-journal", verifyRecoveryCompletionEvidence: () => true });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(buildStageAProductionArtifactsBucketPolicy()) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => args[1] === "get-caller-identity" ? rootIdentity : (() => { throw new Error(`unexpected root ${args[1]}`); })();
  const identity = { operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliationAuthorization.authorizationSha256, recoveryCompletionSha256: completionEvidence.completionEvidenceSha256, savedPlanSha256, preStateLineage: before.lineage, preStateSerial: before.serial, preStateSha256: before.stateSha256, desiredPolicySha256: completionEvidence.desiredPolicySha256 };
  const reservation = createStageAProductionArtifactsReservation(identity);
  const base = ({ journal, rootJournal, root = rootRun } = {}) => ({ sourceSha, recoveryWorkflowRunId: "611", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "612", reconciliationWorkflowRunAttempt: "1", releaseRun, rootRun: root, adapter: { readStateIdentity: async () => ({ ...currentState }), readStateSnapshot: async () => stateSnapshot(currentState), applySavedRefreshOnlyPlan: async () => { applies += 1; currentState = { ...after }; }, readProductionArtifactsPolicy: async () => buildStageAProductionArtifactsBucketPolicy() }, readProtectedSource: source, verifySignature: () => true, preparedEvidence: prepareEvidence, saved, resolveAuthorization: ({ operation }) => ({ authorization: operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryAuthorization : reconciliationAuthorization }), journal, rootJournal });
  const absent = () => null; const denied = () => { const error = new Error("AccessDenied"); error.stderr = "403"; throw error; };
  const journal = (read) => ({ readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completionEvidence)) }), readReservation: read.reservation, readPostApplyEvidence: read.postApplyEvidence, readResult: read.result, reserve: () => ({ reservation }), writePostApplyEvidence: () => ({}), finalize: () => ({}) });
  for (const mode of ["reservation", "postApplyEvidence", "result"]) {
    currentState = { ...before }; applies = 0; let rootReads = 0; let rootIdentityReads = 0;
    const release = journal({ reservation: mode === "reservation" ? denied : absent, postApplyEvidence: mode === "postApplyEvidence" ? denied : absent, result: mode === "result" ? denied : absent });
    const root = journal({ reservation: () => { rootReads += 1; return mode === "reservation" ? { reservation } : null; }, postApplyEvidence: () => { rootReads += 1; if (mode === "postApplyEvidence") throw new Error("Stage A reconciliation post-apply evidence is missing its reservation."); return null; }, result: () => { rootReads += 1; if (mode === "result") throw new Error("Stage A reconciliation journal result is missing its reservation."); return null; } });
    const authenticatedRoot = (args) => { rootIdentityReads += 1; return rootRun(args); };
    await assert.rejects(() => runStageAProductionArtifactsReconciliation(base({ journal: release, rootJournal: root, root: authenticatedRoot })), /retained|reserved execution|completion-only resume|missing its reservation/, mode);
    assert.equal(rootIdentityReads, 1, mode); assert.ok(rootReads >= 1, mode); assert.equal(applies, 0, mode);
  }
  currentState = { ...before }; applies = 0; let rootReads = 0;
  const releaseDenied = journal({ reservation: denied, postApplyEvidence: denied, result: denied });
  const rootAbsent = journal({ reservation: () => { rootReads += 1; return null; }, postApplyEvidence: () => { rootReads += 1; return null; }, result: () => { rootReads += 1; return null; } });
  const completed = await runStageAProductionArtifactsReconciliation(base({ journal: releaseDenied, rootJournal: rootAbsent }));
  assert.equal(completed.applied, true); assert.equal(applies, 1); assert.ok(rootReads >= 3);
  for (const method of ["reservation", "postApplyEvidence", "result"]) for (const error of [new Error("AccessDenied"), new Error("network unavailable")]) {
    currentState = { ...before }; applies = 0;
    const rootFailure = journal({ reservation: method === "reservation" ? () => { throw error; } : absent, postApplyEvidence: method === "postApplyEvidence" ? () => { throw error; } : absent, result: method === "result" ? () => { throw error; } : absent });
    await assert.rejects(() => runStageAProductionArtifactsReconciliation(base({ journal: releaseDenied, rootJournal: rootFailure })), /AccessDenied|network unavailable/);
    assert.equal(applies, 0, method);
  }
  currentState = { ...before }; let rootUsed = false;
  const releaseAbsent = journal({ reservation: absent, postApplyEvidence: absent, result: absent });
  await runStageAProductionArtifactsReconciliation(base({ journal: releaseAbsent, rootJournal: journal({ reservation: () => { rootUsed = true; return null; }, postApplyEvidence: () => { rootUsed = true; return null; }, result: () => { rootUsed = true; return null; } }) }));
  assert.equal(rootUsed, false);
  const wrongRoot = () => JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:role/not-root" });
  currentState = { ...before };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(base({ journal: releaseDenied, rootJournal: rootAbsent, root: wrongRoot })), /exact root identity/);
});

test("compatible protected-main descendant consumes historical recovery completion without replaying recovery", async () => {
  const successorSourceSha = "b".repeat(40); let stateValue = { ...state, serial: 35 }; let applies = 0; let lockOwner = false; const lockWaiters = [];
  const exclusiveLock = { acquire: async () => { if (lockOwner) await new Promise((resolve) => lockWaiters.push(resolve)); lockOwner = true; }, release: async () => { lockOwner = false; lockWaiters.shift()?.(); } };
  let evidenceStartedResolve; const evidenceStarted = new Promise((resolve) => { evidenceStartedResolve = resolve; }); let publishEvidenceResolve; const publishEvidence = new Promise((resolve) => { publishEvidenceResolve = resolve; }); let q1Authenticated = false; let evidenceDurable = false;
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: stateValue, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "203"), verificationRef: "historical" });
  const completionEvidence = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recoveryAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => "c2lnbmF0dXJl" });
  const savedPlanSha256 = "c".repeat(64); const saved = { sourceSha: successorSourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: 1, planPath: "/tmp/stage-a-successor.tfplan", preState: stateValue, terraformVersion: "1.15.8", plan: refreshPlan(buildStageAProductionArtifactsBucketPolicy()) };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha: successorSourceSha, preState: stateValue, recoveryCompletion: completionEvidence.completion, saved });
  const proveDescendant = ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === successorSourceSha;
  const continuationRebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recoveryAuthorization, recoveryCompletion: completionEvidence, reviewedContinuationSourceSha: successorSourceSha, reviewedGovernedExecutableManifestSha256: governedExecutableManifestSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, "205", successorSourceSha), verificationRef: "successor" });
  const substitutedContinuationRebind = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recoveryAuthorization, recoveryCompletion: completionEvidence, reviewedContinuationSourceSha: successorSourceSha, reviewedGovernedExecutableManifestSha256: governedExecutableManifestSha256, protectedEnvironmentApprovalEvidence: approval(STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF, "205", successorSourceSha), verificationRef: "substituted" });
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha: successorSourceSha, recoverySourceSha: sourceSha, preState: stateValue, recoveryAuthorization, recoveryCompletion: completionEvidence, continuationRebindAuthorization: continuationRebind, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "204", successorSourceSha), verificationRef: "successor", verifyRecoveryCompletionEvidence: () => true, proveDescendant, readGovernedExecutableManifestSha256: unchangedGovernedSource });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(buildStageAProductionArtifactsBucketPolicy()) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const adapter = { readStateIdentity: async () => ({ ...stateValue }), readStateSnapshot: async () => stateSnapshot(stateValue), applySavedRefreshOnlyPlan: async () => { applies += 1; stateValue = { ...stateValue, serial: 36, stateSha256: "e".repeat(64) }; }, readProductionArtifactsPolicy: async () => buildStageAProductionArtifactsBucketPolicy() };
  const input = { sourceSha: successorSourceSha, recoverySourceSha: sourceSha, continuationRebindWorkflowRunId: "205", continuationRebindWorkflowRunAttempt: "1", recoveryWorkflowRunId: "203", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "204", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, terraformStateLock: exclusiveLock, readProtectedSource: () => ({ headSha: successorSourceSha }), proveDescendant, readGovernedExecutableManifestSha256: unchangedGovernedSource, verifySignature: () => true, preparedEvidence: prepareEvidence, saved, resolveAuthorization: ({ operation, sourceSha: resolvedSourceSha }) => { assert.equal(resolvedSourceSha, operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? sourceSha : successorSourceSha); return { authorization: operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryAuthorization : operation === STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION ? continuationRebind : reconciliationAuthorization }; }, journal: { readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completionEvidence)) }), readReservation: () => null, readPostApplyEvidence: () => null, readResult: () => null, reserve: (identity) => ({ reservation: identity }), writePostApplyEvidence: async () => { q1Authenticated = true; evidenceStartedResolve(); await publishEvidence; evidenceDurable = true; return {}; }, finalize: () => {} } };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation({ ...input, readGovernedExecutableManifestSha256: (sha) => sha === sourceSha ? governedExecutableManifestSha256 : "8".repeat(64) }), /continuation rebind/); assert.equal(applies, 0);
  await assert.rejects(() => runStageAProductionArtifactsReconciliation({ ...input, resolveAuthorization: ({ operation }) => ({ authorization: operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryAuthorization : operation === STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION ? substitutedContinuationRebind : reconciliationAuthorization }) }), /binding/); assert.equal(applies, 0);
  const execution = runStageAProductionArtifactsReconciliation(input); await evidenceStarted;
  let competingWriterAcquired = false;
  const competingWriter = exclusiveLock.acquire().then(() => { competingWriterAcquired = true; stateValue = { ...stateValue, serial: 37, stateSha256: "f".repeat(64) }; });
  await Promise.resolve(); assert.equal(competingWriterAcquired, false); assert.equal(q1Authenticated, true); assert.equal(evidenceDurable, false);
  publishEvidenceResolve(); const result = await execution; await competingWriter;
  assert.equal(result.applied, true); assert.equal(applies, 1); assert.equal(evidenceDurable, true); assert.equal(competingWriterAcquired, true); await exclusiveLock.release();
});

test("real Stage-A recovery and reconciliation runner composition reaches one state-only apply", async () => {
  const desiredPolicy = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation();
  let livePolicy = buildStageAProductionArtifactsBucketPolicy(); let puts = 0; let applies = 0; let persistedAttempt; let persistedCompletion; let releaseAttemptWrites = 0; let releaseCompletionWrites = 0; let rootAttemptWrites = 0; let rootCompletionReads = 0; let terminal;
  const recoveryAuthorization = createRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "101"), verificationRef: "manual", governedExecutableManifestSha256 });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { livePolicy = desiredPolicy; puts += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const releaseRecoveryJournal = { readRecoveryAttempt: () => persistedAttempt && { bytes: persistedAttempt }, readRecoveryCompletion: () => persistedCompletion && { bytes: persistedCompletion }, writeRecoveryAttempt: ({ bytes }) => { releaseAttemptWrites += 1; persistedAttempt = bytes; return { key: "attempt", sha256: "a".repeat(64) }; } };
  const rootRecoveryJournal = { readRecoveryCompletion: () => { rootCompletionReads += 1; return persistedCompletion && { bytes: persistedCompletion }; }, writeRecoveryAttempt: () => { rootAttemptWrites += 1; throw new Error("root must not write recovery attempt"); } };
  const completionJournal = { readRecoveryCompletion: () => persistedCompletion && { bytes: persistedCompletion }, writeRecoveryCompletion: ({ bytes }) => { releaseCompletionWrites += 1; persistedCompletion = bytes; return { key: "completion", sha256: "c".repeat(64) }; } };
  const recovery = await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "101", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization: recoveryAuthorization }), journal: completionJournal, recoveryJournal: releaseRecoveryJournal, rootRecoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true });
  assert.equal(recovery.putBucketPolicyCount, 1); assert.equal(puts, 1); assert.equal(releaseAttemptWrites, 1); assert.equal(releaseCompletionWrites, 1); assert.equal(rootAttemptWrites, 0); assert.equal(rootCompletionReads, 1);
  const completionEvidence = JSON.parse(persistedCompletion); const recoveryArtifact = { authorization: recoveryAuthorization };
  const savedPlanSha256 = "d".repeat(64);
  const resource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
  const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: 1, planPath: "/tmp/stage-a-refresh.tfplan", preState: state, terraformVersion: "1.15.8", plan: { complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: "aws_s3_bucket_policy", name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(buildStageAProductionArtifactsBucketPolicy()), after: resource(livePolicy), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }] } };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState: state, recoveryCompletion: completionEvidence.completion, saved });
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "102"), verificationRef: "manual", verifyRecoveryCompletionEvidence: () => true });
  const adapter = { readStateIdentity: async () => ({ ...state }), readStateSnapshot: async () => stateSnapshot(state, state.serial === 35 ? buildStageAProductionArtifactsBucketPolicy() : desiredPolicy), createSavedRefreshOnlyPlan: async () => saved, applySavedRefreshOnlyPlan: async () => { applies += 1; state.serial = 36; state.stateSha256 = "e".repeat(64); }, readProductionArtifactsPolicy: async () => livePolicy };
  const result = await runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: "101", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "102", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, readProtectedSource: source, verifySignature: () => true, preparedEvidence: prepareEvidence, saved, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryArtifact : { authorization: reconciliationAuthorization }, journal: { readRecoveryCompletion: () => ({ bytes: persistedCompletion }), readReservation: () => null, readPostApplyEvidence: () => null, readResult: () => null, reserve: (identity) => ({ reservation: identity }), writePostApplyEvidence: () => ({}), finalize: ({ status }) => { terminal = status; } } });
  assert.equal(result.applied, true); assert.equal(applies, 1); assert.equal(terminal, "COMPLETED");
  await assert.rejects(() => runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: "101", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "102", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, readProtectedSource: source, verifySignature: () => false, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? recoveryArtifact : { authorization: reconciliationAuthorization }, journal: { readRecoveryCompletion: () => ({ bytes: persistedCompletion }), readReservation: () => null, readPostApplyEvidence: () => null, readResult: () => null, reserve: () => { throw new Error("must not reserve"); }, writePostApplyEvidence: () => ({}), finalize: () => {} } }), /authorization|signature/);
});

test("historical A-to-B recovery selects the root-backed journal", async () => {
  let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let policyWrites = 0; let rootAttemptWrites = 0; let releaseAttemptWrites = 0; let rootCompletionWrites = 0; let releaseCompletionWrites = 0; let attemptBytes; let completionBytes;
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "103"), verificationRef: "historical-root-writer" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { policyWrites += 1; livePolicy = buildStageAProductionArtifactsBucketPolicy(); return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const releaseJournal = { readRecoveryAttempt: () => { releaseAttemptWrites += 1; throw new Error("release journal is not permitted for A-to-B"); }, readRecoveryCompletion: () => null, writeRecoveryAttempt: () => { releaseAttemptWrites += 1; throw new Error("release journal is not permitted for A-to-B"); }, writeRecoveryCompletion: () => { releaseCompletionWrites += 1; throw new Error("release journal is not permitted for A-to-B"); } };
  const rootJournal = { readRecoveryAttempt: () => attemptBytes && { bytes: attemptBytes }, readRecoveryCompletion: () => completionBytes && { bytes: completionBytes }, writeRecoveryAttempt: ({ bytes }) => { rootAttemptWrites += 1; attemptBytes = bytes; return { key: "attempt" }; }, writeRecoveryCompletion: ({ bytes }) => { rootCompletionWrites += 1; completionBytes = bytes; return { key: "completion" }; } };
  const result = await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "103", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal: releaseJournal, recoveryJournal: releaseJournal, rootRecoveryJournal: rootJournal, sign: () => Buffer.from("root-signature").toString("base64"), verify: () => true });
  assert.equal(result.putBucketPolicyCount, 1); assert.equal(policyWrites, 1); assert.equal(rootAttemptWrites, 1); assert.equal(rootCompletionWrites, 1); assert.equal(releaseAttemptWrites, 0); assert.equal(releaseCompletionWrites, 0);
});

test("reconciliation resumes completion-only after apply succeeds but terminal publication fails", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let applies = 0; let postApplyStateReadFailures = 1; let finalizationFailures = 1; let losePostApplyResponse = false; let loseCompletionResponse = false; let persistedReservation; let persistedResult;
  let lockHeld = false; let lockReleases = 0;
  const stateLock = { acquire: async () => { if (lockHeld) throw new Error("canonical backend lock is held"); lockHeld = true; }, release: async () => { lockHeld = false; lockReleases += 1; }, operatorResolve: () => { lockHeld = false; } };
  const recoveryAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "401"), verificationRef: "completion-resume" });
  const completionEvidence = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: recoveryAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => "c2lnbmF0dXJl" });
  const savedPlanSha256 = "d".repeat(64); const saved = { sourceSha, refreshOnly: true, savedPlanSha256, savedPlanByteLength: 1, planPath: "/tmp/stage-a-completion-resume.tfplan", preState: state, terraformVersion: "1.15.8", plan: refreshPlan(buildStageAProductionArtifactsBucketPolicy()) };
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, preState: state, recoveryCompletion: completionEvidence.completion, saved });
  const reconciliationAuthorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, preState: state, recoveryAuthorization, recoveryCompletion: completionEvidence, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsReconciliationWorkflowRef, "402"), verificationRef: "completion-resume", verifyRecoveryCompletionEvidence: () => true });
  let livePolicy = buildStageAProductionArtifactsBucketPolicy();
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const adapter = { readStateIdentity: async () => { if (applies && postApplyStateReadFailures) { postApplyStateReadFailures -= 1; throw new Error("injected post-apply state read failure"); } return { ...state }; }, readStateSnapshot: async () => stateSnapshot(state), applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36, stateSha256: "e".repeat(64) }; throw new Error("apply exited nonzero after state mutation"); }, readProductionArtifactsPolicy: async () => livePolicy };
  let persistedPostApply;
  const journal = {
    readRecoveryCompletion: () => ({ bytes: Buffer.from(JSON.stringify(completionEvidence)) }),
    readReservation: () => persistedReservation && { reservation: persistedReservation },
    readPostApplyEvidence: () => persistedPostApply && { evidence: persistedPostApply },
    readResult: () => persistedResult && { result: persistedResult },
    reserve: (identity) => { persistedReservation = createStageAProductionArtifactsReservation(identity); return { reservation: persistedReservation }; },
    writePostApplyEvidence: ({ reservation, postState, postLivePolicySha256 }) => { persistedPostApply = createStageAProductionArtifactsPostApplyEvidence({ reservation: reservation?.reservation || reservation, postState, postLivePolicySha256 }); if (losePostApplyResponse) { losePostApplyResponse = false; throw new Error("injected post-apply response loss"); } return { evidence: persistedPostApply }; },
    finalize: ({ reservation, status, postState, postLivePolicySha256 }) => { const result = createStageAProductionArtifactsJournalResult({ reservation, status, postState, postLivePolicySha256 }); if (status === "COMPLETED" && finalizationFailures > 0) { finalizationFailures -= 1; throw new Error("injected terminal publication failure"); } persistedResult = result; if (status === "COMPLETED" && loseCompletionResponse) { loseCompletionResponse = false; throw new Error("injected terminal response loss"); } return { result }; },
  };
  const common = { sourceSha, recoveryWorkflowRunId: "401", recoveryWorkflowRunAttempt: "1", reconciliationWorkflowRunId: "402", reconciliationWorkflowRunAttempt: "1", releaseRun, adapter, terraformStateLock: stateLock, readProtectedSource: source, verifySignature: () => true, preparedEvidence: prepareEvidence, saved, resolveAuthorization: ({ operation }) => operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION ? { authorization: recoveryAuthorization } : { authorization: reconciliationAuthorization }, journal };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /retained the canonical backend lock/);
  assert.equal(applies, 1); assert.ok(persistedReservation); assert.equal(persistedPostApply, undefined); assert.equal(persistedResult, undefined); assert.equal(lockHeld, true); assert.equal(lockReleases, 0);
  stateLock.operatorResolve();
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /terminal publication failure/);
  assert.ok(persistedPostApply); assert.equal(lockHeld, false); assert.equal(lockReleases, 1);
  state = { lineage, serial: 35, stateSha256: "f".repeat(64) };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /pre-state|post-state/);
  state = { lineage, serial: 35, stateSha256 };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /pre-state|post-state/);
  state = { lineage, serial: 36, stateSha256: "e".repeat(64) };
  const savedPlanSubstitution = { ...saved, savedPlanSha256: "a".repeat(64) };
  await assert.rejects(() => runStageAProductionArtifactsReconciliation({ ...common, saved: savedPlanSubstitution }), /prepare evidence|authorization/);
  const savedReservation = persistedReservation;
  persistedReservation = createStageAProductionArtifactsReservation({ ...savedReservation, preStateSha256: "f".repeat(64) });
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /authorized operation|reservation/);
  persistedReservation = savedReservation;
  persistedPostApply = undefined;
  const derivedEvidence = await runStageAProductionArtifactsReconciliation(common);
  assert.equal(derivedEvidence.resumed, true); assert.equal(applies, 1); assert.ok(persistedPostApply); assert.ok(persistedResult);
  persistedResult = undefined;
  persistedPostApply = createStageAProductionArtifactsPostApplyEvidence({ reservation: persistedReservation, postState: state, postLivePolicySha256: completionEvidence.desiredPolicySha256 });
  livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor();
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /exact live desired policy/);
  livePolicy = buildStageAProductionArtifactsBucketPolicy();
  persistedResult = createStageAProductionArtifactsJournalResult({ reservation: persistedReservation, status: "ABORTED_BEFORE_APPLY" });
  await assert.rejects(() => runStageAProductionArtifactsReconciliation(common), /completion result|COMPLETED/);
  persistedResult = undefined;
  const resumed = await runStageAProductionArtifactsReconciliation(common);
  assert.equal(resumed.resumed, true); assert.equal(resumed.applied, false); assert.equal(applies, 1); assert.ok(persistedResult);
  const repeated = await runStageAProductionArtifactsReconciliation(common);
  assert.equal(repeated.alreadyCompleted, true); assert.equal(repeated.applied, false); assert.equal(applies, 1);
  persistedResult = undefined; persistedPostApply = undefined; losePostApplyResponse = true; loseCompletionResponse = true;
  const lostResponses = await runStageAProductionArtifactsReconciliation(common);
  assert.equal(lostResponses.resumed, true); assert.equal(applies, 1); assert.equal(persistedResult.status, "COMPLETED");
});

test("recovery resumes exact desired policy only from its signed immutable attempt", async () => {
  let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let puts = 0; let attemptBytes; let completionBytes; let signCalls = 0; let loseCompletionResponse = true; let releaseCompletionReads = 0; let rootCompletionReads = 0; let lockAcquires = 0; let lockReleases = 0;
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "201"), verificationRef: "resume" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { livePolicy = buildStageAProductionArtifactsBucketPolicy(); puts += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const recoveryJournal = { readRecoveryAttempt: () => attemptBytes && { bytes: attemptBytes }, readRecoveryCompletion: () => { rootCompletionReads += 1; return completionBytes && { bytes: completionBytes }; }, writeRecoveryAttempt: ({ bytes }) => { attemptBytes = bytes; return { key: "attempt" }; }, writeRecoveryCompletion: ({ bytes }) => { completionBytes = bytes; if (loseCompletionResponse) { loseCompletionResponse = false; throw new Error("injected after completion write"); } return { key: "completion", sha256: "c".repeat(64) }; } };
  const journal = { readRecoveryCompletion: () => { releaseCompletionReads += 1; return completionBytes && { bytes: completionBytes }; }, writeRecoveryCompletion: ({ bytes }) => { completionBytes = bytes; if (loseCompletionResponse) { loseCompletionResponse = false; throw new Error("injected after completion write"); } return { key: "completion", sha256: "c".repeat(64) }; } };
  const countedLock = { acquire: async () => { lockAcquires += 1; }, release: async () => { lockReleases += 1; } };
  const input = { sourceSha, workflowRunId: "201", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock: countedLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, verify: () => true };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, sign: () => { signCalls += 1; if (signCalls === 2) throw new Error("injected after policy write"); return Buffer.from("signature").toString("base64"); } }), /injected after policy write/);
  assert.equal(puts, 1); assert.ok(attemptBytes); assert.equal(completionBytes, undefined);
  assert.equal(lockAcquires, 1); assert.equal(lockReleases, 1);
  assert.equal(rootCompletionReads, 1); assert.equal(releaseCompletionReads, 0);
  for (const entry of livePolicy.Statement) if (Array.isArray(entry.Resource) && entry.Resource.length === 1) entry.Resource = entry.Resource[0];
  const successorSourceSha = "b".repeat(40);
  const successorInput = { ...input, sourceSha: successorSourceSha, recoverySourceSha: sourceSha, readProtectedSource: () => ({ headSha: successorSourceSha }), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === successorSourceSha, readGovernedExecutableManifestSha256: unchangedGovernedSource, resolveAuthorization: ({ sourceSha: resolvedSourceSha }) => { assert.equal(resolvedSourceSha, sourceSha); return { authorization }; } };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...successorInput, readGovernedExecutableManifestSha256: (sha) => sha === sourceSha ? governedExecutableManifestSha256 : "8".repeat(64), sign: () => { throw new Error("must not sign"); } }), /governed executable source/); assert.equal(puts, 1);
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...successorInput, proveDescendant: () => false, sign: () => Buffer.from("signature").toString("base64") }), /descendant/);
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...successorInput, verify: () => false, sign: () => Buffer.from("signature").toString("base64") }), /signature/);
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...successorInput, readStateIdentity: async () => ({ ...state, serial: state.serial + 1 }), sign: () => Buffer.from("signature").toString("base64") }), /state identity|authorization binding/);
  const resumed = await runStageAProductionArtifactsRecovery({ ...successorInput, sign: () => Buffer.from("signature").toString("base64") });
  assert.equal(resumed.resumed, true); assert.equal(resumed.putBucketPolicyCount, 0); assert.equal(puts, 1);
  assert.equal(lockAcquires, 3); assert.equal(lockReleases, 3);
  const complete = await runStageAProductionArtifactsRecovery({ ...input, sign: () => { throw new Error("must not sign"); } });
  assert.equal(complete.alreadyComplete, true); assert.equal(complete.putBucketPolicyCount, 0); assert.equal(puts, 1);
  assert.equal(lockAcquires, 3); assert.equal(lockReleases, 3);
  completionBytes = undefined; attemptBytes = undefined;
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, sign: () => Buffer.from("signature").toString("base64") }), /lacks the immutable signed pre-write attempt/);
  assert.equal(puts, 1);
});

test("recovery attempt persistence uses the release writer and gates the root policy mutation", async () => {
  const authorization = createRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "203"), verificationRef: "release-attempt-writer", governedExecutableManifestSha256 });
  let policyWrites = 0; let completionWrites = 0; let rootAttemptWrites = 0;
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(buildStageAProductionArtifactsBucketPolicy()) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { policyWrites += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const releaseRecoveryJournal = { readRecoveryAttempt: () => null, writeRecoveryAttempt: () => { throw new Error("release recovery attempt persistence failed"); } };
  const rootRecoveryJournal = { readRecoveryCompletion: () => null, writeRecoveryAttempt: () => { rootAttemptWrites += 1; } };
  const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => { completionWrites += 1; return { key: "completion" }; } };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "203", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal: releaseRecoveryJournal, rootRecoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true }), /release recovery attempt persistence failed/);
  assert.equal(policyWrites, 0); assert.equal(completionWrites, 0); assert.equal(rootAttemptWrites, 0);
});

test("post-write continuation locks only after authenticated P2 evidence", async () => {
  const authorization = createRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "220"), verificationRef: "post-write-no-lock", governedExecutableManifestSha256 });
  const attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization, sign: () => Buffer.from("signature").toString("base64") });
  let livePolicy = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation(); let lockAcquires = 0; let lockReleases = 0; let policyWrites = 0; let completionWrites = 0; let sourceReads = 0;
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { policyWrites += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const lock = { acquire: async () => { lockAcquires += 1; }, release: async () => { lockReleases += 1; } };
  const recoveryJournal = { readRecoveryAttempt: () => ({ bytes: Buffer.from(JSON.stringify(attempt)) }), readRecoveryCompletion: () => null, writeRecoveryAttempt: () => { throw new Error("post-write continuation must not create an attempt"); }, writeRecoveryCompletion: ({ bytes }) => { completionWrites += 1; return { key: "completion", sha256: "c".repeat(64) }; } };
  const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => { completionWrites += 1; return { key: "completion", sha256: "c".repeat(64) }; } };
  const rootRecoveryJournal = { ...recoveryJournal, readRecoveryCompletion: () => null };
  const input = { sourceSha, workflowRunId: "220", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock: lock, readProtectedSource: () => { sourceReads += 1; return source(); }, resolveAuthorization: () => ({ authorization }), recoveryJournal, rootRecoveryJournal, journal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true };
  const result = await runStageAProductionArtifactsRecovery(input);
  assert.equal(result.classification, "POST_WRITE_COMPLETION_PENDING"); assert.equal(sourceReads, 2); assert.equal(lockAcquires, 1); assert.equal(lockReleases, 1); assert.equal(policyWrites, 0); assert.equal(completionWrites, 1);
  const validCompletion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation(), sign: () => Buffer.from("signature").toString("base64") });
  const denied = () => { const error = new Error("AccessDenied"); error.stderr = "403"; throw error; };
  for (const [label, rootCompletion, expected] of [
    ["authenticated absent completion", null, { locks: 1, writes: 1 }],
    ["existing completion via root fallback", { bytes: Buffer.from(JSON.stringify(validCompletion)) }, { locks: 0, writes: 0, complete: true }],
    ["malformed root fallback completion", { bytes: Buffer.from("{}") }, { locks: 0, writes: 0, reject: /completion/i }],
    ["unverifiable release access denial", new Error("AccessDenied"), { locks: 0, writes: 0, reject: /AccessDenied/i }],
  ]) {
    lockAcquires = 0; lockReleases = 0; completionWrites = 0; let releaseReads = 0; let rootReads = 0;
    const fallbackJournal = { ...journal, readRecoveryCompletion: (sha) => { assert.equal(sha, authorization.authorizationSha256); releaseReads += 1; return denied(); } };
    const fallbackRecoveryJournal = { ...recoveryJournal, readRecoveryCompletion: (sha) => { assert.equal(sha, authorization.authorizationSha256); rootReads += 1; if (rootCompletion instanceof Error) throw rootCompletion; return rootCompletion; } };
    if (expected.reject) await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, journal: fallbackJournal, recoveryJournal: fallbackRecoveryJournal, rootRecoveryJournal: fallbackRecoveryJournal }), expected.reject, label);
    else { const fallback = await runStageAProductionArtifactsRecovery({ ...input, journal: fallbackJournal, recoveryJournal: fallbackRecoveryJournal, rootRecoveryJournal: fallbackRecoveryJournal }); assert.equal(fallback.alreadyComplete === true, expected.complete === true, label); }
    assert.equal(releaseReads, expected.complete ? 1 : expected.reject ? 1 : 2, label); assert.equal(rootReads, releaseReads, label); assert.equal(lockAcquires, expected.locks, label); assert.equal(lockReleases, expected.locks, label); assert.equal(completionWrites, expected.writes, label); assert.equal(policyWrites, 0, label);
  }
  for (const [label, override, expectedLocks] of [
    ["missing attempt", { recoveryJournal: { ...recoveryJournal, readRecoveryAttempt: () => null } }, 0],
    ["invalid attempt", { recoveryJournal: { ...recoveryJournal, readRecoveryAttempt: () => ({ bytes: Buffer.from("{}") }) } }, 0],
    ["invalid authorization", { resolveAuthorization: () => ({ authorization: { ...authorization, desiredPolicySha256: "0".repeat(64) } }) }, 0],
    ["changed state", { readStateIdentity: async () => ({ ...state, serial: state.serial + 1 }) }, 1],
    ["conflicting completion", { journal: { ...journal, readRecoveryCompletion: () => ({ bytes: Buffer.from("{}") }) } }, 0],
    ["completion publication failure", { journal: { ...journal, writeRecoveryCompletion: () => { throw new Error("completion publication failed"); } } }, 1],
  ]) {
    lockAcquires = 0; lockReleases = 0; policyWrites = 0; completionWrites = 0;
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...input, ...override }), /attempt|state identity|authorization binding|completion|transition/i, label);
    assert.equal(lockAcquires, expectedLocks, label); assert.equal(lockReleases, expectedLocks, label); assert.equal(policyWrites, 0, label); assert.equal(completionWrites, 0, label);
  }
  livePolicy = { Version: "2012-10-17", Statement: [] }; lockAcquires = 0; lockReleases = 0; policyWrites = 0;
  await assert.rejects(() => runStageAProductionArtifactsRecovery(input), /not executable|neither the exact predecessor nor desired/i);
  assert.equal(lockAcquires, 0); assert.equal(lockReleases, 0); assert.equal(policyWrites, 0);
});

test("post-write continuation holds the existing lock through state CAS and concurrent completion publication", async () => {
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "221"), verificationRef: "post-write-lock-cas" });
  const attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization, sign: () => Buffer.from("signature").toString("base64") });
  const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => Buffer.from("signature").toString("base64") });
  let stateValue = { ...state }; let livePolicy = buildStageAProductionArtifactsBucketPolicy(); let locked = false; let lockAcquires = 0; let lockReleases = 0; let completionWrites = 0; let completionBytes;
  const lock = { acquire: async () => { assert.equal(locked, false); locked = true; lockAcquires += 1; }, release: async () => { assert.equal(locked, true); locked = false; lockReleases += 1; } };
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? JSON.stringify({ Policy: JSON.stringify(livePolicy) }) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => args[1] === "get-caller-identity" ? rootIdentity : args[1] === "get-bucket-versioning" ? JSON.stringify({ Status: "Enabled" }) : args[1] === "get-bucket-lifecycle-configuration" ? (() => { throw new Error("NoSuchLifecycleConfiguration"); })() : (() => { throw new Error(`unexpected root ${args[1]}`); })();
  const recoveryJournal = { readRecoveryAttempt: () => ({ bytes: Buffer.from(JSON.stringify(attempt)) }), readRecoveryCompletion: () => completionBytes && { bytes: completionBytes }, writeRecoveryAttempt: () => { throw new Error("must not write attempt"); }, writeRecoveryCompletion: ({ bytes }) => { completionWrites += 1; return { key: "completion", sha256: "c".repeat(64) }; } };
  const base = { sourceSha, workflowRunId: "221", workflowRunAttempt: "1", rootRun, releaseRun, terraformStateLock: lock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true };
  const journal = { readRecoveryCompletion: () => completionBytes && { bytes: completionBytes }, writeRecoveryCompletion: () => { completionWrites += 1; return { key: "completion", sha256: "c".repeat(64) }; } };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...base, journal, readStateIdentity: async () => ({ ...stateValue, serial: 55, stateSha256: "d".repeat(64) }) }), /state identity|authorization binding/);
  assert.equal(lockAcquires, 1); assert.equal(lockReleases, 1); assert.equal(completionWrites, 0);
  lockAcquires = 0; lockReleases = 0; completionWrites = 0;
  const tryStateMutation = () => { if (locked) return false; stateValue = { ...stateValue, serial: 55, stateSha256: "d".repeat(64) }; return true; };
  const concurrentJournal = { ...journal, readRecoveryCompletion: () => completionBytes && { bytes: completionBytes }, writeRecoveryCompletion: () => { completionWrites += 1; throw new Error("must not publish after valid concurrent completion"); } };
  const concurrent = await runStageAProductionArtifactsRecovery({ ...base, journal: concurrentJournal, readStateIdentity: async () => { assert.equal(locked, true); assert.equal(tryStateMutation(), false); stateValue = { ...state }; completionBytes = Buffer.from(JSON.stringify(completion)); return { ...stateValue }; } });
  assert.equal(concurrent.alreadyComplete, true); assert.equal(lockAcquires, 1); assert.equal(lockReleases, 1); assert.equal(completionWrites, 0);
  completionBytes = undefined; lockAcquires = 0; lockReleases = 0; completionWrites = 0;
  const collision = await runStageAProductionArtifactsRecovery({ ...base, journal, rootRecoveryJournal: { ...recoveryJournal, writeRecoveryCompletion: () => { completionBytes = Buffer.from(JSON.stringify(completion)); throw new Error("conditional collision"); } }, readStateIdentity: async () => ({ ...state }) });
  assert.equal(collision.alreadyComplete, true); assert.equal(lockAcquires, 1); assert.equal(lockReleases, 1); assert.equal(completionWrites, 0);
  const wrongAuthorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: { ...state, serial: 36, stateSha256: "e".repeat(64) }, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "222"), verificationRef: "wrong-completion" });
  const wrongAuthorizationCompletion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization: wrongAuthorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicy(), sign: () => Buffer.from("signature").toString("base64") });
  for (const [label, concurrentBytes] of [["malformed", Buffer.from("{}")], ["wrong authorization", Buffer.from(JSON.stringify(wrongAuthorizationCompletion))], ["wrong state", Buffer.from(JSON.stringify(wrongAuthorizationCompletion))]]) {
    completionBytes = undefined; lockAcquires = 0; lockReleases = 0;
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ ...base, journal, readStateIdentity: async () => { completionBytes = concurrentBytes; return { ...state }; } }), /completion evidence|completion is malformed|completion binding|completion hash/i, label);
    assert.equal(lockAcquires, 1, label); assert.equal(lockReleases, 1, label);
  }
});

test("root recovery rejects every non-clean protected checkout before AWS", async () => {
  for (const message of ["tracked modifications", "staged modification", "untracked file", "wrong protected main"]) {
    let awsCalls = 0;
    const run = () => { awsCalls += 1; throw new Error("must not call AWS"); };
    const journal = { readRecoveryCompletion() {}, writeRecoveryCompletion() {}, readRecoveryAttempt() {}, writeRecoveryAttempt() {} };
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, rootRun: run, releaseRun: run, readStateIdentity: async () => state, terraformStateLock, resolveAuthorization: () => { throw new Error("must not resolve authorization"); }, journal, sign: () => "signature", verify: () => true, readProtectedSource: () => { throw new Error(message); } }), new RegExp(message));
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
    const recoveryJournal = { readRecoveryAttempt: () => null, readRecoveryCompletion: () => null, writeRecoveryAttempt: () => ({ key: "attempt" }), writeRecoveryCompletion: () => ({ key: "completion" }) };
    const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => ({ key: "completion" }) };
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: `30${index + 1}`, workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => { stateReads += 1; return stateReads === 1 ? alteredState : baselineState; }, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true }), /state identity|authorization binding|state changed before the policy write/, label);
    assert.equal(puts, 0, label);
  }
});

test("root recovery performs no networked work between final state CAS and policy write", async () => {
  const calls = []; let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let stateReads = 0;
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "304"), verificationRef: "adjacency" });
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : args[1] === "get-bucket-policy" ? (calls.push("policy"), JSON.stringify({ Policy: JSON.stringify(livePolicy) })) : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
    if (args[1] === "put-bucket-policy") { calls.push("put-policy"); livePolicy = buildStageAProductionArtifactsBucketPolicy(); return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const recoveryJournal = { readRecoveryAttempt: () => null, readRecoveryCompletion: () => null, writeRecoveryAttempt: () => ({ key: "attempt" }), writeRecoveryCompletion: () => ({ key: "completion" }) };
  const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => ({ key: "completion" }) };
  await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "304", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => { calls.push("state"); stateReads += 1; return state; }, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true });
  const putIndex = calls.indexOf("put-policy");
  assert.equal(calls[putIndex - 1], "policy");
  assert.deepEqual(calls.slice(putIndex - 1, putIndex + 2), ["policy", "put-policy", "policy"]);
});

test("root recovery rejects an intervening live policy before PutBucketPolicy", async () => {
  for (const [index, [label, interveningPolicy]] of [["desired", buildStageAProductionArtifactsBucketPolicy()], ["unknown", { Version: "2012-10-17", Statement: [] }]].entries()) {
    let livePolicy = buildStageAProductionArtifactsBucketPolicyPredecessor(); let policyReads = 0; let puts = 0;
    const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, String(305 + index)), verificationRef: `policy-race-${label}` });
    const releaseRun = (args) => {
      if (args[1] === "get-caller-identity") return releaseIdentity;
      if (args[1] === "get-bucket-policy") { policyReads += 1; if (policyReads === 2) livePolicy = interveningPolicy; return JSON.stringify({ Policy: JSON.stringify(livePolicy) }); }
      throw new Error(`unexpected release ${args[1]}`);
    };
    const rootRun = (args) => {
      if (args[1] === "get-caller-identity") return rootIdentity;
      if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
      if (args[1] === "get-bucket-lifecycle-configuration") throw new Error("NoSuchLifecycleConfiguration");
      if (args[1] === "put-bucket-policy") { puts += 1; return ""; }
      throw new Error(`unexpected root ${args[1]}`);
    };
    const recoveryJournal = { readRecoveryAttempt: () => null, readRecoveryCompletion: () => null, writeRecoveryAttempt: () => ({ key: "attempt" }), writeRecoveryCompletion: () => ({ key: "completion" }) };
    const journal = { readRecoveryCompletion: () => null, writeRecoveryCompletion: () => ({ key: "completion" }) };
    await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: String(305 + index), workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal, sign: () => Buffer.from("signature").toString("base64"), verify: () => true }), /live policy changed before the policy write/);
    assert.equal(puts, 0, label);
  }
});

test("recovery journal retention rejects overlapping current-object expiration and transitions", () => {
  const destructive = (rule) => ({ Status: "Enabled", Expiration: { Days: 1 }, ...rule });
  for (const rule of [
    { Prefix: "" },
    { Prefix: "production-" },
    { Filter: { Prefix: "production-stage-a-production-artifacts-reconciliation/" } },
    { Prefix: "production-stage-a-production-artifacts-reconciliation/recovery/" },
    { Filter: { And: { Prefix: "production-stage-a-production-artifacts-reconciliation/recovery/abc/" } } },
    { Filter: { Tag: { Key: "retention", Value: "short" } } },
    { Filter: { ObjectSizeGreaterThan: 1 } },
  ]) assert.throws(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive(rule)] }), /current records unavailable/);
  assert.throws(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive({ Filter: { And: { Prefix: "production-stage-a-production-artifacts-reconciliation/recovery/", Tag: { Key: "retention", Value: "short" } } } })] }), /current records unavailable/);
  for (const rule of [
    { Prefix: "production-initial-activation-lifecycle-policy-reconciliation/reservations/" },
    { Prefix: "production-initial-activation-lifecycle-policy-reconciliation/" },
    { Prefix: "" },
    { Filter: { And: { Prefix: "production-initial-activation-lifecycle-policy-reconciliation/reservations/", Tag: { Key: "retention", Value: "short" } } } },
  ]) assert.throws(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive(rule)] }), /protected immutable record unavailable/);
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [] }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Disabled", Prefix: "production-initial-activation-lifecycle-policy-reconciliation/reservations/", Expiration: { Days: 1 } }] }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive({ Filter: { And: { Prefix: "unrelated/", Tag: { Key: "retention", Value: "short" } } } })] }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive({ Prefix: "some-other-prefix/" })] }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [destructive({ Filter: { And: { Prefix: "some-other-prefix/", Tag: { Key: "retention", Value: "short" } } } })] }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Disabled", Prefix: "", Expiration: { Days: 1 } }] }));
  for (const transition of [{ Transition: { Days: 1, StorageClass: "GLACIER" } }, { Transitions: [{ Days: 1, StorageClass: "STANDARD_IA" }] }]) {
    assert.throws(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Enabled", Prefix: "production-stage-a-production-artifacts-reconciliation/recovery/", ...transition }] }), /current records unavailable/);
    assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Disabled", Prefix: "", ...transition }] }));
    assert.doesNotThrow(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Enabled", Prefix: "some-other-prefix/", ...transition }] }));
  }
  assert.throws(() => assertStageAProductionArtifactsJournalRetention({ Rules: [{ Status: "Enabled", Prefix: "", NoncurrentVersionExpiration: { NoncurrentDays: 1 }, NoncurrentVersionTransitions: [{ NoncurrentDays: 1, StorageClass: "GLACIER" }] }] }), /protected immutable record unavailable/);
});

test("reservation-affecting lifecycle fails before the governed bucket-policy write", async () => {
  const authorization = createRecoveryAuthorization({ sourceSha, preState: state, protectedEnvironmentApprovalEvidence: approval(PRODUCTION_ENVIRONMENT_APPROVAL.stageAProductionArtifactsRecoveryWorkflowRef, "506"), verificationRef: "retention", governedExecutableManifestSha256 });
  let policyWrites = 0;
  const releaseRun = (args) => args[1] === "get-caller-identity" ? releaseIdentity : (() => { throw new Error(`unexpected release ${args[1]}`); })();
  const rootRun = (args) => {
    if (args[1] === "get-caller-identity") return rootIdentity;
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") return JSON.stringify({ Rules: [{ ID: "reservation-expiry", Status: "Enabled", Prefix: "production-initial-activation-lifecycle-policy-reconciliation/reservations/", Expiration: { Days: 1 } }] });
    if (args[1] === "put-bucket-policy") { policyWrites += 1; return ""; }
    throw new Error(`unexpected root ${args[1]}`);
  };
  const journal = { readRecoveryAttempt: () => null, readRecoveryCompletion: () => null, writeRecoveryAttempt: () => { throw new Error("must not create attempt"); }, writeRecoveryCompletion: () => { throw new Error("must not write completion"); } };
  await assert.rejects(() => runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: "506", workflowRunAttempt: "1", rootRun, releaseRun, readStateIdentity: async () => state, terraformStateLock, readProtectedSource: source, resolveAuthorization: () => ({ authorization }), journal, recoveryJournal: journal, sign: () => "signature", verify: () => true }), /protected immutable record unavailable/);
  assert.equal(policyWrites, 0);
});
