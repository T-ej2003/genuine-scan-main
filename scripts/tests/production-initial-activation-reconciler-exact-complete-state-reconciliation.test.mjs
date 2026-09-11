import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INSTALLATION, assertInstallationPlan } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { EXACT_COMPLETE_STATE_RECONCILIATION as CONTRACT, assertExactCompleteCleanNormalPlan, assertExactCompleteRefreshOnlyPlan, assertExactCompleteStateReconciliationPreparation, assertExactCompleteStateSuccessor, assertExactMixedRecoveryAttachmentTopology, createExactCompleteStateReconciliationAuthorization, createExactCompleteStateReconciliationPreparation, createExactCompleteStateReconciliationRecoveryAuthorization, createExactCompleteStateReconciliationRecoveryPreparation, executeExactCompleteStateReconciliation, executeExactCompleteStateReconciliationRecovery } from "../aws/production-initial-activation-reconciler-exact-complete-state-reconciliation.mjs";
import { exactSavedRefreshOnlyPlanApplyArgs } from "../aws/reconcile-production-initial-activation-exact-complete-state.mjs";

const sourceSha = "a".repeat(40); const now = new Date("2026-09-11T12:00:00.000Z");
const completePlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-complete.json", "utf8"));
const state = (serial, attachmentCount, policyArns) => Buffer.from(JSON.stringify({ version: 4, terraform_version: "1.15.8", serial, lineage: "exact-complete-lineage", outputs: {}, resources: INSTALLATION.expectedAddresses.map((address) => {
  const [type, name] = address.split("."); const attributes = name === "mixed_recovery" && type === "aws_iam_policy" ? { name: "MSCQRProductionMixedDualSlotRecoveryExecutor", attachment_count: attachmentCount } : name === "mixed_recovery" && type === "aws_iam_role" ? { name: "mscqr-production-mixed-dual-slot-recovery-executor", managed_policy_arns: policyArns } : { name };
  return { mode: "managed", type, name, instances: [{ attributes }] };
}) }));
const before = state(3, 0, []); const after = state(4, 1, [CONTRACT.policyArn]);
const refreshPlan = () => {
  const plan = structuredClone(completePlan); plan.applyable = true; for (const change of Object.values(plan.output_changes)) { change.actions = ["no-op"]; change.before = change.after; } plan.resource_drift = [
    { address: "aws_iam_policy.mixed_recovery", change: { actions: ["update"], before: { name: "MSCQRProductionMixedDualSlotRecoveryExecutor", attachment_count: 0 }, after: { name: "MSCQRProductionMixedDualSlotRecoveryExecutor", attachment_count: 1 }, before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } },
    { address: "aws_iam_role.mixed_recovery", change: { actions: ["update"], before: { name: "mscqr-production-mixed-dual-slot-recovery-executor", managed_policy_arns: [] }, after: { name: "mscqr-production-mixed-dual-slot-recovery-executor", managed_policy_arns: [CONTRACT.policyArn] }, before_unknown: {}, after_unknown: {}, before_sensitive: { managed_policy_arns: [] }, after_sensitive: { managed_policy_arns: [false] } } },
  ];
  return plan;
};
const cleanNormalPlan = () => { const plan = structuredClone(completePlan); plan.applyable = false; plan.resource_drift = []; for (const change of Object.values(plan.output_changes)) { change.actions = ["no-op"]; change.before = change.after; } return plan; };
const topology = { roles: [CONTRACT.roleName], users: [], groups: [] };
const object = { versionId: "before-version", etag: "before-etag" };
const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 8, name: CONTRACT.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: CONTRACT.environment, sourceSha, workflowRef: `${CONTRACT.repository}/${CONTRACT.authorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 8, environmentName: CONTRACT.environment, userId: 3, userLogin: "reviewer" } });
const prepared = () => createExactCompleteStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: topology, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), preparedAt: now.toISOString() });

test("admits only the exact two mixed-recovery state drifts with no actionable operation", () => {
  assert.deepEqual(assertExactCompleteRefreshOnlyPlan(refreshPlan()).resourceDrift, CONTRACT.drift);
  for (const resourceChanges of [undefined, []]) { const plan = refreshPlan(); if (resourceChanges === undefined) delete plan.resource_changes; else plan.resource_changes = resourceChanges; assert.doesNotThrow(() => assertExactCompleteRefreshOnlyPlan(plan)); }
  const normal = structuredClone(completePlan); delete normal.resource_changes; assert.throws(() => assertInstallationPlan(normal));
  for (const mutate of [
    (plan) => { delete plan.resource_drift; },
    (plan) => { plan.resource_drift = []; },
    (plan) => { plan.resource_drift.pop(); },
    (plan) => { plan.resource_drift.shift(); },
    (plan) => { plan.resource_drift.push(structuredClone(plan.resource_drift[0])); },
    (plan) => { plan.resource_drift.push({ address: "aws_iam_role.reconciler", change: structuredClone(plan.resource_drift[0].change) }); },
    (plan) => { plan.resource_drift[0].address = "aws_iam_policy.reconciler"; },
    (plan) => { delete plan.resource_drift[0].change.after.attachment_count; plan.resource_drift[0].change.after.unreviewed = 1; },
    (plan) => { plan.resource_drift[0].change.after.attachment_count = 2; },
    (plan) => { plan.resource_drift[1].change.after.managed_policy_arns = ["arn:aws:iam::368992683803:policy/other"]; },
    (plan) => { plan.resource_drift[1].change.after.managed_policy_arns.push(CONTRACT.policyArn); },
    (plan) => { plan.output_changes = { changed: { actions: ["update"] } }; },
  ]) { const plan = refreshPlan(); mutate(plan); assert.throws(() => assertExactCompleteRefreshOnlyPlan(plan)); }
  for (const value of [null, {}, "", false, 0]) { const plan = refreshPlan(); plan.resource_changes = value; assert.throws(() => assertExactCompleteRefreshOnlyPlan(plan)); }
  for (const changes of [[null], [{}]]) { const plan = refreshPlan(); plan.resource_changes = changes; assert.throws(() => assertExactCompleteRefreshOnlyPlan(plan)); }
  for (const actions of [["create"], ["update"], ["delete"], ["replace"], ["delete", "create"], ["create", "delete"], ["read"]]) { const plan = refreshPlan(); plan.resource_changes[0].change.actions = actions; assert.throws(() => assertExactCompleteRefreshOnlyPlan(plan)); }
});

test("requires the exact successor and an authenticated clean second normal plan", () => {
  assert.equal(assertExactCompleteStateSuccessor({ beforeBytes: before, afterBytes: after }).serial, 4);
  assert.doesNotThrow(() => assertExactCompleteCleanNormalPlan(cleanNormalPlan()));
  for (const noDrift of [(plan) => { delete plan.resource_drift; }, (plan) => { plan.resource_drift = null; }, (plan) => { plan.resource_drift = []; }]) { const plan = cleanNormalPlan(); noDrift(plan); assert.doesNotThrow(() => assertExactCompleteCleanNormalPlan(plan)); }
  for (const mutate of [
    (value) => { value.serial = 5; },
    (value) => { value.resources.find(({ type, name }) => type === "aws_iam_role" && name === "mixed_recovery").instances[0].attributes.managed_policy_arns = []; },
    (value) => { value.resources.push({ mode: "managed", type: "aws_iam_user", name: "unexpected", instances: [{ attributes: {} }] }); },
  ]) { const candidate = JSON.parse(after); mutate(candidate); assert.throws(() => assertExactCompleteStateSuccessor({ beforeBytes: before, afterBytes: Buffer.from(JSON.stringify(candidate)) })); }
  const drift = cleanNormalPlan(); drift.resource_drift = [{ address: "aws_iam_role.mixed_recovery" }]; assert.throws(() => assertExactCompleteCleanNormalPlan(drift));
  const originalDrift = cleanNormalPlan(); originalDrift.resource_drift = refreshPlan().resource_drift; assert.throws(() => assertExactCompleteCleanNormalPlan(originalDrift));
  for (const malformed of [{}, "", false, 0]) { const plan = cleanNormalPlan(); plan.resource_drift = malformed; assert.throws(() => assertExactCompleteCleanNormalPlan(plan)); }
  const actionable = cleanNormalPlan(); actionable.applyable = true; actionable.resource_changes[0].change.actions = ["update"]; assert.throws(() => assertExactCompleteCleanNormalPlan(actionable));
});

test("executes only one refresh-only state update and never exposes an AWS mutation adapter", () => {
  const preparation = prepared(); const authorization = createExactCompleteStateReconciliationAuthorization({ preparation, approval, now }); let refreshes = 0;
  const result = executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applyRefreshOnlyPlan: (bytes) => { refreshes += 1; assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), preparation.savedPlanSha256); }, readPostSnapshot: () => ({ bytes: after, object: { versionId: "after-version", etag: "after-etag" } }), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now });
  assert.equal(refreshes, 1); assert.equal(result.remoteIamMutationCount, 0); assert.equal(result.terraformStateMutationCount, 1); assert.equal(result.normalPlan.resourceChangeCount, 0);
  assert.throws(() => executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("different-saved-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applyRefreshOnlyPlan: () => assert.fail("must not apply an unbound plan"), readPostSnapshot: () => ({ bytes: after, object }), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now }));
  assert.throws(() => executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: { roles: [CONTRACT.roleName, "extra"], users: [], groups: [] }, applyRefreshOnlyPlan: () => assert.fail("must not refresh"), readPostSnapshot: () => ({ bytes: after, object }), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now }));
});

test("constructs and executes the exact transaction from Terraform's omitted resource_changes refresh-only shape", () => {
  const plan = refreshPlan(); delete plan.resource_changes;
  const preparation = createExactCompleteStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: topology, planBytes: Buffer.from("omitted-resource-changes-refresh-only-plan"), planJson: plan, preparedAt: now.toISOString() });
  const authorization = createExactCompleteStateReconciliationAuthorization({ preparation, approval, now }); let refreshes = 0;
  const result = executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("omitted-resource-changes-refresh-only-plan"), planJson: plan, beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applyRefreshOnlyPlan: () => { refreshes += 1; }, readPostSnapshot: () => ({ bytes: after, object: { versionId: "after-version", etag: "after-etag" } }), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now });
  assert.equal(refreshes, 1); assert.equal(result.remoteIamMutationCount, 0); assert.equal(result.terraformStateMutationCount, 1); assert.equal(result.normalPlan.resourceChangeCount, 0);
});

test("replays only the exact authorized successor without another Terraform apply", () => {
  const preparation = prepared(); const authorization = createExactCompleteStateReconciliationAuthorization({ preparation, approval, now });
  const result = executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), beforeStateBytes: after, beforeObject: { versionId: "after-version", etag: "after-etag" }, beforeTopology: topology, applyRefreshOnlyPlan: () => assert.fail("must not reapply the exact successor"), readPostSnapshot: () => assert.fail("must not read a post-apply snapshot"), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now });
  assert.equal(result.status, "ALREADY_COMPLETE"); assert.equal(result.refreshOnlyApplyCount, 0); assert.equal(result.terraformStateMutationCount, 0); assert.equal(result.remoteIamMutationCount, 0);
  const wrong = Buffer.from(JSON.stringify({ ...JSON.parse(after), serial: 5 }));
  assert.throws(() => executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), beforeStateBytes: wrong, beforeObject: { versionId: "later-version", etag: "later-etag" }, beforeTopology: topology, applyRefreshOnlyPlan: () => assert.fail("must not apply a later state"), readPostSnapshot: () => assert.fail("must not read a later state"), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now }));
});

test("uses a fresh zero-write authorization to recover only the exact successor after the original approval expires", () => {
  const originalPreparation = prepared(); const originalAuthorization = createExactCompleteStateReconciliationAuthorization({ preparation: originalPreparation, approval, now }); const recoveryNow = new Date(now.getTime() + CONTRACT.maxAgeMs + 1);
  assert.throws(() => executeExactCompleteStateReconciliation({ sourceSha, preparation: originalPreparation, authorization: originalAuthorization, planBytes: Buffer.from("exact-refresh-only-plan"), planJson: refreshPlan(), beforeStateBytes: after, beforeObject: { versionId: "after-version", etag: "after-etag" }, beforeTopology: topology, applyRefreshOnlyPlan: () => assert.fail("must not apply"), readPostSnapshot: () => assert.fail("must not read"), readPostTopology: () => topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now: recoveryNow }), /stale/);
  const recoveryPreparation = createExactCompleteStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalAuthorizationWorkflowRunId: "100", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: after, stateObject: { versionId: "after-version", etag: "after-etag" }, attachmentTopology: topology, preparedAt: recoveryNow.toISOString() });
  const recoveryApproval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 8, name: CONTRACT.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: CONTRACT.environment, sourceSha, workflowRef: `${CONTRACT.repository}/${CONTRACT.recoveryAuthorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: "200", workflowRunAttempt: "1", executionActor: "operator", observedAt: recoveryNow.toISOString(), actualApproval: { state: "approved", environmentId: 8, environmentName: CONTRACT.environment, userId: 3, userLogin: "reviewer" } });
  const recoveryAuthorization = createExactCompleteStateReconciliationRecoveryAuthorization({ recoveryPreparation, approval: recoveryApproval, now: recoveryNow });
  const result = executeExactCompleteStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: after, stateObject: { versionId: "after-version", etag: "after-etag" }, attachmentTopology: topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now: recoveryNow });
  assert.equal(result.status, "RECOVERED_COMPLETE"); assert.equal(result.refreshOnlyApplyCount, 0); assert.equal(result.terraformStateMutationCount, 0); assert.equal(result.remoteIamMutationCount, 0);
  assert.throws(() => executeExactCompleteStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: Buffer.from(JSON.stringify({ ...JSON.parse(after), serial: 5 })), stateObject: { versionId: "later-version", etag: "later-etag" }, attachmentTopology: topology, renderNormalPlan: cleanNormalPlan, reauthenticateSource: () => true, verifyLive: () => true, now: recoveryNow }), /authorized state/);
});

test("attachment topology remains closed world", () => {
  assert.deepEqual(assertExactMixedRecoveryAttachmentTopology(topology), topology);
  for (const value of [{ roles: [], users: [], groups: [] }, { roles: [CONTRACT.roleName], users: ["extra"], groups: [] }, { roles: [CONTRACT.roleName], users: [], groups: [], extra: true }]) assert.throws(() => assertExactMixedRecoveryAttachmentTopology(value));
});

test("preparation rejects malformed or widened state identity", () => {
  const preparation = prepared();
  for (const mutate of [(value) => { value.predecessorState.extra = true; }, (value) => { value.predecessorState.lineage = ""; }, (value) => { value.predecessorState.serial = -1; }]) {
    const candidate = structuredClone(preparation); mutate(candidate); assert.throws(() => assertExactCompleteStateReconciliationPreparation(candidate, { sourceSha, now }));
  }
});

test("workflow and runbook bind the dedicated refresh-only operation", () => {
  const authorizer = fs.readFileSync(".github/workflows/authorize-production-initial-activation-exact-complete-state-reconciliation.yml", "utf8"); const executor = fs.readFileSync(".github/workflows/execute-production-initial-activation-exact-complete-state-reconciliation.yml", "utf8"); const recoveryAuthorizer = fs.readFileSync(".github/workflows/authorize-production-initial-activation-exact-complete-state-reconciliation-recovery.yml", "utf8"); const recoveryExecutor = fs.readFileSync(".github/workflows/execute-production-initial-activation-exact-complete-state-reconciliation-recovery.yml", "utf8"); const cli = fs.readFileSync("scripts/aws/reconcile-production-initial-activation-exact-complete-state.mjs", "utf8"); const runbook = fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationExactCompleteStateReconciliation-v1.md", "utf8");
  for (const workflow of [authorizer, executor, recoveryAuthorizer, recoveryExecutor]) { assert.match(workflow, /environment: production-initial-activation-reconciler-bootstrap/); assert.match(workflow, /group: production-deploy/); assert.match(workflow, /cancel-in-progress: false/); }
  assert.match(executor, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-initial-activation-policy-reconciler-bootstrap/); assert.deepEqual(exactSavedRefreshOnlyPlanApplyArgs("/private/authorized.tfplan"), ["apply", "-input=false", "-lock-timeout=60s", "/private/authorized.tfplan"]); assert.doesNotMatch(cli, /"apply", "-refresh-only"/); assert.match(runbook, /zero remote IAM, Secrets Manager, and ECS writes/);
  assert.match(recoveryExecutor, /Verify exact successor without Terraform apply/); assert.match(recoveryAuthorizer, /Produce zero-write recovery authorization/);
});
