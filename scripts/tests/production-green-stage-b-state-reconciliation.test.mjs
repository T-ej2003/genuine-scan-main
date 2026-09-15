import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { STAGE_B_STATE_RECONCILIATION as CONTRACT, assertCleanStageBNormalPlan, assertExactStageBRefreshOnlyPlan, assertStageBStateReconciliationAuthorization, assertStageBStateReconciliationPreparation, createStageBStateReconciliationAuthorization, createStageBStateReconciliationPreparation, executeStageBStateReconciliation } from "../aws/production-green-stage-b-state-reconciliation.mjs";

const sourceSha = "a".repeat(40); const digest = "b".repeat(64); const now = new Date("2026-09-15T15:00:00.000Z");
const state = { lineage: CONTRACT.expectedLineage, serial: CONTRACT.expectedSerial, stateSha256: digest };
const change = (address) => ({ address, mode: "managed", type: address.startsWith("aws_iam_role_policy") ? "aws_iam_role_policy" : "aws_iam_role", change: { actions: ["update"], before: address.startsWith("aws_iam_role_policy") ? { id: address, name: "policy", role: "role", policy: "old" } : { arn: "arn", name: "role", path: "/", permissions_boundary: null, assume_role_policy: "trust", inline_policy: "old" }, after: address.startsWith("aws_iam_role_policy") ? { id: address, name: "policy", role: "role", policy: "new" } : { arn: "arn", name: "role", path: "/", permissions_boundary: null, assume_role_policy: "trust", inline_policy: "new" }, before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {}, replace_paths: [] } });
const plan = () => ({ format_version: "1.2", terraform_version: "1.15.8", errored: false, complete: true, applyable: true, variables: { tooling_sha: { value: sourceSha } }, resource_changes: [], resource_drift: CONTRACT.addresses.map(change), output_changes: {} });
const cleanPlan = () => ({ format_version: "1.2", terraform_version: "1.15.8", errored: false, complete: true, applyable: true, variables: { tooling_sha: { value: sourceSha } }, resource_changes: [], resource_drift: [], output_changes: {} });
const options = () => ({ sourceSha, stateIdentity: state, tfvarsSha256: digest, bindingSha256: digest });
const approval = () => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: "production", sourceSha, workflowRef: `${CONTRACT.repository}/${CONTRACT.authorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
const bytes = Buffer.from("reviewed-refresh-only-plan");
const prepare = () => createStageBStateReconciliationPreparation({ sourceSha, ticketId: "CHG-20260915-001", stateIdentity: state, tfvarsSha256: digest, bindingSha256: digest, preflightSha256: digest, planBytes: bytes, planJson: plan(), createdAt: now.toISOString() });

test("exact ten-address refresh-only plan is the only accepted state transition", () => {
  assert.deepEqual(assertExactStageBRefreshOnlyPlan(plan(), options()), { refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: 10, addresses: CONTRACT.addresses });
  for (const mutate of [
    (value) => value.resource_drift.pop(),
    (value) => value.resource_drift.push(change('aws_iam_role.extra')),
    (value) => { value.resource_drift[0].address = 'aws_iam_role.execution["other"]'; },
    (value) => { value.resource_drift[0].address = 'module.escape.aws_iam_role.execution["backend"]'; },
    (value) => { value.resource_drift[0].address = 'aws_iam_role.execution["backend"]*'; },
    (value) => { value.resource_drift[0].address = 'aws_iam_role.execution["backеnd"]'; },
    (value) => { value.resource_drift[1].address = value.resource_drift[0].address; },
    (value) => { value.resource_drift[0].change.actions = ["create"]; },
    (value) => { value.resource_drift[0].change.actions = ["delete"]; },
    (value) => { value.resource_drift[0].change.actions = ["delete", "create"]; },
    (value) => { value.resource_changes = [{ change: { actions: ["update"] } }]; },
    (value) => { value.output_changes = { unexpected: { actions: ["update"] } }; },
    (value) => { value.resource_drift[0].change.after_unknown = { injected: true }; },
    (value) => { value.resource_drift[0].change.after.inline_policy = "different"; value.resource_drift[0].change.after.name = "substituted"; },
  ]) { const value = plan(); mutate(value); assert.throws(() => assertExactStageBRefreshOnlyPlan(value, options())); }
});

test("source, lineage, serial, and identity mismatches fail closed", () => {
  assert.throws(() => assertExactStageBRefreshOnlyPlan(plan(), { ...options(), sourceSha: "c".repeat(40) }));
  assert.throws(() => assertExactStageBRefreshOnlyPlan(plan(), { ...options(), stateIdentity: { ...state, lineage: crypto.randomUUID() } }));
  assert.throws(() => assertExactStageBRefreshOnlyPlan(plan(), { ...options(), stateIdentity: { ...state, serial: 105 } }));
  const value = plan(); value.resource_drift[0].change.after.arn = "changed"; assert.throws(() => assertExactStageBRefreshOnlyPlan(value, options()));
});

test("preparation and protected-environment authorization bind every irreversible input", () => {
  const preparation = prepare(); assert.equal(assertStageBStateReconciliationPreparation(preparation, { sourceSha, now }), preparation);
  const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now }); assert.equal(assertStageBStateReconciliationAuthorization(authorization, { preparation, sourceSha, now }), authorization);
  for (const changed of [
    { ...authorization, ticketId: "CHG-20260915-002" },
    { ...authorization, preOperationStateSerial: 105 },
    { ...authorization, addresses: preparation.addresses.slice(1) },
    { ...authorization, refreshOnlyPlanSha256: "c".repeat(64) },
    { ...authorization, tfvarsSha256: "c".repeat(64) },
    { ...authorization, bindingSha256: "c".repeat(64) },
    { ...authorization, preflightSha256: "c".repeat(64) },
  ]) assert.throws(() => assertStageBStateReconciliationAuthorization(changed, { preparation, sourceSha, now }));
  assert.throws(() => assertStageBStateReconciliationPreparation(preparation, { sourceSha, now: new Date(now.getTime() + CONTRACT.maxAgeMs + 1) }));
});

test("execution consumes exactly one approved refresh-only state transition", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  let current = { ...state }; let applies = 0;
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: { tfvarsSha256: digest, bindingSha256: digest, preflightSha256: digest }, planBytes: bytes, planJson: plan(), readState: () => current, applyRefreshOnlyPlan: () => { applies += 1; current = { ...current, serial: current.serial + 1, stateSha256: "c".repeat(64) }; }, renderRefreshClosurePlan: cleanPlan, renderNormalClosurePlan: cleanPlan, now });
  assert.equal(applies, 1); assert.equal(result.remoteResourceMutationCount, 0); assert.equal(result.terraformStateMutationCount, 1);
  assert.throws(() => executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: { tfvarsSha256: digest, bindingSha256: digest, preflightSha256: digest }, planBytes: bytes, planJson: plan(), readState: () => current, applyRefreshOnlyPlan: () => { applies += 1; }, renderRefreshClosurePlan: cleanPlan, renderNormalClosurePlan: cleanPlan, now }), /CAS/);
});

test("execution rejects substituted bound inputs, stale plan, and non-clean closure", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  const common = { sourceSha, preparation, authorization, planBytes: bytes, planJson: plan(), readState: () => state, applyRefreshOnlyPlan: () => {}, renderRefreshClosurePlan: cleanPlan, renderNormalClosurePlan: cleanPlan, now };
  assert.throws(() => executeStageBStateReconciliation({ ...common, bindings: { tfvarsSha256: "c".repeat(64), bindingSha256: digest, preflightSha256: digest } }));
  assert.throws(() => executeStageBStateReconciliation({ ...common, bindings: { tfvarsSha256: digest, bindingSha256: digest, preflightSha256: digest }, planBytes: Buffer.from("substituted") }));
  const unclean = cleanPlan(); unclean.resource_changes = [{ change: { actions: ["update"] } }];
  assert.throws(() => assertCleanStageBNormalPlan(unclean, { sourceSha }));
});
