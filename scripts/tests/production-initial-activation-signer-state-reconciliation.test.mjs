import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { currentInstallationPlan, currentInstallationState } from "./fixtures/production-initial-activation-reconciler-plan-current.mjs";
import { bootstrapOperatorPolicyAuthorizerPermissionsPredecessor } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { runAuthorizeSignerState } from "../aws/authorize-production-initial-activation-signer-state-reconciliation.mjs";
import { assertSignerRefreshOnlyPlan, assertSignerPostRefreshNormalPlan, createSignerStatePreparation, createSignerStateAuthorization, assertSignerStateAuthorization, createSignerStateRecoveryPreparation, createSignerStateRecoveryAuthorization, executeSignerStateReconciliation, executeSignerStateRecovery, SIGNER_STATE_RECONCILIATION as CONTRACT } from "../aws/production-initial-activation-signer-state-reconciliation.mjs";

const sourceSha = "a".repeat(40); const now = new Date("2026-09-29T12:00:00.000Z");
const capturedDrift = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-signer-state-reflection.json", "utf8"));
const baseResources = ["aws_iam_role.reconciler", "aws_iam_policy.reconciler", "aws_iam_role_policy_attachment.reconciler", "aws_iam_role.mixed_recovery", "aws_iam_policy.mixed_recovery", "aws_iam_role_policy_attachment.mixed_recovery"].map((address) => { const [type, name] = address.split("."); return { mode: "managed", type, name, instances: [{ attributes: { name } }] }; });
const state = (serial, refreshed = false) => {
  const value = JSON.parse(currentInstallationState(JSON.stringify({ version: 4, terraform_version: "1.15.8", serial, lineage: "signer-state-lineage", outputs: {}, resources: baseResources })));
  value.resources.find((resource) => resource.type === "aws_iam_role" && resource.name === "signer_policy_installer").instances[0].attributes = structuredClone(refreshed ? capturedDrift.change.after : capturedDrift.change.before);
  return Buffer.from(JSON.stringify(value));
};
const before = state(7); const after = state(8, true);
const stateObject = { versionId: "preimage-version", etag: "preimage-etag" }; const afterObject = { versionId: "successor-version", etag: "successor-etag" };
const plan = () => {
  const value = currentInstallationPlan(JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-complete.json", "utf8")));
  value.resource_changes = []; value.resource_drift = [structuredClone(capturedDrift)]; value.output_changes = {}; value.applyable = true;
  return value;
};
const normalPlan = () => {
  const value = currentInstallationPlan(JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-complete.json", "utf8")));
  const change = value.resource_changes.find(({ address }) => address === "aws_iam_policy.bootstrap_operator_policy_authorizer").change;
  change.actions = ["update"]; change.before = { ...structuredClone(change.after), policy: JSON.stringify(bootstrapOperatorPolicyAuthorizerPermissionsPredecessor()) };
  value.resource_drift = []; value.output_changes = {}; value.applyable = true; return value;
};
const approval = (recovery = false, at = now) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 8, name: CONTRACT.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: CONTRACT.environment, sourceSha, workflowRef: `${CONTRACT.repository}/${recovery ? CONTRACT.recoveryAuthorizationWorkflowPath : CONTRACT.authorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: recovery ? "101" : "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: at.toISOString(), actualApproval: { state: "approved", environmentId: 8, environmentName: CONTRACT.environment, userId: 3, userLogin: "reviewer" } });
const prepared = (at = now) => createSignerStatePreparation({ sourceSha, stateBytes: before, stateObject, planBytes: Buffer.from("exact-saved-plan"), planJson: plan(), preparedAt: at.toISOString() });
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

test("captured Terraform signer reflection is exactly one state-only transition", () => {
  const semantics = assertSignerRefreshOnlyPlan(plan(), before);
  assert.equal(semantics.address, CONTRACT.address); assert.equal(semantics.remoteMutationCount, 0);
  assert.equal(semantics.afterInlinePolicy.length, 1); assert.deepEqual(semantics.afterTags, {});
  assert.equal(assertSignerPostRefreshNormalPlan(normalPlan()).changedAddresses[0], "aws_iam_policy.bootstrap_operator_policy_authorizer");
});

test("captured Terraform no-op resource changes remain non-actionable", () => {
  const captured = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-complete.json", "utf8"));
  const unchanged = captured.resource_changes.filter(({ change }) => change.actions.join() === "no-op");
  const candidate = plan(); candidate.resource_changes = structuredClone(unchanged);
  assert.equal(assertSignerRefreshOnlyPlan(candidate, before).remoteMutationCount, 0);
  for (const mutate of [
    (p) => { p.resource_changes[0].change.actions = ["update"]; },
    (p) => { p.resource_changes[0].change.after.name = "wrong"; },
    (p) => { p.resource_changes[0].address = "aws_iam_role.unrelated"; },
    (p) => { p.resource_changes.push(structuredClone(p.resource_changes[0])); },
    (p) => { p.resource_changes[0].change.after_unknown = { id: true }; },
  ]) { const wrong = structuredClone(candidate); mutate(wrong); assert.throws(() => assertSignerRefreshOnlyPlan(wrong, before)); }
});

test("fresh normal plan requires zero drift and only the intended authorizer update", () => {
  const drift = normalPlan(); drift.resource_drift = [structuredClone(capturedDrift)];
  assert.throws(() => assertSignerPostRefreshNormalPlan(drift));
  const extra = normalPlan(); extra.resource_changes.find(({ address }) => address === "aws_iam_role.signer_policy_installer").change.actions = ["update"];
  assert.throws(() => assertSignerPostRefreshNormalPlan(extra));
  const output = normalPlan(); output.output_changes.unexpected = { actions: ["update"] };
  assert.throws(() => assertSignerPostRefreshNormalPlan(output), /output change/);
});

test("all noncanonical drift, IAM, tag, plan and output variants fail closed", () => {
  const mutations = [
    (p) => { p.resource_drift[0].address = "aws_iam_role.reconciler"; },
    (p) => { p.resource_drift[0].change.after.arn = "arn:aws:iam::368992683803:role/wrong"; },
    (p) => { p.resource_drift[0].change.after.inline_policy[0].name = "Wrong"; },
    (p) => { p.resource_drift[0].change.after.inline_policy[0].policy = JSON.stringify({ Version: "2012-10-17", Statement: [] }); },
    (p) => { p.resource_drift[0].change.after.inline_policy.push(structuredClone(p.resource_drift[0].change.after.inline_policy[0])); },
    (p) => { p.resource_drift[0].change.after.tags = { unexpected: "yes" }; },
    (p) => { p.resource_drift[0].change.before.tags = {}; },
    (p) => { p.resource_drift.push(structuredClone(p.resource_drift[0])); },
    (p) => { p.resource_changes = [{ address: "aws_iam_role.signer_policy_installer", change: { actions: ["update"] } }]; },
    (p) => { p.output_changes.unexpected = { actions: ["update"] }; },
    (p) => { p.resource_drift[0].change.after_unknown.arn = true; },
    (p) => { p.resource_drift[0].change.after_sensitive.inline_policy = [true]; },
    (p) => { p.configuration.root_module.resources.pop(); },
  ];
  for (const mutate of mutations) { const candidate = plan(); mutate(candidate); assert.throws(() => assertSignerRefreshOnlyPlan(candidate, before)); }
  const wrongState = JSON.parse(before); wrongState.resources.find((resource) => resource.type === "aws_iam_role" && resource.name === "signer_policy_installer").instances[0].attributes.name = "wrong";
  assert.throws(() => assertSignerRefreshOnlyPlan(plan(), Buffer.from(JSON.stringify(wrongState))));
  const extraState = JSON.parse(before); extraState.resources.push({ mode: "managed", type: "aws_iam_user", name: "unexpected", instances: [{ attributes: { name: "unexpected" } }] });
  assert.throws(() => assertSignerRefreshOnlyPlan(plan(), Buffer.from(JSON.stringify(extraState))), /unrelated Terraform resource/);
});

test("approval is bound to protected source, exact plan and saved-state preimage", () => {
  const preparation = prepared(); const authorization = createSignerStateAuthorization({ preparation, approval: approval(), now });
  assert.doesNotThrow(() => assertSignerStateAuthorization(authorization, preparation, { sourceSha, now }));
  assert.throws(() => assertSignerStateAuthorization(authorization, preparation, { sourceSha: "b".repeat(40), now }));
  assert.throws(() => assertSignerStateAuthorization({ ...authorization, savedPlanSha256: "b".repeat(64) }, preparation, { sourceSha, now }));
  assert.throws(() => assertSignerStateAuthorization({ ...authorization, predecessorState: { ...preparation.predecessorState, serial: 8 } }, preparation, { sourceSha, now }));
});

test("dedicated protected workflow reaches the real authorization CLI with exact artifact bytes", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-signer-state-authorization-")); fs.chmodSync(directory, 0o700);
  try {
    const current = new Date(); const preparation = prepared(current); const approvalEvidence = approval(false, current);
    const preparationFile = path.join(directory, "preparation.json"); const approvalFile = path.join(directory, "approval.json"); const output = path.join(directory, "authorization.json");
    const preparationBytes = Buffer.from(`${JSON.stringify(preparation)}\n`); const approvalBytes = Buffer.from(`${JSON.stringify(approvalEvidence)}\n`);
    fs.writeFileSync(preparationFile, preparationBytes, { mode: 0o600 }); fs.writeFileSync(approvalFile, approvalBytes, { mode: 0o600 });
    const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: CONTRACT.repository, GITHUB_WORKFLOW_REF: `${CONTRACT.repository}/${CONTRACT.authorizationWorkflowPath}@refs/heads/main`, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "100", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
    const result = runAuthorizeSignerState(["--authorize", "--source-sha", sourceSha, "--preparation", preparationFile, "--preparation-file-sha256", hash(preparationBytes), "--environment-approval", approvalFile, "--environment-approval-file-sha256", hash(approvalBytes), "--output", output], { env, now: current });
    assert.equal(result.operation, CONTRACT.operation); assert.ok(fs.existsSync(output));
    assert.throws(() => runAuthorizeSignerState(["--authorize", "--source-sha", sourceSha, "--preparation", preparationFile, "--preparation-file-sha256", "b".repeat(64), "--environment-approval", approvalFile, "--environment-approval-file-sha256", hash(approvalBytes), "--output", path.join(directory, "bad.json")], { env, now: current }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("state write, ambiguous response, replay and wrong successor remain idempotent", () => {
  const preparation = prepared(); const authorization = createSignerStateAuthorization({ preparation, approval: approval(), now });
  let applyCount = 0; const common = { sourceSha, preparation, authorization, planBytes: Buffer.from("exact-saved-plan"), planJson: plan(), beforeStateBytes: before, beforeObject: stateObject, applySavedPlan: () => { applyCount++; }, readPostSnapshot: () => ({ bytes: after, object: afterObject }), renderNormalPlan: normalPlan, reauthenticateSource: () => {}, verifyLive: () => {}, now };
  const completed = executeSignerStateReconciliation(common); assert.equal(completed.status, "COMPLETE"); assert.equal(completed.normalPlan.resourceDriftCount, 0); assert.equal(applyCount, 1);
  assert.equal(executeSignerStateReconciliation({ ...common, applySavedPlan: () => { applyCount++; throw new Error("ambiguous"); } }).status, "COMPLETED_BY_READBACK"); assert.equal(applyCount, 2);
  assert.equal(executeSignerStateReconciliation({ ...common, beforeStateBytes: after, beforeObject: afterObject }).status, "ALREADY_COMPLETE"); assert.equal(applyCount, 2);
  const invalid = JSON.parse(after); invalid.resources[0].instances[0].attributes.name = "corrupt";
  assert.throws(() => executeSignerStateReconciliation({ ...common, beforeStateBytes: Buffer.from(JSON.stringify(invalid)), beforeObject: afterObject }), /authorized successor/); assert.equal(applyCount, 2);
  assert.throws(() => executeSignerStateReconciliation({ ...common, planBytes: Buffer.from("changed-plan") }), /saved plan/); assert.equal(applyCount, 2);
  assert.throws(() => executeSignerStateReconciliation({ ...common, sourceSha: "b".repeat(40) }), /source|binding/); assert.equal(applyCount, 2);
  assert.throws(() => executeSignerStateReconciliation({ ...common, beforeObject: { ...stateObject, versionId: "changed" } }), /state|successor/); assert.equal(applyCount, 2);
  assert.throws(() => executeSignerStateReconciliation({ ...common, readPostSnapshot: () => ({ bytes: before, object: stateObject }) }), (error) => error.mutationOutcome === "AMBIGUOUS"); assert.equal(applyCount, 3);
});

test("interrupted write recovery requires exact successor, new approval and no second apply", () => {
  const originalPreparation = prepared(); const originalAuthorization = createSignerStateAuthorization({ preparation: originalPreparation, approval: approval(), now });
  const recoveryPreparation = createSignerStateRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalRunId: "100", originalRunAttempt: "1", stateBytes: after, stateObject: afterObject, preparedAt: now.toISOString() });
  const recoveryAuthorization = createSignerStateRecoveryAuthorization({ recoveryPreparation, approval: approval(true), now });
  assert.equal(executeSignerStateRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: after, stateObject: afterObject, renderNormalPlan: normalPlan, reauthenticateSource: () => {}, verifyLive: () => {}, now }).stateWriteCount, 0);
  assert.throws(() => createSignerStateRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalRunId: "999", originalRunAttempt: "1", stateBytes: after, stateObject: afterObject, preparedAt: now.toISOString() }), /original authorization/);
  assert.throws(() => executeSignerStateRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: before, stateObject, renderNormalPlan: normalPlan, reauthenticateSource: () => {}, verifyLive: () => {}, now }), /changed/);
  const wrong = normalPlan(); wrong.resource_changes.push({ address: "aws_iam_role.unrelated", change: { actions: ["create"] } });
  assert.throws(() => executeSignerStateRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: after, stateObject: afterObject, renderNormalPlan: () => wrong, reauthenticateSource: () => {}, verifyLive: () => {}, now }));
});
