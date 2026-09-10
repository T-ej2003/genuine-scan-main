import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { createProductionGithubCommandRunner } from "../aws/production-credential-source-contract.mjs";
import { ensureStageBPrivateFile, readStageBPrivateFileBytes } from "../aws/stage-b-artifact-contract.mjs";
import { assertExactReconcilerRefreshOnlyPlan, assertExactStateSuccessor, assertReconcilerStateReconciliationAuthorization, assertReconcilerStateReconciliationResult, createReconcilerStateReconciliationAuthorization, createReconcilerStateReconciliationPreparation, createReconcilerStateReconciliationRecoveryAuthorization, createReconcilerStateReconciliationRecoveryPreparation, executeReconcilerStateReconciliation, executeReconcilerStateReconciliationRecovery, RECONCILER_STATE_RECONCILIATION as CONTRACT } from "../aws/production-initial-activation-reconciler-state-reconciliation.mjs";
import { assertInstallationPlan } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { resolveReconcilerStateReconciliationAuthorization } from "../aws/reconcile-production-initial-activation-reconciler-state.mjs";

const sourceSha = "a".repeat(40); const now = new Date("2026-09-09T12:00:00.000Z");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const output = Object.freeze({ before: "a".repeat(64), after: CONTRACT.outputReconciliation.after });
const state = (serial, attachmentCount, policyArns, permissionsPolicySha256 = output.before) => Buffer.from(JSON.stringify({ version: 4, terraform_version: "1.15.8", serial, lineage: "state-lineage", outputs: { permissions_policy_sha256: { value: permissionsPolicySha256, type: "string" } }, resources: [
  { mode: "managed", type: "aws_iam_policy", name: "reconciler", instances: [{ attributes: { attachment_count: attachmentCount, name: "MSCQRProductionInitialActivationPolicyReconciler" } }] },
  { mode: "managed", type: "aws_iam_role", name: "reconciler", instances: [{ attributes: { managed_policy_arns: policyArns, name: "mscqr-production-initial-activation-policy-reconciler" } }] },
  { mode: "managed", type: "aws_iam_role_policy_attachment", name: "reconciler", instances: [{ attributes: { role: "mscqr-production-initial-activation-policy-reconciler", policy_arn: CONTRACT.policyArn } }] },
] }));
const before = state(1, 0, []); const after = state(2, 1, [CONTRACT.policyArn], output.after);
const refreshPlan = () => ({ format_version: "1.2", terraform_version: "1.15.8", errored: false, complete: true, applyable: true, resource_changes: [], resource_drift: [
  { address: "aws_iam_policy.reconciler", change: { actions: ["update"], before: { attachment_count: 0, name: "MSCQRProductionInitialActivationPolicyReconciler" }, after: { attachment_count: 1, name: "MSCQRProductionInitialActivationPolicyReconciler" }, before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } },
  { address: "aws_iam_role.reconciler", change: { actions: ["update"], before: { managed_policy_arns: [], name: "mscqr-production-initial-activation-policy-reconciler" }, after: { managed_policy_arns: [CONTRACT.policyArn], name: "mscqr-production-initial-activation-policy-reconciler" }, before_unknown: {}, after_unknown: {}, before_sensitive: { managed_policy_arns: [] }, after_sensitive: { managed_policy_arns: [false] } } },
], output_changes: { permissions_policy_sha256: { actions: ["update"], before: output.before, after: output.after, before_sensitive: false, after_sensitive: false, before_unknown: false, after_unknown: false } } });
const topology = { roles: ["mscqr-production-initial-activation-policy-reconciler"], users: [], groups: [] };
const object = { versionId: "exact-version", etag: "exact-etag" };
const approval = ({ observedAt = now, workflowPath = CONTRACT.authorizationWorkflowPath, runId = "100" } = {}) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 8, name: "production-initial-activation-reconciler-bootstrap", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production-initial-activation-reconciler-bootstrap", sourceSha, workflowRef: `T-ej2003/genuine-scan-main/${workflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: runId, workflowRunAttempt: "1", executionActor: "operator", observedAt: observedAt.toISOString(), actualApproval: { state: "approved", environmentId: 8, environmentName: "production-initial-activation-reconciler-bootstrap", userId: 3, userLogin: "reviewer" } });
const prepared = () => createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: topology, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), preparedAt: now.toISOString() });
const normalPlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-update.json", "utf8"));

test("Terraform-generated backend metadata and saved plans are normalized before private reads", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-state-reconciliation-modes-"));
  fs.chmodSync(directory, 0o700);
  try {
    const metadata = path.join(directory, "terraform.tfstate"); const plan = path.join(directory, "refresh.tfplan"); const postPlan = path.join(directory, "post-refresh.tfplan");
    fs.writeFileSync(metadata, "metadata", { mode: 0o644 }); fs.writeFileSync(plan, "plan", { mode: 0o644 }); fs.writeFileSync(postPlan, "post-plan", { mode: 0o644 });
    for (const [filePath, label] of [[metadata, "State reconciliation backend metadata"], [plan, "State reconciliation saved plan"], [postPlan, "State reconciliation post-refresh Terraform plan"]]) {
      assert.throws(() => readStageBPrivateFileBytes({ filePath, repositoryRoot: process.cwd(), label }), /0600/);
      ensureStageBPrivateFile({ filePath, repositoryRoot: process.cwd(), normalize: true, label });
      assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
      assert.ok(readStageBPrivateFileBytes({ filePath, repositoryRoot: process.cwd(), label }).bytes.length);
    }
    ensureStageBPrivateFile({ filePath: plan, repositoryRoot: process.cwd(), normalize: true, label: "State reconciliation saved plan" });
    assert.equal(fs.statSync(plan).mode & 0o777, 0o600);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("private-file normalization failures fail closed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-state-reconciliation-normalize-fail-"));
  fs.chmodSync(directory, 0o700);
  try {
    const filePath = path.join(directory, "refresh.tfplan"); fs.writeFileSync(filePath, "plan", { mode: 0o644 });
    const fsOps = { lstatSync: fs.lstatSync, realpathSync: fs.realpathSync, readFileSync: fs.readFileSync, chmodSync: () => { throw new Error("chmod denied"); } };
    assert.throws(() => ensureStageBPrivateFile({ filePath, repositoryRoot: process.cwd(), normalize: true, label: "State reconciliation saved plan", fsOps }), /chmod denied/);
    assert.throws(() => readStageBPrivateFileBytes({ filePath, repositoryRoot: process.cwd(), label: "State reconciliation saved plan" }), /0600/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("authorization retrieval isolates GitHub evidence reads from AWS credentials", () => {
  const archive = Buffer.from("fixture-authorization-archive"); const observed = []; const authorization = { fixture: "authorization" }; let workflowPath = CONTRACT.authorizationWorkflowPath; let artifactName = CONTRACT.authorizationArtifactName; let filename = CONTRACT.authorizationFilename;
  const githubRun = createProductionGithubCommandRunner({
    env: {
      PATH: process.env.PATH, GH_TOKEN: "fixture-github-token", AWS_ACCESS_KEY_ID: "fixture-aws-access-key", AWS_SECRET_ACCESS_KEY: "fixture-aws-secret", AWS_SESSION_TOKEN: "fixture-aws-session", AWS_SECURITY_TOKEN: "fixture-aws-security-token", AWS_PROFILE: "fixture-profile", AWS_ROLE_ARN: "arn:aws:iam::368992683803:role/fixture", AWS_WEB_IDENTITY_TOKEN_FILE: "/tmp/fixture-web-identity",
    },
    exec: (file, args, options) => {
      observed.push({ file, args, env: options.env });
      if (file === "unzip") return args[0] === "-Z1" ? `${filename}\n` : JSON.stringify(authorization);
      if (args.at(-1).endsWith("/zip")) return archive;
      if (args.at(-1).endsWith("/artifacts")) return JSON.stringify({ artifacts: [{ id: 456, name: artifactName, expired: false, digest: `sha256:${hash(archive)}`, workflow_run: { id: 123, head_sha: sourceSha, repository_id: 7 } }] });
      return JSON.stringify({ id: 123, repository: { id: 7, full_name: CONTRACT.repository }, head_repository: { full_name: CONTRACT.repository }, path: workflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1 });
    },
  });
  const preparation = { fixture: "preparation" };
  assert.deepEqual(resolveReconcilerStateReconciliationAuthorization({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation, githubRun, assertAuthorization: (value, prepared, options) => { assert.deepEqual(value, authorization); assert.equal(prepared, preparation); assert.equal(options.sourceSha, sourceSha); } }), authorization);
  workflowPath = CONTRACT.recoveryAuthorizationWorkflowPath; artifactName = CONTRACT.recoveryAuthorizationArtifactName; filename = CONTRACT.recoveryAuthorizationFilename;
  assert.deepEqual(resolveReconcilerStateReconciliationAuthorization({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation, githubRun, workflowPath, artifactName, filename, assertAuthorization: (value) => assert.deepEqual(value, authorization) }), authorization);
  for (const call of observed.filter(({ file }) => file === "gh")) {
    for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"]) assert.equal(call.env[key], undefined);
    assert.equal(call.env.GH_TOKEN, "fixture-github-token");
  }
  assert.throws(() => githubRun("gh", ["api", `repos/${CONTRACT.repository}/issues`]), /reviewed read-only/);
  assert.throws(() => githubRun("gh", ["api", `repos/${CONTRACT.repository}/actions/runs/123`, "--method", "POST"]), /reviewed read-only/);
});

test("accepts only the authenticated two-field refresh-only drift and exact output reconciliation", () => {
  assert.deepEqual(assertExactReconcilerRefreshOnlyPlan(refreshPlan(), { stateBytes: before }).resourceDrift, CONTRACT.drift);
  const extra = refreshPlan(); extra.resource_drift[0].change.after.name = "drift";
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(extra, { stateBytes: before }), /outside/);
  const wrongBefore = refreshPlan(); wrongBefore.resource_drift[0].change.before.attachment_count = 1;
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(wrongBefore, { stateBytes: before }), /value/);
  const actionable = refreshPlan(); actionable.resource_changes = [{ change: { actions: ["create"] } }];
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(actionable, { stateBytes: before }), /actionable/);
});

test("refresh-only sensitivity metadata permits exact false-only Terraform structures", () => {
  for (const sensitivity of [false, {}, { tags: {}, tags_all: {} }, { nested: { values: [false, { leaf: false }] } }]) {
    const plan = refreshPlan(); plan.resource_drift[0].change.before_sensitive = plan.resource_drift[0].change.after_sensitive = sensitivity;
    assert.doesNotThrow(() => assertExactReconcilerRefreshOnlyPlan(plan, { stateBytes: before }));
  }
  for (const sensitivity of [{ secret: true }, { nested: { secret: true } }, { values: [false, true] }]) {
    const plan = refreshPlan(); plan.resource_drift[0].change.before_sensitive = plan.resource_drift[0].change.after_sensitive = sensitivity;
    assert.throws(() => assertExactReconcilerRefreshOnlyPlan(plan, { stateBytes: before }), /sensitive/);
  }
  const mismatch = refreshPlan(); mismatch.resource_drift[0].change.before_sensitive = { tags: {} }; mismatch.resource_drift[0].change.after_sensitive = { tags_all: {} };
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(mismatch, { stateBytes: before }), /sensitivity metadata changed/);
});

test("managed-policy sensitivity masks match the exact approved collection values", () => {
  assert.doesNotThrow(() => assertExactReconcilerRefreshOnlyPlan(refreshPlan(), { stateBytes: before }));
  const role = (plan) => plan.resource_drift.find(({ address }) => address === "aws_iam_role.reconciler").change;
  for (const mutate of [
    (change) => { change.after_sensitive.managed_policy_arns = [true]; },
    (change) => { change.before_sensitive.managed_policy_arns = [false]; },
    (change) => { change.after_sensitive.managed_policy_arns = []; },
    (change) => { change.after_sensitive.managed_policy_arns = [false, false]; },
    (change) => { change.after_sensitive.managed_policy_arns = ["false"]; },
    (change) => { change.after_sensitive.managed_policy_arns = [0]; },
    (change) => { change.after_sensitive.managed_policy_arns = [null]; },
    (change) => { change.after_sensitive.managed_policy_arns = [{ nested: true }]; },
    (change) => { change.after.managed_policy_arns = [CONTRACT.policyArn, CONTRACT.policyArn]; },
    (change) => { change.after.managed_policy_arns = ["arn:aws:iam::368992683803:policy/wrong"]; },
  ]) { const plan = refreshPlan(); mutate(role(plan)); assert.throws(() => assertExactReconcilerRefreshOnlyPlan(plan, { stateBytes: before }), /sensitivity|value/); }
});

test("preparation and authorization bind source, state identity, plan, topology, VersionId and ETag", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now });
  assert.doesNotThrow(() => assertReconcilerStateReconciliationAuthorization(authorization, preparation, { sourceSha, now }));
  assert.throws(() => createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: { ...object, etag: "other" }, attachmentTopology: { ...topology, users: ["user"] }, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), preparedAt: now.toISOString() }), /topology/);
  assert.throws(() => assertReconcilerStateReconciliationAuthorization({ ...authorization, savedPlanSha256: "b".repeat(64) }, preparation, { sourceSha, now }), /binding/);
  assert.throws(() => createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: { ...topology, roles: ["wrong-role"] }, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), preparedAt: now.toISOString() }), /topology/);
});

test("exact successor is the only accepted post-state", () => {
  const semantics = assertExactReconcilerRefreshOnlyPlan(refreshPlan(), { stateBytes: before });
  assert.equal(assertExactStateSuccessor({ beforeBytes: before, afterBytes: after, planSemantics: semantics }).serial, 2);
  const unexpected = state(2, 1, ["arn:aws:iam::368992683803:policy/unrelated"]);
  assert.throws(() => assertExactStateSuccessor({ beforeBytes: before, afterBytes: unexpected, planSemantics: semantics }), /outside|fields/);
  const wrongOutput = state(2, 1, [CONTRACT.policyArn], "b".repeat(64));
  assert.throws(() => assertExactStateSuccessor({ beforeBytes: before, afterBytes: wrongOutput, planSemantics: semantics }), /outside|fields/);
});

test("replay and post-apply require the complete authorized successor state", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now });
  const corruptions = [
    (value) => { value.outputs.changed = { value: "unexpected", type: "string" }; },
    (value) => { value.outputs = { changed: { value: "unexpected", type: "string" } }; },
    (value) => { value.resources[0].instances[0].attributes.name = "unexpected"; },
    (value) => { value.resources.push({ mode: "managed", type: "aws_iam_user", name: "unexpected", instances: [{ attributes: { name: "unexpected" } }] }); },
    (value) => { value.resources.pop(); },
    (value) => { value.serial = 3; },
  ];
  for (const mutate of corruptions) {
    const candidate = JSON.parse(after); mutate(candidate); const bytes = Buffer.from(JSON.stringify(candidate)); let applies = 0;
    const common = { sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: bytes, beforeObject: { versionId: "successor-version", etag: "successor-etag" }, beforeTopology: topology, applySavedPlan: () => { applies += 1; }, readPostSnapshot: () => ({ bytes, object: { versionId: "successor-version", etag: "successor-etag" } }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now };
    assert.throws(() => executeReconcilerStateReconciliation(common), /exact authorized successor|not exact/); assert.equal(applies, 0);
    assert.throws(() => executeReconcilerStateReconciliation({ ...common, beforeStateBytes: before, beforeObject: object }), /outside the exact allowance|exact authorized successor|not exact|successor identity/); assert.equal(applies, 1);
  }
});

test("refresh-only output reconciliation is exact and fail-closed", () => {
  const fixture = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-update.json", "utf8")).output_changes.permissions_policy_sha256;
  assert.equal(Object.hasOwn(fixture, "before_unknown"), false);
  assert.equal(fixture.after_unknown, false);
  const omittedBeforeUnknown = refreshPlan(); delete omittedBeforeUnknown.output_changes.permissions_policy_sha256.before_unknown;
  assert.doesNotThrow(() => assertExactReconcilerRefreshOnlyPlan(omittedBeforeUnknown, { stateBytes: before }));
  const falseBeforeUnknown = refreshPlan(); falseBeforeUnknown.output_changes.permissions_policy_sha256.before_unknown = false;
  assert.doesNotThrow(() => assertExactReconcilerRefreshOnlyPlan(falseBeforeUnknown, { stateBytes: before }));
  const trueBeforeUnknown = refreshPlan(); trueBeforeUnknown.output_changes.permissions_policy_sha256.before_unknown = true;
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(trueBeforeUnknown, { stateBytes: before }), /output/);
  for (const malformed of ["false", 0]) {
    const malformedBeforeUnknown = refreshPlan(); malformedBeforeUnknown.output_changes.permissions_policy_sha256.before_unknown = malformed;
    assert.throws(() => assertExactReconcilerRefreshOnlyPlan(malformedBeforeUnknown, { stateBytes: before }), /output/);
  }
  const wrongName = refreshPlan(); wrongName.output_changes = { unexpected: { ...wrongName.output_changes.permissions_policy_sha256 } };
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(wrongName, { stateBytes: before }), /output/);
  const wrongBefore = refreshPlan(); wrongBefore.output_changes.permissions_policy_sha256.before = "b".repeat(64);
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(wrongBefore, { stateBytes: before }), /output/);
  const missingBefore = refreshPlan(); delete missingBefore.output_changes.permissions_policy_sha256.before_unknown; delete missingBefore.output_changes.permissions_policy_sha256.before;
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(missingBefore, { stateBytes: before }), /output/);
  const wrongAfter = refreshPlan(); wrongAfter.output_changes.permissions_policy_sha256.after = "b".repeat(64);
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(wrongAfter, { stateBytes: before }), /output/);
  const extra = refreshPlan(); extra.output_changes.extra = { ...extra.output_changes.permissions_policy_sha256, actions: ["update"] };
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(extra, { stateBytes: before }), /output/);
  const sensitive = refreshPlan(); sensitive.output_changes.permissions_policy_sha256.after_sensitive = true;
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(sensitive, { stateBytes: before }), /output/);
  const unknown = refreshPlan(); unknown.output_changes.permissions_policy_sha256.after_unknown = true;
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(unknown, { stateBytes: before }), /output/);
  const created = refreshPlan(); created.output_changes.permissions_policy_sha256.actions = ["create"];
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(created, { stateBytes: before }), /output/);
  const deleted = refreshPlan(); deleted.output_changes.permissions_policy_sha256.actions = ["delete"];
  assert.throws(() => assertExactReconcilerRefreshOnlyPlan(deleted, { stateBytes: before }), /output/);
});

test("execution applies the saved refresh-only plan once, then requires the strict clean normal plan", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const result = executeReconcilerStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applySavedPlan: (bytes) => { applies += 1; assert.equal(hash(bytes), preparation.savedPlanSha256); }, readPostSnapshot: () => ({ bytes: after, object: { versionId: "successor-version", etag: "successor-etag" } }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now });
  assert.equal(applies, 1); assert.equal(result.remoteIamMutationCount, 0); assert.equal(result.refreshOnlyApplyCount, 1); assert.doesNotThrow(() => assertReconcilerStateReconciliationResult(result, { preparation })); assert.equal(result.planSemantics.terraformResourceAddCount, 0); assert.equal(result.normalPlan.changedAddresses[0], "aws_iam_policy.reconciler");
  assert.throws(() => assertInstallationPlan(refreshPlan()), /envelope/);
});

test("every successful result carries authenticated plan semantics and validated normal-plan evidence", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let normalPlanCalls = 0;
  const result = executeReconcilerStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applySavedPlan: () => { throw new Error("transport lost"); }, readPostSnapshot: () => ({ bytes: after, object: { versionId: "successor-version", etag: "successor-etag" } }), readPostTopology: () => topology, renderNormalPlan: () => { normalPlanCalls += 1; return normalPlan; }, reauthenticateSource: () => true, verifyPostconditions: () => true, now });
  assert.equal(result.status, "COMPLETED_BY_READBACK"); assert.equal(normalPlanCalls, 1); assert.deepEqual(result.planSemantics, preparation.planSemantics); assert.deepEqual(result.normalPlan, assertInstallationPlan(normalPlan)); assert.doesNotThrow(() => assertReconcilerStateReconciliationResult(result, { preparation }));
  for (const mutate of [
    (value) => { delete value.normalPlan; },
    (value) => { delete value.planSemantics; },
    (value) => { value.remoteIamMutationCount = 1; },
    (value) => { value.planSemantics.terraformResourceChangeCount = 1; },
    (value) => { value.normalPlan.resourceChanges[0] = value.normalPlan.resourceChanges[1]; },
    (value) => { value.status = "RECOVERED_COMPLETE"; },
  ]) { const invalid = structuredClone(result); mutate(invalid); assert.throws(() => assertReconcilerStateReconciliationResult(invalid, { preparation }), /result|normal plan|mutation counts/); }
});

test("authenticated successor replay performs zero refresh-only applies", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const result = executeReconcilerStateReconciliation({ sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: after, beforeObject: { versionId: "successor-version", etag: "successor-etag" }, beforeTopology: topology, applySavedPlan: () => { applies += 1; }, readPostSnapshot: () => ({ bytes: after, object: { versionId: "successor-version", etag: "successor-etag" } }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now });
  assert.equal(result.status, "ALREADY_COMPLETE"); assert.equal(applies, 0); assert.doesNotThrow(() => assertReconcilerStateReconciliationResult(result, { preparation })); assert.equal(result.planSemantics.exactTwoFieldDrift, true); assert.equal(result.normalPlan.updateCount, 1);
});

test("final CAS mismatch, authorization substitution, and ambiguous post-state fail closed before or after zero retry", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const common = { sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: { ...object, versionId: "wrong" }, beforeTopology: topology, applySavedPlan: () => { applies += 1; }, readPostSnapshot: () => ({ bytes: before, object }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now };
  assert.throws(() => executeReconcilerStateReconciliation(common), /predecessor|successor/); assert.equal(applies, 0);
  const mismatch = { ...common, beforeObject: object, authorization: { ...authorization, sourceSha: "b".repeat(40) } };
  assert.throws(() => executeReconcilerStateReconciliation(mismatch), /binding/); assert.equal(applies, 0);
});

test("saved-plan substitution, stale authorization, and an unknown apply outcome never permit a retry", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const common = { sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applySavedPlan: () => { applies += 1; throw new Error("transport lost"); }, readPostSnapshot: () => ({ bytes: before, object }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now };
  assert.throws(() => executeReconcilerStateReconciliation({ ...common, planBytes: Buffer.from("substituted-plan") }), /saved plan/); assert.equal(applies, 0);
  assert.throws(() => executeReconcilerStateReconciliation({ ...common, now: new Date(now.getTime() + CONTRACT.maxAgeMs + 1) }), /stale/); assert.equal(applies, 0);
  assert.throws(() => executeReconcilerStateReconciliation(common), (error) => error.mutationOutcome === "AMBIGUOUS"); assert.equal(applies, 1);
});

test("expired exact successor requires fresh zero-write recovery authorization", () => {
  const old = new Date(now.getTime() - CONTRACT.maxAgeMs - 1); const original = createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: topology, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), preparedAt: old.toISOString() });
  const originalAuthorization = createReconcilerStateReconciliationAuthorization({ preparation: original, approval: approval({ observedAt: old }), now: old }); const successorObject = { versionId: "successor-version", etag: "successor-etag" };
  assert.throws(() => executeReconcilerStateReconciliation({ sourceSha, preparation: original, authorization: originalAuthorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: after, beforeObject: successorObject, beforeTopology: topology, applySavedPlan: () => assert.fail("expired authorization must not apply"), readPostSnapshot: () => assert.fail("expired authorization must not read"), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now }), /stale/);
  const recoveryPreparation = createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation: original, originalAuthorization, originalAuthorizationWorkflowRunId: "100", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: after, stateObject: successorObject, attachmentTopology: topology, preparedAt: now.toISOString() });
  assert.throws(() => createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation: original, originalAuthorization, originalAuthorizationWorkflowRunId: "101", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: after, stateObject: successorObject, attachmentTopology: topology, preparedAt: now.toISOString() }), /original authorization/);
  const { preparationSha256, ...incompatibleBody } = original; const incompatiblePreparation = { ...incompatibleBody, terraformRoot: "other", preparationSha256: hash(canonicalJson({ ...incompatibleBody, terraformRoot: "other" })) };
  assert.throws(() => createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation: incompatiblePreparation, originalAuthorization, originalAuthorizationWorkflowRunId: "100", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: after, stateObject: successorObject, attachmentTopology: topology, preparedAt: now.toISOString() }), /binding|incompatible/);
  const recoveryAuthorization = createReconcilerStateReconciliationRecoveryAuthorization({ recoveryPreparation, approval: approval({ workflowPath: CONTRACT.recoveryAuthorizationWorkflowPath, runId: "200" }), now });
  const result = executeReconcilerStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: after, stateObject: successorObject, attachmentTopology: topology, applySavedPlan: () => assert.fail("recovery cannot reach apply"), renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now });
  assert.equal(result.status, "RECOVERED_COMPLETE"); assert.equal(result.refreshOnlyApplyCount, 0); assert.equal(result.terraformStateMutationCount, 0); assert.equal(result.remoteIamMutationCount, 0); assert.doesNotThrow(() => assertReconcilerStateReconciliationResult(result, { preparation: recoveryPreparation })); assert.equal(result.planSemantics.outputDrift, true); assert.equal(result.normalPlan.updateCount, 1); assert.deepEqual(recoveryAuthorization.maxAwsMutations, {});
  assert.throws(() => executeReconcilerStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization: { ...recoveryAuthorization, originalPreparationSha256: "b".repeat(64) }, stateBytes: after, stateObject: successorObject, attachmentTopology: topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now }), /binding/);
  assert.throws(() => createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation: original, originalAuthorization, originalAuthorizationWorkflowRunId: "100", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: before, stateObject: object, attachmentTopology: topology, preparedAt: now.toISOString() }), /exact authorized successor/);
});

test("recovery rejects every merely similar or later state", () => {
  const old = new Date(now.getTime() - CONTRACT.maxAgeMs - 1); const original = createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes: before, stateObject: object, attachmentTopology: topology, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), preparedAt: old.toISOString() }); const originalAuthorization = createReconcilerStateReconciliationAuthorization({ preparation: original, approval: approval({ observedAt: old }), now: old }); const successorObject = { versionId: "successor-version", etag: "successor-etag" };
  const recoveryPreparation = createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation: original, originalAuthorization, originalAuthorizationWorkflowRunId: "100", originalAuthorizationWorkflowRunAttempt: "1", stateBytes: after, stateObject: successorObject, attachmentTopology: topology, preparedAt: now.toISOString() }); const recoveryAuthorization = createReconcilerStateReconciliationRecoveryAuthorization({ recoveryPreparation, approval: approval({ workflowPath: CONTRACT.recoveryAuthorizationWorkflowPath, runId: "200" }), now });
  for (const mutate of [(value) => { value.outputs.unrelated = { value: "changed" }; }, (value) => { value.resources[0].instances[0].attributes.name = "changed"; }, (value) => { value.resources.push({ mode: "managed", type: "aws_iam_user", name: "later", instances: [{ attributes: { name: "later" } }] }); }, (value) => { value.serial = 3; }]) {
    const candidate = JSON.parse(after); mutate(candidate);
    assert.throws(() => executeReconcilerStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes: Buffer.from(JSON.stringify(candidate)), stateObject: successorObject, attachmentTopology: topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now }), /exact authorized successor|live state changed/);
  }
});

test("post-refresh verification rejects a dirty normal plan and unchanged backend object identity", () => {
  const preparation = prepared(); const authorization = createReconcilerStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const common = { sourceSha, preparation, authorization, planBytes: Buffer.from("saved-refresh-plan"), planJson: refreshPlan(), beforeStateBytes: before, beforeObject: object, beforeTopology: topology, applySavedPlan: () => { applies += 1; }, readPostSnapshot: () => ({ bytes: after, object: { ...object } }), readPostTopology: () => topology, renderNormalPlan: () => normalPlan, reauthenticateSource: () => true, verifyPostconditions: () => true, now };
  assert.throws(() => executeReconcilerStateReconciliation(common), /object identity/); assert.equal(applies, 1);
  const dirty = refreshPlan(); dirty.resource_changes = [{ address: "aws_iam_role.reconciler", change: { actions: ["update"] } }];
  assert.throws(() => executeReconcilerStateReconciliation({ ...common, readPostSnapshot: () => ({ bytes: after, object: { versionId: "successor-version", etag: "successor-etag" } }), renderNormalPlan: () => dirty }), /envelope|exact policy update/); assert.equal(applies, 2);
});

test("state-reconciliation runbook documents the current prepare-authorize-execute contract", () => {
  const runbook = fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationReconcilerStateReconciliation-v1.md", "utf8");
  const preparationScript = "production:initial-activation-reconciler:state-reconcile";
  assert.equal(JSON.parse(fs.readFileSync("package.json", "utf8")).scripts[preparationScript], "node scripts/aws/reconcile-production-initial-activation-reconciler-state.mjs");
  const requiredInputs = (workflow) => [...fs.readFileSync(workflow, "utf8").matchAll(/^\s{6}(\w+): \{ description: .*required: true,/gm)].map((match) => match[1]);
  const authorizationWorkflow = ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation.yml";
  const executionWorkflow = ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation.yml";
  const recoveryAuthorizationWorkflow = ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation-recovery.yml";
  const recoveryExecutionWorkflow = ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation-recovery.yml";
  assert.match(runbook, new RegExp(`${preparationScript} -- --mode prepare`));
  assert.match(runbook, /--terraform-data-dir/); assert.match(runbook, /--saved-plan-out/); assert.match(runbook, /--preparation-out/);
  for (const [workflow, command] of [[authorizationWorkflow, "authorize-production-initial-activation-reconciler-state-reconciliation.yml"], [executionWorkflow, "execute-production-initial-activation-reconciler-state-reconciliation.yml"]]) {
    assert.ok(runbook.includes(command));
    for (const input of requiredInputs(workflow)) assert.match(runbook, new RegExp(`-f ${input}=`));
  }
  assert.match(runbook, /authorization_run_id/); assert.match(runbook, /authorization_run_attempt/);
  assert.match(runbook, /--mode recovery-prepare/); assert.match(runbook, /--mode recovery-execute/);
  for (const [workflow, command] of [[recoveryAuthorizationWorkflow, "authorize-production-initial-activation-reconciler-state-reconciliation-recovery.yml"], [recoveryExecutionWorkflow, "execute-production-initial-activation-reconciler-state-reconciliation-recovery.yml"]]) {
    assert.ok(runbook.includes(command));
    for (const input of requiredInputs(workflow)) assert.match(runbook, new RegExp(`-f ${input}=`));
  }
  assert.match(runbook, /original_authorization_run_id/); assert.match(runbook, /original_authorization_run_attempt/); assert.match(runbook, /recovery_authorization_run_id/); assert.match(runbook, /recovery_authorization_run_attempt/);
  assert.match(runbook, new RegExp(`${CONTRACT.maxAgeMs / 1000} seconds`));
  assert.match(runbook, /saved_plan_base64/); assert.match(runbook, /terraform refresh|terraform state push|normal `terraform apply`/);
  for (const field of ["planSemantics", "exactTwoFieldDrift", "outputDrift", "outputReconciliation", "normalPlan", "COMPLETE", "ALREADY_COMPLETE", "COMPLETED_BY_READBACK", "RECOVERED_COMPLETE", "terraformStateMutationCount"]) assert.match(runbook, new RegExp(field));
});

test("quality gate reaches every PR reconciliation production contract", () => {
  const suite = JSON.parse(fs.readFileSync("package.json", "utf8")).scripts["test:production-initial-activation-reconciler"];
  const qualityGate = fs.readFileSync(".github/workflows/quality-gate.yml", "utf8");
  const resolver = fs.readFileSync("scripts/aws/reconcile-production-initial-activation-reconciler-state.mjs", "utf8");
  assert.match(suite, /scripts\/tests\/production-initial-activation-reconciler-state-reconciliation\.test\.mjs/);
  assert.match(suite, /scripts\/tests\/production-credential-source-contract\.test\.mjs/);
  assert.match(suite, /scripts\/tests\/production-github-environment-approval\.test\.mjs/);
  assert.match(qualityGate, /npm run test:production-initial-activation-reconciler/);
  assert.doesNotMatch(resolver, /exec\("gh"/);
  assert.equal([...resolver.matchAll(/githubRun: deps\.githubRun \|\| createProductionGithubCommandRunner\(\)/g)].length, 3);
});

test("reconciliation workflows consume every required dispatch input", () => {
  for (const workflow of [
    ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation.yml",
    ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation.yml",
    ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation-recovery.yml",
    ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation-recovery.yml",
  ]) {
    const text = fs.readFileSync(workflow, "utf8");
    for (const [, input] of text.matchAll(/^      (\w+): \{ description: .*required: true,/gm)) assert.match(text.slice(text.indexOf("jobs:")), new RegExp(`inputs\\.${input}`));
  }
});
