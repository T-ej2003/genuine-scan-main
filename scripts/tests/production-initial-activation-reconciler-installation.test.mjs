import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INSTALLATION, assertInstallationAuthorization, assertInstallationPlan, assertInstallationPreparation, createInstallationAuthorization, createInstallationPreparation, stateIdentity } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { executeInstallation } from "../aws/install-production-initial-activation-reconciler.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-05T12:00:00.000Z");
const trust = fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/trust-policy.json", "utf8");
const permissions = fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json", "utf8");
const capability = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerInstallation-v1.json", "utf8"));
const plan = { resource_changes: [
  { address: "aws_iam_role.reconciler", mode: "managed", type: "aws_iam_role", change: { actions: ["create"], before: null, after: { name: "mscqr-production-initial-activation-policy-reconciler", max_session_duration: 3600, assume_role_policy: trust } } },
  { address: "aws_iam_policy.reconciler", mode: "managed", type: "aws_iam_policy", change: { actions: ["create"], before: null, after: { name: "MSCQRProductionInitialActivationPolicyReconciler", policy: permissions } } },
  { address: "aws_iam_role_policy_attachment.reconciler", mode: "managed", type: "aws_iam_role_policy_attachment", change: { actions: ["create"], before: null, after: { role: "mscqr-production-initial-activation-policy-reconciler" } } },
] };
const planBytes = Buffer.from("exact-saved-plan");
const state = JSON.stringify({ version: 4, terraform_version: "1.15.8", serial: 0, lineage: "first-install-lineage", outputs: {}, resources: [] });
const approval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: INSTALLATION.repository, environment: "production", sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 7, environmentName: "production", userId: 3, userLogin: "reviewer" },
});
const preparation = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(state)), livePredecessor: "ABSENT", planJson: plan, planBytes, preparedAt: now.toISOString() });
const authorization = createInstallationAuthorization({ preparation, preparationSha256: preparation.preparationSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });

test("first-install preparation binds absent state and exact plan addresses", () => {
  assert.equal(preparation.predecessorState.stateExists, true);
  assert.equal(preparation.planSemantics.resourceChangeCount, 3);
  assert.doesNotThrow(() => assertInstallationPreparation(preparation, { sourceSha, planBytes }));
  assert.throws(() => assertInstallationPlan({ resource_changes: [...plan.resource_changes, { address: "aws_s3_bucket.unrelated", mode: "managed", type: "aws_s3_bucket", change: { actions: ["create"], before: null } }] }), /resource count|unreviewed/);
});

test("exact partial installation accepts only the remaining reviewed creates", () => {
  const partial = { resource_changes: [plan.resource_changes[1], plan.resource_changes[2]] };
  assert.equal(assertInstallationPlan(partial).resourceChangeCount, 2);
  const partialPreparation = createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "EXACT_PARTIAL", planJson: partial, planBytes, preparedAt: now.toISOString() });
  assert.doesNotThrow(() => assertInstallationPreparation(partialPreparation, { sourceSha, planBytes }));
});

test("authorization is source, plan, root and environment bound", () => {
  assert.doesNotThrow(() => assertInstallationAuthorization(authorization, { sourceSha, preparation }));
  assert.throws(() => assertInstallationAuthorization({ ...authorization, sourceSha: "b".repeat(40) }, { sourceSha, preparation }), /binding|hash/);
  assert.throws(() => assertInstallationAuthorization({ ...authorization, administratorArn: "arn:aws:iam::368992683803:role/other" }, { sourceSha, preparation }), /operation|hash/);
});

test("executor applies one exact plan and requires canonical verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-test-"));
  const resultPath = path.join(directory, "result.json");
  let applies = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", applySavedPlan: ({ planBytes: bytes }) => { applies += 1; assert.deepEqual(bytes, planBytes); }, verifyInstalled: () => true, readState: () => Buffer.from(state), resultPath, consumptionDirectory: path.join(directory, "consumptions"), now });
  assert.equal(applies, 1);
  assert.equal(result.applyCount, 1);
  assert.equal(result.targetPolicyCreatePolicyVersionCount, 0);
  assert.equal(JSON.parse(fs.readFileSync(resultPath)).verifier, "PASS");
  fs.rmSync(directory, { recursive: true, force: true });
});

test("exact-complete replay performs zero apply", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-replay-"));
  let applies = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "EXACT_COMPLETE", applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(state), resultPath: path.join(directory, "result.json"), now });
  assert.equal(applies, 0);
  assert.equal(result.applyCount, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply recovers only through a successful read-only verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-"));
  let applies = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", applySavedPlan: () => { applies += 1; throw new Error("transport lost after commit"); }, verifyInstalled: () => true, readState: () => Buffer.from(state), resultPath: path.join(directory, "result.json"), consumptionDirectory: path.join(directory, "consumptions"), now });
  assert.equal(applies, 1);
  assert.equal(result.recoveredFromAmbiguousApply, true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply never retries when read-only verification fails", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", applySavedPlan: () => { applies += 1; throw new Error("transport lost"); }, verifyInstalled: () => { throw new Error("not complete"); }, readState: () => Buffer.from(state), resultPath: path.join(directory, "result.json"), consumptionDirectory: path.join(directory, "consumptions"), now }), /transport lost/);
  assert.equal(applies, 1);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("unsafe state and plan changes fail before apply", () => {
  assert.deepEqual(stateIdentity(undefined), { stateExists: false });
  assert.throws(() => createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "UNEXPECTED", planJson: plan, planBytes }), /Unexpected|classification/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes: Buffer.from("changed"), planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, resultPath: path.join(directory, "result.json"), now }), /saved plan/);
  assert.equal(applies, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("no installation artifact contains credential-shaped material", () => {
  const serialized = JSON.stringify({ preparation, authorization });
  assert.doesNotMatch(serialized, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|MFA|token/i);
  assert.ok(crypto.createHash("sha256").update(planBytes).digest("hex") === preparation.savedPlanSha256);
});

test("installation capability is purpose-bound and cannot consume the runtime target", () => {
  assert.equal(capability.sourceOnly, true);
  assert.equal(capability.terraformRoot, INSTALLATION.terraformRoot);
  assert.deepEqual(capability.resources, INSTALLATION.expectedAddresses);
  assert.equal(capability.maxAwsMutations["iam:CreatePolicyVersion"], 0);
  assert.match(capability.postcondition, /canonical-read-only-reconciler-verifier/);
});
