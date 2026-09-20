import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { approveBrokerPolicySuccessor, assertBrokerPolicySuccessorAuthorization, brokerPolicySuccessorSourceBindings } from "../aws/component-broker-policy-successor-authorization.mjs";
import { brokerPolicyPredecessor, brokerPolicySuccessor, brokerPolicySuccessorCapabilitySet, brokerPolicySuccessorDelta, predecessorExecutorPolicySha256, successorExecutorPolicySha256 } from "../aws/component-broker-policy-successor-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";

function fixture() {
  const sourceSha = "b".repeat(40), now = Date.parse("2026-09-20T12:00:00Z"), actor = { type: "User", login: "T-ej2003", id: 183396573 }, repository = { full_name: "T-ej2003/genuine-scan-main", id: 1145608538 };
  const manifest = componentBrokerPackageManifest(sourceSha), packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256: "a".repeat(64) };
  return { sourceSha, now, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "456", packageEvidence,
    main: { name: "main", protected: true, commit: { sha: sourceSha } }, run: { id: 456, head_sha: sourceSha, head_branch: "main", path: brokerPolicySuccessor.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository, head_repository: repository, actor, triggering_actor: actor },
    environment: { id: 97, name: brokerPolicySuccessor.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] }, approvals: [{ state: "approved", user: actor, environments: [{ id: 97, name: brokerPolicySuccessor.environment }] }] };
}

test("successor authorization binds exact immutable generations and minimal delta", () => {
  const f = fixture(), value = approveBrokerPolicySuccessor(f); assert.equal(assertBrokerPolicySuccessorAuthorization(value, f.packageEvidence, f.now), digest(value));
  assert.deepEqual(value.predecessor, brokerPolicyPredecessor); assert.equal(predecessorExecutorPolicySha256, "777b32148b2c03bf740db2a955b11dc5c524b1437d4d73a83d6f8d47745ea8a6");
  assert.equal(successorExecutorPolicySha256, "0f08fdee746a32153be9e04394beb71a4ebd7c710020207d6339fc2080c6f4bf");
  assert.equal(value.successor.brokerVersion, "7"); assert.deepEqual(value.delta, brokerPolicySuccessorDelta); assert.deepEqual(value, { ...value, ...brokerPolicySuccessorSourceBindings(f.packageEvidence) });
});

for (const mutate of [f => { f.main.commit.sha = "c".repeat(40); }, f => { f.run.path = "other"; }, f => { f.environment.can_admins_bypass = true; }, f => { f.branches.branch_policies[0].name = "*"; }, f => { f.approvals[0].user.id = 1; }])
  test("successor authorization rejects substituted governance", () => { const f = fixture(); mutate(f); assert.throws(() => approveBrokerPolicySuccessor(f)); });

test("successor authorization rejects every altered binding and expiry", () => {
  const f = fixture(), value = approveBrokerPolicySuccessor(f);
  for (const field of Object.keys(value)) { const changed = structuredClone(value); changed[field] = "different"; assert.throws(() => assertBrokerPolicySuccessorAuthorization(changed, f.packageEvidence, f.now), field); }
  assert.throws(() => assertBrokerPolicySuccessorAuthorization(value, f.packageEvidence, Date.parse(value.expiresAt)));
});

test("root capability and workflow expose only the exact one-time successor surface", () => {
  const capability = brokerPolicySuccessorCapabilitySet(), actions = capability.Statement.flatMap(({ Action }) => [].concat(Action));
  for (const required of ["iam:PutRolePolicy", "lambda:UpdateFunctionCode", "lambda:PublishVersion", "s3:PutObject"]) assert(actions.includes(required));
  for (const forbidden of ["iam:CreateRole", "iam:PassRole", "lambda:AddPermission", "lambda:DeleteFunction", "s3:DeleteObject"]) assert(!actions.includes(forbidden));
  for (const statement of capability.Statement) assert(![].concat(statement.Resource).includes("*"));
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/authorize-component-broker-policy-successor.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.permissions, { contents: "read", actions: "read" }); assert.equal(workflow.jobs.authorize.environment, brokerPolicySuccessor.environment); assert(!JSON.stringify(workflow).includes("configure-aws-credentials"));
});
