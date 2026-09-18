import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { approveBrokerChange, assertBrokerChangeAuthorization, brokerChangeSourceBindings } from "../aws/component-broker-change-authorization.mjs";
import { brokerChange, brokerChangeCapabilitySet } from "../aws/component-broker-change-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";

function fixture() {
  const sourceSha = "b".repeat(40), now = Date.parse("2026-09-18T12:00:00Z"), actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const repository = { full_name: "T-ej2003/genuine-scan-main", id: 1145608538 }, manifest = componentBrokerPackageManifest(sourceSha);
  const packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256: "a".repeat(64) };
  return { sourceSha, now, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "456", packageEvidence,
    main: { name: "main", protected: true, commit: { sha: sourceSha } },
    run: { id: 456, head_sha: sourceSha, head_branch: "main", path: brokerChange.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository, head_repository: repository, actor, triggering_actor: actor },
    environment: { id: 92, name: brokerChange.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] }, approvals: [{ state: "approved", user: actor, environments: [{ id: 92, name: brokerChange.environment }] }],
  };
}

test("broker change approval binds both immutable recovered predecessor and exact successor", () => {
  const f = fixture(), value = approveBrokerChange(f);
  assert.equal(assertBrokerChangeAuthorization(value, f.packageEvidence, f.now), digest(value));
  assert.equal(value.successorLambdaCodeSha256, Buffer.from(value.successorPackageSha256, "hex").toString("base64"));
  assert.deepEqual(value.remainingOperations, brokerChangeSourceBindings(f.packageEvidence).remainingOperations);
});

for (const mutate of [
  f => { f.main.commit.sha = "c".repeat(40); }, f => { f.run.path = "other"; }, f => { f.environment.can_admins_bypass = true; },
  f => { f.environment.protection_rules[0].prevent_self_review = true; }, f => { f.branches.branch_policies[0].name = "*"; },
  f => { f.approvals[0].user.id = 1; },
]) test("broker change rejects substituted governance or successor", () => { const f = fixture(); mutate(f); assert.throws(() => approveBrokerChange(f)); });

test("authorization rejects every altered binding and expiry", () => {
  const f = fixture(), value = approveBrokerChange(f);
  for (const field of Object.keys(value)) { const changed = structuredClone(value); changed[field] = "different"; assert.throws(() => assertBrokerChangeAuthorization(changed, f.packageEvidence, f.now), field); }
  assert.throws(() => assertBrokerChangeAuthorization(value, f.packageEvidence, Date.parse(value.expiresAt)));
});

test("broker change capability has no persistent composition or generic Lambda authority", () => {
  const actions = brokerChangeCapabilitySet().Statement.flatMap(({ Action }) => [].concat(Action));
  for (const required of ["lambda:UpdateFunctionCode", "lambda:PublishVersion", "iam:PutRolePolicy"]) assert(actions.includes(required));
  for (const forbidden of ["iam:PassRole", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "lambda:CreateFunction", "lambda:DeleteFunction", "lambda:AddPermission", "lambda:PutFunctionConcurrency"]) assert(!actions.includes(forbidden));
  for (const statement of brokerChangeCapabilitySet().Statement) assert(![].concat(statement.Resource).includes("*"));
});

test("broker change workflow obtains approval before it builds the successor and never obtains AWS credentials", () => {
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/authorize-component-installation-broker-change.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.permissions, { contents: "read", actions: "read" }); assert.equal(workflow.jobs.authorize.environment, brokerChange.environment);
  assert(!JSON.stringify(workflow).includes("configure-aws-credentials")); assert(!JSON.stringify(workflow).includes("id-token"));
});
