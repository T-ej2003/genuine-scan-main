import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { approveIdentityBootstrap, assertIdentityBootstrapAuthorization, bootstrapAuthorizationContract } from "../aws/component-identity-bootstrap-authorization.mjs";
import { identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";

function fixture() {
  const sourceSha = "b".repeat(40), now = Date.parse("2026-09-17T12:00:00Z");
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const repository = { full_name: "T-ej2003/genuine-scan-main", id: 1145608538 };
  const manifest = componentBrokerPackageManifest(sourceSha);
  return { sourceSha, now, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "123",
    main: { name: "main", protected: true, commit: { sha: sourceSha } },
    run: { id: 123, head_sha: sourceSha, head_branch: "main", repository, head_repository: repository, path: bootstrapAuthorizationContract.workflow,
      event: "workflow_dispatch", status: "in_progress", run_attempt: 1, actor, triggering_actor: actor },
    environment: { id: 91, name: identityBootstrap.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
      protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] },
    approvals: [{ state: "approved", user: actor, environments: [{ id: 91, name: identityBootstrap.environment }] }],
    packageEvidence: { manifest, manifestSha256: digest(manifest), packageSha256: "a".repeat(64) },
  };
}
test("dedicated solo-operator bootstrap approval binds all identities and broker configurations", () => {
  const f = fixture(), approval = approveIdentityBootstrap(f);
  assert.equal(assertIdentityBootstrapAuthorization(approval, f.packageEvidence, f.now), digest(approval));
  assert.deepEqual(Object.keys(approval.brokerConfigurations), ["INSTALL", "CLEANUP", "AUTHORIZE"]);
});
for (const [name, change] of Object.entries({
  source: f => { f.main.commit.sha = "c".repeat(40); },
  branch: f => { f.run.head_branch = "other"; },
  workflow: f => { f.run.path = "other"; },
  fork: f => { f.run.head_repository = { id: 1 }; },
  actor: f => { f.run.actor = { type: "User", login: "T-ej2003", id: 1 }; },
  missingApproval: f => { f.approvals = []; },
  wrongReviewer: f => { f.approvals[0].user = { type: "User", login: "other", id: 1 }; },
  wrongEnvironment: f => { f.approvals[0].environments[0].id = 92; },
  adminBypass: f => { f.environment.can_admins_bypass = true; },
  team: f => { f.environment.protection_rules[0].reviewers[0].type = "Team"; },
  selfReview: f => { f.environment.protection_rules[0].prevent_self_review = true; },
  wildcard: f => { f.branches.branch_policies[0].name = "*"; },
  rerun: f => { f.run.run_attempt = 2; },
  differentPackage: f => { f.packageEvidence.manifestSha256 = "d".repeat(64); },
})) test(`bootstrap approval rejects ${name}`, () => {
  const f = fixture(); change(f); assert.throws(() => approveIdentityBootstrap(f));
});
for (const field of Object.keys(approveIdentityBootstrap(fixture()))) {
  test(`bootstrap execution rejects substituted ${field}`, () => {
    const f = fixture(), approval = approveIdentityBootstrap(f);
    approval[field] = "different";
    assert.throws(() => assertIdentityBootstrapAuthorization(approval, f.packageEvidence, f.now));
  });
}
test("bootstrap expiry, future approval and extra document override fail closed", () => {
  const f = fixture(), approval = approveIdentityBootstrap(f);
  for (const time of [f.now - 1, Date.parse(approval.expiresAt), NaN]) assert.throws(() => assertIdentityBootstrapAuthorization(approval, f.packageEvidence, time));
  assert.throws(() => assertIdentityBootstrapAuthorization({ ...approval, policy: {} }, f.packageEvidence, f.now));
});

test("bootstrap approval workflow gates package construction and cannot acquire AWS credentials", () => {
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/authorize-component-installation-identity-bootstrap.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.permissions, { contents: "read", actions: "read" });
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs), ["source_sha", "transition_id"]);
  const job = workflow.jobs.authorize;
  assert.equal(job.environment, identityBootstrap.environment);
  assert(job.if.includes("github.ref == 'refs/heads/main'"));
  assert.equal(job.steps.filter(step => step.run === "node scripts/aws/component-identity-bootstrap-authorization.mjs prepare").length, 1);
  assert(!JSON.stringify(workflow).includes("configure-aws-credentials"));
  assert(!JSON.stringify(workflow).includes("id-token"));
});

for (const args of [[], ["execute"], ["prepare", "policy.json"], ["prepare"]]) test(`bootstrap publisher actual CLI rejects untrusted invocation ${JSON.stringify(args)}`, () => {
  const file = fileURLToPath(new URL("../aws/component-identity-bootstrap-authorization.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [file, ...args], { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" });
  assert.equal(result.status, 1); assert.equal(result.stdout, "");
  assert.equal(result.stderr, "Component identity bootstrap approval rejected.\n");
});
