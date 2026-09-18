import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { approveBootstrapRecovery, assertBootstrapRecoveryAuthorization, recoverySourceBindings } from "../aws/component-bootstrap-partial-recovery-authorization.mjs";
import { bootstrapPartialStateDigest, bootstrapRecovery, bootstrapRecoveryCapabilitySet, historicalBootstrapIncident } from "../aws/component-bootstrap-partial-recovery-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";

function fixture() {
  const sourceSha = "b".repeat(40), now = Date.parse("2026-09-18T12:00:00Z"), actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const repository = { full_name: "T-ej2003/genuine-scan-main", id: 1145608538 }, manifest = componentBrokerPackageManifest(sourceSha);
  const packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256: "a".repeat(64) };
  return { sourceSha, now, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "456", packageEvidence,
    main: { name: "main", protected: true, commit: { sha: sourceSha } },
    run: { id: 456, head_sha: sourceSha, head_branch: "main", path: bootstrapRecovery.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1,
      repository, head_repository: repository, actor, triggering_actor: actor },
    environment: { id: 92, name: bootstrapRecovery.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
      protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] },
    approvals: [{ state: "approved", user: actor, environments: [{ id: 92, name: bootstrapRecovery.environment }] }],
  };
}

test("recovery approval binds exact historical incident, corrected package and remaining operations", () => {
  const f = fixture(), value = approveBootstrapRecovery(f); assert.equal(assertBootstrapRecoveryAuthorization(value, f.packageEvidence, f.now), digest(value));
  assert.equal(value.partialStateSha256, bootstrapPartialStateDigest()); assert.equal(value.historicalTransitionId, historicalBootstrapIncident.transitionId);
  assert.equal(value.newLambdaCodeSha256, Buffer.from(value.newPackageSha256, "hex").toString("base64"));
});

for (const mutate of [
  f => { f.run.path = "other"; }, f => { f.main.commit.sha = "c".repeat(40); }, f => { f.environment.can_admins_bypass = true; },
  f => { f.environment.protection_rules[0].prevent_self_review = true; }, f => { f.environment.protection_rules[0].reviewers.push(f.environment.protection_rules[0].reviewers[0]); },
  f => { f.branches.branch_policies[0].name = "*"; }, f => { f.approvals[0].user.id = 1; }, f => { f.packageEvidence.packageSha256 = historicalBootstrapIncident.packageSha256; },
]) test("recovery authorization rejects substituted governance or package binding", () => { const f = fixture(); mutate(f); assert.throws(() => approveBootstrapRecovery(f)); });

test("recovery authorization rejects every substituted field and expiry", () => {
  const f = fixture(), value = approveBootstrapRecovery(f);
  for (const field of Object.keys(value)) { const changed = structuredClone(value); changed[field] = "different"; assert.throws(() => assertBootstrapRecoveryAuthorization(changed, f.packageEvidence, f.now), field); }
  assert.throws(() => assertBootstrapRecoveryAuthorization(value, f.packageEvidence, Date.parse(value.expiresAt)));
});

test("recovery capability is exact and cannot create identities, deploy arbitrary Lambda, pass roles or mutate unrelated resources", () => {
  const policy = bootstrapRecoveryCapabilitySet(), actions = policy.Statement.flatMap(statement => [].concat(statement.Action));
  assert(actions.includes("lambda:UpdateFunctionCode"));
  for (const forbidden of ["iam:CreateRole", "iam:PutRolePolicy", "iam:PassRole", "lambda:CreateFunction", "lambda:DeleteFunction", "lambda:AddPermission", "lambda:DeleteFunctionCodeSigningConfig"]) assert(!actions.includes(forbidden));
  for (const statement of policy.Statement.filter(statement => [].concat(statement.Action).some(action => /^(?:iam|lambda):/.test(action)))) {
    assert.notDeepEqual(statement.Resource, "*");
  }
});

test("dedicated recovery workflow has approval before package binding and no AWS credentials", () => {
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/authorize-component-installation-identity-bootstrap-recovery.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.permissions, { contents: "read", actions: "read" }); assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs), ["source_sha", "transition_id"]);
  const job = workflow.jobs.authorize; assert.equal(job.environment, bootstrapRecovery.environment); assert(job.if.includes("github.ref == 'refs/heads/main'"));
  assert.equal(job.steps.filter(step => step.run === "node scripts/aws/component-bootstrap-partial-recovery-authorization.mjs prepare").length, 1);
  assert(!JSON.stringify(workflow).includes("configure-aws-credentials")); assert(!JSON.stringify(workflow).includes("id-token"));
});

for (const args of [[], ["execute"], ["prepare", "policy.json"], ["prepare"]]) test(`recovery publisher CLI rejects ${JSON.stringify(args)}`, () => {
  const file = fileURLToPath(new URL("../aws/component-bootstrap-partial-recovery-authorization.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [file, ...args], { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" });
  assert.equal(result.status, 1); assert.equal(result.stdout, ""); assert.equal(result.stderr, "Component bootstrap recovery approval rejected.\n");
});
