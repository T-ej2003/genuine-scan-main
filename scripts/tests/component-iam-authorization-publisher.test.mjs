import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { spawnSync } from "node:child_process";
import { approvedInstallationRequest } from "../aws/component-iam-authorization-publisher.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";
import { componentSessionIdentities } from "../aws/component-installation-identity-contract.mjs";

function fixture() {
  const actor = { login: "T-ej2003", id: 183396573, type: "User" };
  const sourceSha = "a".repeat(40);
  const manifest = componentBrokerPackageManifest(sourceSha);
  const environment = { id: 42, name: installationIdentity.authorizationEnvironment, can_admins_bypass: false,
    deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
    protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] };
  return structuredClone({ sourceSha, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "12345", now: Date.parse("2026-09-17T12:00:00Z"),
    main: { name: "main", protected: true, commit: { sha: sourceSha } },
    run: { id: 12345, head_sha: sourceSha, head_branch: "main", repository: { full_name: installationIdentity.repository, id: 1145608538 }, head_repository: { id: 1145608538 },
      path: ".github/workflows/authorize-component-iam-installation.yml", event: "workflow_dispatch", status: "in_progress", run_attempt: 1, actor, triggering_actor: actor },
    environment, branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] },
    approvals: [{ state: "approved", user: actor, environments: [{ id: environment.id, name: environment.name }] }],
    packageEvidence: { manifest, manifestSha256: digest(manifest), packageSha256: "b".repeat(64) },
  });
}

test("publisher binds observed explicit approval to exact package, source, identity and transition", () => {
  const f = fixture();
  const request = approvedInstallationRequest(f);
  assert.equal(request.operation, "AUTHORIZE");
  assert.equal(request.authorization.sourceSha, f.sourceSha);
  assert.equal(request.authorization.brokerPackageSha256, f.packageEvidence.packageSha256);
  assert.equal(request.authorization.brokerManifestSha256, f.packageEvidence.manifestSha256);
  assert.equal(Date.parse(request.authorization.expiresAt) - f.now, 1800000);
  assert.equal(request.authorization.approvalObservedAt, new Date(f.now).toISOString());
});

for (const [name, mutate] of Object.entries({
  "source movement": (f) => { f.main.commit.sha = "c".repeat(40); },
  "unprotected main": (f) => { f.main.protected = false; },
  "wrong run source": (f) => { f.run.head_sha = "c".repeat(40); },
  "wrong repository ID": (f) => { f.run.repository.id++; },
  "fork source": (f) => { f.run.head_repository.id++; },
  "different workflow": (f) => { f.run.path = ".github/workflows/other.yml"; },
  "rerun": (f) => { f.run.run_attempt++; },
  "different run": (f) => { f.run.id++; },
  "wrong actor": (f) => { f.run.actor.id++; },
  "wrong triggering actor": (f) => { f.run.triggering_actor.login = "different"; },
  "missing approval": (f) => { f.approvals = []; },
  "wrong reviewer": (f) => { f.approvals[0].user.id++; },
  "wrong approved environment": (f) => { f.approvals[0].environments[0].id++; },
  "self review prevented": (f) => { f.environment.protection_rules[0].prevent_self_review = true; },
  "admin bypass": (f) => { f.environment.can_admins_bypass = true; },
  "wildcard branch": (f) => { f.branches.branch_policies[0].name = "*"; },
  "manifest substitution": (f) => { f.packageEvidence.manifest.sourceSha = "c".repeat(40); },
  "manifest hash substitution": (f) => { f.packageEvidence.manifestSha256 = "c".repeat(64); },
  "malformed package hash": (f) => { f.packageEvidence.packageSha256 = "invalid"; },
  "invalid transition": (f) => { f.transitionId = "other"; },
})) test(`publisher rejects ${name}`, () => {
  const f = fixture(); mutate(f); assert.throws(() => approvedInstallationRequest(f));
});

test("reusable publisher approval and preparation precede OIDC; only exact broker authorization may be invoked", () => {
  const file = ".github/workflows/component-iam-authorization-publisher.yml";
  const source = fs.readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
  const workflow = yaml.load(source);
  assert.deepEqual(Object.keys(workflow.on), ["workflow_call"]);
  const job = workflow.jobs.publish;
  assert.equal(job.environment, installationIdentity.authorizationEnvironment);
  assert.match(job.if, /github.ref == 'refs\/heads\/main'/);
  const credentials = job.steps.findIndex((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@"));
  assert(credentials > job.steps.findIndex((step) => step.run?.includes("authorization-publisher.mjs prepare")));
  assert.equal(job.steps[credentials].with["role-duration-seconds"], 900);
  assert.match(source, /component-iam-installer:3/);
  assert.doesNotMatch(source, /lambda (create|update|delete)|iam |terraform |pull_request_target/);
  const authorizer = componentSessionIdentities()[2];
  assert.equal(authorizer.trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"], `${installationIdentity.repository}/${file}@refs/heads/main`);
  assert.equal(authorizer.trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:actor_id"], "183396573");
});

test("actual publisher CLI rejects unsupported commands before acquiring credentials or building a package", () => {
  for (const mode of ["apply", "publish", "prepare --policy", ""]) {
    const child = spawnSync(process.execPath, [new URL("../aws/component-iam-authorization-publisher.mjs", import.meta.url).pathname, ...mode.split(" ").filter(Boolean)], { env: {}, encoding: "utf8" });
    assert.equal(child.status, 1);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr.trim(), "Component installation authorization preparation rejected.");
  }
});
