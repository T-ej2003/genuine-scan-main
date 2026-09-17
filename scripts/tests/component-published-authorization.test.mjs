import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { authenticatePublishedComponentAuthorization, authenticateIdentityBootstrapPublication, componentIamAuthorization as installationContract } from "../aws/component-iam-authorization.mjs";
import { approveIdentityBootstrap, bootstrapAuthorizationContract } from "../aws/component-identity-bootstrap-authorization.mjs";
import { identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { approvedInstallationRequest } from "../aws/component-iam-authorization-publisher.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";

const now = Date.parse("2026-09-17T12:05:00Z");
const input = { sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", runId: "1234" };
const actor = { type: "User", login: "T-ej2003", id: 183396573 };
function fixture(change = () => {}, bootstrap = false) {
  const contract = bootstrap ? { ...installationContract, workflow: bootstrapAuthorizationContract.workflow, environment: identityBootstrap.environment } : installationContract;
  const manifest = componentBrokerPackageManifest(input.sourceSha);
  const main = { name: "main", protected: true, commit: { sha: input.sourceSha } };
  const repository = { id: 1145608538, full_name: contract.repository };
  const run = { id: 1234, repository, head_repository: { ...repository }, head_sha: input.sourceSha, head_branch: "main", path: contract.workflow,
    event: "workflow_dispatch", status: "in_progress", run_attempt: 1, actor, triggering_actor: actor, created_at: "2026-09-17T12:00:00Z", updated_at: "2026-09-17T12:04:00Z" };
  const environment = { id: 91, name: contract.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
    protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] };
  const branches = { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] };
  const approvals = [{ state: "approved", user: actor, environments: [{ id: 91, name: contract.environment }] }];
  const packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256: "b".repeat(64) };
  const request = (bootstrap ? approveIdentityBootstrap : approvedInstallationRequest)({ ...input, main, run, environment, branches, approvals,
    packageEvidence, now: now - 120000 });
  Object.assign(run, { status: "completed", conclusion: "success" });
  const files = bootstrap ? { [bootstrapAuthorizationContract.file]: request } : { "component-installation-invocation.json": { StatusCode: 200, ExecutedVersion: "3" }, "component-installation-request.json": request,
    "component-installation-result.json": { authorizationSha256: digest(request.authorization) } };
  const f = { main, run, environment, branches, approvals, files, calls: [], now };
  change(f);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "component-published-test-"));
  let archive;
  try {
    for (const [name, value] of Object.entries(files)) fs.writeFileSync(path.join(directory, name), JSON.stringify(value));
    execFileSync("/usr/bin/zip", ["-q", "archive.zip", ...Object.keys(files)], { cwd: directory });
    archive = fs.readFileSync(path.join(directory, "archive.zip"));
  } finally { fs.rmSync(directory, { recursive: true }); }
  const artifact = { id: 55, name: bootstrap ? bootstrapAuthorizationContract.artifact : "component-installation-authorization-audit", expired: false, size_in_bytes: archive.length,
    digest: `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}`, workflow_run: { id: 1234, head_sha: input.sourceSha, repository_id: 1145608538 }, ...f.artifact };
  const authenticate = bootstrap ? (value, deps) => authenticateIdentityBootstrapPublication(value, packageEvidence, deps) : authenticatePublishedComponentAuthorization;
  f.authenticate = () => authenticate(input, { now: () => f.now, env: {}, execute: (_cmd, args) => {
    const suffix = args[3].slice(`repos/${contract.repository}/`.length); f.calls.push(suffix);
    if (suffix === "actions/artifacts/55/zip") return archive;
    const values = { "branches/main": f.main, "actions/runs/1234": f.run, [`environments/${contract.environment}`]: f.environment,
      [`environments/${contract.environment}/deployment-branch-policies`]: f.branches, "actions/runs/1234/approvals": f.approvals, "actions/runs/1234/artifacts": [{ artifacts: [artifact] }] };
    assert(Object.hasOwn(values, suffix)); return JSON.stringify(values[suffix]);
  } });
  return f;
}
test("actual publisher audit archive authenticates before operator session issuance", () => {
  const f = fixture();
  assert.equal(f.authenticate().authorizationSha256, f.files["component-installation-result.json"].authorizationSha256);
  assert.equal(f.calls.filter(name => name === "branches/main").length, 2);
});
const invalid = {
  "missing approval": f => { f.approvals = []; },
  "different reviewer": f => { f.approvals = [{ ...f.approvals[0], user: { ...actor, id: 1 } }]; },
  "different environment": f => { f.environment.name = "other"; },
  "rerun": f => { f.run.run_attempt = 2; },
  "failed publisher": f => { f.run.conclusion = "failure"; },
  "different source": f => { f.main.commit.sha = "c".repeat(40); },
  "expired authorization": f => { f.now = now + 3600000; },
  "different artifact": f => { f.artifact = { name: "other" }; },
  "forged archive hash": f => { f.artifact = { digest: `sha256:${"d".repeat(64)}` }; },
  "wrong broker version": f => { f.files["component-installation-invocation.json"].ExecutedVersion = "$LATEST"; },
  "broker error": f => { f.files["component-installation-invocation.json"].FunctionError = "Unhandled"; },
  "different archived result": f => { f.files["component-installation-result.json"].authorizationSha256 = "c".repeat(64); },
  "extra archive member": f => { f.files["extra.json"] = {}; },
  "different manifest": f => { f.files["component-installation-request.json"].authorization.brokerManifestSha256 = "c".repeat(64); },
  "approval before run": f => { f.files["component-installation-request.json"].authorization.approvalObservedAt = "2026-09-17T11:59:00.000Z"; },
};
for (const [name, mutate] of Object.entries(invalid)) test(`publisher audit rejects ${name}`, () => assert.throws(fixture(mutate).authenticate));

test("bootstrap independently authenticates the dedicated one-file approved GitHub archive", () => {
  const f = fixture(() => {}, true);
  assert.equal(f.authenticate().authorizationSha256, digest(f.files[bootstrapAuthorizationContract.file]));
});
for (const name of ["missing approval", "different reviewer", "different environment", "rerun", "failed publisher", "different source", "expired authorization", "different artifact", "forged archive hash", "extra archive member"]) {
  test(`bootstrap archive rejects ${name}`, () => assert.throws(fixture(invalid[name], true).authenticate));
}
for (const field of ["sourceSha", "transitionId", "runId", "identitySetSha256", "capabilitySetSha256", "documentBindingsSha256", "packageSha256", "manifestSha256", "brokerConfigurations"]) {
  test(`bootstrap archive rejects substitution of ${field}`, () => {
    const f = fixture(value => { value.files[bootstrapAuthorizationContract.file][field] = "different"; }, true);
    assert.throws(f.authenticate);
  });
}
