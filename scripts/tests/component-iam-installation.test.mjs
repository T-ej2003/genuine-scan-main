import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { run } from "../aws/component-iam-installation.mjs";
import { installationDocuments, documentBindings, digest } from "../aws/component-iam-installation-contract.mjs";

const sourceSha = "a".repeat(40);
const transitionId = "12345678-1234-4234-8234-123456789abc";
const approval = { sourceSha, transitionId, runId: "1234", authorizationSha256: "b".repeat(64), documentBindingsSha256: digest(documentBindings()) };
const live = installationDocuments().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }));
function fixture() {
  const calls = [];
  const f = { calls, approval: { ...approval }, receipt: { schemaVersion: 1, sourceSha, transitionId, authorizationSha256: approval.authorizationSha256, documentBindingsSha256: approval.documentBindingsSha256, state: "IAM_VERIFIED", live }, source: sourceSha };
  const invoke = async operation => { calls.push(operation); return operation === "CLOSE" ? { state: "CLOSED", transitionId } : f.receipt; };
  f.deps = {
    source: () => { calls.push("source"); return f.source; },
    authorize: input => { calls.push("approval"); assert.deepEqual(input, { sourceSha, transitionId, runId: "1234" }); if (f.rejectApproval) throw Error("Denied"); return f.approval; },
    installSession: async binding => { calls.push("MFA_INSTALL"); assert.deepEqual(binding, { sourceSha, transitionId, authorizationSha256: approval.authorizationSha256, purpose: "INSTALL" }); return { invoke }; },
    cleanupSession: async id => { calls.push("MFA_CLEANUP_CONTEXT"); assert.equal(id, transitionId); return { invoke }; },
  };
  return f;
}

test("real controller orders approval before MFA and invokes only fixed installation", async () => {
  const f = fixture();
  assert.deepEqual(await run(["install", "1234", transitionId], f.deps), f.receipt);
  assert.deepEqual(f.calls, ["source", "approval", "source", "MFA_INSTALL", "source", "INSTALL"]);
});
test("cleanup needs only the transition and scoped durable-context client, not GitHub artifacts", async () => {
  const f = fixture(); f.rejectApproval = true;
  assert.deepEqual(await run(["close", transitionId], f.deps), { state: "CLOSED", transitionId });
  assert.deepEqual(f.calls, ["source", "MFA_CLEANUP_CONTEXT", "CLOSE"]);
});
test("rejected or substituted approval cannot issue credentials", async () => {
  for (const change of [{ sourceSha: "c".repeat(40) }, { transitionId: "different" }, { runId: "2" }, { documentBindingsSha256: "d".repeat(64) }]) {
    const f = fixture(); Object.assign(f.approval, change);
    await assert.rejects(run(["install", "1234", transitionId], f.deps));
    assert.deepEqual(f.calls, ["source", "approval"]);
  }
  const f = fixture(); f.rejectApproval = true;
  await assert.rejects(run(["install", "1234", transitionId], f.deps));
  assert.deepEqual(f.calls, ["source", "approval"]);
});
test("source movement before issuance or invocation stops installation", async () => {
  for (const at of [2, 3]) {
    const f = fixture(); let n = 0;
    f.deps.source = () => ++n === at ? "d".repeat(40) : sourceSha;
    await assert.rejects(run(["install", "1234", transitionId], f.deps), /Source moved/);
    assert(!f.calls.includes("INSTALL"));
    if (at === 2) assert(!f.calls.includes("MFA_INSTALL"));
  }
});
for (const change of [{ state: "IAM_INSTALLING" }, { authorizationSha256: "c".repeat(64) }, { live: [] }, { credentials: "must-not-be-output" }]) {
  test(`controller rejects mismatched broker result ${Object.keys(change)[0]}`, async () => {
    const f = fixture(); Object.assign(f.receipt, change);
    await assert.rejects(run(["install", "1234", transitionId], f.deps));
  });
}
test("inspect is read-only semantic invocation and validates exact target inventory", async () => {
  const f = fixture();
  assert.equal((await run(["inspect", "1234", transitionId], f.deps)).state, "IAM_VERIFIED");
  assert.equal(f.calls.at(-1), "INSPECT");
  f.receipt.live = [];
  await assert.rejects(run(["inspect", "1234", transitionId], f.deps));
});
test("actual CLI rejects legacy administrator routes and malformed inputs before external execution", () => {
  for (const args of [[], ["activate"], ["recover"], ["renew"], ["prepare-table"], ["apply-table"], ["install", "bad", transitionId], ["install", "1234", transitionId, "override.json"], ["close", "bad"], ["close", transitionId, "local-authorization.json"]]) {
    const result = spawnSync(process.execPath, ["scripts/aws/component-iam-installation.mjs", ...args], { encoding: "utf8", env: { PATH: "/nonexistent", HOME: "/nonexistent", AWS_SECRET_ACCESS_KEY: "disposable-not-to-log" } });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "Component installation rejected; authenticate durable broker evidence before retry.\n");
  }
});
test("supported controller cannot select IAM, broker deployment, root, or local Terraform adapters", () => {
  const source = fs.readFileSync("scripts/aws/component-iam-installation.mjs", "utf8");
  for (const forbidden of ["default\", region", "runTableActivation", "temporaryInstallationPolicies", "CreateRole", "PutRolePolicy", "UpdateFunctionCode", "administrator =", "aws\", ["]) assert(!source.includes(forbidden));
});
