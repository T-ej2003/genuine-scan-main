import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { run } from "../aws/component-identity-bootstrap-cli.mjs";

const sourceSha = "a".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc", authorizationSha256 = "b".repeat(64);
const args = ["execute", "123", transitionId];
function fixture() {
  const calls = [], f = { sourceSha, rejectApproval: false, failExecution: false };
  const packageEvidence = { manifest: { sourceSha } };
  const authorization = { sourceSha, transitionId, runId: "123" };
  const operatorProof = { purpose: "IDENTITY_BOOTSTRAP", authorizationSha256 };
  f.run = () => run(args, {
    source: () => { calls.push("source"); return f.sourceSha; },
    build: async () => { calls.push("build"); return packageEvidence; },
    authorize: (input, bundle) => { calls.push("approval"); assert.deepEqual(input, { sourceSha, transitionId, runId: "123" }); assert.equal(bundle, packageEvidence); if (f.rejectApproval) throw new Error("missing approval"); return { ...authorization, authorizationSha256 }; },
    admin: async () => { calls.push("admin"); return { issuanceEvents: async () => [], authenticate: async () => { calls.push("admin-identity"); }, close: () => { calls.push("close-admin"); } }; },
    human: async binding => { calls.push("MFA"); assert.deepEqual(binding, { sourceSha, transitionId, authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" }); if (f.moveSource) f.sourceSha = "c".repeat(40); return operatorProof; },
    execute: async (input, authority) => {
      calls.push("transaction"); assert.deepEqual(input, { authorization, packageEvidence, operatorProof });
      await authority.authenticate();
      if (f.failExecution) throw new Error("ambiguous write");
      calls.push("exact-source-writes"); return { state: "BOOTSTRAP_CLOSED" };
    },
  });
  f.calls = calls; return f;
}
test("first-bootstrap approval precedes exceptional credentials and MFA; only non-secret closure is returned", async () => {
  const f = fixture(); assert.deepEqual(await f.run(), { state: "BOOTSTRAP_CLOSED", sourceSha, transitionId, authorizationSha256 });
  assert.deepEqual(f.calls, ["source", "build", "approval", "source", "admin", "MFA", "transaction", "source", "admin-identity", "exact-source-writes", "close-admin"]);
});
test("missing approval never loads administrator or human credentials", async () => {
  const f = fixture(); f.rejectApproval = true; await assert.rejects(f.run(), /missing approval/);
  assert.deepEqual(f.calls, ["source", "build", "approval"]);
});
test("protected source movement closes the exceptional adapter before any mutation", async () => {
  const f = fixture(); f.moveSource = true; await assert.rejects(f.run(), /Protected main moved/);
  assert(!f.calls.includes("exact-source-writes")); assert.equal(f.calls.at(-1), "close-admin");
});
test("ambiguous bootstrap failure closes clients and is not automatically retried", async () => {
  const f = fixture(); f.failExecution = true; await assert.rejects(f.run(), /ambiguous write/);
  assert.equal(f.calls.filter(value => value === "transaction").length, 1); assert.equal(f.calls.at(-1), "close-admin");
});
for (const argv of [[], ["prepare"], ["execute"], ["execute", "../run", transitionId], ["execute", "123", "../transition"], [...args, "--policy", "arbitrary.json"], ["put-role-policy", "release", "document"], ["recover", "123", transitionId]]) {
  test(`actual bootstrap CLI rejects unsupported input before source/credentials: ${JSON.stringify(argv)}`, () => {
    const result = spawnSync(process.execPath, ["scripts/aws/component-identity-bootstrap-cli.mjs", ...argv], { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: 15000 });
    assert.equal(result.status, 1); assert.equal(result.stdout, "");
    assert.equal(result.stderr, "Identity bootstrap rejected; preserve its durable reservation and reconcile exact live targets.\n");
  });
}
