import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { run } from "../aws/component-bootstrap-partial-recovery-cli.mjs";

const sourceSha = "b".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc", authorizationSha256 = "a".repeat(64);
function fixture() {
  const calls = [], packageEvidence = { manifest: { sourceSha } };
  return { calls, run: () => run(["execute", "456", transitionId], {
    source: () => sourceSha, build: async () => packageEvidence,
    authorize: input => { calls.push(["authorize", input]); return { authorizationSha256, sourceSha, transitionId: input.transitionId }; },
    admin: async () => { calls.push(["admin"]); return { issuanceEvents: async () => [], authenticate: async () => {}, close: () => calls.push(["close"]) }; },
    human: async binding => { calls.push(["human", binding]); return { proof: true }; },
    execute: async (input, dependencies) => { calls.push(["execute", input, typeof dependencies.authenticate]); return { state: "BOOTSTRAP_CLOSED" }; },
  }) };
}

test("recovery CLI authenticates approval before admin/MFA and exposes no target or package input", async () => {
  const f = fixture(), result = await f.run(); assert.equal(result.state, "BOOTSTRAP_CLOSED");
  assert.deepEqual(f.calls.map(([name]) => name), ["authorize", "admin", "human", "execute", "close"]);
  assert.deepEqual(f.calls[2][1], { sourceSha, transitionId, authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" });
});

for (const argv of [[], ["execute"], ["recover", "456", transitionId], ["execute", "456", transitionId, "package.zip"], ["execute", "456", "bad"]]) {
  test(`recovery CLI rejects unsupported surface ${JSON.stringify(argv)}`, async () => { const f = fixture(); await assert.rejects(() => run(argv, { source: () => sourceSha })); assert.deepEqual(f.calls, []); });
}

test("actual recovery CLI fails closed without printing credentials or incident data", () => {
  const file = fileURLToPath(new URL("../aws/component-bootstrap-partial-recovery-cli.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [file], { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" });
  assert.equal(result.status, 1); assert.equal(result.stdout, ""); assert.equal(result.stderr, "Component bootstrap recovery rejected; preserve the durable journal and reconcile exact live targets.\n");
});
