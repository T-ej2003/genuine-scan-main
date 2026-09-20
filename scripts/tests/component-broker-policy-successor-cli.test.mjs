import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { run } from "../aws/component-broker-policy-successor-cli.mjs";

test("successor CLI authenticates approval before root/MFA and exposes no target input", async () => {
  const calls = [], sourceSha = "a".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc", packageEvidence = { manifest: { sourceSha }, bytes: Buffer.from("x") };
  const dependencies = {
    source: () => sourceSha, build: async () => { calls.push("build"); return packageEvidence; },
    authorize: input => { calls.push("authorize"); assert.deepEqual(input, { runId: "456", transitionId, sourceSha }); return { authorizationSha256: "b".repeat(64), transitionId }; },
    admin: async () => { calls.push("admin"); return { issuanceEvents: async () => [], authenticate: async () => {}, close: () => calls.push("close") }; },
    human: async binding => { calls.push("human"); assert.equal(binding.purpose, "BROKER_POLICY_SUCCESSOR"); return {}; },
    execute: async () => { calls.push("execute"); return { brokerPolicySuccessor: { state: "BROKER_POLICY_SUCCESSOR_CLOSED" } }; },
  };
  assert.equal((await run(["execute", "456", transitionId], dependencies)).state, "BROKER_POLICY_SUCCESSOR_CLOSED"); assert.deepEqual(calls, ["build", "authorize", "admin", "human", "execute", "close"]);
  calls.length = 0; dependencies.authorize = () => { calls.push("authorize"); throw new Error("denied"); };
  await assert.rejects(run(["execute", "456", transitionId], dependencies), /denied/); assert.deepEqual(calls, ["build", "authorize"]);
});

for (const argv of [[], ["execute"], ["execute", "456", "bad"], ["execute", "456", "12345678-1234-4234-8234-123456789abc", "role"]]) test(`actual successor CLI rejects unsupported surface ${JSON.stringify(argv)}`, () => {
  assert.throws(() => execFileSync(process.execPath, [new URL("../aws/component-broker-policy-successor-cli.mjs", import.meta.url), ...argv], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
});
