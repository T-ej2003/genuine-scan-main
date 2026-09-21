import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { assertBrokerRecoverySuccessorIamRequest, run } from "../aws/component-broker-recovery-successor-cli.mjs";
import { brokerRecoverySuccessorManagedIdentities } from "../aws/component-installation-identity-contract.mjs";
import { canonical } from "../aws/component-iam-installation-contract.mjs";

test("recovery successor root adapter permits only the five exact successor policy writes", () => {
  const identities = brokerRecoverySuccessorManagedIdentities();
  const writable = identities.filter(({ role }) => ["mscqr-production-component-iam-provisioner", "mscqr-production-component-table-installer", "mscqr-production-component-installation-session", "mscqr-production-component-cleanup-session", "mscqr-production-component-installation-authorizer"].includes(role));
  assert.equal(writable.length, 5);
  for (const identity of writable) assert.doesNotThrow(() => assertBrokerRecoverySuccessorIamRequest("PutRolePolicy", { RoleName: identity.role, PolicyName: identity.policyName, PolicyDocument: canonical(identity.policy) }));
  assert.throws(() => assertBrokerRecoverySuccessorIamRequest("PutRolePolicy", { RoleName: "other", PolicyName: identities[0].policyName, PolicyDocument: canonical(identities[0].policy) }));
});

test("recovery successor CLI authenticates approval before root/MFA and always closes local credentials", async () => {
  const calls = [], sourceSha = "a".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc", packageEvidence = { manifest: { sourceSha }, bytes: Buffer.from("x") };
  const dependencies = {
    source: () => sourceSha, build: async () => { calls.push("build"); return packageEvidence; },
    authorize: input => { calls.push("authorize"); assert.deepEqual(input, { runId: "456", transitionId, sourceSha }); return { authorizationSha256: "b".repeat(64), transitionId }; },
    admin: async () => { calls.push("admin"); return { issuanceEvents: async () => [], authenticate: async () => {}, close: () => calls.push("close") }; },
    human: async binding => { calls.push("human"); assert.equal(binding.purpose, "BROKER_RECOVERY_SUCCESSOR"); return {}; },
    execute: async () => { calls.push("execute"); return { brokerRecoverySuccessor: { state: "BROKER_RECOVERY_SUCCESSOR_CLOSED" } }; },
  };
  assert.equal((await run(["execute", "456", transitionId], dependencies)).state, "BROKER_RECOVERY_SUCCESSOR_CLOSED");
  assert.deepEqual(calls, ["build", "authorize", "admin", "human", "execute", "close"]);
  calls.length = 0; dependencies.authorize = () => { calls.push("authorize"); throw new Error("denied"); };
  await assert.rejects(run(["execute", "456", transitionId], dependencies), /denied/); assert.deepEqual(calls, ["build", "authorize"]);
  dependencies.authorize = input => { calls.push("authorize"); return { authorizationSha256: "b".repeat(64), transitionId: input.transitionId }; };
  calls.length = 0; dependencies.execute = async () => { calls.push("execute"); throw new Error("execution denied"); };
  await assert.rejects(run(["execute", "456", transitionId], dependencies), /execution denied/); assert.equal(calls.at(-1), "close");
});

for (const argv of [[], ["execute"], ["execute", "456", "bad"], ["execute", "456", "12345678-1234-4234-8234-123456789abc", "extra"]]) test(`actual recovery-successor CLI rejects unsupported surface ${JSON.stringify(argv)}`, () => {
  assert.throws(() => execFileSync(process.execPath, [new URL("../aws/component-broker-recovery-successor-cli.mjs", import.meta.url), ...argv], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
});
