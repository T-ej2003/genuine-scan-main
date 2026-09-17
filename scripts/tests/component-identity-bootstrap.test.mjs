import test from "node:test";
import assert from "node:assert/strict";
import { executeIdentityBootstrap } from "../aws/component-identity-bootstrap.mjs";
import { bootstrapSourceBindings } from "../aws/component-identity-bootstrap-authorization.mjs";
import { bootstrapManagedIdentities, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { canonical } from "../aws/component-iam-installation-contract.mjs";
import { fixture as brokerFixture } from "./helpers/component-bootstrap-fixture.mjs";

function fixture() {
  const f = brokerFixture();
  const now = Date.parse("2026-09-17T12:00:00Z");
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const authorization = { schemaVersion: 1, transitionType: identityBootstrap.transitionType, account: identityBootstrap.account, region: identityBootstrap.region,
    ...bootstrapSourceBindings(f.packageEvidence), transitionId: "12345678-1234-4234-8234-123456789abc", runId: "123", environment: identityBootstrap.environment,
    operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  f.roles = new Map(); f.iamWrites = []; f.s3Writes = []; f.afterIam = () => {}; f.afterS3 = () => {}; f.beforeIam = () => {}; f.clock = now;
  const targets = bootstrapManagedIdentities();
  const iam = async (operation, input) => {
    const target = targets.find(value => value.role === input.RoleName); assert(target);
    const live = f.roles.get(input.RoleName);
    if (operation === "CreateRole") {
      f.beforeIam(operation);
      assert.equal(live, undefined);
      assert.deepEqual(input, { RoleName: target.role, Path: target.path, MaxSessionDuration: target.maxSessionDuration,
        AssumeRolePolicyDocument: canonical(target.trust), Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })) });
      f.roles.set(target.role, { RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration, AssumeRolePolicyDocument: target.trust });
    } else if (operation === "PutRolePolicy") {
      f.beforeIam(operation);
      assert(live); assert.equal(live.policy, undefined);
      assert.deepEqual(input, { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) });
      live.policy = target.policy;
    } else {
      if (!live) throw Object.assign(new Error("absent"), { name: "NoSuchEntity" });
      const result = {
        GetRole: { Role: live }, ListRolePolicies: { PolicyNames: live.policy ? [target.policyName] : [], IsTruncated: false },
        ListAttachedRolePolicies: { AttachedPolicies: [], IsTruncated: false },
        ListRoleTags: { Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })), IsTruncated: false },
        GetRolePolicy: { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: live.policy },
      }[operation]; assert(result); return result;
    }
    f.iamWrites.push(operation); f.afterIam(operation, f.iamWrites.length); return {};
  };
  const s3 = async (operation, input) => {
    assert.equal(input.Bucket, identityBootstrap.bucket);
    assert.equal(input.Key || input.Prefix, `${identityBootstrap.prefix}identity-bootstrap.json`);
    if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: f.record ? [{ Key: input.Prefix }] : [] };
    if (operation === "GetObject") { assert(f.record); return { ETag: String(f.s3Writes.length), Body: { transformToString: async () => JSON.stringify(f.record) } }; }
    assert.equal(operation, "PutObject"); assert.equal(input.ServerSideEncryption, "AES256");
    if (input.IfNoneMatch === "*" && f.record || input.IfMatch && input.IfMatch !== String(f.s3Writes.length)) throw Object.assign(new Error("CAS"), { name: "PreconditionFailed" });
    assert(input.IfNoneMatch === "*" || input.IfMatch);
    f.record = JSON.parse(input.Body); f.s3Writes.push(f.record.state); f.afterS3(f.s3Writes.length); return {};
  };
  f.execute = () => executeIdentityBootstrap({ authorization, packageEvidence: f.packageEvidence }, { iam, lambda: f.lambda, s3, authenticate: async () => f.guard(), now: () => f.clock, sleep: async () => {} });
  return f;
}

test("first-bootstrap transaction reserves, creates exact five identities and broker, verifies and closes", async () => {
  const f = fixture(), closed = await f.execute();
  assert.equal(closed.state, "BOOTSTRAP_CLOSED");
  assert.equal(f.iamWrites.length, 10); assert.equal(f.writes.length, 8);
  assert.deepEqual(f.s3Writes, ["BOOTSTRAP_EXECUTING", "BOOTSTRAP_CLOSED"]);
  assert.equal(closed.identities.length, 5);
  await assert.rejects(f.execute(), /already reserved or closed/);
  assert.equal(f.iamWrites.length, 10); assert.equal(f.writes.length, 8);
});
for (let boundary = 1; boundary <= 10; boundary++) test(`accepted IAM write ${boundary} with lost response is read back, not repeated`, async () => {
  const f = fixture(); f.afterIam = (_op, count) => { if (count === boundary) throw new Error("timeout"); };
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED");
  assert.equal(f.iamWrites.length, 10);
});
for (let boundary = 1; boundary <= 2; boundary++) test(`accepted journal write ${boundary} with lost response is authenticated by exact readback`, async () => {
  const f = fixture(); f.afterS3 = count => { if (count === boundary) throw new Error("timeout"); };
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED"); assert.equal(f.s3Writes.length, 2);
});
test("two simultaneous first bootstraps have one reservation winner", async () => {
  const f = fixture(); const results = await Promise.allSettled([f.execute(), f.execute()]);
  assert.equal(results.filter(value => value.status === "fulfilled").length, 1);
  assert.equal(results.filter(value => value.status === "rejected").length, 1);
  assert.equal(f.iamWrites.length, 10); assert.equal(f.writes.length, 8);
});
test("missing authority fails before reservation or IAM", async () => {
  const f = fixture(); f.guard = () => { throw new Error("MFA or source proof failed"); };
  await assert.rejects(f.execute());
  assert.deepEqual(f.s3Writes, []); assert.deepEqual(f.iamWrites, []);
});
test("failed-before-acceptance IAM write retains reservation without blind retry or age takeover", async () => {
  const f = fixture(); f.beforeIam = () => { throw new Error("not accepted"); };
  await assert.rejects(f.execute());
  assert.deepEqual(f.iamWrites, []); assert.equal(f.record.state, "BOOTSTRAP_EXECUTING");
  f.beforeIam = () => {}; await assert.rejects(f.execute(), /already reserved/);
  assert.deepEqual(f.iamWrites, []);
});
for (let boundary = 1; boundary <= 8; boundary++) test(`broker crash after write ${boundary} retains durable incomplete bootstrap`, async () => {
  const f = fixture(); f.after = (_op, count) => { if (count === boundary) throw new Error("crash"); };
  await assert.rejects(f.execute());
  assert.equal(f.record.state, "BOOTSTRAP_EXECUTING");
  assert.equal(f.iamWrites.length, 10); assert.equal(f.writes.length, boundary);
  f.after = () => {}; await assert.rejects(f.execute(), /already reserved/);
  assert.equal(f.writes.length, boundary);
});
