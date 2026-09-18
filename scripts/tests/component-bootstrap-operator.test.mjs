import test from "node:test";
import assert from "node:assert/strict";
import { authenticateBootstrapOperator } from "../aws/component-bootstrap-operator.mjs";

const account = "368992683803", operator = `arn:aws:iam::${account}:user/mscqr-production-bootstrap-operator`;
const binding = { sourceSha: "a".repeat(40), authorizationSha256: "b".repeat(64), transitionId: "12345678-1234-4234-8234-123456789abc", purpose: "IDENTITY_BOOTSTRAP" };
const start = Date.parse("2026-09-18T12:00:00Z");
function fixture() {
  const principal = `arn:aws:sts::${account}:assumed-role/mscqr-production-release-deployer/component-${binding.transitionId}`;
  const key = ["A", "S", "I", "A"].join("") + "0".repeat(16);
  const f = { calls: [], clock: start + 1000, identity: { Account: account, Arn: operator }, missing: false, closed: 0 };
  const base = { AccessKeyId: "base-fixture", SecretAccessKey: "base-placeholder" };
  const human = { AccessKeyId: "human-fixture", SecretAccessKey: "human-placeholder", SessionToken: "human-session-placeholder" };
  const scoped = { AccessKeyId: key, SecretAccessKey: "role-placeholder", SessionToken: "role-session-placeholder", Expiration: new Date(start + 900000) };
  f.event = { eventID: "12345678-1234-4234-8234-123456789def", eventTime: new Date(start).toISOString(), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "eu-west-2", recipientAccountId: account,
    userIdentity: { type: "IAMUser", arn: operator, accountId: account, sessionContext: { attributes: { mfaAuthenticated: "true" } } },
    requestParameters: { roleArn: `arn:aws:iam::${account}:role/mscqr-production-release-deployer`, roleSessionName: `component-${binding.transitionId}`, durationSeconds: 900 },
    responseElements: { credentials: { accessKeyId: key, expiration: scoped.Expiration.toISOString() }, assumedRoleUser: { arn: principal, assumedRoleId: "role:session" } } };
  f.base = base; f.secrets = [base, human, scoped];
  f.run = () => authenticateBootstrapOperator(binding, {
    load: async () => base, mfa: async () => "123456", now: () => f.clock, sleep: async ms => { f.clock += ms; },
    issuanceEvents: async () => f.missing ? [] : [f.event], verify: async () => ({ Account: account, Arn: principal, UserId: "role:session" }),
    sts: value => ({ close: () => { f.closed++; }, send: async (operation, input) => {
      f.calls.push({ operation, input });
      if (operation === "GetCallerIdentity") return value === base ? f.identity : { Account: account, Arn: principal, UserId: "role:session" };
      if (operation === "GetSessionToken") { assert.equal(value, base); assert.equal(input.DurationSeconds, 900); assert.equal(input.SerialNumber, `arn:aws:iam::${account}:mfa/mscqr-production-bootstrap-operator`); return { Credentials: human }; }
      assert.equal(operation, "AssumeRole"); assert.equal(value, human);
      assert.deepEqual(input, { RoleArn: `arn:aws:iam::${account}:role/mscqr-production-release-deployer`, RoleSessionName: `component-${binding.transitionId}`, DurationSeconds: 900 });
      return { Credentials: scoped, AssumedRoleUser: { Arn: principal, AssumedRoleId: "role:session" } };
    } }),
  });
  return f;
}
test("first bootstrap obtains only existing human MFA release proof, never root session or mutation credentials", async () => {
  const f = fixture(), evidence = await f.run();
  assert.equal(evidence.purpose, "IDENTITY_BOOTSTRAP"); assert.equal(evidence.mfaAuthenticated, true);
  assert.equal(evidence.operatorArn, operator); assert.equal(evidence.issuanceEventId, f.event.eventID);
  assert.equal(f.closed, 3);
  for (const value of f.secrets) for (const key of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) assert.equal(value[key], undefined);
  for (const key of ["AccessKeyId", "SecretAccessKey", "SessionToken", "TokenCode"]) assert(!JSON.stringify(evidence).includes(key));
});
for (const arn of [`arn:aws:iam::${account}:root`, `arn:aws:sts::${account}:assumed-role/mscqr-production-release-deployer/other`, `arn:aws:iam::${account}:user/other`]) test(`bootstrap MFA rejects alternate principal ${arn} before MFA/STS issuance`, async () => {
  const f = fixture(); f.identity.Arn = arn;
  await assert.rejects(f.run()); assert.deepEqual(f.calls.map(value => value.operation), ["GetCallerIdentity"]);
});
for (const mutate of [event => { event.userIdentity.sessionContext.attributes.mfaAuthenticated = "false"; }, event => { event.eventName = "AssumeRoleWithWebIdentity"; }, event => { event.requestParameters.durationSeconds = 3600; }, event => { event.responseElements.credentials.expiration = "2099-01-01T00:00:00Z"; }]) test("bootstrap rejects unauthenticated or overlong issuance after bounded read-only polling", async () => {
  const f = fixture(); mutate(f.event); await assert.rejects(f.run(), /evidence unavailable/);
  assert.equal(f.calls.filter(value => value.operation === "AssumeRole").length, 1);
});
test("existing user token is not accepted as fresh bootstrap MFA", async () => {
  const f = fixture(); f.base.SessionToken = "old-token-fixture";
  await assert.rejects(f.run(), /fresh interactive MFA/);
  assert.equal(f.calls.length, 1);
});
test("missing CloudTrail proof never falls back to ARN-only provenance", async () => {
  const f = fixture(); f.missing = true; await assert.rejects(f.run(), /evidence unavailable/);
  assert.equal(f.calls.filter(value => value.operation === "GetSessionToken").length, 1);
});
