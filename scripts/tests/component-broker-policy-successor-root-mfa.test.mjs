import assert from "node:assert/strict";
import test from "node:test";
import { convergeRootMfaIssuance } from "../aws/component-broker-policy-successor-cli.mjs";
import { brokerPolicySuccessorRootMfaSource, createBrokerPolicySuccessorRootMfaSession, loadRootSource } from "../aws/component-broker-policy-successor-root-mfa.mjs";

const account = "368992683803", rootArn = `arn:aws:iam::${account}:root`, serial = `arn:aws:iam::${account}:mfa/root-fixture`;
const nowValue = Date.parse("2026-09-20T20:00:00.000Z"), expiration = new Date(nowValue + 3600000).toISOString();
const source = () => ({ credentials: { AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }, serial });

test("root MFA source is one fixed sanitized local profile with a profile-owned device ARN", () => {
  const calls = [], result = loadRootSource((file, args, options) => {
    calls.push({ file, args, env: options.env });
    return args[1] === "export-credentials" ? JSON.stringify({ AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }) : `${serial}\n`;
  });
  assert.equal(result.serial, serial); assert.equal(calls.length, 2);
  for (const call of calls) { assert.equal(call.file, "aws"); assert.equal(call.env.AWS_PROFILE, brokerPolicySuccessorRootMfaSource.profile); assert.equal(call.env.AWS_ACCESS_KEY_ID, undefined); assert.equal(call.env.AWS_SESSION_TOKEN, undefined); }
  assert.deepEqual(calls[0].args, ["configure", "export-credentials", "--format", "process"]);
  assert.deepEqual(calls[1].args, ["configure", "get", "mfa_serial", "--profile", brokerPolicySuccessorRootMfaSource.profile]);
});

function transport({ sourceIdentity = rootArn, sessionIdentity = rootArn, issued = { AccessKeyId: "SESSIONKEY", SecretAccessKey: "session-secret", SessionToken: "session-token", Expiration: expiration } } = {}) {
  const calls = [], closed = [];
  return { calls, closed, create: value => ({
    async send(operation, input) {
      calls.push({ session: Boolean(value.SessionToken), operation, input: structuredClone(input) });
      if (operation === "GetCallerIdentity") return { Account: account, Arn: value.SessionToken ? sessionIdentity : sourceIdentity };
      if (operation === "GetSessionToken") return { Credentials: structuredClone(issued) };
      throw new Error("unexpected operation");
    },
    close() { closed.push(Boolean(value.SessionToken)); },
  }) };
}

test("root MFA helper exchanges only the fixed long-term root profile and hands off an ephemeral session", async () => {
  const wire = transport();
  const session = await createBrokerPolicySuccessorRootMfaSession({ load: source, sts: wire.create, mfa: async () => "123456", now: () => nowValue });
  assert.deepEqual(wire.calls.map(({ operation }) => operation), ["GetCallerIdentity", "GetSessionToken", "GetCallerIdentity"]);
  assert.deepEqual(wire.calls[1].input, { DurationSeconds: brokerPolicySuccessorRootMfaSource.durationSeconds, SerialNumber: serial, TokenCode: "123456" });
  assert.deepEqual(session.credentials, { accessKeyId: "SESSIONKEY", secretAccessKey: "session-secret", sessionToken: "session-token" });
  assert.equal(session.expiresAt, expiration); assert.deepEqual(wire.closed, [false]); session.close();
  assert.deepEqual(session.credentials, {}); assert.deepEqual(wire.closed, [false, true]);
});

test("root MFA helper rejects temporary/login credentials, wrong identities, device ARNs, prompts and lifetimes", async () => {
  const check = (options, pattern) => assert.rejects(() => createBrokerPolicySuccessorRootMfaSession({ load: source, mfa: async () => "123456", now: () => nowValue, ...options }), pattern);
  await check({ load: async () => ({ credentials: { AccessKeyId: "A", SecretAccessKey: "S", SessionToken: "aws-login-token" }, serial }), sts: transport().create }, /Temporary root credentials/);
  await check({ load: async () => ({ credentials: { AccessKeyId: "A", SecretAccessKey: "S", Expiration: expiration }, serial }), sts: transport().create }, /Temporary root credentials/);
  await check({ load: async () => ({ credentials: { AccessKeyId: "A", SecretAccessKey: "S" }, serial: "" }), sts: transport().create }, /MFA device ARN/);
  await check({ load: async () => ({ credentials: { AccessKeyId: "A", SecretAccessKey: "S" }, serial: "arn:aws:iam::111111111111:mfa/root" }), sts: transport().create }, /MFA device ARN/);
  await check({ sts: transport({ sourceIdentity: `arn:aws:iam::${account}:user/not-root` }).create }, /must be account root/);
  await check({ sts: transport({ sessionIdentity: `arn:aws:iam::${account}:user/not-root` }).create }, /not account root/);
  await check({ sts: transport().create, mfa: async () => { throw new Error("sensitive-123456"); } }, error => error.message === "Interactive root MFA entry failed" && !error.message.includes("123456"));
  await check({ sts: transport({ issued: { AccessKeyId: "A", SecretAccessKey: "S", SessionToken: "T", Expiration: new Date(nowValue + 120000).toISOString() } }).create }, /lifetime/);
});

const issuance = ({ accessKeyId = "SESSIONKEY", arn = rootArn, mfa = "true", expires = expiration, errorCode } = {}) => ({ userIdentity: { type: "Root", arn, sessionContext: { attributes: { mfaAuthenticated: mfa } } }, responseElements: { credentials: { accessKeyId, expiration: expires } }, ...(errorCode ? { errorCode } : {}) });

test("root MFA CloudTrail proof converges only on one exact issuance", async () => {
  let clock = nowValue, attempts = 0;
  const event = await convergeRootMfaIssuance({ events: async () => ++attempts === 3 ? [issuance()] : [], accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => clock, sleep: async milliseconds => { clock += milliseconds; } });
  assert.equal(event.responseElements.credentials.accessKeyId, "SESSIONKEY"); assert.equal(attempts, 3);
  const verify = events => convergeRootMfaIssuance({ events: async () => events, accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  await assert.rejects(verify([]), /unavailable/);
  await assert.rejects(verify([issuance(), issuance()]), /Unique/);
  await assert.rejects(verify([issuance({ mfa: "false" })]));
  await assert.rejects(verify([{ ...issuance(), userIdentity: { type: "IAMUser", arn: rootArn, sessionContext: { attributes: { mfaAuthenticated: "true" } } } }]));
  await assert.rejects(verify([issuance({ arn: `arn:aws:iam::${account}:user/not-root` })]));
  await assert.rejects(verify([issuance({ errorCode: "AccessDenied" })]));
  await assert.rejects(verify([issuance({ expires: new Date(nowValue + 3500000).toISOString() })]), /expiration differs/);
  await assert.rejects(verify([issuance({ accessKeyId: "OTHER" })]), /unavailable/);
});
