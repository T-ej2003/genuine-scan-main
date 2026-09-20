import assert from "node:assert/strict";
import test from "node:test";
import { convergeRootMfaIssuance, convergeRootMfaSessionProof, lookupCloudTrailEvents } from "../aws/component-broker-policy-successor-cli.mjs";
import { brokerPolicySuccessorRootMfaSource, createBrokerPolicySuccessorRootMfaSession, loadRootSource, rootAwsExecutable } from "../aws/component-broker-policy-successor-root-mfa.mjs";

const account = "368992683803", rootArn = `arn:aws:iam::${account}:root`, serial = `arn:aws:iam::${account}:mfa/root-fixture`;
const nowValue = Date.parse("2026-09-20T20:00:00.000Z"), expiration = new Date(nowValue + 3600000).toISOString();
const source = () => ({ credentials: { AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }, serial });
const canonicalAws = "/usr/local/aws-cli/aws";
const awsInstallation = ({ present = true, resolved = canonicalAws, mode = 0o100755 } = {}) => ({
  existsSync: candidate => present && candidate === "/usr/local/bin/aws",
  realpathSync: () => resolved,
  statSync: () => ({ isFile: () => true, mode }),
});

test("root MFA source pins one canonical absolute CLI before loading the fixed profile", () => {
  const calls = [], result = loadRootSource((file, args, options) => {
    calls.push({ file, args, env: options.env });
    return args[1] === "export-credentials" ? JSON.stringify({ AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }) : `${serial}\n`;
  }, awsInstallation());
  assert.equal(result.serial, serial); assert.equal(calls.length, 2);
  for (const call of calls) { assert.equal(call.file, canonicalAws); assert.equal(call.file.startsWith("/"), true); assert.equal(call.env.AWS_PROFILE, brokerPolicySuccessorRootMfaSource.profile); assert.equal(call.env.AWS_ACCESS_KEY_ID, undefined); assert.equal(call.env.AWS_SESSION_TOKEN, undefined); }
  assert.deepEqual(calls[0].args, ["configure", "export-credentials", "--format", "process"]);
  assert.deepEqual(calls[1].args, ["configure", "get", "mfa_serial", "--profile", brokerPolicySuccessorRootMfaSource.profile]);
});

test("root MFA source cannot be redirected by PATH, cwd, or a caller-selected executable", () => {
  const calls = [], candidates = [], filesystem = awsInstallation();
  const existsSync = filesystem.existsSync;
  filesystem.existsSync = candidate => { candidates.push(candidate); return existsSync(candidate); };
  loadRootSource((file, args, options) => {
    calls.push({ file, shell: options.shell, path: options.env.PATH });
    return args[1] === "export-credentials" ? JSON.stringify({ AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }) : `${serial}\n`;
  }, filesystem, { HOME: "/tmp/operator", PATH: "/tmp/attacker-cwd:/tmp/attacker-bin" });
  assert.deepEqual(calls.map(({ file }) => file), [canonicalAws, canonicalAws]);
  assert.equal(calls.every(({ path }) => path === "/tmp/attacker-cwd:/tmp/attacker-bin"), true);
  assert.equal(candidates.every(candidate => candidate.startsWith("/")), true);
  assert.equal(calls.every(({ shell }) => shell === undefined), true);
  assert.throws(() => rootAwsExecutable(awsInstallation({ resolved: "/tmp/attacker/aws" })), /outside canonical safelist/);
});

test("root MFA source fails closed before profile loading when no canonical safe CLI exists", () => {
  let executions = 0;
  assert.throws(() => loadRootSource(() => { executions += 1; }, awsInstallation({ present: false })), error => error.message === "No safelisted AWS CLI installation found");
  assert.equal(executions, 0);
  for (const unsafe of [{ resolved: "/tmp/aws" }, { mode: 0o100777 }]) assert.throws(() => rootAwsExecutable(awsInstallation(unsafe)), /(?:outside canonical safelist|Unsafe AWS executable)/);
});

test("root source failures redact CLI output and clear credentials already loaded", () => {
  const sensitive = "sensitive-root-material";
  assert.throws(() => loadRootSource(() => { throw new Error(sensitive); }, awsInstallation()), error => error.message === "Long-term root credential source is unavailable" && !error.message.includes(sensitive));
  assert.throws(() => loadRootSource((_file, args) => args[1] === "export-credentials" ? JSON.stringify({ AccessKeyId: sensitive, SecretAccessKey: sensitive }) : (() => { throw new Error(sensitive); })(), awsInstallation()), error => error.message === "Root MFA device configuration is unavailable" && !error.message.includes(sensitive));
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
  assert.deepEqual({ expiresAt: session.expiresAt, mfaSerial: session.mfaSerial, durationSeconds: session.durationSeconds }, { expiresAt: expiration, mfaSerial: serial, durationSeconds: 3600 });
  assert.equal(JSON.stringify(session).includes("123456"), false); assert.deepEqual(wire.closed, [false]); session.close();
  assert.deepEqual(session.credentials, {}); assert.deepEqual(wire.closed, [false, true]);
});

test("root MFA failure clears long-term and returned credentials without exposing the MFA code", async () => {
  const base = { AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }, issued = { AccessKeyId: "SESSIONKEY", SecretAccessKey: "session-secret", SessionToken: "session-token", Expiration: expiration }, closed = [];
  await assert.rejects(createBrokerPolicySuccessorRootMfaSession({ load: async () => ({ credentials: base, serial }), mfa: async () => "123456", now: () => nowValue, sts: value => ({
    close: () => closed.push(Boolean(value.SessionToken)), async send(operation) { if (operation === "GetSessionToken") return { Credentials: issued }; if (value.SessionToken) throw new Error("returned identity rejected"); return { Account: account, Arn: rootArn }; },
  }) }), error => !error.message.includes("123456") && !error.message.includes("session-secret"));
  assert.deepEqual(base, {}); assert.deepEqual(issued, { Expiration: expiration }); assert.deepEqual(closed, [false, true]);
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
  await check({ load: async () => null, sts: transport().create }, /credential source/);
  await check({ sts: transport({ issued: null }).create }, /issuance failed/);
  await check({ sts: transport({ issued: { AccessKeyId: "A", SecretAccessKey: "S", SessionToken: "T", Expiration: "not-a-date" } }).create }, /lifetime/);
  await check({ sts: transport({ issued: { AccessKeyId: "A", SecretAccessKey: "S", SessionToken: "T", Expiration: new Date(nowValue + 3601001).toISOString() } }).create }, /lifetime/);
  await check({ sts: value => ({ close() {}, async send(operation) { if (operation === "GetCallerIdentity") return { Account: account, Arn: rootArn }; throw new Error("fixture STS rejection"); } }) }, /fixture STS rejection/);
});

const issuance = ({ accessKeyId = "SESSIONKEY", arn = rootArn, accountId = account, serialNumber = serial, durationSeconds = 3600, mfa, expires = expiration, errorCode } = {}) => ({
  eventSource: "sts.amazonaws.com", eventName: "GetSessionToken", awsRegion: "eu-west-2",
  userIdentity: { type: "Root", accountId, arn, ...(mfa === undefined ? {} : { sessionContext: { attributes: { mfaAuthenticated: mfa } } }) },
  requestParameters: { serialNumber, durationSeconds }, responseElements: { credentials: { accessKeyId, expiration: expires } }, ...(errorCode ? { errorCode } : {}) });
const sessionProof = ({ accessKeyId = "SESSIONKEY", arn = rootArn, accountId = account, mfa = "true", errorCode } = {}) => ({
  eventSource: "sts.amazonaws.com", eventName: "GetCallerIdentity", awsRegion: "eu-west-2",
  userIdentity: { type: "Root", accountId, arn, accessKeyId, sessionContext: { attributes: { mfaAuthenticated: mfa } } }, ...(errorCode ? { errorCode } : {}) });
const issuanceProof = options => convergeRootMfaIssuance({ mfaSerial: serial, durationSeconds: 3600, ...options });
const cloudTrailEntry = event => ({ CloudTrailEvent: JSON.stringify(event) });

test("one CloudTrail pagination chain reuses one lookup window while time advances", async () => {
  let clock = nowValue, page = 0; const requests = [];
  const values = await lookupCloudTrailEvents({ eventName: "GetSessionToken", now: () => clock, lookup: async (_operation, input) => {
    requests.push(input); clock += 30000; page += 1;
    return page === 1 ? { Events: [], NextToken: "page-2" } : { Events: [cloudTrailEntry(issuance())] };
  } });
  assert.equal(values.length, 1); assert.equal(requests.length, 2);
  assert.strictEqual(requests[0].LookupAttributes, requests[1].LookupAttributes);
  assert.strictEqual(requests[0].StartTime, requests[1].StartTime);
  assert.strictEqual(requests[0].EndTime, requests[1].EndTime);
  assert.deepEqual(Object.keys(requests[0]).sort(), ["EndTime", "LookupAttributes", "StartTime"]);
  assert.deepEqual(Object.keys(requests[1]).sort(), ["EndTime", "LookupAttributes", "NextToken", "StartTime"]);
  assert.equal(requests[1].NextToken, "page-2");
  const accepted = await issuanceProof({ events: async () => values, accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  assert.equal(accepted.responseElements.credentials.accessKeyId, "SESSIONKEY");
});

test("a new CloudTrail convergence lookup captures a new window", async () => {
  let clock = nowValue; const requests = [], lookup = async (_operation, input) => { requests.push(input); return { Events: [] }; };
  await lookupCloudTrailEvents({ lookup, eventName: "GetSessionToken", now: () => clock });
  clock += 5000;
  await lookupCloudTrailEvents({ lookup, eventName: "GetSessionToken", now: () => clock });
  assert.equal(requests[1].EndTime.getTime() - requests[0].EndTime.getTime(), 5000);
  assert.equal(requests[1].StartTime.getTime() - requests[0].StartTime.getTime(), 5000);
});

test("root MFA proof accepts an exact issuance on a later valid CloudTrail page", async () => {
  let page = 0;
  const events = eventName => lookupCloudTrailEvents({ eventName, now: () => nowValue, lookup: async () => {
    page += 1; return page < 3 ? { Events: [], NextToken: `page-${page + 1}` } : { Events: [cloudTrailEntry(issuance())] };
  } });
  const event = await issuanceProof({ events, accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  assert.equal(event.responseElements.credentials.accessKeyId, "SESSIONKEY"); assert.equal(page, 3);
});

test("CloudTrail pagination rejects repeated tokens and chains beyond its bound", async () => {
  await assert.rejects(() => lookupCloudTrailEvents({ eventName: "GetSessionToken", lookup: async () => ({ Events: [{ CloudTrailEvent: "not-json" }] }) }));
  await assert.rejects(() => lookupCloudTrailEvents({ eventName: "GetSessionToken", lookup: async () => ({ Events: [], NextToken: "repeat" }) }));
  let page = 0;
  await assert.rejects(() => lookupCloudTrailEvents({ eventName: "GetSessionToken", lookup: async () => ({ Events: [], NextToken: `page-${++page}` }) }));
  assert.equal(page, 21);
});

test("root MFA CloudTrail proof binds one exact issuance without misreading its signing context", async () => {
  let clock = nowValue, attempts = 0;
  const event = await issuanceProof({ events: async () => ++attempts === 3 ? [issuance({ mfa: "false" })] : [], accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => clock, sleep: async milliseconds => { clock += milliseconds; } });
  assert.equal(event.responseElements.credentials.accessKeyId, "SESSIONKEY"); assert.equal(attempts, 3);
  await issuanceProof({ events: async () => [issuance({ mfa: undefined })], accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  const verify = events => issuanceProof({ events: async () => events, accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  await assert.rejects(verify([]), /unavailable/);
  await assert.rejects(verify([issuance(), issuance()]), /Unique/);
  await assert.rejects(verify([{ ...issuance(), userIdentity: { type: "IAMUser", accountId: account, arn: rootArn } }]));
  await assert.rejects(verify([issuance({ arn: `arn:aws:iam::${account}:user/not-root` })]));
  await assert.rejects(verify([issuance({ accountId: "111111111111" })]));
  await assert.rejects(verify([issuance({ serialNumber: `arn:aws:iam::${account}:mfa/other` })]));
  await assert.rejects(verify([issuance({ durationSeconds: 900 })]));
  await assert.rejects(convergeRootMfaIssuance({ events: async () => [issuance()], accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue }), /match/);
  await assert.rejects(verify([issuance({ errorCode: "AccessDenied" })]));
  await assert.rejects(verify([issuance({ expires: new Date(nowValue + 3500000).toISOString() })]), /expiration differs/);
  await assert.rejects(verify([issuance({ accessKeyId: "OTHER" })]), /unavailable/);
});

test("returned root MFA session accepts repeated exact proof events from the same session", async () => {
  let clock = nowValue, attempts = 0;
  const event = await convergeRootMfaSessionProof({ events: async () => ++attempts === 2 ? [sessionProof()] : [], accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => clock, sleep: async milliseconds => { clock += milliseconds; } });
  assert.equal(event.userIdentity.accessKeyId, "SESSIONKEY"); assert.equal(attempts, 2);
  const verify = events => convergeRootMfaSessionProof({ events: async () => events, accessKeyId: "SESSIONKEY", rootExpires: Date.parse(expiration), now: () => nowValue, sleep: async () => {}, maxWaitMs: 1 });
  await assert.rejects(verify([]), /unavailable/);
  assert.equal((await verify([sessionProof(), sessionProof()])).userIdentity.accessKeyId, "SESSIONKEY");
  assert.equal((await verify([sessionProof({ accessKeyId: "OTHER" }), sessionProof(), sessionProof()])).userIdentity.accessKeyId, "SESSIONKEY");
  await assert.rejects(verify([sessionProof({ mfa: "false" })]));
  await assert.rejects(verify([sessionProof(), sessionProof({ mfa: "false" })]));
  await assert.rejects(verify([sessionProof({ accessKeyId: "OTHER" })]), /unavailable/);
  await assert.rejects(verify([sessionProof({ arn: `arn:aws:iam::${account}:user/not-root` })]));
  await assert.rejects(verify([sessionProof({ accountId: "111111111111" })]));
  await assert.rejects(verify([sessionProof({ errorCode: "AccessDenied" })]));
});
