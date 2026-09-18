import test from "node:test";
import assert from "node:assert/strict";
import { establishComponentSession, establishComponentCleanupSession, establishComponentTerraformSession } from "../aws/component-installation-session.mjs";
import { authenticateComponentSession } from "../aws/component-session-proof.mjs";
import { identityBootstrap, componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";

const start = Date.parse("2026-09-17T12:00:00Z");
function fixture(purpose = "INSTALL") {
  const binding = { sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "b".repeat(64), purpose };
  const role = { INSTALL: identityBootstrap.installationRole, CLEANUP: identityBootstrap.cleanupRole, TERRAFORM: "mscqr-production-component-table-installer" }[purpose];
  const version = purpose === "CLEANUP" ? "2" : "1";
  const principal = `arn:aws:sts::368992683803:assumed-role/${role}/component-${binding.transitionId}`;
  const user = { Account: "368992683803", Arn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator" };
  const key = ["A", "S", "I", "A"].join("") + "0".repeat(16);
  const base = { AccessKeyId: "source-fixture", SecretAccessKey: "disposable-source-secret" };
  const scoped = { AccessKeyId: key, SecretAccessKey: "disposable-scoped-secret", SessionToken: "disposable-scoped-session", Expiration: new Date(start + 900000) };
  const f = { binding, base, user, scoped, principal, calls: [], closed: 0, clock: start + 1000, prompts: 0, payloads: [], before: () => {} };
  f.dependencies = {
    sleep: async milliseconds => { f.clock += milliseconds; },
    loadUser: async () => ({ ...base }), now: () => f.clock, mfa: async () => { f.prompts++; return "0".repeat(6); },
    sts: (credentials) => ({ close: () => { f.closed++; }, send: async (operation, input) => {
      f.calls.push(operation); f.before(operation);
      if (operation === "GetCallerIdentity") return credentials.AccessKeyId === key ? { Account: "368992683803", Arn: principal, UserId: "role-id:session" } : f.user;
      if (operation === "GetSessionToken") {
        assert.deepEqual(input, { DurationSeconds: 900, SerialNumber: "arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator", TokenCode: "0".repeat(6) });
        return { Credentials: { ...base, SessionToken: "disposable-human-mfa-session" } };
      }
      assert.equal(operation, "AssumeRole");
      assert(credentials.SessionToken);
      assert.deepEqual(input, { RoleArn: `arn:aws:iam::368992683803:role/${role}`, RoleSessionName: `component-${binding.transitionId}`, DurationSeconds: 900 });
      return { Credentials: scoped, AssumedRoleUser: { Arn: principal, AssumedRoleId: "role-id:session" } };
    } }),
    invoke: async (input) => {
      assert.equal(input.FunctionName, `${componentBrokerArn}:${version}`);
      assert.equal(input.InvocationType, "RequestResponse");
      f.payloads.push(JSON.parse(Buffer.from(input.Payload).toString("utf8")));
      const payload = f.payloads.at(-1);
      if (payload.operation.startsWith("PROVE_") && f.proofFailures > 0) {
        f.proofFailures--;
        return { StatusCode: 200, ExecutedVersion: version, FunctionError: "Unhandled" };
      }
      const result = ["CLEANUP_CONTEXT", "TERRAFORM_CONTEXT"].includes(payload.operation) ? (f.context || binding) : payload.operation.startsWith("PROVE_")
        ? { state: "SESSION_VERIFIED", principal, expiresAt: scoped.Expiration.toISOString(), sourceSha: binding.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256 }
        : { state: "test-accepted" };
      if (purpose === "TERRAFORM" && payload.operation === "PROVE_TERRAFORM_SESSION") result.session = { account: "368992683803", region: "eu-west-2", ...binding, principal,
        issuedAt: new Date(start).toISOString(), expiresAt: scoped.Expiration.toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def", issuanceEventTime: new Date(start).toISOString(),
        operatorArn: user.Arn, mfaAuthenticated: true, ...(f.sessionOverride || {}) };
      return { StatusCode: 200, ExecutedVersion: version, Payload: Buffer.from(JSON.stringify(result)) };
    },
  };
  f.open = () => establishComponentSession(binding, f.dependencies);
  return f;
}

test("normal client issues a 900-second MFA human session and exposes only fixed broker operations", async () => {
  for (const purpose of ["INSTALL", "CLEANUP"]) {
    const f = fixture(purpose);
    const client = await f.open();
    assert.equal(client.principal, f.principal);
    assert.equal(f.prompts, 1);
    assert.equal(f.closed, 3);
    assert.equal(client.expiresAt, "2026-09-17T12:15:00.000Z");
    assert(!JSON.stringify(client).includes("disposable"));
    const operation = purpose === "INSTALL" ? "INSTALL" : "CLOSE";
    assert.equal((await client.invoke(operation)).state, "test-accepted");
    const proof = f.payloads[0].proof;
    assert.equal(proof.query["X-Amz-SignedHeaders"], "host;x-mscqr-component-binding");
    assert.equal(proof.query["X-Amz-Expires"], "60");
    assert.equal(proof.query["X-Amz-Security-Token"], f.scoped.SessionToken);
    // The real SDK-generated proof must pass the broker's complete parser;
    // transport remains mocked so this test never calls AWS.
    const event = { eventID: "12345678-1234-4234-8234-123456789def", eventTime: "2026-09-17T12:00:00Z", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "eu-west-2", recipientAccountId: "368992683803",
      userIdentity: { type: "IAMUser", accountId: "368992683803", arn: f.user.Arn, sessionContext: { attributes: { mfaAuthenticated: "true" } } },
      requestParameters: { roleArn: `arn:aws:iam::368992683803:role/${purpose === "INSTALL" ? identityBootstrap.installationRole : identityBootstrap.cleanupRole}`, roleSessionName: `component-${f.binding.transitionId}`, durationSeconds: 900 },
      responseElements: { credentials: { accessKeyId: f.scoped.AccessKeyId, expiration: client.expiresAt }, assumedRoleUser: { arn: f.principal, assumedRoleId: "role-id:session" } } };
    assert.equal((await authenticateComponentSession(proof, f.binding, { now: f.clock, sts: async () => ({ Account: "368992683803", Arn: f.principal, UserId: "role-id:session" }), issuanceEvents: async () => [event] })).principal, f.principal);
    await assert.rejects(client.invoke("CreateRole"));
    await assert.rejects(client.invoke(purpose === "INSTALL" ? "CLOSE" : "INSTALL"));
    f.clock = start + 900000;
    await assert.rejects(client.invoke(operation), /expired/);
    assert.equal(f.payloads.length, 2);
  }
});

test("Terraform operator authenticates broker MFA proof and sends only its scoped session to the isolated runner once", async () => {
  const f = fixture("TERRAFORM"); let executions = 0;
  f.dependencies.isolated = async (input, options) => {
    executions++; assert.equal(input.mode, "prepare"); assert.equal(input.plan, null);
    assert.deepEqual(input.credentials, { AccessKeyId: f.scoped.AccessKeyId, SecretAccessKey: f.scoped.SecretAccessKey, SessionToken: f.scoped.SessionToken });
    assert.notEqual(input.credentials.AccessKeyId, f.base.AccessKeyId); assert.equal(typeof options.checkpoint, "function");
    return { fixture: "saved-plan" };
  };
  const client = await f.open(); assert.equal(client.invoke, undefined);
  const result = await client.execute({ mode: "prepare", plan: null }, { checkpoint: async () => {} });
  assert.equal(result.session.purpose, "TERRAFORM"); assert.equal(result.result.fixture, "saved-plan");
  assert.deepEqual(f.payloads.map(value => value.operation), ["PROVE_TERRAFORM_SESSION"]);
  assert.equal(executions, 1); assert.equal(f.scoped.SecretAccessKey, undefined);
  await assert.rejects(client.execute({ mode: "prepare", plan: null }, { checkpoint: async () => {} }), /already consumed/);
});
test("substituted Terraform session evidence never reaches a container", async () => {
  const f = fixture("TERRAFORM"); f.sessionOverride = { authorizationSha256: "c".repeat(64) };
  f.dependencies.isolated = async () => assert.fail("must not run");
  const client = await f.open();
  await assert.rejects(client.execute({ mode: "prepare", plan: null }, { checkpoint: async () => {} }), /proof unavailable/);
  assert.equal(f.scoped.SecretAccessKey, undefined);
});

for (const reserve of [false, true]) test(`isolated apply requires exactly one authenticated reservation: ${reserve}`, async () => {
  const f = fixture("TERRAFORM"); let reservations = 0, closed = 0;
  f.dependencies.state = () => ({ inspect: async () => ({ stateIdentity: "ABSENT" }), close: () => { closed++; }, reserve: async record => {
    reservations++; assert.equal(record.session.purpose, "TERRAFORM"); assert.equal(record.session.principal, f.principal);
  } });
  f.dependencies.isolated = async (_input, options) => { await options.checkpoint({ stage: "apply" }); return {}; };
  const client = await f.open();
  await assert.rejects(client.reserve({}), /No active/);
  const execution = client.execute({ mode: "apply", plan: Buffer.from("fixture") }, { checkpoint: async () => {
    if (reserve) { await client.reserve({}); await assert.rejects(client.reserve({}), /No active/); }
  } });
  if (reserve) await execution;
  else await assert.rejects(execution, /reservation required/);
  assert.equal(reservations, Number(reserve)); assert.equal(closed, 1);
  assert.equal(f.scoped.SecretAccessKey, undefined);
  await assert.rejects(client.reserve({}), /No active/);
});

for (const arn of ["arn:aws:iam::368992683803:root", "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session", "arn:aws:iam::368992683803:user/other"]) test(`issuer rejects ${arn} before MFA or AssumeRole`, async () => {
  const f = fixture(); f.user.Arn = arn;
  await assert.rejects(f.open());
  assert.deepEqual(f.calls, ["GetCallerIdentity"]);
  assert.equal(f.prompts, 0);
});

test("invalid binding or unknown purpose never loads credentials", async () => {
  const f = fixture();
  for (const binding of [{ ...f.binding, purpose: "ADMIN" }, { ...f.binding, roleArn: "other" }, { ...f.binding, transitionId: "invalid" }]) {
    await assert.rejects(establishComponentSession(binding, { loadUser: async () => assert.fail("Must reject before credentials") }));
  }
});

test("unexpected AWS expiration rejects issuance and closes STS transports", async () => {
  const f = fixture(); f.scoped.Expiration = new Date(start + 3600000);
  await assert.rejects(f.open(), /expiration/);
  assert.equal(f.closed, 2);
  assert.deepEqual(f.payloads, []);
});

test("cleanup discovers durable coordinates without GitHub artifacts or local authorization bytes", async () => {
  const f = fixture("CLEANUP");
  const client = await establishComponentCleanupSession(f.binding.transitionId, f.dependencies);
  assert.deepEqual(f.payloads, [{ operation: "CLEANUP_CONTEXT" }]);
  await client.invoke("CLOSE");
  assert.equal(f.payloads[1].operation, "PROVE_CLEANUP_SESSION");
  assert.equal(f.payloads[2].authorizationSha256, f.binding.authorizationSha256);
  assert.equal(f.payloads[2].transitionId, f.binding.transitionId);
  assert(f.payloads[2].proof);
  await assert.rejects(client.invoke("INSTALL"));
});

test("Terraform discovers closed verified installation provenance without the expired GitHub artifact", async () => {
  const f = fixture("TERRAFORM");
  f.context = f.binding;
  f.dependencies.state = () => ({ inspect: async () => ({ stateIdentity: "ABSENT" }), reserve: async () => {}, close: () => {} });
  const client = await establishComponentTerraformSession({ sourceSha: f.binding.sourceSha, transitionId: f.binding.transitionId }, f.dependencies);
  assert.deepEqual(f.payloads, [{ operation: "TERRAFORM_CONTEXT", transitionId: f.binding.transitionId }]);
  await client.inspect();
  assert.equal(f.payloads[1].operation, "PROVE_TERRAFORM_SESSION");
  client.close();
});
test("Terraform provenance from a different protected source is rejected before execution", async () => {
  const f = fixture("TERRAFORM");
  f.context = { ...f.binding, sourceSha: "c".repeat(40) };
  await assert.rejects(establishComponentTerraformSession({ sourceSha: f.binding.sourceSha, transitionId: f.binding.transitionId }, f.dependencies), /different protected source/);
});

for (const change of [{ purpose: "INSTALL" }, { transitionId: "12345678-1234-4234-8234-123456789def" }, { sourceSha: "invalid" }, { evidenceKey: "alternate" }]) {
  test(`cleanup discovery rejects substituted coordinates ${Object.keys(change)[0]}`, async () => {
    const f = fixture("CLEANUP"); f.context = { ...f.binding, ...change };
    await assert.rejects(establishComponentCleanupSession(f.binding.transitionId, f.dependencies));
    assert.deepEqual(f.payloads, [{ operation: "CLEANUP_CONTEXT" }]);
  });
}

test("CloudTrail propagation reuses one session and retries only read-only proof", async () => {
  const f = fixture(); f.proofFailures = 3;
  const client = await f.open(); await client.invoke("INSTALL");
  assert.equal(f.calls.filter(value => value === "AssumeRole").length, 1);
  assert.deepEqual(f.payloads.map(value => value.operation), [...Array(4).fill("PROVE_INSTALL_SESSION"), "INSTALL"]);
});

test("unavailable issuance proof stops at the deadline without any installation attempt", async () => {
  const f = fixture(); f.proofFailures = 100;
  const client = await f.open();
  await assert.rejects(client.invoke("INSTALL"), /proof unavailable/);
  assert(f.payloads.length <= 60 && f.payloads.every(value => value.operation === "PROVE_INSTALL_SESSION"));
  assert.equal(f.calls.filter(value => value === "AssumeRole").length, 1);
});
