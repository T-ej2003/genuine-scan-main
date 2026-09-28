import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { executeSignerBrokerOperation } from "../aws/component-iam-broker.mjs";
import { establishSignerInstallSession, establishSignerRevokeSession } from "../aws/component-installation-session.mjs";
import { assertBrokerEntryPoint, brokerSignerSuccessorEntryPoints } from "../aws/component-broker-configuration.mjs";
import { componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { sessionProofBinding } from "../aws/component-session-proof.mjs";
import { run as runSignerCli } from "../aws/production-signer-broker-transition-cli.mjs";
import { buildSignerBrokerAuthorization, createSignerPolicyBroker, signerAbortAllowed, signerBrokerContract, signerLifecycleEvidenceBinding, SIGNER_BROKER_LIFECYCLE } from "../aws/component-signer-policy-transition.mjs";
import { buildSignerTemporaryPolicy, SIGNER_TEMPORARY_CAPABILITY as C } from "../aws/production-signer-temporary-capability.mjs";

const sourceSha = "a".repeat(40), transitionId = "123e4567-e89b-42d3-a456-426614174000", now = Date.parse("2026-09-28T12:00:00.000Z");
const steady = JSON.parse(fs.readFileSync(new URL("../../documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", import.meta.url)));
const temporary = buildSignerTemporaryPolicy(steady, { sourceSha, transitionId });
const authorization = (operation, offset = -1000, workflowRunId = "42", protectedMainSha = sourceSha, authorizedAt = now) => buildSignerBrokerAuthorization({ sourceSha, protectedMainSha, transitionId, operation, workflowRunId, approvedAt: new Date(authorizedAt + offset).toISOString(), expiresAt: new Date(authorizedAt + offset + 30 * 60 * 1000).toISOString() });

function fixture({ main = { sha: sourceSha }, clock = { value: now }, entityPages = [{ PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }] } = {}) {
  let object, etag = 0, versions = [{ VersionId: "v1", IsDefaultVersion: true, CreateDate: "2026-09-01T00:00:00Z", document: steady }];
  const calls = [];
  const iam = async (operation, input) => {
    calls.push({ operation, input });
    if (operation === "GetPolicy") return { Policy: { Arn: C.sourcePolicyArn, DefaultVersionId: versions.find(value => value.IsDefaultVersion).VersionId, PermissionsBoundaryUsageCount: 0 } };
    if (operation === "ListEntitiesForPolicy") return entityPages[input.Marker ? Number(input.Marker) : 0];
    if (operation === "ListPolicyVersions") return { Versions: versions.map(({ document, ...value }) => value), IsTruncated: false };
    if (operation === "GetPolicyVersion") return { PolicyVersion: { Document: versions.find(value => value.VersionId === input.VersionId).document } };
    if (operation === "CreatePolicyVersion") {
      versions = versions.map(value => ({ ...value, IsDefaultVersion: false }));
      versions.push({ VersionId: `v${versions.length + 1}`, IsDefaultVersion: true, CreateDate: new Date(now).toISOString(), document: JSON.parse(input.PolicyDocument) }); return {};
    }
    if (operation === "DeletePolicyVersion") { versions = versions.filter(value => value.VersionId !== input.VersionId); return {}; }
    throw new Error(`unexpected IAM ${operation}`);
  };
  const s3 = async (operation, input) => {
    assert.equal(input.Key, signerBrokerContract.ledgerKey, "Signer operations must not read the ordinary component archive");
    if (operation === "GetObject") { if (!object) { const error = new Error(); error.name = "NoSuchKey"; throw error; } return { ETag: `"${etag}"`, Body: { transformToString: async () => object } }; }
    if (operation === "PutObject") { if (input.IfNoneMatch && object) { const error = new Error(); error.name = "PreconditionFailed"; throw error; } assert(!input.IfMatch || input.IfMatch === `"${etag}"`); object = input.Body; etag += 1; return { ETag: `"${etag}"` }; }
    throw new Error(`unexpected S3 ${operation}`);
  };
  return { broker: createSignerPolicyBroker({ iam, s3, currentMain: async () => main.sha, now: () => clock.value }), iam, s3, main, clock, calls, ledger: () => object && JSON.parse(object), versions: () => versions };
}

function composedFixture(options) {
  const f = fixture(options), operations = [], ordinaryArchive = [];
  const accessKey = "ASIA" + "0".repeat(16), operator = `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator`;
  const base = () => ({ AccessKeyId: "base-fixture", SecretAccessKey: "base-placeholder" });
  const session = purpose => {
    const role = purpose === "SIGNER_REVOKE" ? identityBootstrap.cleanupRole : identityBootstrap.installationRole;
    const principal = `arn:aws:sts::${C.accountId}:assumed-role/${role}/component-${transitionId}`;
    const issued = new Date(f.clock.value - 1000).toISOString(), expiration = new Date(f.clock.value + 899000).toISOString();
    const scoped = { AccessKeyId: accessKey, SecretAccessKey: "scoped-placeholder", SessionToken: "scoped-session-placeholder", Expiration: new Date(expiration) };
    const issuance = { eventID: "12345678-1234-4234-8234-123456789def", eventTime: issued, eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: C.region, recipientAccountId: C.accountId,
      userIdentity: { type: "IAMUser", accountId: C.accountId, arn: operator, sessionContext: { attributes: { mfaAuthenticated: "true" } } },
      requestParameters: { roleArn: `arn:aws:iam::${C.accountId}:role/${role}`, roleSessionName: `component-${transitionId}`, durationSeconds: 900 },
      responseElements: { credentials: { accessKeyId: accessKey, expiration }, assumedRoleUser: { arn: principal, assumedRoleId: "role-id:session" } } };
    return { role, principal, scoped, issuance };
  };
  const dispatch = async (event, version) => {
    operations.push(event.operation);
    assertBrokerEntryPoint({ functionVersion: version, invokedFunctionArn: `${componentBrokerArn}:${version}` }, event.operation, brokerSignerSuccessorEntryPoints);
    if (!event.operation.startsWith("SIGNER_")) { ordinaryArchive.push(event.operation); throw new Error("Ordinary component archive reached"); }
    const purpose = ["SIGNER_REVOKE", "SIGNER_PROVE_REVOKE_SESSION"].includes(event.operation) ? "SIGNER_REVOKE" : "SIGNER_INSTALL";
    const current = session(purpose);
    return executeSignerBrokerOperation(event, { iam: f.iam, s3: f.s3, currentMain: async () => f.main.sha, now: () => f.clock.value,
      sts: async request => { assert.equal(request.headers["x-mscqr-component-binding"], sessionProofBinding({ sourceSha, transitionId, authorizationSha256: event.authorizationSha256, purpose })); return { Account: C.accountId, Arn: current.principal, UserId: "role-id:session" }; },
      issuanceEvents: async () => [current.issuance] });
  };
  const deps = purpose => {
    const current = session(purpose);
    return { loadUser: async () => base(), mfa: async () => "123456", now: () => f.clock.value, sleep: async () => { throw new Error("AWS issuance proof unavailable: unexpected retry"); },
      sts: credentials => ({ close: () => {}, send: async (operation, input) => {
        if (operation === "GetCallerIdentity") return credentials.AccessKeyId === accessKey ? { Account: C.accountId, Arn: current.principal, UserId: "role-id:session" } : { Account: C.accountId, Arn: operator };
        if (operation === "GetSessionToken") return { Credentials: { AccessKeyId: "human-fixture", SecretAccessKey: "human-placeholder", SessionToken: "human-session-placeholder" } };
        assert.equal(operation, "AssumeRole"); assert.equal(input.RoleArn, `arn:aws:iam::${C.accountId}:role/${current.role}`);
        return { Credentials: current.scoped, AssumedRoleUser: { Arn: current.principal, AssumedRoleId: "role-id:session" } };
      } }),
      invoke: async input => {
        const version = input.FunctionName.split(":").at(-1), event = JSON.parse(Buffer.from(input.Payload).toString("utf8"));
        const result = await dispatch(event, version);
        return { StatusCode: 200, ExecutedVersion: version, Payload: Buffer.from(JSON.stringify(result)) };
      } };
  };
  const binding = () => ({ sourceSha, transitionId, authorizationSha256: f.ledger().authorization.authorizationSha256 });
  return { ...f, operations, ordinaryArchive, dispatch, binding,
    authorize: operation => dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization(operation, operation === "INSTALL" ? -1000 : -500, operation === "INSTALL" ? "42" : "43") }, "15"),
    installSession: (selected = binding()) => establishSignerInstallSession(selected, deps("SIGNER_INSTALL")),
    revokeSession: (selected = binding()) => establishSignerRevokeSession(selected, deps("SIGNER_REVOKE")) };
}

test("real signer session composition uses the signer ledger from authorization through revoke", async () => {
  const f = composedFixture(); await f.authorize("INSTALL");
  let client = await f.installSession(), ledger = await client.invoke("SIGNER_INSTALL");
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, state));
  }
  await f.authorize("REVOKE"); client = await f.revokeSession(); ledger = f.ledger();
  const revoke = { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false };
  ledger = await client.invoke("SIGNER_REVOKE", revoke);
  assert.equal((await client.invoke("SIGNER_REVOKE", revoke)).state, "REVOKED");
  assert.equal(ledger.state, "REVOKED"); assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, steady);
  assert.deepEqual(f.operations, ["SIGNER_AUTHORIZE", "SIGNER_PROVE_INSTALL_SESSION", "SIGNER_INSTALL", ...Array(6).fill(["SIGNER_PROVE_INSTALL_SESSION", "SIGNER_ADVANCE"]).flat(), "SIGNER_AUTHORIZE", "SIGNER_PROVE_REVOKE_SESSION", "SIGNER_REVOKE", "SIGNER_PROVE_REVOKE_SESSION", "SIGNER_REVOKE"]);
  assert.deepEqual(f.ordinaryArchive, []);
});

test("production signer CLI install and revoke reach their signer broker operations", async () => {
  const f = composedFixture(); await f.authorize("INSTALL");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "signer-cli-composed-")), file = path.join(directory, "ledger.json");
  try {
    fs.chmodSync(directory, 0o700); fs.writeFileSync(file, JSON.stringify(f.ledger()), { mode: 0o600 });
    const dependencies = { installSession: binding => f.installSession(binding), revokeSession: binding => f.revokeSession(binding) };
    let ledger = await runSignerCli(["--phase", "install", "--state-file", file], dependencies);
    assert.equal(ledger.state, "INSTALLED");
    const client = await f.installSession();
    for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, state));
    await f.authorize("REVOKE"); fs.writeFileSync(file, JSON.stringify(f.ledger()), { mode: 0o600 });
    ledger = await runSignerCli(["--phase", "revoke", "--state-file", file], dependencies);
    assert.equal(ledger.state, "REVOKED");
    assert(f.operations.includes("SIGNER_INSTALL") && f.operations.includes("SIGNER_REVOKE"));
    assert.deepEqual(f.ordinaryArchive, []);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("composed signer proof rejects absent, unrelated, substituted, stale, and replayed authority", async () => {
  const f = composedFixture(), initial = { sourceSha, transitionId, authorizationSha256: authorization("INSTALL").authorizationSha256 };
  await assert.rejects((await f.installSession(initial)).invoke("SIGNER_INSTALL"), /Signer lifecycle ledger is absent|proof unavailable/);
  await f.authorize("INSTALL");
  assert.notEqual(sessionProofBinding({ ...f.binding(), purpose: "SIGNER_INSTALL" }), sessionProofBinding({ ...f.binding(), purpose: "INSTALL" }));
  assert.notEqual(sessionProofBinding({ ...f.binding(), purpose: "SIGNER_REVOKE" }), sessionProofBinding({ ...f.binding(), purpose: "CLEANUP" }));
  await assert.rejects((await f.installSession()).invoke("SIGNER_INSTALL", { sourceSha: "b".repeat(40) }), /Caller cannot override sourceSha/);
  for (const changed of [{ sourceSha: "b".repeat(40) }, { transitionId: "123e4567-e89b-42d3-a456-426614174001" }, { authorizationSha256: "f".repeat(64) }]) {
    await assert.rejects(async () => (await f.installSession({ ...f.binding(), ...changed })).invoke("SIGNER_INSTALL"));
  }
  await assert.rejects(f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: { ...authorization("INSTALL"), repository: "other/repository" } }, "15"), /binding differs/);
  await assert.rejects(f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: { ...authorization("INSTALL"), purpose: "other" } }, "15"), /binding differs/);
  await assert.rejects(f.authorize("INSTALL"), /replay/);
  const older = f.clock.value; f.clock.value += 31 * 60 * 1000;
  await assert.rejects((await f.installSession()).invoke("SIGNER_INSTALL"), /stale|proof unavailable/); f.clock.value = older;
  assert.deepEqual(f.ordinaryArchive, []);
});

test("composed signer retries keep the signer ledger authoritative and block stale abort after apply", async () => {
  const f = composedFixture(); await f.authorize("INSTALL");
  let client = await f.installSession(), ledger = await client.invoke("SIGNER_INSTALL");
  assert.equal((await client.invoke("SIGNER_INSTALL")).state, "INSTALLED");
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED"]) {
    const input = advance(ledger, state); ledger = await client.invoke("SIGNER_ADVANCE", input);
    assert.equal((await client.invoke("SIGNER_ADVANCE", input)).state, state);
  }
  await assert.rejects(f.authorize("REVOKE"), /cannot interrupt/);
  for (const stale of ["INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED"]) {
    assert.notEqual(signerLifecycleEvidenceBinding({ state: stale, ...f.binding() }), evidence(f.ledger()));
  }
  await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -500, "44") }, "15");
  client = await f.installSession();
  assert.equal((await client.invoke("SIGNER_RECOVERY", { state: "PLAN_GENERATED", planSha256: "d".repeat(64), approvalReference: null })).recovery.state, "PLAN_GENERATED");
  assert.equal((await client.invoke("SIGNER_RECOVERY", { state: "PLAN_GENERATED", planSha256: "d".repeat(64), approvalReference: null })).recovery.state, "PLAN_GENERATED");
  assert.deepEqual(f.ordinaryArchive, []);
});

test("expired recovery after APPLIED renews through the real signer session and verifies without reapply", async () => {
  const f = composedFixture(); await f.authorize("INSTALL");
  let client = await f.installSession(), ledger = await client.invoke("SIGNER_INSTALL");
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED"]) ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, state));
  await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -500, "43") }, "15");
  client = await f.installSession();
  const planSha256 = "d".repeat(64), approvalReference = "change:recovery-apply";
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_STARTED"]) await client.invoke("SIGNER_RECOVERY", { state, planSha256, approvalReference: state === "PLAN_GENERATED" ? null : approvalReference });
  let applyCount = 0;
  const terraformApply = async () => { applyCount++; return client.invoke("SIGNER_ADVANCE", { ...advance(f.ledger(), "APPLIED"), planSha256, approvalReference }); };
  ledger = await terraformApply(); assert.equal(ledger.state, "APPLIED");
  f.clock.value += 31 * 60 * 1000;
  await assert.rejects(f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -600, "44", sourceSha, f.clock.value) }, "15"), /cannot interrupt/);
  await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -500, "45", sourceSha, f.clock.value) }, "15");
  client = await f.installSession(); ledger = f.ledger();
  await assert.rejects(client.invoke("SIGNER_RECOVERY", { state: "PLAN_GENERATED", planSha256: "e".repeat(64), approvalReference: null }), /only after authoritative apply start/);
  ledger = await client.invoke("SIGNER_ADVANCE", { ...advance(ledger, "CONVERGED"), planSha256, approvalReference });
  assert.equal(ledger.state, "CONVERGED"); assert.equal(applyCount, 1);
  await assert.rejects(f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -250, "46", sourceSha, f.clock.value) }, "15"), /authoritative apply start or completion/);
  await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -250, "47", sourceSha, f.clock.value) }, "15");
  client = await f.revokeSession(); ledger = f.ledger();
  ledger = await client.invoke("SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false });
  assert.equal(ledger.state, "REVOKED"); assert.equal(applyCount, 1);
  assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, steady);
  const versionWrites = f.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length;
  f.clock.value += 31 * 60 * 1000;
  await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "48", sourceSha, f.clock.value) }, "15");
  client = await f.revokeSession(); ledger = f.ledger();
  assert.equal((await client.invoke("SIGNER_REVOKE", { evidenceState: ledger.history.at(-1).state,
    evidenceSha256: signerLifecycleEvidenceBinding({ state: ledger.history.at(-1).state, ...f.binding() }), abort: false })).state, "REVOKED");
  assert.equal(f.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length, versionWrites, "revoke retry must not recreate the temporary policy");
  assert.deepEqual(f.ordinaryArchive, []);
  const reconciliation = fs.readFileSync(new URL("../aws/reconcile-production-signer-temporary-capability.mjs", import.meta.url), "utf8");
  const verify = reconciliation.slice(reconciliation.indexOf('if (phase === "verify-convergence")'), reconciliation.indexOf('if (phase === "revoke")'));
  assert.doesNotMatch(verify, /terraform[^\n]*"apply"|recover-apply/);
});

const request = (ledger, operation, extra = {}) => ({ operation, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256, ...extra });
const evidence = ledger => signerLifecycleEvidenceBinding({ state: ledger.state, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256 });
const advance = (ledger, state) => ({ state, evidenceSha256: evidence(ledger), planSha256: "b".repeat(64),
  approvalReference: state === "PLAN_GENERATED" ? null : "change:signer-approved",
  signerReadbackSha256: state === "CONVERGED" ? "c".repeat(64) : null });

test("authorization expiry and replacement matrix covers every authoritative signer state", async () => {
  for (const state of SIGNER_BROKER_LIFECYCLE) {
    const clock = { value: now }, f = fixture({ clock });
    const original = authorization("INSTALL"); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: original });
    let ledger = f.ledger();
    if (state !== "INSTALLING") ledger = await f.broker(request(ledger, "SIGNER_INSTALL"));
    for (const next of SIGNER_BROKER_LIFECYCLE.slice(2, SIGNER_BROKER_LIFECYCLE.indexOf(state) + 1)) {
      if (next === "REVOKED") {
        await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
        ledger = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false }));
      } else ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, next)));
    }
    const proofOperation = state === "REVOKED" ? "SIGNER_PROVE_REVOKE_SESSION" : "SIGNER_PROVE_INSTALL_SESSION";
    assert.equal((await f.broker(request(ledger, proofOperation))).sourceSha, sourceSha, `${state}: valid authorization`);
    clock.value += 31 * 60 * 1000;
    await assert.rejects(f.broker(request(ledger, proofOperation)), /stale/, `${state}: expired authorization`);
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: original }), /stale|replay/, `${state}: older authorization`);
    const fresh = operation => authorization(operation, -500, "44", sourceSha, clock.value);
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: { ...fresh("INSTALL"), transitionId: "123e4567-e89b-42d3-a456-426614174001" } }), /binding differs/, `${state}: wrong transition`);
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: { ...fresh("INSTALL"), sourceSha: "d".repeat(40) } }), /binding differs/, `${state}: wrong source`);
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: { ...fresh("INSTALL"), purpose: "other" } }), /binding differs/, `${state}: wrong purpose`);
    const wrong = ["APPLY_STARTED", "APPLIED"].includes(state) ? "REVOKE" : "RECOVER";
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: fresh(wrong) }), /apply start|cannot interrupt|already revoked/, `${state}: wrong operation`);
    const same = state === "REVOKED" ? "REVOKE" : "INSTALL";
    if (state === "CONVERGED") await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: fresh(same) }), /convergence/, `${state}: install cannot renew`);
    else {
      await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: fresh(same) });
      assert.equal(f.ledger().state, state, `${state}: renewal cannot move the lifecycle`);
      if (["APPLY_STARTED", "APPLIED"].includes(state)) {
        await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -400, "45", sourceSha, clock.value) });
        assert.equal(f.ledger().state, state, `${state}: fresh recovery cannot move the lifecycle`);
      }
      if (state === "REVOKED") {
        const retry = f.ledger();
        assert.equal((await f.broker(request(retry, "SIGNER_REVOKE", { evidenceState: retry.history.at(-1).state,
          evidenceSha256: signerLifecycleEvidenceBinding({ state: retry.history.at(-1).state, sourceSha, transitionId, authorizationSha256: retry.authorization.authorizationSha256 }), abort: false }))).state, "REVOKED");
        assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, steady);
      }
    }
    if (state === "CONVERGED") {
      await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: fresh("REVOKE") });
      assert.equal(f.ledger().state, "CONVERGED", "revoke authorization precedes actual revocation");
    }
  }
});

test("real signer sessions resume after an expired authorization at each durable state", async () => {
  for (const interrupted of SIGNER_BROKER_LIFECYCLE) {
    const f = composedFixture(); await f.authorize("INSTALL");
    let client = await f.installSession(), ledger = f.ledger();
    if (interrupted !== "INSTALLING") ledger = await client.invoke("SIGNER_INSTALL");
    for (const state of SIGNER_BROKER_LIFECYCLE.slice(2, SIGNER_BROKER_LIFECYCLE.indexOf(interrupted) + 1)) {
      if (state === "REVOKED") {
        await f.authorize("REVOKE"); client = await f.revokeSession(); ledger = f.ledger();
        ledger = await client.invoke("SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false });
      } else ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, state));
    }
    const writes = f.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length;
    f.clock.value += 31 * 60 * 1000;
    const renewal = ["APPLY_STARTED", "APPLIED"].includes(interrupted) ? "RECOVER" : ["CONVERGED", "REVOKED"].includes(interrupted) ? "REVOKE" : "INSTALL";
    await f.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization(renewal, -500, "55", sourceSha, f.clock.value) }, "15");
    client = renewal === "REVOKE" ? await f.revokeSession() : await f.installSession(); ledger = f.ledger();
    if (interrupted === "INSTALLING") ledger = await client.invoke("SIGNER_INSTALL");
    else if (interrupted === "CONVERGED" || interrupted === "REVOKED") ledger = await client.invoke("SIGNER_REVOKE", {
      evidenceState: interrupted === "REVOKED" ? ledger.history.at(-1).state : ledger.state,
      evidenceSha256: signerLifecycleEvidenceBinding({ state: interrupted === "REVOKED" ? ledger.history.at(-1).state : ledger.state, ...f.binding() }), abort: false });
    else ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, SIGNER_BROKER_LIFECYCLE[SIGNER_BROKER_LIFECYCLE.indexOf(interrupted) + 1]));
    assert.equal(ledger.state, interrupted === "REVOKED" ? "REVOKED" : SIGNER_BROKER_LIFECYCLE[SIGNER_BROKER_LIFECYCLE.indexOf(interrupted) + 1], `${interrupted}: resume`);
    if (interrupted === "REVOKED") assert.equal(f.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length, writes, "terminal retry must not mutate IAM");
    assert.deepEqual(f.ordinaryArchive, [], `${interrupted}: ordinary archive must remain unused`);
  }
});

test("expired authorization after ambiguous IAM install or revoke resumes by readback without another write", async () => {
  const install = composedFixture(); await install.authorize("INSTALL");
  await install.iam("CreatePolicyVersion", { PolicyArn: C.sourcePolicyArn, PolicyDocument: JSON.stringify(temporary), SetAsDefault: true });
  install.clock.value += 31 * 60 * 1000;
  await install.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL", -500, "49", sourceSha, install.clock.value) }, "15");
  let client = await install.installSession(), writes = install.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length;
  assert.equal((await client.invoke("SIGNER_INSTALL")).state, "INSTALLED");
  assert.equal(install.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length, writes, "install readback must not repeat AWS mutation");

  const revoke = composedFixture(); await revoke.authorize("INSTALL");
  client = await revoke.installSession(); let ledger = await client.invoke("SIGNER_INSTALL");
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) ledger = await client.invoke("SIGNER_ADVANCE", advance(ledger, state));
  await revoke.authorize("REVOKE");
  await revoke.iam("CreatePolicyVersion", { PolicyArn: C.sourcePolicyArn, PolicyDocument: JSON.stringify(steady), SetAsDefault: true });
  revoke.clock.value += 31 * 60 * 1000;
  await revoke.dispatch({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "49", sourceSha, revoke.clock.value) }, "15");
  client = await revoke.revokeSession(); ledger = revoke.ledger(); writes = revoke.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length;
  assert.equal((await client.invoke("SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false })).state, "REVOKED");
  assert.equal(revoke.calls.filter(({ operation }) => operation === "CreatePolicyVersion").length, writes, "revoke readback must not repeat AWS mutation");
});

test("broker alone performs the fixed canonical install and revoke", async () => {
  const f = fixture();
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  assert.equal(ledger.state, "INSTALLED"); assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, temporary);
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
  }
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
  ledger = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false }));
  assert.equal(ledger.state, "REVOKED"); assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, steady);
  const mutations = f.calls.filter(({ operation }) => ["CreatePolicyVersion", "DeletePolicyVersion"].includes(operation));
  assert(mutations.every(({ input }) => input.PolicyArn === C.sourcePolicyArn));
  assert.deepEqual(mutations.filter(({ operation }) => operation === "CreatePolicyVersion").map(({ input }) => JSON.parse(input.PolicyDocument)), [temporary, steady]);
});

test("broker rejects hidden managed-policy consumers on later IAM pages", async () => {
  const f = fixture({ entityPages: [
    { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [], IsTruncated: true, Marker: "1" },
    { PolicyRoles: [], PolicyUsers: [{ UserName: "unexpected" }], PolicyGroups: [], IsTruncated: false },
  ] });
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") }), /sole|consumer|attached/i);
  assert.deepEqual(f.calls.filter(({ operation }) => operation === "ListEntitiesForPolicy").map(({ input }) => input), [
    { PolicyArn: C.sourcePolicyArn }, { PolicyArn: C.sourcePolicyArn, Marker: "1" },
  ]);
  assert.equal(f.calls.some(({ operation }) => operation === "CreatePolicyVersion"), false);
});

test("authoritative lifecycle is monotonic and stale pre-apply evidence cannot abort after APPLY_STARTED", async () => {
  for (const authoritative of ["APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    for (const stale of ["INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED"]) {
      const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") }); let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
      for (const state of SIGNER_BROKER_LIFECYCLE.slice(2, SIGNER_BROKER_LIFECYCLE.indexOf(authoritative) + 1)) ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
      if (authoritative === "CONVERGED") {
        await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
        await assert.rejects(f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: stale, evidenceSha256: signerLifecycleEvidenceBinding({ state: stale, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256 }), abort: true })), /stale|APPLY_STARTED|current authoritative/);
      } else {
        await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }), /cannot interrupt/);
        assert.notEqual(signerLifecycleEvidenceBinding({ state: stale, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256 }), evidence(ledger));
      }
      assert.notEqual(f.ledger().state, "REVOKED");
    }
  }
});

test("lost acknowledgements make install, advance, and revoke retries idempotent", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  const installing = f.ledger(), installed = await f.broker(request(installing, "SIGNER_INSTALL"));
  assert.equal((await f.broker(request(installing, "SIGNER_INSTALL"))).state, "INSTALLED");
  let ledger = installed;
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    const predecessor = ledger, transition = advance(predecessor, state);
    ledger = await f.broker(request(predecessor, "SIGNER_ADVANCE", transition));
    assert.equal((await f.broker(request(predecessor, "SIGNER_ADVANCE", transition))).state, state);
  }
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") });
  const converged = f.ledger(), revoke = request(converged, "SIGNER_REVOKE", { evidenceState: converged.state, evidenceSha256: evidence(converged), abort: false });
  assert.equal((await f.broker(revoke)).state, "REVOKED");
  assert.equal((await f.broker(revoke)).state, "REVOKED");
});

test("lifecycle bindings are introduced once and cannot be replaced", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "PLAN_GENERATED"), planSha256: null })), /match/);
  ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "PLAN_GENERATED")));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "PLAN_REVIEWED"), planSha256: "d".repeat(64) })), /plan binding changed/);
  ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "PLAN_REVIEWED")));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "APPLY_AUTHORIZED"), approvalReference: "change:other" })), /approval binding changed/);
});

test("current pre-apply abort is allowed and rollback or skipped advances are rejected", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") }); let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "APPLY_STARTED"))), /skip/);
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
  ledger = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: true }));
  assert.equal(ledger.state, "REVOKED"); assert.equal(signerAbortAllowed("PLAN_REVIEWED"), true); assert.equal(signerAbortAllowed("APPLY_STARTED"), false);
});

test("pre-mutation abort restores steady state through the authoritative ledger without an IAM write", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") });
  const ledger = f.ledger(), result = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: true }));
  assert.equal(result.state, "REVOKED"); assert.equal(f.calls.some(({ operation }) => operation === "CreatePolicyVersion"), false);
});

test("broker request surface exposes no caller-selected policy or document", async () => {
  const f = fixture(), auth = authorization("INSTALL");
  for (const injected of [{ policyArn: "arn:aws:iam::368992683803:policy/other" }, { policyDocument: { Version: "2012-10-17", Statement: [] } }, { account: "000000000000" }, { region: "us-east-1" }, { purpose: "other" }]) {
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: { ...auth, ...injected } }), /fields differ|binding differs/);
  }
});

test("fresh install authorization renews monotonically and consumed authorization cannot replay", async () => {
  const f = fixture(), first = authorization("INSTALL", -2000, "41"), second = authorization("INSTALL", -1000, "42");
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: first });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: second });
  assert.equal(f.ledger().authorization.authorizationSha256, second.authorizationSha256);
  assert.deepEqual(f.ledger().authorizationHistory.map(value => value.authorizationSha256), [first.authorizationSha256]);
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: first }), /replay|approval time/);
});

test("revoke rebinds to unchanged descendant protected main without changing the transition source", async () => {
  const main = { sha: sourceSha }, descendant = "d".repeat(40), f = fixture({ main });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  main.sha = descendant;
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43", descendant) });
  assert.equal(f.ledger().authorization.sourceSha, sourceSha);
  assert.equal(f.ledger().authorization.protectedMainSha, descendant);
  const ledger = f.ledger();
  assert.equal((await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: true }))).state, "REVOKED");
});

test("source rebind cannot authorize install or a non-current protected main", async () => {
  const main = { sha: sourceSha }, descendant = "d".repeat(40), f = fixture({ main });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  main.sha = descendant;
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: buildSignerBrokerAuthorization({ sourceSha, protectedMainSha: descendant, transitionId, operation: "INSTALL", workflowRunId: "43", approvedAt: new Date(now - 500).toISOString(), expiresAt: new Date(now - 500 + 30 * 60 * 1000).toISOString() }) }), /current protected main/);
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "44", "e".repeat(40)) }), /Protected source moved/);
});

test("expired revoke authorization can be renewed without replaying prior authority", async () => {
  const clock = { value: now }, f = fixture({ clock });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL", -2000, "41") });
  await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -1000, "42") });
  const expired = f.ledger().authorization;
  clock.value = now + 31 * 60 * 1000;
  const renewed = authorization("REVOKE", -500, "43", sourceSha, clock.value);
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: renewed });
  assert.equal(f.ledger().authorization.authorizationSha256, renewed.authorizationSha256);
  assert(f.ledger().authorizationHistory.some(value => value.authorizationSha256 === expired.authorizationSha256));
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: expired }), /stale|replay|approval time/);
});

test("authorization renewal retains a readable bounded replay window", async () => {
  const f = fixture();
  for (let index = 0; index < 40; index++) await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL", -40000 + index * 1000, String(100 + index)) });
  assert.equal(f.ledger().authorizationHistory.length, 32);
  assert.equal((await f.broker(request(f.ledger(), "SIGNER_INSTALL"))).state, "INSTALLED");
});

test("partial apply recovery binds each reviewed plan and permits deterministic repeated attempts", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED"]) ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
  const recover = (state, planSha256, approvalReference = null) => f.broker(request(f.ledger(), "SIGNER_RECOVERY", { state, planSha256, approvalReference }));
  const first = "d".repeat(64), second = "e".repeat(64);
  await recover("PLAN_GENERATED", first); await recover("PLAN_REVIEWED", first, "change:recovery-1"); await recover("APPLY_STARTED", first, "change:recovery-1");
  await recover("PLAN_GENERATED", first); await recover("PLAN_REVIEWED", first, "change:recovery-2"); await recover("APPLY_STARTED", first, "change:recovery-2");
  await recover("PLAN_GENERATED", second); await recover("PLAN_REVIEWED", second, "change:recovery-3"); await recover("APPLY_STARTED", second, "change:recovery-3");
  ledger = f.ledger();
  await assert.rejects(recover("PLAN_GENERATED", first), /cannot be replaced|binding|replay/);
  ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "APPLIED"), planSha256: second, approvalReference: "change:recovery-3" }));
  assert.equal(ledger.state, "APPLIED"); assert.equal(ledger.recovery, null); assert.equal(ledger.planSha256, second);
});

test("post-apply recovery authority can rebind to unchanged descendant main only after APPLY_STARTED", async () => {
  const main = { sha: sourceSha }, descendant = "d".repeat(40), f = fixture({ main });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -500, "43") }), /apply start/);
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED"]) ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
  main.sha = descendant;
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -600, "43", descendant) }), /cannot interrupt/);
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("RECOVER", -500, "44", descendant) });
  ledger = f.ledger(); assert.equal(ledger.authorization.operation, "RECOVER"); assert.equal(ledger.authorization.protectedMainSha, descendant);
  assert.equal((await f.broker(request(ledger, "SIGNER_RECOVERY", { state: "PLAN_GENERATED", planSha256: "f".repeat(64), approvalReference: null }))).recovery.state, "PLAN_GENERATED");
});
