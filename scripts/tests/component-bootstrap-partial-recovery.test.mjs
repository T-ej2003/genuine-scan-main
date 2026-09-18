import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { executeBootstrapRecovery } from "../aws/component-bootstrap-partial-recovery.mjs";
import { recoverySourceBindings } from "../aws/component-bootstrap-partial-recovery-authorization.mjs";
import { bootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident, historicalBrokerConfiguration } from "../aws/component-bootstrap-partial-recovery-contract.mjs";
import { brokerConfiguration } from "../aws/component-broker-configuration.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { canonical, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";

function fixture() {
  const now = Date.parse("2026-09-18T12:00:00Z"), sourceSha = "b".repeat(40), bytes = Buffer.from("corrected deterministic broker package");
  const manifest = componentBrokerPackageManifest(sourceSha), packageSha256 = createHash("sha256").update(bytes).digest("hex");
  const packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256, bytes };
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const authorization = { schemaVersion: 1, transitionType: bootstrapRecovery.transitionType, account: identityBootstrap.account, region: identityBootstrap.region,
    ...recoverySourceBindings(packageEvidence), transitionId: "12345678-1234-4234-8234-123456789abc", runId: "456", environment: bootstrapRecovery.environment,
    operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + bootstrapRecovery.maxAgeMs).toISOString() };
  const authorizationSha256 = digest(authorization), targets = bootstrapManagedIdentities();
  const old = historicalBrokerConfiguration(), runtimeArn = historicalBootstrapIncident.runtimeVersionArn;
  const state = {
    clock: now, writes: [], after: () => {}, before: () => {}, policies: new Set(), concurrency: {}, runtime: { UpdateRuntimeOn: "Auto", RuntimeVersionArn: null },
    versions: { $LATEST: { ...old, CodeSize: 1000, RevisionId: historicalBootstrapIncident.revisionId, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } } },
    record: { schemaVersion: 1, state: "BOOTSTRAP_EXECUTING", sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId,
      authorizationSha256: historicalBootstrapIncident.authorizationSha256, authorization: historicalBootstrapAuthorization(), owner: "12345678-1234-4234-8234-123456789aaa",
      manifestSha256: historicalBootstrapIncident.manifestSha256, identitySetSha256: historicalBootstrapIncident.identitySetSha256,
      packageSha256: historicalBootstrapIncident.packageSha256, operatorProof: { account: identityBootstrap.account, region: identityBootstrap.region,
        sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256,
        purpose: "IDENTITY_BOOTSTRAP", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/component-${historicalBootstrapIncident.transitionId}`,
        issuedAt: "2026-09-18T09:33:54.000Z", expiresAt: "2026-09-18T09:48:54.000Z", issuanceEventId: "12345678-1234-4234-8234-123456789aaa",
        issuanceEventTime: "2026-09-18T09:33:54.000Z", operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true } },
    etag: historicalBootstrapIncident.journalEtag, s3Writes: 0, afterS3: () => {},
  };
  const iam = async (operation, input) => {
    const target = targets.find(value => value.role === input.RoleName); assert(target);
    return {
      GetRole: { Role: { RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration,
        AssumeRolePolicyDocument: target.trust, Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })) } },
      GetRolePolicy: { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: target.policy },
      ListRolePolicies: { PolicyNames: [target.policyName], IsTruncated: false }, ListAttachedRolePolicies: { AttachedPolicies: [], IsTruncated: false },
      ListRoleTags: { Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })), IsTruncated: false },
    }[operation];
  };
  const absent = () => { throw Object.assign(new Error("absent"), { name: "ResourceNotFoundException" }); };
  const lambda = async (operation, input) => {
    assert.equal(input.FunctionName, installationIdentity.functionName);
    const version = input.Qualifier || "$LATEST";
    if (operation === "GetFunction") return state.versions[version] ? { Configuration: structuredClone(state.versions[version]), Code: { RepositoryType: "S3", Location: "https://example.invalid/?X-Amz-Signature=secret" } } : absent();
    if (operation === "GetPolicy") return state.policies.has(version) ? { Policy: "unexpected" } : absent();
    if (operation === "ListVersionsByFunction") return { Versions: Object.keys(state.versions).map(Version => ({ Version })) };
    if (operation === "GetFunctionConcurrency") return structuredClone(state.concurrency);
    if (operation === "GetFunctionCodeSigningConfig") return { $metadata: { httpStatusCode: 200 } };
    if (operation === "GetRuntimeManagementConfig") return structuredClone(state.runtime);
    state.before(operation, input);
    if (operation === "UpdateFunctionCode") {
      assert.deepEqual(Object.keys(input).sort(), ["FunctionName", "Publish", "RevisionId", "ZipFile"]); assert.equal(input.Publish, false);
      assert.equal(input.RevisionId, historicalBootstrapIncident.revisionId); assert.deepEqual(input.ZipFile, bytes);
      Object.assign(state.versions.$LATEST, { CodeSha256: Buffer.from(packageSha256, "hex").toString("base64"), RevisionId: "revision-code" });
    } else if (operation === "UpdateFunctionConfiguration") {
      assert.deepEqual(Object.keys(input).sort(), ["Description", "FunctionName", "RevisionId"]); assert.equal(input.RevisionId, state.versions.$LATEST.RevisionId);
      Object.assign(state.versions.$LATEST, { Description: input.Description, RevisionId: `revision-${state.writes.length + 1}` });
    } else if (operation === "PutFunctionConcurrency") state.concurrency = { ReservedConcurrentExecutions: input.ReservedConcurrentExecutions };
    else if (operation === "PutRuntimeManagementConfig") state.runtime = { UpdateRuntimeOn: input.UpdateRuntimeOn, RuntimeVersionArn: null };
    else if (operation === "PublishVersion") {
      assert.equal(input.CodeSha256, Buffer.from(packageSha256, "hex").toString("base64")); assert.equal(input.RevisionId, state.versions.$LATEST.RevisionId);
      const next = String(Object.keys(state.versions).length); state.versions[next] = { ...structuredClone(state.versions.$LATEST), FunctionArn: `${componentBrokerArn}:${next}`, Version: next };
    } else assert.fail(`Unexpected Lambda write ${operation}`);
    state.writes.push(operation); state.after(operation, state.writes.length); return {};
  };
  const s3 = async (operation, input) => {
    assert.equal(input.Bucket, identityBootstrap.bucket); assert.equal(input.Key || input.Prefix, `${identityBootstrap.prefix}identity-bootstrap.json`);
    if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: [{ Key: input.Prefix }] };
    if (operation === "GetObject") return { ETag: state.etag, Body: { transformToString: async () => JSON.stringify(state.record) } };
    assert.equal(operation, "PutObject"); assert.equal(input.IfMatch, state.etag); assert.equal(input.ServerSideEncryption, "AES256");
    state.record = JSON.parse(input.Body); state.etag = `"recovery-${++state.s3Writes}"`; state.afterS3(state.s3Writes); return { ETag: state.etag };
  };
  const operatorProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha, transitionId: authorization.transitionId, authorizationSha256,
    purpose: "IDENTITY_BOOTSTRAP", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/component-${authorization.transitionId}`,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def",
    issuanceEventTime: new Date(now).toISOString(), operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  state.authenticate = async () => {};
  state.renew = (advance = bootstrapRecovery.maxAgeMs + 60_001) => {
    state.clock += advance;
    authorization.runId = String(Number(authorization.runId) + 1);
    authorization.approvalObservedAt = new Date(state.clock).toISOString();
    authorization.expiresAt = new Date(state.clock + bootstrapRecovery.maxAgeMs).toISOString();
    operatorProof.authorizationSha256 = digest(authorization);
    operatorProof.issuedAt = new Date(state.clock).toISOString();
    operatorProof.issuanceEventTime = new Date(state.clock).toISOString();
    operatorProof.expiresAt = new Date(state.clock + 900_000).toISOString();
    operatorProof.issuanceEventId = `12345678-1234-4234-8234-${String(123456789000 + Number(authorization.runId)).slice(-12)}`;
  };
  state.execute = () => executeBootstrapRecovery({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate: state.authenticate, now: () => state.clock, sleep: async () => {} });
  return state;
}

test("production-shaped partial bootstrap repairs exact package then forward-completes without IAM or CreateFunction writes", async () => {
  const f = fixture(), closed = await f.execute(); assert.equal(closed.state, "BOOTSTRAP_CLOSED");
  assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
  assert.deepEqual(f.writes, ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PutFunctionConcurrency", "PutRuntimeManagementConfig", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion"]);
  assert.deepEqual(Object.keys(f.versions).sort(), ["$LATEST", "1", "2", "3"].sort());
  for (const version of ["1", "2", "3"]) assert.notEqual(f.versions[version].CodeSha256, historicalBootstrapIncident.lambdaCodeSha256);
  assert.equal(closed.recovery.state, "RECOVERY_CLOSED"); assert.equal(f.s3Writes, 2);
  assert.doesNotMatch(JSON.stringify(closed), /Location|X-Amz-Credential|X-Amz-Signature|X-Amz-Security-Token/);
});

test("accepted-but-lost code update is read back and never repeated", async () => {
  const f = fixture(); f.after = (operation) => { if (operation === "UpdateFunctionCode") throw new Error("timeout"); };
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED"); assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});

for (let boundary = 1; boundary <= 2; boundary++) test(`accepted-but-lost guarded recovery write ${boundary} is reconciled in place`, async () => {
  const f = fixture(); f.after = (_operation, count) => { if (count === boundary) throw new Error("timeout"); };
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED"); assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});
for (let boundary = 3; boundary <= 9; boundary++) test(`accepted-but-lost forward-completion write ${boundary} resumes from live readback`, async () => {
  const f = fixture(); f.after = (_operation, count) => { if (count === boundary) throw new Error("timeout"); };
  await assert.rejects(f.execute()); f.after = () => {}; f.renew();
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED"); assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});

test("accepted-but-lost recovery claim and closure are reconciled by exact journal readback", async () => {
  for (const boundary of [1, 2]) {
    const f = fixture(); f.afterS3 = count => { if (count === boundary) throw new Error("timeout"); };
    assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED"); assert.equal(f.s3Writes, 2);
  }
});

test("two concurrent recoveries have one journal-CAS winner", async () => {
  const f = fixture(), outcomes = await Promise.allSettled([f.execute(), f.execute()]);
  assert.equal(outcomes.filter(value => value.status === "fulfilled").length, 1); assert.equal(outcomes.filter(value => value.status === "rejected").length, 1);
  assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});

test("expired recovery owner transfers only through fresh approval, fenced session and CAS", async () => {
  const f = fixture(); f.after = (_operation, count) => { if (count === 3) throw new Error("lost controller"); };
  await assert.rejects(f.execute(), /lost controller/); f.after = () => {};
  await assert.rejects(f.execute(), /fresh approval/);
  f.renew(bootstrapRecovery.maxAgeMs - 1);
  await assert.rejects(f.execute(), /safely fenced/);
  f.renew(60_002);
  assert.equal((await f.execute()).state, "BOOTSTRAP_CLOSED");
  assert.equal(f.record.recovery.authorizationHistory.length, 1);
  assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});

test("concurrent fenced resumptions have one CAS owner before any remaining Lambda write", async () => {
  const f = fixture(); f.after = (_operation, count) => { if (count === 3) throw new Error("lost controller"); };
  await assert.rejects(f.execute()); f.after = () => {}; f.renew();
  const before = f.writes.length, outcomes = await Promise.allSettled([f.execute(), f.execute()]);
  assert.equal(outcomes.filter(value => value.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter(value => value.status === "rejected").length, 1);
  assert.equal(f.writes.slice(before).filter(value => value === "PublishVersion").length, 3);
});

test("definite pre-acceptance package failure leaves old code and never retries blindly", async () => {
  const f = fixture(); f.before = operation => { if (operation === "UpdateFunctionCode") throw new Error("not accepted"); };
  await assert.rejects(f.execute(), /did not converge/); assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 0);
});

test("expired recovery approval and protected-source movement fail before mutation", async () => {
  const expired = fixture(); expired.clock += bootstrapRecovery.maxAgeMs; await assert.rejects(expired.execute()); assert.equal(expired.s3Writes, 0);
  const moved = fixture(); moved.authenticate = async () => { throw new Error("Protected main moved"); };
  await assert.rejects(moved.execute(), /Protected main moved/); assert.equal(moved.s3Writes, 0); assert.deepEqual(moved.writes, []);
});

for (const drift of [
  f => { f.versions.$LATEST.CodeSha256 = Buffer.from("d".repeat(64), "hex").toString("base64"); },
  f => { f.versions.$LATEST.Role = "arn:aws:iam::368992683803:role/other"; },
  f => { f.versions["1"] = structuredClone(f.versions.$LATEST); f.versions["1"].Version = "1"; },
  f => { f.policies.add("$LATEST"); },
  f => { f.etag = '"different"'; },
  f => { f.record.transitionId = "different"; },
  f => { f.record.authorization = { forged: true }; },
]) test("different historical incident state fails before recovery mutation", async () => {
  const f = fixture(); drift(f); await assert.rejects(f.execute()); assert.deepEqual(f.writes, []); assert.equal(f.s3Writes, 0);
});

test("package repair structurally rejects publish, alternate function and configuration smuggling", async () => {
  const f = fixture(); f.before = (operation, input) => {
    if (operation === "UpdateFunctionCode") {
      assert.equal(input.FunctionName, installationIdentity.functionName); assert.equal(input.Publish, false);
      assert.equal("Architectures" in input || "S3Bucket" in input || "ImageUri" in input, false);
    }
  };
  await f.execute();
});

test("post-bootstrap identities cannot compose broker replacement, authority mutation and invocation", () => {
  for (const target of bootstrapManagedIdentities()) {
    const actions = target.policy.Statement.flatMap(statement => [].concat(statement.Action));
    assert(!actions.includes("lambda:UpdateFunctionCode")); assert(!actions.includes("lambda:UpdateFunctionConfiguration"));
    assert(!actions.includes("iam:PassRole"));
  }
});

test("closed recovery authorization and ordinary bootstrap are not replayable", async () => {
  const f = fixture(); await f.execute(); await assert.rejects(f.execute()); assert.equal(f.writes.filter(value => value === "UpdateFunctionCode").length, 1);
});
