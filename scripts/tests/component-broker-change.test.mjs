import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { executeBrokerChange } from "../aws/component-broker-change.mjs";
import { assertEffectiveBootstrapTrustAnchor } from "../aws/component-bootstrap-trust-anchor.mjs";
import { brokerChange } from "../aws/component-broker-change-contract.mjs";
import { brokerChangeSourceBindings } from "../aws/component-broker-change-authorization.mjs";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, completedBootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident } from "../aws/component-bootstrap-partial-recovery-contract.mjs";
import { brokerConfiguration, brokerChangeEntryPoints, brokerEntryPoints } from "../aws/component-broker-configuration.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { canonical, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";

const fault = name => Object.assign(new Error(name), { name });
function fixture() {
  const now = Date.parse("2026-09-18T13:00:00Z"), sourceSha = "b".repeat(40), bytes = Buffer.from("exact broker change successor package");
  const manifest = componentBrokerPackageManifest(sourceSha), packageSha256 = createHash("sha256").update(bytes).digest("hex"), packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256, bytes };
  const actor = { type: "User", login: "T-ej2003", id: 183396573 }, bindings = brokerChangeSourceBindings(packageEvidence);
  const authorization = { schemaVersion: 1, transitionType: brokerChange.transitionType, account: identityBootstrap.account, region: identityBootstrap.region, ...bindings, transitionId: "12345678-1234-4234-8234-123456789abc", runId: "456", environment: brokerChange.environment, operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + brokerChange.maxAgeMs).toISOString() };
  const old = Object.fromEntries(Object.keys(brokerEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: completedBootstrapRecovery.packageSha256, manifestSha256: completedBootstrapRecovery.manifestSha256, entryPoint })]));
  const runtimeArn = `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}`, oldIdentities = bootstrapManagedIdentities(), newIdentities = brokerChangeManagedIdentities();
  const identities = new Map(oldIdentities.map(target => [target.role, structuredClone(target)]));
  const operatorProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha, transitionId: authorization.transitionId, authorizationSha256: digest(authorization), purpose: "BROKER_CHANGE", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/component-${authorization.transitionId}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def", issuanceEventTime: new Date(now).toISOString(), operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  const bootstrapIdentities = oldIdentities.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }));
  const originalProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256, purpose: "IDENTITY_BOOTSTRAP", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/component-${historicalBootstrapIncident.transitionId}`, issuedAt: "2026-09-18T09:33:54.000Z", expiresAt: "2026-09-18T09:48:54.000Z", issuanceEventId: "12345678-1234-4234-8234-123456789aaa", issuanceEventTime: "2026-09-18T09:33:54.000Z", operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  const runtimeVersions = { 1: runtimeArn, 2: runtimeArn, 3: runtimeArn };
  const record = { schemaVersion: 1, state: "BOOTSTRAP_CLOSED", sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256, authorization: historicalBootstrapAuthorization(), owner: "12345678-1234-4234-8234-123456789aaa", manifestSha256: historicalBootstrapIncident.manifestSha256, identitySetSha256: historicalBootstrapIncident.identitySetSha256, packageSha256: historicalBootstrapIncident.packageSha256, operatorProof: originalProof, identities: bootstrapIdentities, identityReadbackSha256: digest(bootstrapIdentities), runtimeVersions, broker: { functionArn: componentBrokerArn, packageSha256: completedBootstrapRecovery.packageSha256, manifestSha256: completedBootstrapRecovery.manifestSha256, runtimeVersions }, closedAt: "2026-09-18T12:00:00.000Z", recovery: { schemaVersion: 1, state: "RECOVERY_CLOSED", transitionId: completedBootstrapRecovery.transitionId, authorizationSha256: completedBootstrapRecovery.authorizationSha256, sourceSha: completedBootstrapRecovery.sourceSha, oldPackageSha256: historicalBootstrapIncident.packageSha256, newPackageSha256: completedBootstrapRecovery.packageSha256, newManifestSha256: completedBootstrapRecovery.manifestSha256, partialStateSha256: bootstrapPartialStateDigest(), remainingOperations: bootstrapRecoveryOperations, authorizationExpiresAt: "2026-09-18T12:30:00.000Z", sessionExpiresAt: "2026-09-18T12:15:00.000Z", authorizationHistory: [], owner: "12345678-1234-4234-8234-123456789def", closedAt: "2026-09-18T12:01:00.000Z", oldRevisionId: historicalBootstrapIncident.revisionId, finalPackageSha256: completedBootstrapRecovery.packageSha256, finalManifestSha256: completedBootstrapRecovery.manifestSha256, versions: ["1", "2", "3"] } };
  const state = { now, record, etag: "before", writes: [], s3Writes: 0, before: () => {}, after: () => {}, versions: { $LATEST: { ...old.AUTHORIZE, FunctionArn: componentBrokerArn, Version: "$LATEST", CodeSize: 1000, RevisionId: "old-revision", State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } }, 1: { ...old.INSTALL, CodeSize: 1000, RevisionId: "one", State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } }, 2: { ...old.CLEANUP, CodeSize: 1000, RevisionId: "two", State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } }, 3: { ...old.AUTHORIZE, CodeSize: 1000, RevisionId: "three", State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } } } };
  const iam = async (operation, input) => {
    const target = identities.get(input.RoleName); assert(target, "Unexpected role");
    if (operation === "GetRole") return { Role: { RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration, AssumeRolePolicyDocument: target.trust } };
    if (operation === "GetRolePolicy") return { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: target.policy };
    if (operation === "ListRolePolicies") return { IsTruncated: false, PolicyNames: [target.policyName] };
    if (operation === "ListAttachedRolePolicies") return { IsTruncated: false, AttachedPolicies: [] };
    if (operation === "ListRoleTags") return { IsTruncated: false, Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })) };
    assert.equal(operation, "PutRolePolicy"); assert.equal(input.PolicyName, target.policyName); target.policy = JSON.parse(input.PolicyDocument); target.policySha256 = digest(target.policy); state.writes.push(operation); state.after(operation, state.writes.length); return {};
  };
  const lambda = async (operation, input) => {
    assert.equal(input.FunctionName, installationIdentity.functionName);
    const qualifier = input.Qualifier || "$LATEST";
    if (operation === "GetFunction") { const value = state.versions[qualifier]; if (!value) throw fault("ResourceNotFoundException"); return { Configuration: structuredClone(value) }; }
    if (operation === "GetPolicy") throw fault("ResourceNotFoundException");
    if (operation === "ListVersionsByFunction") return { Versions: Object.keys(state.versions).map(Version => ({ Version })) };
    if (operation === "GetFunctionConcurrency") return { ReservedConcurrentExecutions: 1 };
    if (operation === "GetFunctionCodeSigningConfig") return {};
    if (operation === "GetRuntimeManagementConfig") return { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
    state.before(operation, input);
    if (operation === "UpdateFunctionCode") { assert.equal(input.Publish, false); assert.deepEqual(input.ZipFile, bytes); Object.assign(state.versions.$LATEST, { CodeSha256: Buffer.from(packageSha256, "hex").toString("base64"), RevisionId: "new-code" }); }
    else if (operation === "UpdateFunctionConfiguration") { Object.assign(state.versions.$LATEST, { Description: input.Description, RevisionId: `config-${state.writes.length}` }); }
    else if (operation === "PublishVersion") { const next = String(Object.keys(state.versions).length); state.versions[next] = { ...structuredClone(state.versions.$LATEST), FunctionArn: `${componentBrokerArn}:${next}`, Version: next, RevisionId: `version-${next}` }; }
    else assert.fail(`Unexpected Lambda mutation ${operation}`);
    state.writes.push(operation); state.after(operation, state.writes.length); return {};
  };
  const s3 = async (operation, input) => { assert.equal(input.Bucket, identityBootstrap.bucket); assert.equal(input.Key || input.Prefix, `${identityBootstrap.prefix}identity-bootstrap.json`); if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: [{ Key: input.Prefix }] }; if (operation === "GetObject") return { ETag: state.etag, Body: { transformToString: async () => JSON.stringify(state.record) } }; assert.equal(operation, "PutObject"); assert.equal(input.IfMatch, state.etag); state.record = JSON.parse(input.Body); state.etag = `etag-${++state.s3Writes}`; return { ETag: state.etag }; };
  state.execute = () => executeBrokerChange({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate: async () => {}, now: () => state.now, sleep: async () => {} });
  state.renew = () => { state.now += brokerChange.maxAgeMs + 60_001; authorization.runId = String(Number(authorization.runId) + 1); authorization.approvalObservedAt = new Date(state.now).toISOString(); authorization.expiresAt = new Date(state.now + brokerChange.maxAgeMs).toISOString(); operatorProof.authorizationSha256 = digest(authorization); operatorProof.issuedAt = new Date(state.now).toISOString(); operatorProof.issuanceEventTime = new Date(state.now).toISOString(); operatorProof.expiresAt = new Date(state.now + 900000).toISOString(); };
  return state;
}

test("governed broker change authenticates predecessor, publishes only successor versions and closes", async () => {
  const f = fixture(), result = await f.execute(); assert.equal(result.brokerChange.state, "BROKER_CHANGE_CLOSED");
  assert.equal(f.writes.filter(write => write === "UpdateFunctionCode").length, 1); assert.deepEqual(Object.keys(f.versions).sort(), ["$LATEST", "1", "2", "3", "4", "5", "6"].sort());
  for (const version of ["4", "5", "6"]) assert.equal(f.versions[version].CodeSha256, result.brokerChange.successor.lambdaCodeSha256);
  assert.match(result.brokerChange.successor.packageSha256, /^[a-f0-9]{64}$/);
});

for (const mutate of [
  f => { f.record.schemaVersion = 2; },
  f => { f.versions.$LATEST.CodeSha256 = Buffer.from("d".repeat(64), "hex").toString("base64"); },
  f => { f.versions["4"] = structuredClone(f.versions.$LATEST); },
  f => { f.record.recovery.authorizationSha256 = "d".repeat(64); },
]) test("broker change rejects corrupted predecessor lineage before mutation", async () => { const f = fixture(); mutate(f); await assert.rejects(f.execute()); assert.deepEqual(f.writes, []); assert.equal(f.s3Writes, 0); });

test("ambiguous accepted update and closure reconcile by exact readback without replay", async () => {
  const f = fixture(); let once = true; f.after = operation => { if (operation === "UpdateFunctionCode" && once) { once = false; throw new Error("lost"); } };
  const result = await f.execute(); assert.equal(result.brokerChange.state, "BROKER_CHANGE_CLOSED"); assert.equal(f.writes.filter(write => write === "UpdateFunctionCode").length, 1);
});

test("interrupted broker change requires fresh fenced authorization and rejects malformed checkpoint lineage", async () => {
  const f = fixture(); f.before = operation => { if (operation === "UpdateFunctionConfiguration") throw new Error("interrupted"); };
  await assert.rejects(f.execute()); assert.equal(f.record.brokerChange.state, "CODE_UPDATED");
  const writes = f.writes.length; f.renew(); f.record.brokerChange.policyCheckpoints = [brokerChangeManagedIdentities()[0].role];
  await assert.rejects(f.execute()); assert.equal(f.writes.length, writes);
  f.record.brokerChange.policyCheckpoints = []; f.before = () => {};
  assert.equal((await f.execute()).brokerChange.state, "BROKER_CHANGE_CLOSED");
});

test("broker change resumption reauthenticates the immutable recovery lineage before mutation", async () => {
  const f = fixture(); f.before = operation => { if (operation === "UpdateFunctionConfiguration") throw new Error("interrupted"); };
  await assert.rejects(f.execute()); const writes = f.writes.length;
  f.renew(); f.record.recovery.authorizationSha256 = "d".repeat(64);
  await assert.rejects(f.execute());
  assert.equal(f.writes.length, writes); assert.equal(f.s3Writes, 2);
});

test("broker change resumption rejects an unsupported nested schema before mutation", async () => {
  const f = fixture(); f.before = operation => { if (operation === "UpdateFunctionConfiguration") throw new Error("interrupted"); };
  await assert.rejects(f.execute()); const writes = f.writes.length, checkpoints = f.s3Writes;
  f.renew(); f.before = () => {}; f.record.brokerChange.schemaVersion = 2;
  await assert.rejects(f.execute());
  assert.equal(f.writes.length, writes); assert.equal(f.s3Writes, checkpoints);
});

for (const mutate of [
  change => { change.owner = "not-a-uuid"; },
  change => { change.authorizationExpiresAt = "not-a-timestamp"; },
  change => { change.sessionExpiresAt = "2026-09-18T13:00:00Z"; },
  change => { change.configurationSha256 = "d".repeat(64); },
  change => { change.identitySetSha256 = "d".repeat(64); },
]) test("broker change resumption rejects corrupt closure-bound fields before takeover", async () => {
  const f = fixture(); f.before = operation => { if (operation === "UpdateFunctionConfiguration") throw new Error("interrupted"); };
  await assert.rejects(f.execute()); const writes = f.writes.length, checkpoints = f.s3Writes;
  f.renew(); f.before = () => {}; mutate(f.record.brokerChange);
  await assert.rejects(f.execute());
  assert.equal(f.writes.length, writes); assert.equal(f.s3Writes, checkpoints);
});

test("closed broker change cannot replay and no changed identity receives broker mutation capability", async () => {
  const f = fixture(), closed = await f.execute(); await assert.rejects(f.execute());
  const anchor = assertEffectiveBootstrapTrustAnchor(closed, componentBrokerPackageManifest(closed.brokerChange.sourceSha), closed.brokerChange.successor.packageSha256);
  assert.deepEqual(anchor.entryPoints, brokerChangeEntryPoints);
  for (const mutate of [value => { value.brokerChange.successor.manifestSha256 = "d".repeat(64); }, value => { value.brokerChange.state = "EXECUTING"; }, value => { delete value.brokerChange.closedAt; }]) {
    const invalid = structuredClone(closed); mutate(invalid); assert.throws(() => assertEffectiveBootstrapTrustAnchor(invalid, componentBrokerPackageManifest(closed.brokerChange.sourceSha), closed.brokerChange.successor.packageSha256));
  }
  for (const target of brokerChangeManagedIdentities()) for (const statement of target.policy.Statement) for (const action of [].concat(statement.Action)) assert(!/^(?:lambda:(?:Update|Publish|Create|Delete)|iam:PassRole)/.test(action));
  const broker = brokerChangeManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole);
  const reads = broker.policy.Statement.find(({ Action }) => [].concat(Action).includes("lambda:GetPolicy"));
  assert.deepEqual(reads.Resource, [componentBrokerArn, ...[1, 2, 3, 4, 5, 6].map(version => `${componentBrokerArn}:${version}`)]);
});
