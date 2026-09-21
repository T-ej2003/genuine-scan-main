import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { executeBrokerRecoverySuccessor } from "../aws/component-broker-recovery-successor.mjs";
import { assertEffectiveBootstrapTrustAnchor } from "../aws/component-bootstrap-trust-anchor.mjs";
import { brokerRecoverySuccessorSourceBindings } from "../aws/component-broker-recovery-successor-authorization.mjs";
import { assertBrokerRecoverySuccessorClosureMetadata, brokerRecoverySuccessor, brokerRecoverySuccessorBindings, recoverySuccessorExecutorPolicy } from "../aws/component-broker-recovery-successor-contract.mjs";
import { brokerConfiguration, brokerPolicySuccessorEntryPoints, brokerRecoverySuccessorEntryPoints } from "../aws/component-broker-configuration.mjs";
import { brokerPolicyPredecessor, brokerPolicySuccessorBindings, brokerPolicySuccessorClosureMetadata } from "../aws/component-broker-policy-successor-contract.mjs";
import { brokerChangeOperations, brokerChangePredecessor } from "../aws/component-broker-change-contract.mjs";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, completedBootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident } from "../aws/component-bootstrap-partial-recovery-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, brokerRecoverySuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { canonical, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

const fault = name => Object.assign(new Error(name), { name });
const packageEvidence = (sourceSha, label) => { const bytes = Buffer.from(label), manifest = componentBrokerPackageManifest(sourceSha); return { bytes, manifest, manifestSha256: digest(manifest), packageSha256: createHash("sha256").update(bytes).digest("hex") }; };

function historicalBootstrap(runtime) {
  const proof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256, purpose: "IDENTITY_BOOTSTRAP", principal: `arn:aws:sts::${identityBootstrap.account}:assumed-role/mscqr-production-release-deployer/component-${historicalBootstrapIncident.transitionId}`, issuedAt: "2026-09-18T09:33:54.000Z", expiresAt: "2026-09-18T09:48:54.000Z", issuanceEventId: "12345678-1234-4234-8234-123456789aaa", issuanceEventTime: "2026-09-18T09:33:54.000Z", operatorArn: `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`, mfaAuthenticated: true };
  const identities = bootstrapManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }));
  return { schemaVersion: 1, state: "BOOTSTRAP_CLOSED", sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256, authorization: historicalBootstrapAuthorization(), owner: "12345678-1234-4234-8234-123456789aaa", manifestSha256: historicalBootstrapIncident.manifestSha256, identitySetSha256: historicalBootstrapIncident.identitySetSha256, packageSha256: historicalBootstrapIncident.packageSha256, operatorProof: proof, identities, identityReadbackSha256: digest(identities), runtimeVersions: { 1: runtime, 2: runtime, 3: runtime }, broker: { functionArn: componentBrokerArn, packageSha256: completedBootstrapRecovery.packageSha256, manifestSha256: completedBootstrapRecovery.manifestSha256, runtimeVersions: { 1: runtime, 2: runtime, 3: runtime } }, closedAt: "2026-09-18T12:00:00.000Z",
    recovery: { schemaVersion: 1, state: "RECOVERY_CLOSED", transitionId: completedBootstrapRecovery.transitionId, authorizationSha256: completedBootstrapRecovery.authorizationSha256, sourceSha: completedBootstrapRecovery.sourceSha, oldPackageSha256: historicalBootstrapIncident.packageSha256, newPackageSha256: completedBootstrapRecovery.packageSha256, newManifestSha256: completedBootstrapRecovery.manifestSha256, partialStateSha256: bootstrapPartialStateDigest(), remainingOperations: bootstrapRecoveryOperations, authorizationExpiresAt: "2026-09-18T12:30:00.000Z", sessionExpiresAt: "2026-09-18T12:15:00.000Z", authorizationHistory: [], owner: "12345678-1234-4234-8234-123456789def", closedAt: "2026-09-18T12:01:00.000Z", oldRevisionId: historicalBootstrapIncident.revisionId, finalPackageSha256: completedBootstrapRecovery.packageSha256, finalManifestSha256: completedBootstrapRecovery.manifestSha256, versions: ["1", "2", "3"] },
    brokerChange: { schemaVersion: 1, state: "BROKER_CHANGE_CLOSED", transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "d".repeat(64), authorizationExpiresAt: "2026-09-19T12:30:00.000Z", sessionExpiresAt: "2026-09-19T12:15:00.000Z", authorizationHistory: [], owner: "12345678-1234-4234-8234-123456789def", closedAt: "2026-09-19T12:01:00.000Z", predecessor: brokerChangePredecessor(), sourceSha: brokerPolicyPredecessor.sourceSha, configurationSha256: brokerPolicyPredecessor.configurationSha256, identitySetSha256: brokerPolicyPredecessor.identitySetSha256, identityReadbackSha256: digest(brokerChangeManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }))), remainingOperations: brokerChangeOperations, policyCheckpoints: brokerChangeManagedIdentities().map(({ role }) => role), runtimeVersions: { 4: runtime, 5: runtime, 6: runtime }, successor: { sourceSha: brokerPolicyPredecessor.sourceSha, packageSha256: brokerPolicyPredecessor.packageSha256, lambdaCodeSha256: Buffer.from(brokerPolicyPredecessor.packageSha256, "hex").toString("base64"), manifestSha256: brokerPolicyPredecessor.manifestSha256, configurationSha256: brokerPolicyPredecessor.configurationSha256, identitySetSha256: brokerPolicyPredecessor.identitySetSha256, versions: ["4", "5", "6"] } } };
}

function fixture() {
  const now = Date.parse("2026-09-20T12:00:00.000Z"), runtime = `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}`;
  const firstPackage = packageEvidence("a".repeat(40), "immutable-v7-package"), candidate = packageEvidence("b".repeat(40), "reviewed-v10-package");
  const firstBindings = brokerPolicySuccessorBindings(firstPackage), firstRecord = { schemaVersion: 1, state: "VERIFIED", transitionId: "11111111-1111-4111-8111-111111111111", owner: "22222222-2222-4222-8222-222222222222", authorizationSha256: "1".repeat(64), authorizationExpiresAt: new Date(now + 1000).toISOString(), sessionExpiresAt: new Date(now + 2000).toISOString(), authorizationHistory: [], bindings: firstBindings };
  const firstMetadata = brokerPolicySuccessorClosureMetadata(firstRecord, firstBindings, { 7: runtime, 8: runtime, 9: runtime }, '"first-etag"', new Date(now - 1000).toISOString());
  const firstClosure = JSON.parse(Buffer.from(firstMetadata["broker-policy-successor"], "base64url").toString("utf8"));
  const transitionId = "33333333-3333-4333-8333-333333333333", actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const authorization = { schemaVersion: 1, transitionType: brokerRecoverySuccessor.transitionType, account: identityBootstrap.account, region: identityBootstrap.region, ...brokerRecoverySuccessorSourceBindings(candidate, firstClosure), transitionId, runId: "456", environment: brokerRecoverySuccessor.environment, operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + brokerRecoverySuccessor.maxAgeMs).toISOString() };
  const operatorProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: candidate.manifest.sourceSha, transitionId, authorizationSha256: digest(authorization), purpose: "BROKER_RECOVERY_SUCCESSOR", principal: `arn:aws:sts::${identityBootstrap.account}:assumed-role/mscqr-production-release-deployer/component-${transitionId}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventId: "44444444-4444-4444-8444-444444444444", issuanceEventTime: new Date(now).toISOString(), operatorArn: `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`, mfaAuthenticated: true };
  const oldConfigs = Object.fromEntries(Object.keys(brokerPolicySuccessorEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: firstPackage.packageSha256, manifestSha256: firstPackage.manifestSha256, entryPoint, entryPoints: brokerPolicySuccessorEntryPoints })]));
  const config = value => ({ ...value, CodeSize: 1000, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtime } });
  const predecessor = brokerPolicySuccessorManagedIdentities(), successor = brokerRecoverySuccessorManagedIdentities();
  const policies = new Map(predecessor.map(value => [value.role, value.policy]));
  const journalKey = `${identityBootstrap.prefix}identity-bootstrap.json`, firstKey = `${identityBootstrap.prefix}broker-policy-successor.json`;
  const state = { now, writes: [], metadata: new Map([[journalKey, firstMetadata]]), etags: new Map([[journalKey, '"journal"'], [firstKey, '"first-etag"']]), objects: new Map([[journalKey, historicalBootstrap(runtime)], [firstKey, firstRecord]]), versions: {} };
  state.versions.$LATEST = { ...config(oldConfigs.AUTHORIZE), FunctionArn: componentBrokerArn, Version: "$LATEST", RevisionId: "old" };
  for (let version = 1; version <= 9; version++) state.versions[String(version)] = { ...config(oldConfigs[version % 3 === 1 ? "INSTALL" : version % 3 === 2 ? "CLEANUP" : "AUTHORIZE"]), FunctionArn: `${componentBrokerArn}:${version}`, Version: String(version), RevisionId: `v${version}` };
  const lambda = async (operation, input) => {
    const qualifier = input.Qualifier || "$LATEST", value = state.versions[qualifier];
    if (operation === "GetFunction") { if (!value) throw fault("ResourceNotFoundException"); return { Configuration: structuredClone(value) }; }
    if (operation === "GetPolicy") throw fault("ResourceNotFoundException");
    if (operation === "ListVersionsByFunction") return { Versions: Object.keys(state.versions).map(Version => ({ Version })) };
    if (operation === "GetFunctionConcurrency") return { ReservedConcurrentExecutions: 1 };
    if (operation === "GetFunctionCodeSigningConfig") return {};
    if (operation === "GetRuntimeManagementConfig") return { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
    if (operation === "UpdateFunctionCode") Object.assign(state.versions.$LATEST, { CodeSha256: Buffer.from(candidate.packageSha256, "hex").toString("base64"), RevisionId: "code" });
    else if (operation === "UpdateFunctionConfiguration") Object.assign(state.versions.$LATEST, { Description: input.Description, RevisionId: `description-${state.writes.length}` });
    else if (operation === "PublishVersion") { const version = String(Math.max(...Object.keys(state.versions).filter(v => v !== "$LATEST").map(Number)) + 1); state.versions[version] = { ...structuredClone(state.versions.$LATEST), FunctionArn: `${componentBrokerArn}:${version}`, Version: version, RevisionId: `v${version}` }; }
    else assert.fail(operation);
    state.writes.push(operation); return {};
  };
  const iam = async (operation, input) => {
    const target = predecessor.find(value => value.role === input.RoleName); assert(target); assert.equal(input.PolicyName, target.policyName);
    if (operation === "GetRolePolicy") return { RoleName: input.RoleName, PolicyName: input.PolicyName, PolicyDocument: policies.get(input.RoleName) };
    assert.equal(operation, "PutRolePolicy"); policies.set(input.RoleName, JSON.parse(input.PolicyDocument)); state.writes.push(operation); return {};
  };
  const s3 = async (operation, input) => {
    if (operation === "GetObject") { if (!state.objects.has(input.Key)) throw fault("NoSuchKey"); return { ETag: state.etags.get(input.Key), Metadata: state.metadata.get(input.Key) || {}, Body: { transformToString: async () => JSON.stringify(state.objects.get(input.Key)) } }; }
    assert.equal(operation, "PutObject"); if (input.IfNoneMatch) assert(!state.objects.has(input.Key)); if (input.IfMatch) assert.equal(input.IfMatch, state.etags.get(input.Key)); state.objects.set(input.Key, JSON.parse(input.Body)); state.metadata.set(input.Key, input.Metadata || {}); state.etags.set(input.Key, `"etag-${state.writes.length}"`); state.writes.push(`PutObject:${input.Key}`); return {};
  };
  const exact = identities => identities.every(identity => digest(policies.get(identity.role)) === identity.policySha256);
  state.execute = () => executeBrokerRecoverySuccessor({ authorization, packageEvidence: candidate, operatorProof }, { iam, lambda, s3, authenticate: async () => {}, now: () => state.now, sleep: async () => {}, inspectPredecessor: async () => [{ role: "EXPECTED", policy: exact(predecessor) ? "EXPECTED" : "DRIFT" }], inspectSuccessor: async () => [{ role: "EXPECTED", policy: exact(successor) ? "EXPECTED" : "DRIFT" }], verifyEffective: assertEffectiveBootstrapTrustAnchor });
  return { state, candidate, firstRecord, firstClosure, authorization, operatorProof, policies, successor };
}

test("exact second successor publishes 10/11/12, installs exact policies, closes distinctly and blocks replay", async () => {
  const f = fixture(), result = await f.state.execute();
  assert.equal(result.brokerRecoverySuccessor.state, "BROKER_RECOVERY_SUCCESSOR_CLOSED");
  assert.deepEqual(Object.keys(f.state.versions).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b)), Array.from({ length: 12 }, (_, index) => String(index + 1)));
  assert.equal(digest(f.policies.get(installationIdentity.terraformRole)), digest(recoverySuccessorExecutorPolicy()));
  assert(f.successor.every(identity => digest(f.policies.get(identity.role)) === identity.policySha256));
  assert.deepEqual(f.state.writes.filter(value => ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy"].includes(value)), ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy"]);
  const metadata = f.state.metadata.get(`${identityBootstrap.prefix}identity-bootstrap.json`);
  assert(Object.hasOwn(metadata, "broker-policy-successor")); assert(Object.hasOwn(metadata, "broker-recovery-successor"));
  assert.equal(f.state.objects.get(`${identityBootstrap.prefix}broker-policy-successor.json`), f.firstRecord);
  await assert.rejects(f.state.execute(), /already closed/);
});

test("second successor rejects missing historical reservation, mixed predecessor and arbitrary published versions before mutation", async () => {
  for (const mutate of [
    f => f.state.objects.delete(`${identityBootstrap.prefix}broker-policy-successor.json`),
    f => f.policies.set(installationIdentity.terraformRole, { Version: "2012-10-17", Statement: [] }),
    f => { f.state.versions["13"] = structuredClone(f.state.versions["9"]); f.state.versions["13"].Version = "13"; },
  ]) {
    const f = fixture(); mutate(f); await assert.rejects(f.state.execute());
    assert.equal(f.state.writes.some(value => ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy"].includes(value)), false);
  }
});

test("second successor rejects stale authorization and substituted operator proof before reservation", async () => {
  for (const mutate of [
    f => { f.state.now = Date.parse(f.authorization.expiresAt); },
    f => { f.operatorProof.transitionId = "55555555-5555-4555-8555-555555555555"; },
    f => { f.operatorProof.mfaAuthenticated = false; },
  ]) {
    const f = fixture(); mutate(f); await assert.rejects(f.state.execute()); assert.deepEqual(f.state.writes, []);
    assert.equal(f.state.objects.has(brokerRecoverySuccessor.reservationKey), false);
  }
});

test("second closure authentication rejects reservation substitution and preserves first metadata", async () => {
  const f = fixture(); await f.state.execute();
  const metadata = f.state.metadata.get(`${identityBootstrap.prefix}identity-bootstrap.json`), bindings = brokerRecoverySuccessorBindings(f.candidate, f.firstClosure), reservation = f.state.objects.get(brokerRecoverySuccessor.reservationKey), etag = f.state.etags.get(brokerRecoverySuccessor.reservationKey);
  assertBrokerRecoverySuccessorClosureMetadata(metadata, bindings, reservation, etag);
  assert.throws(() => assertBrokerRecoverySuccessorClosureMetadata(metadata, bindings, { ...reservation, transitionId: "55555555-5555-4555-8555-555555555555" }, etag));
  assert.throws(() => assertBrokerRecoverySuccessorClosureMetadata(metadata, bindings, reservation, '"substituted"'));
  const altered = structuredClone(metadata); altered["broker-policy-successor"] = "changed"; assert.throws(() => assertBrokerRecoverySuccessorClosureMetadata(altered, bindings, reservation, etag));
});
