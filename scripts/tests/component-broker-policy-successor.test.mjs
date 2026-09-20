import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { executeBrokerPolicySuccessor } from "../aws/component-broker-policy-successor.mjs";
import { convergeRootMfaIssuance, convergeRootMfaSessionProof } from "../aws/component-broker-policy-successor-cli.mjs";
import { createBrokerPolicySuccessorRootMfaSession } from "../aws/component-broker-policy-successor-root-mfa.mjs";
import { assertEffectiveBootstrapTrustAnchor } from "../aws/component-bootstrap-trust-anchor.mjs";
import { brokerPolicySuccessorSourceBindings } from "../aws/component-broker-policy-successor-authorization.mjs";
import { assertBrokerPolicySuccessorClosureMetadata, brokerPolicyPredecessor, brokerPolicySuccessor, brokerPolicySuccessorBindings, brokerPolicySuccessorConfiguration, predecessorExecutorPolicy, successorExecutorPolicy } from "../aws/component-broker-policy-successor-contract.mjs";
import { brokerChangeEntryPoints, brokerConfiguration, brokerPolicySuccessorEntryPoints } from "../aws/component-broker-configuration.mjs";
import { brokerChangeOperations, brokerChangePredecessor } from "../aws/component-broker-change-contract.mjs";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, completedBootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident } from "../aws/component-bootstrap-partial-recovery-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

const fault = name => Object.assign(new Error(name), { name });
function fixture() {
  const now = Date.parse("2026-09-20T12:00:00.000Z"), sourceSha = "b".repeat(40), bytes = Buffer.from("successor-package");
  const manifest = componentBrokerPackageManifest(sourceSha), packageEvidence = { manifest, manifestSha256: digest(manifest), bytes, packageSha256: createHash("sha256").update(bytes).digest("hex") };
  const actor = { type: "User", login: "T-ej2003", id: 183396573 }, transitionId = "12345678-1234-4234-8234-123456789abc";
  const authorization = { schemaVersion: 1, transitionType: brokerPolicySuccessor.transitionType, account: identityBootstrap.account, region: identityBootstrap.region, ...brokerPolicySuccessorSourceBindings(packageEvidence), transitionId, runId: "456", environment: brokerPolicySuccessor.environment, operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + brokerPolicySuccessor.maxAgeMs).toISOString() };
  const operatorProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha, transitionId, authorizationSha256: digest(authorization), purpose: "BROKER_POLICY_SUCCESSOR", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/component-${transitionId}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def", issuanceEventTime: new Date(now).toISOString(), operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  const runtime = `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}`, old = Object.fromEntries(Object.keys(brokerChangeEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: brokerPolicyPredecessor.packageSha256, manifestSha256: brokerPolicyPredecessor.manifestSha256, entryPoint, entryPoints: brokerChangeEntryPoints })]));
  const config = value => ({ ...value, CodeSize: 1000, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtime } });
  const predecessorIdentities = brokerChangeManagedIdentities(), successorIdentities = brokerPolicySuccessorManagedIdentities();
  const predecessorBroker = predecessorIdentities.find(({ role }) => role === installationIdentity.provisionerRole), successorBroker = successorIdentities.find(({ role }) => role === installationIdentity.provisionerRole);
  const predecessorSession = predecessorIdentities.find(({ role }) => role === identityBootstrap.installationRole);
  const predecessorCleanup = predecessorIdentities.find(({ role }) => role === identityBootstrap.cleanupRole);
  const predecessorAuthorization = predecessorIdentities.find(({ role }) => role === identityBootstrap.authorizationRole);
  const state = { now, rootExpires: now + 3600000, authorization, operatorProof, packageEvidence, runtime, writes: [], iamWrites: [], authentications: 0, after: () => {}, failInspect: false, policy: predecessorExecutorPolicy(), brokerPolicy: predecessorBroker.policy, sessionPolicy: predecessorSession.policy, cleanupPolicy: predecessorCleanup.policy, authorizationPolicy: predecessorAuthorization.policy, etags: new Map([[`${identityBootstrap.prefix}identity-bootstrap.json`, "journal-1"]]), metadata: new Map([[`${identityBootstrap.prefix}identity-bootstrap.json`, {}]]), objects: new Map([[`${identityBootstrap.prefix}identity-bootstrap.json`, { brokerChange: {} }]]), versions: {
    $LATEST: { ...config(old.AUTHORIZE), FunctionArn: componentBrokerArn, Version: "$LATEST", RevisionId: "old" },
    1: { ...config(old.INSTALL), FunctionArn: `${componentBrokerArn}:1`, Version: "1", RevisionId: "one" }, 2: { ...config(old.CLEANUP), FunctionArn: `${componentBrokerArn}:2`, Version: "2", RevisionId: "two" }, 3: { ...config(old.AUTHORIZE), FunctionArn: `${componentBrokerArn}:3`, Version: "3", RevisionId: "three" },
    4: { ...config(old.INSTALL), FunctionArn: `${componentBrokerArn}:4`, Version: "4", RevisionId: "four" }, 5: { ...config(old.CLEANUP), FunctionArn: `${componentBrokerArn}:5`, Version: "5", RevisionId: "five" }, 6: { ...config(old.AUTHORIZE), FunctionArn: `${componentBrokerArn}:6`, Version: "6", RevisionId: "six" },
  } };
  const lambda = async (operation, input) => {
    const qualifier = input.Qualifier || "$LATEST", value = state.versions[qualifier];
    if (operation === "GetFunction") { if (!value) throw fault("ResourceNotFoundException"); return { Configuration: structuredClone(value) }; }
    if (operation === "GetPolicy") throw fault("ResourceNotFoundException");
    if (operation === "ListVersionsByFunction") return { Versions: Object.keys(state.versions).map(Version => ({ Version })) };
    if (operation === "GetFunctionConcurrency") return { ReservedConcurrentExecutions: 1 };
    if (operation === "GetFunctionCodeSigningConfig") return {};
    if (operation === "GetRuntimeManagementConfig") return { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
    if (operation === "UpdateFunctionCode") Object.assign(state.versions.$LATEST, { CodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"), RevisionId: "code" });
    else if (operation === "UpdateFunctionConfiguration") Object.assign(state.versions.$LATEST, { Description: input.Description, RevisionId: "description" });
    else if (operation === "PublishVersion") { const version = String(Math.max(...Object.keys(state.versions).filter(value => value !== "$LATEST").map(Number)) + 1); state.versions[version] = { ...structuredClone(state.versions.$LATEST), FunctionArn: `${componentBrokerArn}:${version}`, Version: version, RevisionId: `version-${version}` }; }
    else assert.fail(operation);
    state.writes.push(operation); state.after(operation); return {};
  };
  const iam = async (operation, input) => {
    const field = input.RoleName === installationIdentity.provisionerRole ? "brokerPolicy" : input.RoleName === identityBootstrap.installationRole ? "sessionPolicy" : input.RoleName === identityBootstrap.cleanupRole ? "cleanupPolicy" : input.RoleName === identityBootstrap.authorizationRole ? "authorizationPolicy" : "policy";
    const identity = predecessorIdentities.find(({ role }) => role === input.RoleName); assert(identity); assert.equal(input.PolicyName, identity.policyName);
    if (operation === "GetRolePolicy") return { RoleName: input.RoleName, PolicyName: input.PolicyName, PolicyDocument: state[field] };
    assert.equal(operation, "PutRolePolicy"); state[field] = JSON.parse(input.PolicyDocument);
    state.writes.push(operation); state.iamWrites.push(input.RoleName); state.after(operation); return {};
  };
  const s3 = async (operation, input) => {
    const key = input.Key;
    if (operation === "GetObject") { if (state.crashNextReadKey === key) { state.crashNextReadKey = null; throw new Error("crash"); } if (!state.objects.has(key)) throw fault("NoSuchKey"); return { ETag: state.etags.get(key), Metadata: state.metadata.get(key) || {}, Body: { transformToString: async () => JSON.stringify(state.objects.get(key)) } }; }
    assert.equal(operation, "PutObject"); if (input.IfNoneMatch) assert(!state.objects.has(key)); if (input.IfMatch) assert.equal(input.IfMatch, state.etags.get(key)); const body = JSON.parse(input.Body); state.objects.set(key, body); state.metadata.set(key, input.Metadata || {}); state.etags.set(key, `${key}-${state.writes.length}`); state.writes.push(`${operation}:${key}`); if ((key === brokerPolicySuccessor.reservationKey && body.state === state.crashAfterCheckpoint) || (key.endsWith("identity-bootstrap.json") && input.Metadata && state.crashAfterClosure)) state.crashNextReadKey = key; state.after(operation); return {};
  };
  const predecessor = () => ({ ...brokerPolicyPredecessor, entryPoints: brokerChangeEntryPoints, allVersions: ["1", "2", "3", "4", "5", "6"], runtimeVersions: { 4: runtime, 5: runtime, 6: runtime } });
  const matches = identities => [["policy", installationIdentity.terraformRole], ["brokerPolicy", installationIdentity.provisionerRole], ["sessionPolicy", identityBootstrap.installationRole], ["cleanupPolicy", identityBootstrap.cleanupRole], ["authorizationPolicy", identityBootstrap.authorizationRole]].every(([field, role]) => digest(state[field]) === identities.find(identity => identity.role === role).policySha256);
  state.execute = () => executeBrokerPolicySuccessor({ authorization: state.authorization, packageEvidence, operatorProof: state.operatorProof }, { iam, lambda, s3, authenticate: async () => { state.authentications += 1; assert(state.now + 120000 < state.rootExpires, "Root MFA session expired"); }, now: () => state.now, sleep: async () => {}, verifyPredecessor: predecessor, inspectPredecessor: async () => [{ role: "EXPECTED", policy: matches(predecessorIdentities) ? "EXPECTED" : "DRIFT" }], inspectSuccessor: async () => { if (state.failInspect) throw new Error("crash"); return [{ role: "EXPECTED", policy: matches(successorIdentities) ? "EXPECTED" : "DRIFT" }]; }, verifyEffective: (value, _manifest, _packageSha256, metadata) => { assert(!Object.hasOwn(value, "brokerPolicySuccessor")); assertBrokerPolicySuccessorClosureMetadata(metadata, brokerPolicySuccessorBindings(packageEvidence)); } });
  state.renew = () => { state.now += brokerPolicySuccessor.maxAgeMs + 120001; state.rootExpires = state.now + 3600000; state.authorization.runId = String(Number(state.authorization.runId) + 1); state.authorization.approvalObservedAt = new Date(state.now).toISOString(); state.authorization.expiresAt = new Date(state.now + brokerPolicySuccessor.maxAgeMs).toISOString(); state.operatorProof.authorizationSha256 = digest(state.authorization); state.operatorProof.issuedAt = state.operatorProof.issuanceEventTime = new Date(state.now).toISOString(); state.operatorProof.expiresAt = new Date(state.now + 900000).toISOString(); };
  return state;
}

test("one-time successor publishes versions 7-9, installs exact policies and closes lineage", async () => {
  const f = fixture(), result = await f.execute(); assert.equal(result.brokerPolicySuccessor.state, "BROKER_POLICY_SUCCESSOR_CLOSED"); for (const version of ["7", "8", "9"]) assert(Object.hasOwn(f.versions, version)); assert.equal(digest(f.policy), digest(successorExecutorPolicy()));
  assert.equal(digest(f.brokerPolicy), digest(brokerPolicySuccessorManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole).policy));
  assert.equal(digest(f.sessionPolicy), brokerPolicySuccessorManagedIdentities().find(({ role }) => role === identityBootstrap.installationRole).policySha256);
  assert.equal(digest(f.cleanupPolicy), brokerPolicySuccessorManagedIdentities().find(({ role }) => role === identityBootstrap.cleanupRole).policySha256);
  assert.equal(digest(f.authorizationPolicy), brokerPolicySuccessorManagedIdentities().find(({ role }) => role === identityBootstrap.authorizationRole).policySha256);
  assert(!Object.hasOwn(f.objects.get(`${identityBootstrap.prefix}identity-bootstrap.json`), "brokerPolicySuccessor")); assert(Object.hasOwn(f.metadata.get(`${identityBootstrap.prefix}identity-bootstrap.json`), "broker-policy-successor"));
  assert.deepEqual(f.writes.filter(value => ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy"].includes(value)), ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy", "PutRolePolicy"]);
  assert.deepEqual(f.iamWrites, [installationIdentity.provisionerRole, installationIdentity.terraformRole, identityBootstrap.installationRole, identityBootstrap.cleanupRole, identityBootstrap.authorizationRole]);
  await assert.rejects(f.execute(), /already closed/);
});

test("intended root-MFA path authenticates repeated same-session proof before one-time successor closure", async () => {
  const f = fixture(), accessKeyId = "SESSIONKEY", rootArn = `arn:aws:iam::${identityBootstrap.account}:root`, serial = `arn:aws:iam::${identityBootstrap.account}:mfa/root-fixture`, expiration = new Date(f.rootExpires).toISOString();
  const base = { AccessKeyId: "BASEKEY", SecretAccessKey: "base-secret" }, issued = { AccessKeyId: accessKeyId, SecretAccessKey: "session-secret", SessionToken: "session-token", Expiration: expiration }, closed = [];
  const session = await createBrokerPolicySuccessorRootMfaSession({ load: async () => ({ credentials: base, serial }), mfa: async () => "123456", now: () => f.now, sts: value => ({
    close: () => closed.push(Boolean(value.SessionToken)), send: async operation => operation === "GetSessionToken" ? { Credentials: issued } : { Account: identityBootstrap.account, Arn: rootArn },
  }) });
  const issuance = { eventSource: "sts.amazonaws.com", eventName: "GetSessionToken", awsRegion: identityBootstrap.region, userIdentity: { type: "Root", accountId: identityBootstrap.account, arn: rootArn }, requestParameters: { serialNumber: serial, durationSeconds: 3600 }, responseElements: { credentials: { accessKeyId, expiration } } };
  const proof = { eventSource: "sts.amazonaws.com", eventName: "GetCallerIdentity", awsRegion: identityBootstrap.region, userIdentity: { type: "Root", accountId: identityBootstrap.account, arn: rootArn, accessKeyId, sessionContext: { attributes: { mfaAuthenticated: "true" } } } };
  await convergeRootMfaIssuance({ events: async () => [issuance], accessKeyId, rootExpires: f.rootExpires, mfaSerial: serial, durationSeconds: 3600, now: () => f.now, sleep: async () => {}, maxWaitMs: 1 });
  await convergeRootMfaSessionProof({ events: async () => [proof, structuredClone(proof)], accessKeyId, rootExpires: f.rootExpires, now: () => f.now, sleep: async () => {}, maxWaitMs: 1 });
  assert.equal((await f.execute()).brokerPolicySuccessor.state, "BROKER_POLICY_SUCCESSOR_CLOSED"); await assert.rejects(f.execute(), /already closed/);
  session.close(); assert.deepEqual(session.credentials, {}); assert.deepEqual(closed, [false, true]);
});

for (const boundary of ["authorization", "operator", "root"]) test(`successor performs zero infrastructure mutation when ${boundary} freshness expires after reservation`, async () => {
  const f = fixture(); let advanced = false; f.after = operation => {
    if (!advanced && operation === "PutObject") { advanced = true; f.now = boundary === "authorization" ? Date.parse(f.authorization.expiresAt) : boundary === "operator" ? Date.parse(f.operatorProof.expiresAt) : f.rootExpires - 120000; }
  };
  await assert.rejects(f.execute());
  assert.equal(f.writes.some(value => ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy"].includes(value)), false);
});

for (const stopAfter of ["UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "PutRolePolicy"]) test(`successor reconciles an ambiguous ${stopAfter} response without replay`, async () => {
  const f = fixture(); let stopped = false; f.after = operation => { if (!stopped && operation === stopAfter) { stopped = true; throw new Error("crash"); } };
  assert.equal((await f.execute()).brokerPolicySuccessor.state, "BROKER_POLICY_SUCCESSOR_CLOSED");
  assert.equal(f.writes.filter(value => value === stopAfter).length, stopAfter === "PutRolePolicy" ? 5 : stopAfter === "UpdateFunctionCode" ? 1 : 3);
  if (stopAfter === "PutRolePolicy") assert.deepEqual(f.iamWrites, [installationIdentity.provisionerRole, installationIdentity.terraformRole, identityBootstrap.installationRole, identityBootstrap.cleanupRole, identityBootstrap.authorizationRole]);
});

test("wrong predecessor policy, version lineage or policy widening fails before IAM mutation", async () => {
  for (const mutate of [f => { f.policy.Statement.push({ Effect: "Allow", Action: "s3:*", Resource: "*" }); }, f => { f.brokerPolicy.Statement.push({ Effect: "Allow", Action: "lambda:*", Resource: "*" }); }, f => { delete f.versions["6"]; }, f => { f.versions["4"].Description = "wrong"; }]) {
    const f = fixture(); mutate(f); await assert.rejects(f.execute()); assert(!f.writes.includes("PutRolePolicy"));
  }
});

test("interrupted successor requires a fresh authorization after the prior owner is fenced", async () => {
  const f = fixture(); f.failInspect = true; await assert.rejects(f.execute(), /crash/); assert.equal(f.objects.get(brokerPolicySuccessor.reservationKey).state, "AUTHORIZATION_SESSION_POLICY_INSTALLED");
  f.renew(); f.failInspect = false; const result = await f.execute(); assert.equal(result.brokerPolicySuccessor.state, "BROKER_POLICY_SUCCESSOR_CLOSED"); assert.equal(result.brokerPolicySuccessor.authorizationHistory.length, 1);
});

for (const checkpoint of ["EXECUTING", "CODE_UPDATED", "INSTALL_DESCRIPTION_SET", "INSTALL_VERSION_PUBLISHED", "CLEANUP_DESCRIPTION_SET", "CLEANUP_VERSION_PUBLISHED", "AUTHORIZE_DESCRIPTION_SET", "AUTHORIZE_VERSION_PUBLISHED", "BROKER_POLICY_INSTALLED", "POLICY_INSTALLED", "INSTALLATION_SESSION_POLICY_INSTALLED", "CLEANUP_SESSION_POLICY_INSTALLED", "AUTHORIZATION_SESSION_POLICY_INSTALLED", "VERIFIED"]) test(`successor resumes safely after process death at ${checkpoint}`, async () => {
  const f = fixture(); f.crashAfterCheckpoint = checkpoint; await assert.rejects(f.execute(), /crash/); assert.equal(f.objects.get(brokerPolicySuccessor.reservationKey).state, checkpoint);
  f.crashAfterCheckpoint = null; f.renew(); assert.equal((await f.execute()).brokerPolicySuccessor.state, "BROKER_POLICY_SUCCESSOR_CLOSED");
});

test("a lost closure response remains durably closed and blocks replay", async () => {
  const f = fixture(), key = `${identityBootstrap.prefix}identity-bootstrap.json`; f.crashAfterClosure = true; await assert.rejects(f.execute(), /crash/); assert(Object.hasOwn(f.metadata.get(key), "broker-policy-successor"));
  f.renew(); await assert.rejects(f.execute(), /already closed/);
});

test("the production trust anchor authenticates the exact predecessor and successor generations", async () => {
  const f = fixture(); await f.execute();
  const originalProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId,
    authorizationSha256: historicalBootstrapIncident.authorizationSha256, purpose: "IDENTITY_BOOTSTRAP", principal: `arn:aws:sts::${identityBootstrap.account}:assumed-role/mscqr-production-release-deployer/component-${historicalBootstrapIncident.transitionId}`,
    issuedAt: "2026-09-18T09:33:54.000Z", expiresAt: "2026-09-18T09:48:54.000Z", issuanceEventId: "12345678-1234-4234-8234-123456789aaa", issuanceEventTime: "2026-09-18T09:33:54.000Z",
    operatorArn: `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`, mfaAuthenticated: true };
  const bootstrapIdentities = bootstrapManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }));
  const journal = { schemaVersion: 1, state: "BOOTSTRAP_CLOSED", sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId,
    authorizationSha256: historicalBootstrapIncident.authorizationSha256, authorization: historicalBootstrapAuthorization(), owner: "12345678-1234-4234-8234-123456789aaa", manifestSha256: historicalBootstrapIncident.manifestSha256,
    identitySetSha256: historicalBootstrapIncident.identitySetSha256, packageSha256: historicalBootstrapIncident.packageSha256, operatorProof: originalProof, identities: bootstrapIdentities,
    identityReadbackSha256: digest(bootstrapIdentities), runtimeVersions: { 1: f.runtime, 2: f.runtime, 3: f.runtime }, broker: { functionArn: componentBrokerArn, packageSha256: completedBootstrapRecovery.packageSha256,
      manifestSha256: completedBootstrapRecovery.manifestSha256, runtimeVersions: { 1: f.runtime, 2: f.runtime, 3: f.runtime } }, closedAt: "2026-09-18T12:00:00.000Z",
    recovery: { schemaVersion: 1, state: "RECOVERY_CLOSED", transitionId: completedBootstrapRecovery.transitionId, authorizationSha256: completedBootstrapRecovery.authorizationSha256, sourceSha: completedBootstrapRecovery.sourceSha,
      oldPackageSha256: historicalBootstrapIncident.packageSha256, newPackageSha256: completedBootstrapRecovery.packageSha256, newManifestSha256: completedBootstrapRecovery.manifestSha256,
      partialStateSha256: bootstrapPartialStateDigest(), remainingOperations: bootstrapRecoveryOperations, authorizationExpiresAt: "2026-09-18T12:30:00.000Z", sessionExpiresAt: "2026-09-18T12:15:00.000Z",
      authorizationHistory: [], owner: "12345678-1234-4234-8234-123456789def", closedAt: "2026-09-18T12:01:00.000Z", oldRevisionId: historicalBootstrapIncident.revisionId,
      finalPackageSha256: completedBootstrapRecovery.packageSha256, finalManifestSha256: completedBootstrapRecovery.manifestSha256, versions: ["1", "2", "3"] },
    brokerChange: { schemaVersion: 1, state: "BROKER_CHANGE_CLOSED", transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "d".repeat(64), authorizationExpiresAt: "2026-09-19T12:30:00.000Z",
      sessionExpiresAt: "2026-09-19T12:15:00.000Z", authorizationHistory: [], owner: "12345678-1234-4234-8234-123456789def", closedAt: "2026-09-19T12:01:00.000Z", predecessor: brokerChangePredecessor(),
      sourceSha: brokerPolicyPredecessor.sourceSha, configurationSha256: brokerPolicyPredecessor.configurationSha256, identitySetSha256: brokerPolicyPredecessor.identitySetSha256,
      identityReadbackSha256: digest(brokerChangeManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }))), remainingOperations: brokerChangeOperations,
      policyCheckpoints: brokerChangeManagedIdentities().map(({ role }) => role), runtimeVersions: { 4: f.runtime, 5: f.runtime, 6: f.runtime }, successor: { sourceSha: brokerPolicyPredecessor.sourceSha,
        packageSha256: brokerPolicyPredecessor.packageSha256, lambdaCodeSha256: Buffer.from(brokerPolicyPredecessor.packageSha256, "hex").toString("base64"), manifestSha256: brokerPolicyPredecessor.manifestSha256,
        configurationSha256: brokerPolicyPredecessor.configurationSha256, identitySetSha256: brokerPolicyPredecessor.identitySetSha256, versions: ["4", "5", "6"] } } };
  const metadata = f.metadata.get(`${identityBootstrap.prefix}identity-bootstrap.json`), anchor = assertEffectiveBootstrapTrustAnchor(journal, f.packageEvidence.manifest, f.packageEvidence.packageSha256, metadata);
  assert.deepEqual(anchor.entryPoints, brokerPolicySuccessorEntryPoints); assert.equal(anchor.predecessor.packageSha256, brokerPolicyPredecessor.packageSha256);
  const substituted = structuredClone(journal); substituted.brokerChange.successor.packageSha256 = "e".repeat(64);
  assert.throws(() => assertEffectiveBootstrapTrustAnchor(substituted, f.packageEvidence.manifest, f.packageEvidence.packageSha256, metadata));
  const malformed = structuredClone(journal); malformed.brokerChange.transitionId = "not-a-transition";
  assert.throws(() => assertEffectiveBootstrapTrustAnchor(malformed, f.packageEvidence.manifest, f.packageEvidence.packageSha256, metadata));
  const substitutedMetadata = structuredClone(metadata), closure = JSON.parse(Buffer.from(substitutedMetadata["broker-policy-successor"], "base64url").toString("utf8"));
  closure.bindingsSha256 = "f".repeat(64); substitutedMetadata["broker-policy-successor"] = Buffer.from(JSON.stringify(closure)).toString("base64url");
  assert.throws(() => assertEffectiveBootstrapTrustAnchor(journal, f.packageEvidence.manifest, f.packageEvidence.packageSha256, substitutedMetadata));
});

test("successor configuration is immutable install version 7", () => { const f = fixture(), expected = brokerPolicySuccessorConfiguration({ manifest: componentBrokerPackageManifest("b".repeat(40)), manifestSha256: digest(componentBrokerPackageManifest("b".repeat(40))), packageSha256: createHash("sha256").update("successor-package").digest("hex") }); assert.match(expected.Description, /INSTALL/); assert.equal(f.versions["4"].Version, "4"); });
