import assert from "node:assert/strict";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, completedBootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident } from "./component-bootstrap-partial-recovery-contract.mjs";
import { brokerChangeConfigurationSha256, brokerChangeOperations, brokerChangePredecessor } from "./component-broker-change-contract.mjs";
import { brokerChangeEntryPoints, brokerEntryPoints, brokerPolicySuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { assertBrokerPolicySuccessorClosureMetadata, brokerPolicySuccessorBindings, brokerPolicySuccessorMetadataKey } from "./component-broker-policy-successor-contract.mjs";
import { digest } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, componentBrokerArn } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";

const sha256 = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
const timestamp = value => assert.equal(new Date(Date.parse(value)).toISOString(), value);

function assertHistoricalLineage(bootstrap) {
  const incident = historicalBootstrapIncident;
  for (const [field, expected] of Object.entries({ sourceSha: incident.sourceSha, transitionId: incident.transitionId,
    authorizationSha256: incident.authorizationSha256, manifestSha256: incident.manifestSha256,
    identitySetSha256: incident.identitySetSha256, packageSha256: incident.packageSha256 })) assert.equal(bootstrap[field], expected, `Historical bootstrap ${field} differs`);
  assert.deepEqual(bootstrap.authorization, historicalBootstrapAuthorization());
  assertComponentSessionRecord(bootstrap.operatorProof);
  for (const [field, expected] of Object.entries({ sourceSha: incident.sourceSha, transitionId: incident.transitionId,
    authorizationSha256: incident.authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" })) assert.equal(bootstrap.operatorProof[field], expected);
  uuid(bootstrap.owner);
}

function assertRecoveredClosure(bootstrap, manifest, packageSha256) {
  const expectedKeys = ["authorization", "authorizationSha256", "broker", ...(Object.hasOwn(bootstrap, "brokerChange") ? ["brokerChange"] : []), "closedAt", "identities", "identityReadbackSha256", "identitySetSha256", "manifestSha256", "operatorProof", "owner", "packageSha256", "recovery", "runtimeVersions", "schemaVersion", "sourceSha", "state", "transitionId"];
  assert.deepEqual(Object.keys(bootstrap).sort(), expectedKeys.sort(), "Malformed recovered bootstrap closure");
  assert.equal(bootstrap.schemaVersion, 1);
  assertHistoricalLineage(bootstrap);
  assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED"); timestamp(bootstrap.closedAt);
  assert(Array.isArray(bootstrap.identities));
  assert.deepEqual(bootstrap.identities.map(({ arn }) => arn), bootstrapManagedIdentities().map(({ arn }) => arn));
  for (const identity of bootstrap.identities) {
    assert.deepEqual(Object.keys(identity).sort(), ["arn", "policy", "role"]);
    assert.equal(identity.role, "EXPECTED"); assert.equal(identity.policy, "EXPECTED");
  }
  assert.equal(bootstrap.identityReadbackSha256, digest(bootstrap.identities));
  assert.equal(bootstrap.identitySetSha256, digest(bootstrapManagedIdentities()), "Recovery identity set differs");
  const recovery = bootstrap.recovery;
  const recoveryKeys = ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "closedAt", "finalManifestSha256", "finalPackageSha256", "newManifestSha256", "newPackageSha256", "oldPackageSha256", "oldRevisionId", "owner", "partialStateSha256", "remainingOperations", "schemaVersion", "sessionExpiresAt", "sourceSha", "state", "transitionId", "versions"];
  assert(recovery && typeof recovery === "object" && !Array.isArray(recovery), "Missing recovery closure");
  assert.deepEqual(Object.keys(recovery).sort(), recoveryKeys.sort(), "Malformed recovery closure");
  assert.equal(recovery.schemaVersion, 1); assert.equal(recovery.state, "RECOVERY_CLOSED");
  uuid(recovery.owner);
  for (const field of ["transitionId", "authorizationSha256", "sourceSha"]) assert.equal(recovery[field], completedBootstrapRecovery[field], `Recovery ${field} differs`);
  for (const field of ["newPackageSha256", "finalPackageSha256"]) assert.equal(recovery[field], completedBootstrapRecovery.packageSha256, `Recovery ${field} differs`);
  for (const field of ["newManifestSha256", "finalManifestSha256"]) assert.equal(recovery[field], completedBootstrapRecovery.manifestSha256, `Recovery ${field} differs`);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt", "closedAt"]) timestamp(recovery[field]);
  assert.deepEqual(recovery.remainingOperations, bootstrapRecoveryOperations);
  assert.equal(recovery.oldPackageSha256, historicalBootstrapIncident.packageSha256);
  assert.equal(recovery.oldRevisionId, historicalBootstrapIncident.revisionId);
  assert.equal(recovery.partialStateSha256, bootstrapPartialStateDigest());
  assert(Array.isArray(recovery.authorizationHistory));
  const authorizations = new Set([recovery.authorizationSha256]);
  for (const prior of recovery.authorizationHistory) {
    assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]);
    sha256(prior.authorizationSha256); uuid(prior.owner); timestamp(prior.authorizationExpiresAt); timestamp(prior.sessionExpiresAt);
    assert(!authorizations.has(prior.authorizationSha256), "Repeated recovery authorization"); authorizations.add(prior.authorizationSha256);
  }
  assert.deepEqual(bootstrap.broker, { functionArn: componentBrokerArn, packageSha256: completedBootstrapRecovery.packageSha256,
    manifestSha256: completedBootstrapRecovery.manifestSha256, runtimeVersions: bootstrap.runtimeVersions });
  assert.deepEqual(recovery.versions, ["1", "2", "3"]);
  if (manifest !== undefined || packageSha256 !== undefined) {
    assert(manifest && typeof manifest === "object" && !Array.isArray(manifest), "Recovery manifest is required"); sha256(packageSha256);
    assert.equal(manifest.sourceSha, recovery.sourceSha, "Recovery source differs");
    assert.equal(digest(manifest), recovery.finalManifestSha256, "Recovery manifest differs");
    assert.equal(packageSha256, recovery.finalPackageSha256, "Recovery package differs");
  }
  return { sourceSha: recovery.sourceSha, packageSha256: recovery.finalPackageSha256, manifestSha256: recovery.finalManifestSha256, recovered: true, entryPoints: brokerEntryPoints, allVersions: ["1", "2", "3"], runtimeVersions: bootstrap.runtimeVersions };
}

export function assertHistoricalBrokerChangeClosure(bootstrap) {
  const recovery = assertRecoveredClosure(bootstrap);
  const change = bootstrap.brokerChange;
  const keys = ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "closedAt", "configurationSha256", "identityReadbackSha256", "identitySetSha256", "owner", "policyCheckpoints", "predecessor", "remainingOperations", "runtimeVersions", "schemaVersion", "sessionExpiresAt", "sourceSha", "state", "successor", "transitionId"];
  assert(change && typeof change === "object" && !Array.isArray(change)); assert.deepEqual(Object.keys(change).sort(), keys.sort());
  assert.equal(change.schemaVersion, 1); assert.equal(change.state, "BROKER_CHANGE_CLOSED"); uuid(change.transitionId); uuid(change.owner); sha256(change.authorizationSha256);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt", "closedAt"]) timestamp(change[field]);
  assert.deepEqual(change.predecessor, brokerChangePredecessor()); assert.deepEqual(change.remainingOperations, brokerChangeOperations);
  assert.deepEqual(change.policyCheckpoints, brokerChangeManagedIdentities().map(({ role }) => role));
  assert(Array.isArray(change.authorizationHistory)); const authorizations = new Set([change.authorizationSha256]); for (const prior of change.authorizationHistory) { assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]); sha256(prior.authorizationSha256); uuid(prior.owner); timestamp(prior.authorizationExpiresAt); timestamp(prior.sessionExpiresAt); assert(!authorizations.has(prior.authorizationSha256)); authorizations.add(prior.authorizationSha256); }
  assert.equal(change.identitySetSha256, digest(brokerChangeManagedIdentities()));
  assert.equal(change.identityReadbackSha256, digest(brokerChangeManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }))));
  assert.deepEqual(change.successor?.versions, ["4", "5", "6"]); assert.equal(change.successor?.identitySetSha256, change.identitySetSha256);
  assert.match(change.successor?.sourceSha || "", /^[a-f0-9]{40}$/); for (const field of ["packageSha256", "manifestSha256", "configurationSha256", "identitySetSha256"]) sha256(change.successor?.[field]);
  assert.equal(change.successor.lambdaCodeSha256, Buffer.from(change.successor.packageSha256, "hex").toString("base64"));
  assert.equal(change.sourceSha, change.successor.sourceSha); assert.equal(change.configurationSha256, change.successor.configurationSha256);
  assert.deepEqual(Object.keys(change.runtimeVersions || {}).sort(), ["4", "5", "6"]); for (const runtime of Object.values(change.runtimeVersions)) assert.match(runtime || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  return { ...change.successor, entryPoints: brokerChangeEntryPoints, allVersions: ["1", "2", "3", "4", "5", "6"], runtimeVersions: change.runtimeVersions, predecessor: recovery };
}

function assertBrokerPolicySuccessorClosure(bootstrap, manifest, packageSha256, metadata) {
  const predecessor = assertHistoricalBrokerChangeClosure(bootstrap);
  const packageEvidence = { manifest, manifestSha256: digest(manifest), packageSha256 };
  const bindings = brokerPolicySuccessorBindings(packageEvidence);
  for (const field of ["sourceSha", "packageSha256", "manifestSha256", "configurationSha256", "identitySetSha256"]) assert.equal(predecessor[field], bindings.predecessor[field], `Broker-policy predecessor ${field} differs`);
  const closure = assertBrokerPolicySuccessorClosureMetadata(metadata, bindings);
  return { sourceSha: bindings.successor.sourceSha, packageSha256, manifestSha256: bindings.successor.manifestSha256, recovered: true, changed: true, policySuccessor: true,
    entryPoints: brokerPolicySuccessorEntryPoints, allVersions: ["1", "2", "3", "4", "5", "6", "7", "8", "9"], runtimeVersions: { ...predecessor.runtimeVersions, ...closure.runtimeVersions }, predecessor };
}

// The BROKER_CHANGE controller authenticates this immutable predecessor before
// it can reserve a successor transition. It deliberately refuses any existing
// change metadata; resumption is handled by that controller's exact CAS record.
export function assertCompletedRecoveryTrustAnchor(bootstrap) {
  assert(bootstrap && typeof bootstrap === "object" && !Array.isArray(bootstrap));
  assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED");
  assert(Object.hasOwn(bootstrap, "recovery"), "Completed recovery predecessor required");
  assert(!Object.hasOwn(bootstrap, "brokerChange"), "Existing broker change requires exact resumption");
  return assertRecoveredBootstrapLineage(bootstrap);
}

// A broker-change resumption must re-authenticate immutable outer lineage
// before accepting its mutable-in-progress nested checkpoint.
export function assertRecoveredBootstrapLineage(bootstrap) {
  assert(bootstrap && typeof bootstrap === "object" && !Array.isArray(bootstrap));
  assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED");
  assert(Object.hasOwn(bootstrap, "recovery"), "Completed recovery predecessor required");
  return assertRecoveredClosure(bootstrap);
}

function assertBrokerChangeClosure(bootstrap, manifest, packageSha256) {
  const recovery = assertRecoveredClosure(bootstrap);
  const change = bootstrap.brokerChange;
  const keys = ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "closedAt", "configurationSha256", "identityReadbackSha256", "identitySetSha256", "owner", "policyCheckpoints", "predecessor", "remainingOperations", "runtimeVersions", "schemaVersion", "sessionExpiresAt", "sourceSha", "state", "successor", "transitionId"];
  assert(change && typeof change === "object" && !Array.isArray(change), "Missing broker change closure");
  assert.deepEqual(Object.keys(change).sort(), keys.sort(), "Malformed broker change closure");
  assert.equal(change.schemaVersion, 1); assert.equal(change.state, "BROKER_CHANGE_CLOSED"); uuid(change.owner);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt", "closedAt"]) timestamp(change[field]);
  assert.deepEqual(change.predecessor, brokerChangePredecessor(), "Broker change predecessor differs");
  assert.deepEqual(change.remainingOperations, brokerChangeOperations, "Broker change operations differ");
  assert.deepEqual(change.policyCheckpoints, brokerChangeManagedIdentities().map(({ role }) => role), "Broker change identity checkpoint lineage differs");
  assert(Array.isArray(change.authorizationHistory));
  const authorizations = new Set([change.authorizationSha256]); sha256(change.authorizationSha256);
  for (const prior of change.authorizationHistory) {
    assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]);
    sha256(prior.authorizationSha256); uuid(prior.owner); timestamp(prior.authorizationExpiresAt); timestamp(prior.sessionExpiresAt);
    assert(!authorizations.has(prior.authorizationSha256), "Repeated broker change authorization"); authorizations.add(prior.authorizationSha256);
  }
  const evidence = { manifest, manifestSha256: digest(manifest), packageSha256 };
  const successor = { sourceSha: manifest.sourceSha, packageSha256, lambdaCodeSha256: Buffer.from(packageSha256, "hex").toString("base64"), manifestSha256: digest(manifest),
    configurationSha256: brokerChangeConfigurationSha256(evidence), identitySetSha256: digest(brokerChangeManagedIdentities()), versions: ["4", "5", "6"] };
  assert.deepEqual(change.successor, successor, "Broker change successor differs");
  assert.equal(change.sourceSha, successor.sourceSha); assert.equal(change.configurationSha256, successor.configurationSha256);
  assert.deepEqual(change.runtimeVersions && Object.keys(change.runtimeVersions).sort(), successor.versions, "Broker change runtime versions differ");
  for (const value of Object.values(change.runtimeVersions || {})) assert.match(value || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.equal(change.identitySetSha256, successor.identitySetSha256); assert.equal(change.identityReadbackSha256, digest(brokerChangeManagedIdentities().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" }))));
  return { sourceSha: successor.sourceSha, packageSha256, manifestSha256: successor.manifestSha256, recovered: true, changed: true,
    entryPoints: brokerChangeEntryPoints, allVersions: ["1", "2", "3", "4", "5", "6"], runtimeVersions: change.runtimeVersions, predecessor: recovery };
}

// The original record is immutable incident lineage. A completed recovery adds
// a second, fully-bound effective lineage; malformed recovery never falls back.
export function assertEffectiveBootstrapTrustAnchor(bootstrap, manifest, packageSha256, metadata = {}) {
  assert(bootstrap && typeof bootstrap === "object" && !Array.isArray(bootstrap));
  assert.equal(bootstrap.schemaVersion, 1); assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED", "Trust anchor bootstrap is incomplete");
  sha256(packageSha256);
  if (Object.hasOwn(metadata, brokerPolicySuccessorMetadataKey)) {
    assert(Object.hasOwn(bootstrap, "brokerChange"), "Broker-policy successor lacks broker predecessor");
    return assertBrokerPolicySuccessorClosure(bootstrap, manifest, packageSha256, metadata);
  }
  if (Object.hasOwn(bootstrap, "brokerChange")) {
    assert(Object.hasOwn(bootstrap, "recovery"), "Broker change without recovered predecessor is invalid");
    return assertBrokerChangeClosure(bootstrap, manifest, packageSha256);
  }
  if (Object.hasOwn(bootstrap, "recovery")) return assertRecoveredClosure(bootstrap, manifest, packageSha256);
  assert.equal(bootstrap.sourceSha, manifest.sourceSha);
  assert.equal(bootstrap.manifestSha256, digest(manifest));
  assert.equal(bootstrap.identitySetSha256, digest(manifest.identities));
  assert.equal(bootstrap.packageSha256, packageSha256);
  return { sourceSha: bootstrap.sourceSha, packageSha256, manifestSha256: bootstrap.manifestSha256, recovered: false, entryPoints: brokerEntryPoints, allVersions: ["1", "2", "3"], runtimeVersions: bootstrap.runtimeVersions };
}
