import assert from "node:assert/strict";
import { brokerConfiguration, brokerPolicySuccessorEntryPoints, brokerRecoverySuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { canonical, digest, installationIdentity, terraformExecutorPolicyGeneration } from "./component-iam-installation-contract.mjs";
import { brokerPolicySuccessorManagedIdentities, brokerRecoverySuccessorManagedIdentities, componentBrokerArn, componentRoleArn, identityBootstrap } from "./component-installation-identity-contract.mjs";

const sha = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export const brokerRecoverySuccessor = Object.freeze({
  transitionType: "COMPONENT_BROKER_RECOVERY_SUCCESSOR",
  environment: "production-component-broker-recovery-successor-evidence",
  workflow: ".github/workflows/authorize-component-broker-recovery-successor.yml",
  artifact: "component-broker-recovery-successor-authorization",
  file: "component-broker-recovery-successor-authorization.json",
  reservationKey: `${identityBootstrap.prefix}broker-recovery-successor.json`,
  metadataKey: "broker-recovery-successor",
  maxAgeMs: 30 * 60 * 1000,
});

// Authenticated production checkpoint at the metadata-size failure. This is
// the only historical package allowed to cross a new protected-main SHA.
export const recoveryClosurePredecessor = Object.freeze({
  transitionId: "22955a47-da8b-4d7f-a01d-cc39fbef5a5c",
  sourceSha: "14419fd8ff13336777c83e1f2e7b025adea09a55",
  bindingsSha256: "df78583447af83b2a246007297ece8d6b7a2069c93423e0b1e82d07eeed1179c",
  authorizationSha256: "8cd96d3c78c9d8e3768bdae4ffdc9447cd97d4c5bbe39e1adf9fd92916dc9d5e",
  owner: "97940a83-3936-4c2d-95eb-22fb3b44a68b",
  authorizationExpiresAt: "2026-09-28T22:39:20.815Z",
  sessionExpiresAt: "2026-09-28T22:32:43.000Z",
  initialReservationSha256: "2a28491074b92cb234d1c79efbab156c2b3e245a76f885f36d215da5d66df99f",
});

export function assertVerifiedRecoveryClosurePredecessor(record, firstClosure) {
  assert.deepEqual(Object.keys(record || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort());
  assert.equal(record.schemaVersion, 1); assert.equal(record.state, "VERIFIED");
  assert.equal(record.transitionId, recoveryClosurePredecessor.transitionId);
  assert.equal(record.bindings?.successor?.sourceSha, recoveryClosurePredecessor.sourceSha);
  assert.equal(digest(record.bindings), recoveryClosurePredecessor.bindingsSha256);
  assert.deepEqual(record.bindings.firstClosure, firstClosure);
  assert(Array.isArray(record.authorizationHistory));
  if (record.authorizationHistory.length === 0) {
    assert.equal(digest(record), recoveryClosurePredecessor.initialReservationSha256);
  } else {
    assert.deepEqual(record.authorizationHistory[0], {
      authorizationSha256: recoveryClosurePredecessor.authorizationSha256,
      authorizationExpiresAt: recoveryClosurePredecessor.authorizationExpiresAt,
      sessionExpiresAt: recoveryClosurePredecessor.sessionExpiresAt,
      owner: recoveryClosurePredecessor.owner,
    });
    const seen = new Set();
    for (const prior of record.authorizationHistory) { sha(prior.authorizationSha256); uuid(prior.owner); assert(!seen.has(prior.authorizationSha256)); seen.add(prior.authorizationSha256); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(prior[field])).toISOString(), prior[field]); }
    assert(!seen.has(record.authorizationSha256));
  }
  uuid(record.owner); sha(record.authorizationSha256);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(record[field])).toISOString(), record[field]);
  return record.bindings;
}

export const recoverySuccessorPredecessorPolicy = () => terraformExecutorPolicyGeneration("7", true);
export const recoverySuccessorExecutorPolicy = () => terraformExecutorPolicyGeneration("10", true);
export const recoverySuccessorPredecessorPolicySha256 = digest(recoverySuccessorPredecessorPolicy());
export const recoverySuccessorExecutorPolicySha256 = digest(recoverySuccessorExecutorPolicy());
export const s3UserMetadataLimitBytes = 2048;
export function assertS3UserMetadataSize(metadata) {
  const bytes = Object.entries(metadata).reduce((total, [key, value]) => {
    assert.equal(typeof value, "string");
    return total + Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8");
  }, 0);
  assert(bytes <= s3UserMetadataLimitBytes, `S3 user metadata exceeds ${s3UserMetadataLimitBytes} bytes`);
  return bytes;
}
export const compactClosureMetadata = value => `sha256:${digest(value)}`;

export function authenticateFirstSuccessorReservation(value, firstClosure, reservationEtag) {
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "VERIFIED"); uuid(value.transitionId); sha(value.authorizationSha256);
  assert.deepEqual(Object.keys(value.bindings || {}).sort(), ["authorizationSession", "cleanupSession", "delta", "installationSession", "mutations", "policyName", "predecessor", "role", "successor"].sort());
  assert.equal(value.bindings.predecessor.brokerVersion, "4"); assert.deepEqual(value.bindings.successor.brokerVersions, Object.values(brokerPolicySuccessorEntryPoints));
  assert.equal(value.transitionId, firstClosure.transitionId); assert.equal(value.authorizationSha256, firstClosure.authorizationSha256);
  assert.equal(digest(value), firstClosure.reservationSha256, "Historical first-successor reservation digest differs");
  assert(typeof reservationEtag === "string" && reservationEtag); assert.equal(digest(reservationEtag), firstClosure.reservationEtagSha256, "Historical first-successor reservation ETag differs");
  assert.equal(digest(value.bindings), firstClosure.bindingsSha256, "Historical first-successor binding digest differs");
  return Object.freeze(structuredClone(value.bindings));
}

export function brokerRecoverySuccessorConfigurations(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  return Object.freeze(Object.fromEntries(Object.keys(brokerRecoverySuccessorEntryPoints).map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, entryPoint, entryPoints: brokerRecoverySuccessorEntryPoints })])));
}

export function brokerRecoverySuccessorBindings(packageEvidence, firstClosure) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assert.deepEqual(Object.keys(firstClosure || {}).sort(), ["authorizationSha256", "bindingsSha256", "closedAt", "reservationEtagSha256", "reservationSha256", "runtimeVersions", "schemaVersion", "state", "transitionId"].sort());
  assert.equal(firstClosure.schemaVersion, 1); assert.equal(firstClosure.state, "BROKER_POLICY_SUCCESSOR_CLOSED");
  for (const field of ["authorizationSha256", "bindingsSha256", "reservationEtagSha256", "reservationSha256"]) sha(firstClosure[field]); uuid(firstClosure.transitionId);
  assert.deepEqual(Object.keys(firstClosure.runtimeVersions).sort(), Object.values(brokerPolicySuccessorEntryPoints));
  const predecessor = brokerPolicySuccessorManagedIdentities(), successor = brokerRecoverySuccessorManagedIdentities();
  const identity = role => { const old = predecessor.find(value => value.role === role), next = successor.find(value => value.role === role); assert(old && next && old.policyName === next.policyName); return { role, policyName: old.policyName, predecessorPolicySha256: old.policySha256, successorPolicySha256: next.policySha256 }; };
  const configurations = brokerRecoverySuccessorConfigurations(packageEvidence);
  return Object.freeze({
    firstClosure, predecessor: { entryPoints: brokerPolicySuccessorEntryPoints, policySha256: recoverySuccessorPredecessorPolicySha256 },
    successor: { sourceSha: packageEvidence.manifest.sourceSha, packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, lambdaCodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"), entryPoints: brokerRecoverySuccessorEntryPoints, policySha256: recoverySuccessorExecutorPolicySha256, configurationSetSha256: digest(configurations), identitySetSha256: digest(successor) },
    role: installationIdentity.terraformRole, policyName: "MSCQRComponentTableExecutor", broker: identity(installationIdentity.provisionerRole), installationSession: identity(identityBootstrap.installationRole), cleanupSession: identity(identityBootstrap.cleanupRole), authorizationSession: identity(identityBootstrap.authorizationRole),
  });
}

export function brokerRecoverySuccessorCapabilitySet() {
  const identities = brokerRecoverySuccessorManagedIdentities();
  return { Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:PutRolePolicy"], Resource: identities.map(({ arn }) => arn) },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion"], Resource: componentBrokerArn },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: Array.from({ length: 15 }, (_, index) => `${componentBrokerArn}:${index + 1}`) },
    { Effect: "Allow", Action: "s3:GetObject", Resource: [`arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}broker-policy-successor.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${brokerRecoverySuccessor.reservationKey}`] },
    { Effect: "Allow", Action: "s3:PutObject", Resource: [`arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${brokerRecoverySuccessor.reservationKey}`], Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ] };
}

export function brokerRecoverySuccessorClosure(record, bindings, runtimeVersions, reservationEtag, closedAt, historicalMetadata) {
  assert.equal(record.state, "VERIFIED"); assert.deepEqual(record.bindings, bindings); assert(typeof reservationEtag === "string" && reservationEtag);
  assert.equal(new Date(Date.parse(closedAt)).toISOString(), closedAt);
  assert.deepEqual(Object.keys(runtimeVersions || {}).sort(), Object.values(brokerRecoverySuccessorEntryPoints));
  assert.deepEqual(Object.keys(historicalMetadata || {}), ["broker-policy-successor"]);
  const value = { schemaVersion: 1, state: "BROKER_RECOVERY_SUCCESSOR_CLOSED", transitionId: record.transitionId, authorizationSha256: record.authorizationSha256,
    bindingsSha256: digest(bindings), reservationSha256: digest(record), reservationEtagSha256: digest(reservationEtag), firstAuthorizationSha256: bindings.firstClosure.authorizationSha256, closedAt, runtimeVersions };
  const metadata = Object.freeze({ ...historicalMetadata, [brokerRecoverySuccessor.metadataKey]: compactClosureMetadata(value) });
  assertS3UserMetadataSize(metadata);
  return Object.freeze({ value: Object.freeze(value), metadata });
}

export function assertBrokerRecoverySuccessorClosureMetadata(metadata, bindings, reservation, reservationEtag, bootstrap) {
  assert.deepEqual(Object.keys(metadata || {}).sort(), ["broker-policy-successor", brokerRecoverySuccessor.metadataKey].sort());
  assertS3UserMetadataSize(metadata);
  const firstClosure = JSON.parse(Buffer.from(metadata["broker-policy-successor"], "base64url").toString("utf8"));
  assert.equal(canonical(firstClosure), canonical(bindings.firstClosure), "First successor closure differs");
  const encoded = metadata[brokerRecoverySuccessor.metadataKey];
  const compact = /^sha256:[a-f0-9]{64}$/.test(encoded || "");
  const value = compact ? bootstrap?.brokerRecoverySuccessorClosure : JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  if (compact) assert.equal(encoded, compactClosureMetadata(value), "Second successor body and metadata differ");
  else {
    assert.equal(Buffer.from(canonical(value)).toString("base64url"), encoded, "Noncanonical historical second closure");
    if (bootstrap?.brokerRecoverySuccessorClosure) assert.equal(canonical(bootstrap.brokerRecoverySuccessorClosure), canonical(value), "Historical second closure body differs");
  }
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationSha256", "bindingsSha256", "closedAt", "firstAuthorizationSha256", "reservationEtagSha256", "reservationSha256", "runtimeVersions", "schemaVersion", "state", "transitionId"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BROKER_RECOVERY_SUCCESSOR_CLOSED"); uuid(value.transitionId); for (const field of ["authorizationSha256", "bindingsSha256", "firstAuthorizationSha256", "reservationEtagSha256", "reservationSha256"]) sha(value[field]);
  assert.equal(value.firstAuthorizationSha256, bindings.firstClosure.authorizationSha256); assert.equal(value.bindingsSha256, digest(bindings));
  if (reservation !== undefined) {
    assert.equal(reservation?.state, "VERIFIED"); assert.equal(reservation?.transitionId, value.transitionId); assert.equal(reservation?.authorizationSha256, value.authorizationSha256);
    assert.equal(digest(reservation), value.reservationSha256); assert.deepEqual(reservation?.bindings, bindings);
    assert(typeof reservationEtag === "string" && reservationEtag); assert.equal(digest(reservationEtag), value.reservationEtagSha256, "Second-successor reservation ETag differs");
  }
  assert.deepEqual(Object.keys(value.runtimeVersions || {}).sort(), Object.values(brokerRecoverySuccessorEntryPoints));
  for (const runtime of Object.values(value.runtimeVersions)) assert.match(runtime || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.equal(new Date(Date.parse(value.closedAt)).toISOString(), value.closedAt);
  return Object.freeze(structuredClone(value));
}

export function authenticateSecondSuccessorReservation(value, closure, reservationEtag) {
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "VERIFIED"); uuid(value.transitionId); sha(value.authorizationSha256);
  assert.equal(value.transitionId, closure.transitionId); assert.equal(value.authorizationSha256, closure.authorizationSha256);
  assert.equal(digest(value), closure.reservationSha256, "Historical second-successor reservation digest differs");
  assert(typeof reservationEtag === "string" && reservationEtag); assert.equal(digest(reservationEtag), closure.reservationEtagSha256, "Historical second-successor reservation ETag differs");
  assert.equal(digest(value.bindings), closure.bindingsSha256, "Historical second-successor binding digest differs");
  assert.deepEqual(Object.keys(closure.runtimeVersions || {}).sort(), Object.values(brokerRecoverySuccessorEntryPoints));
  return Object.freeze(structuredClone(value.bindings));
}
