import assert from "node:assert/strict";
import { brokerConfiguration, brokerRecoverySuccessorEntryPoints, brokerSignerSuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { canonical, digest, installationIdentity, terraformExecutorPolicyGeneration } from "./component-iam-installation-contract.mjs";
import { brokerRecoverySuccessorManagedIdentities, brokerSignerSuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "./component-installation-identity-contract.mjs";
import { assertS3UserMetadataSize, compactClosureMetadata } from "./component-broker-recovery-successor-contract.mjs";

const sha = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export const brokerSignerSuccessor = Object.freeze({
  transitionType: "COMPONENT_BROKER_SIGNER_SUCCESSOR",
  environment: "production-component-broker-recovery-successor-evidence",
  workflow: ".github/workflows/authorize-component-broker-recovery-successor.yml",
  artifact: "component-broker-signer-successor-authorization",
  file: "component-broker-signer-successor-authorization.json",
  reservationKey: `${identityBootstrap.prefix}broker-signer-successor.json`,
  metadataKey: "broker-signer-successor",
  maxAgeMs: 30 * 60 * 1000,
});

export const signerSuccessorPredecessorPolicy = () => terraformExecutorPolicyGeneration("10", true);
export const signerSuccessorExecutorPolicy = () => terraformExecutorPolicyGeneration("13", true);
export const signerSuccessorPredecessorPolicySha256 = digest(signerSuccessorPredecessorPolicy());
export const signerSuccessorExecutorPolicySha256 = digest(signerSuccessorExecutorPolicy());

export function brokerSignerSuccessorConfigurations(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  return Object.freeze(Object.fromEntries(Object.keys(brokerSignerSuccessorEntryPoints).map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, entryPoint, entryPoints: brokerSignerSuccessorEntryPoints })])));
}

export function brokerSignerSuccessorBindings(packageEvidence, secondClosure) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assert.deepEqual(Object.keys(secondClosure || {}).sort(), ["authorizationSha256", "bindingsSha256", "closedAt", "firstAuthorizationSha256", "reservationEtagSha256", "reservationSha256", "runtimeVersions", "schemaVersion", "state", "transitionId"].sort());
  assert.equal(secondClosure.schemaVersion, 1); assert.equal(secondClosure.state, "BROKER_RECOVERY_SUCCESSOR_CLOSED");
  for (const field of ["authorizationSha256", "bindingsSha256", "reservationEtagSha256", "reservationSha256"]) sha(secondClosure[field]); uuid(secondClosure.transitionId);
  assert.deepEqual(Object.keys(secondClosure.runtimeVersions).sort(), Object.values(brokerRecoverySuccessorEntryPoints));
  const predecessor = brokerRecoverySuccessorManagedIdentities(), successor = brokerSignerSuccessorManagedIdentities();
  const identity = role => { const old = predecessor.find(value => value.role === role), next = successor.find(value => value.role === role); assert(old && next && old.policyName === next.policyName); return { role, policyName: old.policyName, predecessorPolicySha256: old.policySha256, successorPolicySha256: next.policySha256 }; };
  const configurations = packageEvidence.configurations || brokerSignerSuccessorConfigurations(packageEvidence);
  return Object.freeze({
    secondClosure, predecessor: { entryPoints: brokerRecoverySuccessorEntryPoints, policySha256: signerSuccessorPredecessorPolicySha256 },
    successor: { sourceSha: packageEvidence.manifest.sourceSha, packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, lambdaCodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"), entryPoints: brokerSignerSuccessorEntryPoints, policySha256: signerSuccessorExecutorPolicySha256, configurationSetSha256: digest(configurations), identitySetSha256: digest(successor) },
    role: installationIdentity.terraformRole, policyName: "MSCQRComponentTableExecutor", broker: identity(installationIdentity.provisionerRole), installationSession: identity(identityBootstrap.installationRole), cleanupSession: identity(identityBootstrap.cleanupRole), authorizationSession: identity(identityBootstrap.authorizationRole),
  });
}

export function brokerSignerSuccessorCapabilitySet() {
  const identities = brokerSignerSuccessorManagedIdentities();
  return { Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:PutRolePolicy"], Resource: identities.map(({ arn }) => arn) },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion"], Resource: componentBrokerArn },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"].map(version => `${componentBrokerArn}:${version}`) },
    { Effect: "Allow", Action: "s3:GetObject", Resource: [`arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}broker-policy-successor.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}broker-recovery-successor.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${brokerSignerSuccessor.reservationKey}`] },
    { Effect: "Allow", Action: "s3:PutObject", Resource: [`arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`, `arn:aws:s3:::${identityBootstrap.bucket}/${brokerSignerSuccessor.reservationKey}`], Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ] };
}

export function brokerSignerSuccessorClosure(record, bindings, runtimeVersions, reservationEtag, closedAt, historicalMetadata) {
  assert.equal(record.state, "VERIFIED"); assert.deepEqual(record.bindings, bindings); assert(typeof reservationEtag === "string" && reservationEtag);
  assert.equal(new Date(Date.parse(closedAt)).toISOString(), closedAt);
  assert.deepEqual(Object.keys(runtimeVersions || {}).sort(), Object.values(brokerSignerSuccessorEntryPoints));
  assert.deepEqual(Object.keys(historicalMetadata || {}).sort(), ["broker-policy-successor", "broker-recovery-successor"].sort());
  const value = { schemaVersion: 1, state: "BROKER_SIGNER_SUCCESSOR_CLOSED", transitionId: record.transitionId, authorizationSha256: record.authorizationSha256,
    bindingsSha256: digest(bindings), reservationSha256: digest(record), reservationEtagSha256: digest(reservationEtag), secondAuthorizationSha256: bindings.secondClosure.authorizationSha256,
    historicalMetadataSha256: digest(historicalMetadata), closedAt, runtimeVersions };
  const metadata = Object.freeze({ ...historicalMetadata, [brokerSignerSuccessor.metadataKey]: compactClosureMetadata(value) });
  assertS3UserMetadataSize(metadata);
  return Object.freeze({ value: Object.freeze(value), metadata });
}

export function assertBrokerSignerSuccessorClosureMetadata(metadata, bindings, reservation, reservationEtag, bootstrap) {
  assert.deepEqual(Object.keys(metadata || {}).sort(), ["broker-policy-successor", "broker-recovery-successor", brokerSignerSuccessor.metadataKey].sort());
  assertS3UserMetadataSize(metadata);
  const secondEncoded = metadata["broker-recovery-successor"];
  const secondClosure = /^sha256:[a-f0-9]{64}$/.test(secondEncoded || "") ? bootstrap?.brokerRecoverySuccessorClosure : JSON.parse(Buffer.from(secondEncoded, "base64url").toString("utf8"));
  if (/^sha256:[a-f0-9]{64}$/.test(secondEncoded || "")) assert.equal(secondEncoded, compactClosureMetadata(secondClosure), "Second successor body and metadata differ");
  assert.equal(canonical(secondClosure), canonical(bindings.secondClosure), "Second successor closure differs");
  const value = bootstrap?.brokerSignerSuccessorClosure;
  assert.equal(metadata[brokerSignerSuccessor.metadataKey], compactClosureMetadata(value), "Signer successor body and metadata differ");
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationSha256", "bindingsSha256", "closedAt", "secondAuthorizationSha256", "historicalMetadataSha256", "reservationEtagSha256", "reservationSha256", "runtimeVersions", "schemaVersion", "state", "transitionId"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BROKER_SIGNER_SUCCESSOR_CLOSED"); uuid(value.transitionId); for (const field of ["authorizationSha256", "bindingsSha256", "secondAuthorizationSha256", "historicalMetadataSha256", "reservationEtagSha256", "reservationSha256"]) sha(value[field]);
  assert.equal(value.historicalMetadataSha256, digest({ "broker-policy-successor": metadata["broker-policy-successor"], "broker-recovery-successor": metadata["broker-recovery-successor"] }), "Historical successor metadata differs");
  assert.equal(value.secondAuthorizationSha256, bindings.secondClosure.authorizationSha256); assert.equal(value.bindingsSha256, digest(bindings));
  if (reservation !== undefined) {
    assert.equal(reservation?.state, "VERIFIED"); assert.equal(reservation?.transitionId, value.transitionId); assert.equal(reservation?.authorizationSha256, value.authorizationSha256);
    assert.equal(digest(reservation), value.reservationSha256); assert.deepEqual(reservation?.bindings, bindings);
    assert(typeof reservationEtag === "string" && reservationEtag); assert.equal(digest(reservationEtag), value.reservationEtagSha256, "Second-successor reservation ETag differs");
  }
  assert.deepEqual(Object.keys(value.runtimeVersions || {}).sort(), Object.values(brokerSignerSuccessorEntryPoints));
  for (const runtime of Object.values(value.runtimeVersions)) assert.match(runtime || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.equal(new Date(Date.parse(value.closedAt)).toISOString(), value.closedAt);
  return Object.freeze(structuredClone(value));
}
