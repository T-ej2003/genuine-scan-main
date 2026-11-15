import assert from "node:assert/strict";
import { brokerConfiguration, brokerStaleSignerSuccessorEntryPoints, brokerSignerSuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { brokerStaleSignerSuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "./component-installation-identity-contract.mjs";
import { assertS3UserMetadataSize, compactClosureMetadata } from "./component-broker-recovery-successor-contract.mjs";
import { assertBrokerSignerSuccessorClosureMetadata } from "./component-broker-signer-successor-contract.mjs";

export const staleSignerSuccessor = Object.freeze({
  transitionType: "COMPONENT_BROKER_STALE_SIGNER_SUCCESSOR",
  environment: "production-component-broker-recovery-successor-evidence",
  workflow: ".github/workflows/authorize-component-broker-recovery-successor.yml",
  artifact: "component-broker-stale-signer-successor-authorization",
  file: "component-broker-stale-signer-successor-authorization.json",
  reservationKey: `${identityBootstrap.prefix}broker-stale-signer-successor.json`,
  metadataKey: "broker-stale-signer-successor",
  maxAgeMs: 30 * 60 * 1000,
});

export const staleSignerPublisherPolicy = Object.freeze({ Version: "2012-10-17", Statement: [{
  Sid: "PublishExactSignerTransitionAuthorizationToBroker", Effect: "Allow", Action: "lambda:InvokeFunction",
  Resource: `${componentBrokerArn}:18`, Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
}] });

const sha = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export function staleSignerSuccessorConfigurations(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  return Object.freeze(Object.fromEntries(Object.keys(brokerStaleSignerSuccessorEntryPoints).map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, entryPoint, entryPoints: brokerStaleSignerSuccessorEntryPoints })])));
}

export function staleSignerSuccessorBindings(packageEvidence, predecessorClosure, predecessorReservation, predecessorEtag, historicalMetadata, bootstrap) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assertBrokerSignerSuccessorClosureMetadata(historicalMetadata, predecessorReservation.bindings, predecessorReservation, predecessorEtag, bootstrap);
  assert.equal(canonical(predecessorClosure), canonical(bootstrap.brokerSignerSuccessorClosure));
  assert.equal(predecessorReservation.state, "VERIFIED");
  const identities = brokerStaleSignerSuccessorManagedIdentities();
  const configurations = packageEvidence.configurations || staleSignerSuccessorConfigurations(packageEvidence);
  return Object.freeze({
    predecessor: { closureSha256: digest(predecessorClosure), reservationSha256: digest(predecessorReservation), reservationEtagSha256: digest(predecessorEtag), entryPoints: brokerSignerSuccessorEntryPoints },
    successor: { sourceSha: packageEvidence.manifest.sourceSha, packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256,
      lambdaCodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"), entryPoints: brokerStaleSignerSuccessorEntryPoints,
      configurationSetSha256: digest(configurations), identitySetSha256: digest(identities) },
    brokerPolicySha256: identities.find(({ role }) => role === installationIdentity.provisionerRole).policySha256,
    publisherRoleArn: `arn:aws:iam::${identityBootstrap.account}:role/mscqr-production-signer-policy-installer`,
    publisherPolicySha256: digest(staleSignerPublisherPolicy),
    publisherVersion: brokerStaleSignerSuccessorEntryPoints.AUTHORIZE,
  });
}

export function staleSignerSuccessorCapabilitySet() {
  const identities = brokerStaleSignerSuccessorManagedIdentities();
  return { Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:PutRolePolicy"], Resource: [...identities.map(({ arn }) => arn), `arn:aws:iam::${identityBootstrap.account}:role/mscqr-production-signer-policy-installer`] },
    { Effect: "Allow", Action: ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource: `arn:aws:iam::${identityBootstrap.account}:policy/MSCQRProductionGreenStageARelease` },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion"], Resource: componentBrokerArn },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: Array.from({ length: 18 }, (_, i) => `${componentBrokerArn}:${i + 1}`) },
    { Effect: "Allow", Action: "s3:GetObject", Resource: ["broker-policy-successor.json", "broker-recovery-successor.json", "broker-signer-successor.json", "identity-bootstrap.json", "broker-stale-signer-successor.json", "signer-policy-transition.json"].map(name => `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}${name}`) },
    { Effect: "Allow", Action: "s3:PutObject", Resource: ["identity-bootstrap.json", "broker-stale-signer-successor.json"].map(name => `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}${name}`), Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ] };
}

export function staleSignerSuccessorClosure(record, bindings, runtimeVersions, reservationEtag, closedAt, historicalMetadata) {
  assert.equal(record.state, "VERIFIED"); assert.deepEqual(record.bindings, bindings); assert(typeof reservationEtag === "string" && reservationEtag);
  assert.deepEqual(Object.keys(runtimeVersions || {}).sort(), Object.values(brokerStaleSignerSuccessorEntryPoints));
  assert.deepEqual(Object.keys(historicalMetadata || {}).sort(), ["broker-policy-successor", "broker-recovery-successor", "broker-signer-successor"].sort());
  const value = { schemaVersion: 1, state: "BROKER_STALE_SIGNER_SUCCESSOR_CLOSED", transitionId: record.transitionId,
    authorizationSha256: record.authorizationSha256, bindingsSha256: digest(bindings), reservationSha256: digest(record),
    reservationEtagSha256: digest(reservationEtag), historicalMetadataSha256: digest(historicalMetadata), closedAt, runtimeVersions };
  const metadata = Object.freeze({ ...historicalMetadata, [staleSignerSuccessor.metadataKey]: compactClosureMetadata(value) });
  assertS3UserMetadataSize(metadata);
  return Object.freeze({ value: Object.freeze(value), metadata });
}

export function assertStaleSignerSuccessorClosure(metadata, bindings, reservation, reservationEtag, bootstrap) {
  const historical = Object.fromEntries(Object.entries(metadata || {}).filter(([name]) => name !== staleSignerSuccessor.metadataKey));
  assert.deepEqual(Object.keys(historical).sort(), ["broker-policy-successor", "broker-recovery-successor", "broker-signer-successor"].sort());
  assert.deepEqual(Object.keys(metadata || {}).sort(), [...Object.keys(historical), staleSignerSuccessor.metadataKey].sort());
  assertS3UserMetadataSize(metadata);
  const value = bootstrap?.brokerStaleSignerSuccessorClosure;
  assert.deepEqual(Object.keys(value || {}).sort(), ["schemaVersion", "state", "transitionId", "authorizationSha256", "bindingsSha256", "reservationSha256", "reservationEtagSha256", "historicalMetadataSha256", "closedAt", "runtimeVersions"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BROKER_STALE_SIGNER_SUCCESSOR_CLOSED"); uuid(value.transitionId);
  for (const field of ["authorizationSha256", "bindingsSha256", "reservationSha256", "reservationEtagSha256", "historicalMetadataSha256"]) sha(value[field]);
  assert.equal(value.bindingsSha256, digest(bindings)); assert.equal(value.historicalMetadataSha256, digest(historical));
  assert.equal(metadata[staleSignerSuccessor.metadataKey], compactClosureMetadata(value));
  assert.deepEqual(Object.keys(value.runtimeVersions || {}).sort(), Object.values(brokerStaleSignerSuccessorEntryPoints));
  for (const runtime of Object.values(value.runtimeVersions)) assert.match(runtime || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.equal(new Date(Date.parse(value.closedAt)).toISOString(), value.closedAt);
  if (reservation) {
    assert.equal(reservation.state, "VERIFIED"); assert.deepEqual(reservation.bindings, bindings);
    assert.equal(reservation.transitionId, value.transitionId); assert.equal(reservation.authorizationSha256, value.authorizationSha256);
    assert.equal(value.reservationSha256, digest(reservation)); assert.equal(value.reservationEtagSha256, digest(reservationEtag));
  }
  return value;
}
