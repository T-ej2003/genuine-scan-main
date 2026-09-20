import assert from "node:assert/strict";
import { brokerChangeEntryPoints, brokerConfiguration, brokerPolicySuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { canonical, digest, installationIdentity, terraformExecutorPolicyGeneration } from "./component-iam-installation-contract.mjs";
import { brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, componentBrokerArn, componentRoleArn, identityBootstrap } from "./component-installation-identity-contract.mjs";

const sha = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
const timestamp = value => assert.equal(new Date(Date.parse(value)).toISOString(), value);

export const brokerPolicySuccessor = Object.freeze({
  transitionType: "COMPONENT_BROKER_POLICY_SUCCESSOR",
  environment: "production-component-broker-policy-successor",
  workflow: ".github/workflows/authorize-component-broker-policy-successor.yml",
  artifact: "component-broker-policy-successor-authorization",
  file: "component-broker-policy-successor-authorization.json",
  reservationKey: `${identityBootstrap.prefix}broker-policy-successor.json`,
  maxAgeMs: 30 * 60 * 1000,
});
export const brokerPolicySuccessorMetadataKey = "broker-policy-successor";

export const predecessorExecutorPolicy = () => terraformExecutorPolicyGeneration("4", false);
export const successorExecutorPolicy = () => terraformExecutorPolicyGeneration("7", true);
export const predecessorExecutorPolicySha256 = digest(predecessorExecutorPolicy());
export const successorExecutorPolicySha256 = digest(successorExecutorPolicy());
export const predecessorBrokerPolicySha256 = brokerChangeManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole).policySha256;
export const successorBrokerPolicySha256 = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole).policySha256;
assert.equal(predecessorExecutorPolicySha256, "777b32148b2c03bf740db2a955b11dc5c524b1437d4d73a83d6f8d47745ea8a6");
assert.equal(successorExecutorPolicySha256, "0f08fdee746a32153be9e04394beb71a4ebd7c710020207d6339fc2080c6f4bf");

export const brokerPolicySuccessorDelta = Object.freeze({
  invocation: Object.freeze({ from: `${componentBrokerArn}:${brokerChangeEntryPoints.INSTALL}`, to: `${componentBrokerArn}:${brokerPolicySuccessorEntryPoints.INSTALL}` }),
  installationSessionInvocation: Object.freeze({ from: `${componentBrokerArn}:${brokerChangeEntryPoints.INSTALL}`, to: `${componentBrokerArn}:${brokerPolicySuccessorEntryPoints.INSTALL}` }),
  versionedReads: Object.freeze(successorExecutorPolicy().Statement.find(({ Action }) => Action === "s3:GetObjectVersion").Resource),
});

export const brokerPolicySuccessorMutations = Object.freeze([
  "RESERVE_EXACT_TRANSITION", "UPDATE_EXACT_BROKER_CODE", "SET_SUCCESSOR_INSTALL_DESCRIPTION", "PUBLISH_IMMUTABLE_VERSION_7",
  "PUT_EXACT_BROKER_POLICY", "PUT_EXACT_EXECUTOR_POLICY", "PUT_EXACT_INSTALLATION_SESSION_POLICY", "CLOSE_SUCCESSOR_LINEAGE",
]);

export const brokerPolicyPredecessor = Object.freeze({
  sourceSha: "b8096c297b2269abf22888f9df9283a0d037f32d",
  packageSha256: "6faeb336dbf9a21d58bcde76c1adbf7d764e248861658157d8f6ee79d17f57eb",
  manifestSha256: "2e128bfa018c376e2daf214cc2887fd3c501d64c04f2e1f3a62e43317a9d7910",
  configurationSha256: "bfd864339c37822eb8ca7bfc65c036506420990d11938a5985335dc81c6580cf",
  brokerVersion: "4", policySha256: predecessorExecutorPolicySha256, brokerPolicySha256: predecessorBrokerPolicySha256,
  identitySetSha256: "d31834166a87c78bbd5c72d7501f94706665d43cbaee6925ba9b447e91fceef0",
});

export function brokerPolicySuccessorConfiguration(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  return brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256,
    entryPoint: "INSTALL", entryPoints: brokerPolicySuccessorEntryPoints });
}

export function brokerPolicySuccessorBindings(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest)); sha(packageEvidence.packageSha256);
  const predecessorSession = brokerChangeManagedIdentities().find(({ role }) => role === identityBootstrap.installationRole), successorSession = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === identityBootstrap.installationRole);
  return Object.freeze({
    predecessor: brokerPolicyPredecessor,
    successor: { sourceSha: packageEvidence.manifest.sourceSha, packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256,
      lambdaCodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"), brokerVersion: "7", policySha256: successorExecutorPolicySha256, brokerPolicySha256: successorBrokerPolicySha256,
      configurationSha256: digest(brokerPolicySuccessorConfiguration(packageEvidence)), identitySetSha256: digest(brokerPolicySuccessorManagedIdentities()) },
    role: installationIdentity.terraformRole, policyName: "MSCQRComponentTableExecutor",
    installationSession: { role: identityBootstrap.installationRole, policyName: predecessorSession.policyName, predecessorPolicySha256: predecessorSession.policySha256, successorPolicySha256: successorSession.policySha256 },
    delta: brokerPolicySuccessorDelta, mutations: brokerPolicySuccessorMutations,
  });
}

export function brokerPolicySuccessorCapabilitySet() {
  const journal = `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`;
  const reservation = `arn:aws:s3:::${identityBootstrap.bucket}/${brokerPolicySuccessor.reservationKey}`;
  const identities = brokerPolicySuccessorManagedIdentities();
  return { Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"], Resource: identities.map(({ arn }) => arn) },
    { Effect: "Allow", Action: "iam:PutRolePolicy", Resource: [componentRoleArn(installationIdentity.provisionerRole), componentRoleArn(installationIdentity.terraformRole), componentRoleArn(identityBootstrap.installationRole)] },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion"], Resource: componentBrokerArn },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: [...[1, 2, 3, 4, 5, 6, 7].map(version => `${componentBrokerArn}:${version}`)] },
    { Effect: "Allow", Action: "s3:GetObject", Resource: [journal, reservation] },
    { Effect: "Allow", Action: "s3:PutObject", Resource: [journal, reservation], Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ] };
}

export function assertBrokerPolicySuccessorRecord(value, bindings) {
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationHistory", "authorizationSha256", "closedAt", "owner", "schemaVersion", "state", "transitionId", "authorizationExpiresAt", "sessionExpiresAt", "bindings", "runtimeVersionArn"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BROKER_POLICY_SUCCESSOR_CLOSED"); uuid(value.transitionId); uuid(value.owner);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt", "closedAt"]) timestamp(value[field]);
  sha(value.authorizationSha256); assert(Array.isArray(value.authorizationHistory)); const authorizations = new Set([value.authorizationSha256]); for (const prior of value.authorizationHistory) { assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]); sha(prior.authorizationSha256); uuid(prior.owner); timestamp(prior.authorizationExpiresAt); timestamp(prior.sessionExpiresAt); assert(!authorizations.has(prior.authorizationSha256), "Repeated successor authorization"); authorizations.add(prior.authorizationSha256); }
  assert.match(value.runtimeVersionArn || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/); assert.equal(canonical(value.bindings), canonical(bindings), "Broker-policy successor bindings differ");
  return Object.freeze(structuredClone(value));
}

export function brokerPolicySuccessorClosureMetadata(record, bindings, runtimeVersionArn, reservationEtag, closedAt) {
  assert.equal(record.state, "VERIFIED"); assert(typeof reservationEtag === "string" && reservationEtag); timestamp(closedAt); assert.match(runtimeVersionArn || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  const value = { schemaVersion: 1, state: "BROKER_POLICY_SUCCESSOR_CLOSED", transitionId: record.transitionId, authorizationSha256: record.authorizationSha256,
    bindingsSha256: digest(bindings), reservationSha256: digest(record), reservationEtagSha256: digest(reservationEtag), runtimeVersionArn, closedAt };
  return Object.freeze({ [brokerPolicySuccessorMetadataKey]: Buffer.from(canonical(value)).toString("base64url") });
}

export function assertBrokerPolicySuccessorClosureMetadata(metadata, bindings) {
  assert.deepEqual(Object.keys(metadata || {}), [brokerPolicySuccessorMetadataKey], "Unexpected broker-policy successor metadata");
  const value = JSON.parse(Buffer.from(metadata[brokerPolicySuccessorMetadataKey], "base64url").toString("utf8"));
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationSha256", "bindingsSha256", "closedAt", "reservationEtagSha256", "reservationSha256", "runtimeVersionArn", "schemaVersion", "state", "transitionId"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BROKER_POLICY_SUCCESSOR_CLOSED"); uuid(value.transitionId); for (const field of ["authorizationSha256", "reservationEtagSha256", "reservationSha256"]) sha(value[field]);
  assert.equal(value.bindingsSha256, digest(bindings)); assert.match(value.runtimeVersionArn || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/); timestamp(value.closedAt);
  return Object.freeze(structuredClone(value));
}
