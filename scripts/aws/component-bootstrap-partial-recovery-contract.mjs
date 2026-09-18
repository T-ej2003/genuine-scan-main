import assert from "node:assert/strict";
import { brokerConfiguration } from "./component-broker-configuration.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, componentBrokerArn, identityBootstrap } from "./component-installation-identity-contract.mjs";

export const bootstrapRecovery = Object.freeze({
  transitionType: "COMPONENT_IDENTITY_BOOTSTRAP_RECOVERY",
  environment: "production-component-installation-identity-bootstrap-recovery",
  workflow: ".github/workflows/authorize-component-installation-identity-bootstrap-recovery.yml",
  artifact: "component-identity-bootstrap-recovery-authorization",
  file: "component-identity-bootstrap-recovery-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
});

export const historicalBootstrapIncident = Object.freeze({
  sourceSha: "adf2eda47b5e32dc3222adb060a9b6fd832189a1",
  transitionId: "bb793961-e6bc-4618-932a-0ea2cc8b05ad",
  authorizationRunId: "35329458948",
  authorizationSha256: "37fdaaa290e9d1da94d09bda2ab9d40251f615169926e97ec229d7563968fb18",
  journalEtag: '"fb0f2c83aae755302ea34378281c99fa"',
  packageSha256: "c7c88cf954b9d3ec499546f65c0f02f40a5d9c01fcc0199f9471d3185d3622d5",
  lambdaCodeSha256: "x8iM+VS50+xJlUb2XA8C9ApdnAH8wBmflHHTGF02ItU=",
  manifestSha256: "f3a20c806417c7ee1beb3bffb0541d7c67ab4d10479ffc69170d2a5d4446fb55",
  revisionId: "b826e594-d956-4556-9fd6-346c69a7b78b",
  runtimeVersionArn: "arn:aws:lambda:eu-west-2::runtime:499184cc22861bf242d649538cd9643369901c319b3a13ee104b5d2d15ec9d43",
  identitySetSha256: "95b1712a10c127205368f28cf474202bb7ccb9c700908baf1d72ed2ed1d1bdc4",
  capabilitySetSha256: "906e1deff4dd6076d1fa52cf3ecd0bde15bb9ec30f1e1ff8e582d68f2bd5dcba",
  documentBindingsSha256: "28278e4c91df4f30d3dac16aadb2253031908308b43dcb675beb6368d5f4a2d1",
});

export const bootstrapRecoveryOperations = Object.freeze([
  "UPDATE_EXACT_BROKER_CODE",
  "SET_EXACT_RESERVED_CONCURRENCY",
  "SET_EXACT_RUNTIME_MANAGEMENT",
  "PUBLISH_INSTALL_VERSION",
  "SET_CLEANUP_DESCRIPTION",
  "PUBLISH_CLEANUP_VERSION",
  "SET_AUTHORIZE_DESCRIPTION",
  "PUBLISH_AUTHORIZE_VERSION",
  "VERIFY_EXACT_BOOTSTRAP",
  "CLOSE_EXISTING_BOOTSTRAP_JOURNAL",
]);

export function historicalBrokerConfiguration() {
  const value = brokerConfiguration({ packageSha256: historicalBootstrapIncident.packageSha256, manifestSha256: historicalBootstrapIncident.manifestSha256, entryPoint: "INSTALL" });
  return { ...value, FunctionArn: componentBrokerArn, Version: "$LATEST" };
}

const historicalActor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
export function historicalBootstrapAuthorization() {
  const brokerConfigurations = Object.fromEntries(["INSTALL", "CLEANUP", "AUTHORIZE"].map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: historicalBootstrapIncident.packageSha256, manifestSha256: historicalBootstrapIncident.manifestSha256, entryPoint })]));
  const value = { schemaVersion: 1, transitionType: "INITIAL_IDENTITY_BOOTSTRAP", account: identityBootstrap.account, region: identityBootstrap.region,
    sourceSha: historicalBootstrapIncident.sourceSha, identitySetSha256: historicalBootstrapIncident.identitySetSha256,
    capabilitySetSha256: historicalBootstrapIncident.capabilitySetSha256, documentBindingsSha256: historicalBootstrapIncident.documentBindingsSha256,
    packageSha256: historicalBootstrapIncident.packageSha256, manifestSha256: historicalBootstrapIncident.manifestSha256, brokerConfigurations,
    transitionId: historicalBootstrapIncident.transitionId, runId: historicalBootstrapIncident.authorizationRunId,
    environment: identityBootstrap.environment, operator: historicalActor, reviewer: historicalActor,
    approvalObservedAt: "2026-09-18T09:27:06.557Z", expiresAt: "2026-09-18T09:57:06.557Z" };
  assert.equal(digest(value), historicalBootstrapIncident.authorizationSha256);
  return value;
}

export function bootstrapPartialStateDigest() {
  const identities = bootstrapManagedIdentities();
  assert.equal(digest(identities), historicalBootstrapIncident.identitySetSha256);
  return digest({
    journal: { state: "BOOTSTRAP_EXECUTING", etag: historicalBootstrapIncident.journalEtag, sourceSha: historicalBootstrapIncident.sourceSha,
      transitionId: historicalBootstrapIncident.transitionId, authorizationSha256: historicalBootstrapIncident.authorizationSha256,
      manifestSha256: historicalBootstrapIncident.manifestSha256, identitySetSha256: historicalBootstrapIncident.identitySetSha256,
      packageSha256: historicalBootstrapIncident.packageSha256 },
    identities: identities.map(({ arn, trustSha256, policyName, policySha256 }) => ({ arn, trustSha256, policyName, policySha256, state: "EXPECTED" })),
    broker: { functionName: installationIdentity.functionName, functionArn: componentBrokerArn, revisionId: historicalBootstrapIncident.revisionId,
      codeSha256: historicalBootstrapIncident.lambdaCodeSha256, packageSha256: historicalBootstrapIncident.packageSha256,
      configuration: historicalBrokerConfiguration(), versions: [], reservedConcurrency: null, runtimeManagement: "Auto", resourcePolicy: "ABSENT" },
    remainingOperations: bootstrapRecoveryOperations,
  });
}

export function bootstrapRecoveryCapabilitySet() {
  const policy = Statement => ({ Version: "2012-10-17", Statement });
  const roles = bootstrapManagedIdentities().map(({ arn }) => arn);
  const evidence = `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`;
  return policy([
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"], Resource: roles },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PutFunctionConcurrency", "lambda:PutRuntimeManagementConfig", "lambda:PublishVersion"], Resource: componentBrokerArn, Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: [1, 2, 3].map(version => `${componentBrokerArn}:${version}`), Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${identityBootstrap.bucket}`, Condition: { StringEquals: { "s3:prefix": `${identityBootstrap.prefix}identity-bootstrap.json` } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: evidence },
    { Effect: "Allow", Action: "s3:PutObject", Resource: evidence, Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ]);
}
