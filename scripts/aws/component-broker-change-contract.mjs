import assert from "node:assert/strict";
import { brokerChangeEntryPoints, brokerConfiguration } from "./component-broker-configuration.mjs";
import { completedBootstrapRecovery, historicalBootstrapIncident } from "./component-bootstrap-partial-recovery-contract.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, componentBrokerArn, identityBootstrap } from "./component-installation-identity-contract.mjs";

// A one-use successor transition. It deliberately has no generic function,
// package, version, role, or policy parameter.
export const brokerChange = Object.freeze({
  transitionType: "COMPONENT_BROKER_CHANGE",
  environment: "production-component-installation-broker-change",
  workflow: ".github/workflows/authorize-component-installation-broker-change.yml",
  artifact: "component-broker-change-authorization",
  file: "component-broker-change-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
});

export const brokerChangeOperations = Object.freeze([
  "UPDATE_EXACT_BROKER_CODE",
  "PUBLISH_INSTALL_SUCCESSOR_VERSION",
  "SET_CLEANUP_SUCCESSOR_DESCRIPTION",
  "PUBLISH_CLEANUP_SUCCESSOR_VERSION",
  "SET_AUTHORIZE_SUCCESSOR_DESCRIPTION",
  "PUBLISH_AUTHORIZE_SUCCESSOR_VERSION",
  "REBIND_EXACT_BROKER_INVOKERS",
  "VERIFY_EXACT_BROKER_CHANGE",
  "CLOSE_BROKER_CHANGE",
]);

export function brokerChangeConfigurations(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assert.match(packageEvidence.packageSha256 || "", /^[a-f0-9]{64}$/);
  return Object.freeze(Object.fromEntries(Object.keys(brokerChangeEntryPoints).map((entryPoint) => [entryPoint,
    brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, entryPoint, entryPoints: brokerChangeEntryPoints })])));
}

export function brokerChangeConfigurationSha256(packageEvidence) {
  return digest(brokerChangeConfigurations(packageEvidence));
}

export function brokerChangePredecessor() {
  return Object.freeze({
    historicalSourceSha: historicalBootstrapIncident.sourceSha,
    historicalTransitionId: historicalBootstrapIncident.transitionId,
    historicalAuthorizationSha256: historicalBootstrapIncident.authorizationSha256,
    recoveryTransitionId: completedBootstrapRecovery.transitionId,
    recoveryAuthorizationSha256: completedBootstrapRecovery.authorizationSha256,
    recoverySourceSha: completedBootstrapRecovery.sourceSha,
    recoveryPackageSha256: completedBootstrapRecovery.packageSha256,
    recoveryManifestSha256: completedBootstrapRecovery.manifestSha256,
    functionArn: componentBrokerArn,
    executionRoleArn: `arn:aws:iam::${identityBootstrap.account}:role/${installationIdentity.provisionerRole}`,
    identitySetSha256: digest(bootstrapManagedIdentities()),
    versions: ["1", "2", "3"],
  });
}

export function brokerChangeCapabilitySet() {
  const policy = Statement => ({ Version: "2012-10-17", Statement });
  const roles = brokerChangeManagedIdentities().map(({ arn }) => arn);
  const evidence = `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`;
  return policy([
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:PutRolePolicy"], Resource: roles },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion"], Resource: componentBrokerArn, Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: [...[1, 2, 3, 4, 5, 6].map((version) => `${componentBrokerArn}:${version}`)], Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${identityBootstrap.bucket}`, Condition: { StringEquals: { "s3:prefix": `${identityBootstrap.prefix}identity-bootstrap.json` } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: evidence },
    { Effect: "Allow", Action: "s3:PutObject", Resource: evidence, Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ]);
}
