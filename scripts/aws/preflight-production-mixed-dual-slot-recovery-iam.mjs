#!/usr/bin/env node
import fs from "node:fs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { assertResourcePolicyAllowsRuntime } from "./production-ecs-runtime-consumability.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_EXECUTION_TRUST_PATH, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, buildMixedDualSlotRecoveryIamPreflight, mixedDualSlotRecoverySha256, readMixedDualSlotRecoveryGithubEnvironmentGuard } from "./production-mixed-dual-slot-recovery-contract.mjs";

const parse = (run, args) => JSON.parse(run(args));
const missingContext = (result) => {
  if (result.MissingContextValues === undefined) return [];
  if (!Array.isArray(result.MissingContextValues)) throw new Error("Mixed recovery IAM simulation context result is malformed.");
  return result.MissingContextValues;
};
const restriction = (result, detail, field) => {
  if (result[detail] === undefined) return null;
  if (!result[detail] || typeof result[detail] !== "object" || ![true, false].includes(result[detail][field])) throw new Error("Mixed recovery IAM simulation restriction result is malformed.");
  return result[detail][field];
};

export function readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now = new Date(), run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: "eu-west-2" }), githubRun = createProductionGithubCommandRunner() } = {}) {
  const caller = parse(run, ["sts", "get-caller-identity"]);
  if (caller.Account !== "368992683803" || caller.Arn !== "arn:aws:iam::368992683803:root") throw new Error("Mixed recovery IAM preflight requires the exact administrator identity.");
  let organizationsGuard;
  try {
    parse(run, ["organizations", "describe-organization"]);
    throw new Error("Mixed recovery IAM preflight cannot authenticate the effective SCP layer for an Organizations member account.");
  } catch (error) {
    const message = `${error?.stderr || ""} ${error?.message || ""}`;
    if (!/AWSOrganizationsNotInUseException/.test(message)) throw error;
    organizationsGuard = { accountId: caller.Account, status: "NOT_IN_ORGANIZATION", evidence: "AWSOrganizationsNotInUseException" };
  }
  const provider = parse(run, ["iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN]);
  if (provider?.Url !== "token.actions.githubusercontent.com" || !Array.isArray(provider.ClientIDList) || provider.ClientIDList.length !== 1 || provider.ClientIDList[0] !== "sts.amazonaws.com") throw new Error("Mixed recovery GitHub Actions OIDC provider URL or audience changed.");
  const oidcProviderGuard = { providerArn: MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, url: provider.Url, audience: "sts.amazonaws.com" };
  const githubEnvironmentGuard = readMixedDualSlotRecoveryGithubEnvironmentGuard({ run: githubRun });
  const role = parse(run, ["iam", "get-role", "--role-name", "mscqr-production-mixed-dual-slot-recovery-executor"]).Role;
  if (role?.Arn !== MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN || role.PermissionsBoundary) throw new Error("Mixed recovery execution role or permissions boundary changed.");
  const expectedTrust = JSON.parse(fs.readFileSync(MIXED_DUAL_SLOT_RECOVERY_EXECUTION_TRUST_PATH, "utf8"));
  const liveTrust = normalizeIamPolicyDocument(role.AssumeRolePolicyDocument, "mixed recovery execution role trust");
  const roleTrustPolicySha256 = mixedDualSlotRecoverySha256(liveTrust);
  if (roleTrustPolicySha256 !== mixedDualSlotRecoverySha256(expectedTrust)) throw new Error("Mixed recovery execution role trust changed.");
  const secretEncryptionGuards = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => {
    const response = parse(run, ["secretsmanager", "describe-secret", "--secret-id", resource]);
    if (response?.ARN !== resource || response.KmsKeyId != null) throw new Error(`Mixed recovery secret encryption changed for ${resource}.`);
    return { resource, kmsKeyId: null, encryption: "AWS_MANAGED" };
  });
  const resourcePolicies = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => {
    const response = parse(run, ["secretsmanager", "get-resource-policy", "--secret-id", resource]);
    if (response?.ARN !== resource) throw new Error(`Mixed recovery secret resource-policy identity changed for ${resource}.`);
    return { resource, ...assertResourcePolicyAllowsRuntime({ policy: response.ResourcePolicy ?? null, principalArn: role.Arn, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resource, label: `Mixed recovery secret resource policy for ${resource}` }) };
  });
  const evaluations = MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES.flatMap(({ action, resources }) => resources.map((resource) => {
    const response = parse(run, ["iam", "simulate-principal-policy", "--policy-source-arn", MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, "--action-names", action, "--resource-arns", resource]);
    if (!Array.isArray(response.EvaluationResults) || response.EvaluationResults.length !== 1) throw new Error("Mixed recovery IAM simulation result count is not exact.");
    const result = response.EvaluationResults[0];
    if (!result || result.EvalActionName !== action) throw new Error("Mixed recovery IAM simulation action or resource changed.");
    let evaluated = result;
    if (resource === "*") {
      if (result.EvalResourceName !== "*" || result.ResourceSpecificResults !== undefined && (!Array.isArray(result.ResourceSpecificResults) || result.ResourceSpecificResults.length !== 0)) throw new Error("Mixed recovery IAM simulation wildcard result is not exact.");
    } else {
      if (!Array.isArray(result.ResourceSpecificResults) || result.ResourceSpecificResults.length !== 1) throw new Error("Mixed recovery IAM simulation per-resource result count is not exact.");
      evaluated = result.ResourceSpecificResults[0];
      if (evaluated?.EvalResourceName !== resource || result.EvalDecision !== evaluated.EvalResourceDecision) throw new Error("Mixed recovery IAM simulation action or resource changed.");
    }
    const missingContextValues = [...missingContext(result), ...(evaluated === result ? [] : missingContext(evaluated))];
    const organizations = [result, ...(evaluated === result ? [] : [evaluated])].map((value) => restriction(value, "OrganizationsDecisionDetail", "AllowedByOrganizations"));
    const permissionsBoundary = [result, ...(evaluated === result ? [] : [evaluated])].map((value) => restriction(value, "PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary"));
    const organizationsAllowed = organizations.includes(false) ? false : organizations.includes(true) ? true : null;
    const permissionsBoundaryAllowed = permissionsBoundary.includes(false) ? false : permissionsBoundary.includes(true) ? true : null;
    return { action: result.EvalActionName, resource: evaluated.EvalResourceName, decision: resource === "*" ? result.EvalDecision : evaluated.EvalResourceDecision, missingContextValues, organizationsAllowed, permissionsBoundaryAllowed };
  }));
  return buildMixedDualSlotRecoveryIamPreflight({ sourceSha, principalArn: role.Arn, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resources: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES], roleTrustPolicySha256, rolePermissionsBoundary: null, oidcProviderGuard, githubEnvironmentGuard, organizationsGuard, secretEncryptionGuards, resourcePolicies, evaluations, observedAt: now.toISOString() });
}
