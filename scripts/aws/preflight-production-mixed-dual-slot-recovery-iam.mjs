#!/usr/bin/env node
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { assertResourcePolicyAllowsRuntime } from "./production-ecs-runtime-consumability.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, buildMixedDualSlotRecoveryIamPreflight } from "./production-mixed-dual-slot-recovery-contract.mjs";

const parse = (run, args) => JSON.parse(run(args));

export function readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now = new Date(), run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: "eu-west-2" }) } = {}) {
  const caller = parse(run, ["sts", "get-caller-identity"]);
  if (caller.Account !== "368992683803" || caller.Arn !== "arn:aws:iam::368992683803:root") throw new Error("Mixed recovery IAM preflight requires the exact administrator identity.");
  const role = parse(run, ["iam", "get-role", "--role-name", "mscqr-production-release-deployer"]).Role;
  if (role?.Arn !== MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN || role.PermissionsBoundary) throw new Error("Mixed recovery execution role or permissions boundary changed.");
  const resourcePolicies = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => {
    const response = parse(run, ["secretsmanager", "get-resource-policy", "--secret-id", resource]);
    if (response?.ARN !== resource) throw new Error(`Mixed recovery secret resource-policy identity changed for ${resource}.`);
    return { resource, ...assertResourcePolicyAllowsRuntime({ policy: response.ResourcePolicy ?? null, principalArn: role.Arn, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resource, label: `Mixed recovery secret resource policy for ${resource}` }) };
  });
  const evaluations = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => {
    const response = parse(run, ["iam", "simulate-principal-policy", "--policy-source-arn", MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, "--action-names", MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, "--resource-arns", resource]);
    if (!Array.isArray(response.EvaluationResults) || response.EvaluationResults.length !== 1) throw new Error("Mixed recovery IAM simulation result count is not exact.");
    const result = response.EvaluationResults[0];
    if (!result || result.EvalActionName !== MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION) throw new Error("Mixed recovery IAM simulation action or resource changed.");
    return { action: result.EvalActionName, resource: result.EvalResourceName, decision: result.EvalDecision, missingContextValues: result.MissingContextValues || [], organizationsAllowed: result.OrganizationsDecisionDetail?.AllowedByOrganizations ?? null, permissionsBoundaryAllowed: result.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary ?? null };
  });
  return buildMixedDualSlotRecoveryIamPreflight({ sourceSha, principalArn: role.Arn, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resources: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES], rolePermissionsBoundary: null, resourcePolicies, evaluations, observedAt: now.toISOString() });
}
