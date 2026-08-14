import { assertGitHubApprovedMutationContext, GITHUB_MUTATION_ROLE_ARN, PRODUCTION_CALLER_MODES } from "../aws/production-caller-identity-contract.mjs";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
};

const result = assertGitHubApprovedMutationContext({
  callerArn: `arn:aws:sts::368992683803:assumed-role/mscqr-production-github-actions-mutation/contract-preflight`,
  mode: PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION,
  repository: required("GITHUB_REPOSITORY"),
  environment: required("GITHUB_ENVIRONMENT"),
  ref: required("GITHUB_REF"),
  workflowRef: required("GITHUB_WORKFLOW_REF"),
  eventName: required("GITHUB_EVENT_NAME"),
  sourceSha: required("SOURCE_SHA"),
  trustedMainSha: required("TRUSTED_MAIN_SHA"),
  environmentApproved: process.env.PRODUCTION_ENVIRONMENT_APPROVED === "true",
});

if (process.env.EXPECTED_ROLE_ARN !== GITHUB_MUTATION_ROLE_ARN) throw new Error("The configured CI role is not the reviewed mutation role.");
process.stdout.write(`${JSON.stringify({ valid: true, mode: result.mode, roleArn: result.roleArn, sourceSha: result.sourceSha, workflowRef: result.workflowRef })}\n`);
