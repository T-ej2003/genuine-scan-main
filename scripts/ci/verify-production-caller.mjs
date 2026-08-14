import { assertGitHubApprovedMutationContext, assertProductionCaller, PRODUCTION_CALLER_MODES } from "../aws/production-caller-identity-contract.mjs";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
};

const mode = required("MSCQR_PRODUCTION_CALLER_MODE");
const callerArn = required("AWS_CALLER_ARN");
const identity = mode === PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION
  ? assertGitHubApprovedMutationContext({
    callerArn,
    mode,
    repository: required("GITHUB_REPOSITORY"),
    environment: required("GITHUB_ENVIRONMENT"),
    ref: required("GITHUB_REF"),
    workflowRef: required("GITHUB_WORKFLOW_REF"),
    eventName: required("GITHUB_EVENT_NAME"),
    sourceSha: required("SOURCE_SHA"),
    trustedMainSha: required("TRUSTED_MAIN_SHA"),
    environmentApproved: process.env.PRODUCTION_ENVIRONMENT_APPROVED === "true",
  })
  : assertProductionCaller({ callerArn, mode });

process.stdout.write(`${JSON.stringify({ valid: true, mode: identity.mode, roleArn: identity.roleArn, callerArn: identity.callerArn })}\n`);
