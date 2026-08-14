import assert from "node:assert/strict";
import test from "node:test";
import {
  GITHUB_MUTATION_ROLE_ARN,
  PRODUCTION_CALLER_MODES,
  PRODUCTION_GITHUB_OIDC_CONTRACT,
  RELEASE_ROLE_ARN,
  assertGitHubApprovedMutationContext,
  assertProductionCaller,
} from "../aws/production-caller-identity-contract.mjs";

const sha = "a".repeat(40);
const human = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/human-mfa";
const ci = "arn:aws:sts::368992683803:assumed-role/mscqr-production-github-actions-mutation/run-123";
const context = {
  callerArn: ci,
  mode: PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION,
  repository: "T-ej2003/genuine-scan-main",
  environment: "production",
  ref: "refs/heads/main",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main",
  eventName: "workflow_dispatch",
  sourceSha: sha,
  trustedMainSha: sha,
  environmentApproved: true,
};

test("the two production caller modes are exact and distinct", () => {
  assert.equal(assertProductionCaller({ callerArn: human, mode: PRODUCTION_CALLER_MODES.HUMAN_MFA_RELEASE_DEPLOYER }).roleArn, RELEASE_ROLE_ARN);
  assert.equal(assertProductionCaller({ callerArn: ci, mode: PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION }).roleArn, GITHUB_MUTATION_ROLE_ARN);
  for (const callerArn of ["arn:aws:sts::368992683803:assumed-role/github-actions-mscqr-deploy/run", "arn:aws:sts::368992683803:assumed-role/mscqr-production-github-actions-readonly/run", "arn:aws:sts::368992683803:assumed-role/mscqr-production-green-stage-b-image-publisher/run"]) {
    assert.throws(() => assertProductionCaller({ callerArn, mode: PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION }));
  }
});

test("CI mode requires the exact approved repository, environment, workflow, branch, event, and SHA", () => {
  assert.deepEqual(assertGitHubApprovedMutationContext(context).roleArn, GITHUB_MUTATION_ROLE_ARN);
  for (const [field, value] of [
    ["repository", "other/repository"], ["environment", "staging"], ["ref", "refs/heads/feature"],
    ["workflowRef", "T-ej2003/genuine-scan-main/.github/workflows/other.yml@refs/heads/main"],
    ["eventName", "pull_request"], ["sourceSha", "b".repeat(40)], ["trustedMainSha", "b".repeat(40)],
  ]) assert.throws(() => assertGitHubApprovedMutationContext({ ...context, [field]: value }));
  assert.throws(() => assertGitHubApprovedMutationContext({ ...context, environmentApproved: false }));
  assert.equal(PRODUCTION_GITHUB_OIDC_CONTRACT.audience, "sts.amazonaws.com");
  assert.equal(PRODUCTION_GITHUB_OIDC_CONTRACT.branch, "refs/heads/main");
});

test("human mode never accepts the CI role and CI mode never accepts the human role", () => {
  assert.throws(() => assertProductionCaller({ callerArn: ci, mode: PRODUCTION_CALLER_MODES.HUMAN_MFA_RELEASE_DEPLOYER }));
  assert.throws(() => assertGitHubApprovedMutationContext({ ...context, callerArn: human }));
  assert.throws(() => assertProductionCaller({ callerArn: human, mode: "UNREVIEWED_ROLE" }));
});
