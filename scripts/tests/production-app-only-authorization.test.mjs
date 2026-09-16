import test from "node:test";
import assert from "node:assert/strict";
import { createAppOnlyAuthorization, assertAppOnlyAuthorization } from "../aws/production-app-only-authorization.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";

function fixture(phase = "VERIFIER") {
  const now = Date.now(), sourceSha = "a".repeat(40);
  const [kind, workflowRef] = {
    BOOTSTRAP: ["APP_ONLY_BOOTSTRAP_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyBootstrapWorkflowRef],
    VERIFIER: ["APP_ONLY_VERIFIER_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef],
    PROVISION_DEPLOYER: ["APP_ONLY_PERMISSION_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyProvisioningWorkflowRef],
    DEPLOY: ["APP_ONLY_DEPLOYMENT_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyDeploymentWorkflowRef],
  }[phase];
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_SHA: sourceSha,
    GITHUB_REF: "refs/heads/main", GITHUB_WORKFLOW_REF: workflowRef, GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
  const body = { schemaVersion: 1, kind, sourceSha, generatedAt: new Date(now).toISOString(),
    eligible: phase === "DEPLOY", ...(phase === "PROVISION_DEPLOYER" ? { phase: "DEPLOYER", eligibilitySha256: "b".repeat(64) } : {}) };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const approval = createProductionEnvironmentApprovalEvidence({ sourceSha, repository: env.GITHUB_REPOSITORY,
    environment: "production", workflowRef, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID,
    workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, observedAt: new Date(now).toISOString(),
    environmentConfig: { id: 1, name: "production", can_admins_bypass: false,
      protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] },
    actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
  return { phase, preparation, approval, env, now };
}

test("each operation binds its exact subject to the actual protected production approval", () => {
  for (const phase of ["BOOTSTRAP", "VERIFIER", "PROVISION_DEPLOYER", "DEPLOY"]) {
    const input = fixture(phase), authorization = createAppOnlyAuthorization(input);
    assert.equal(authorization.preparationSha256, input.preparation.preparationSha256);
    assert.equal(authorization.approvedBy, "reviewer");
    assert.equal(assertAppOnlyAuthorization({ ...input, authorization, now: input.now + 1000 }), true);
  }
});

test("wrong context, reruns, stale subjects and phase substitution cannot authorize mutation", () => {
  for (const field of Object.keys(fixture().env)) {
    const input = fixture(); input.env[field] = "wrong";
    assert.throws(() => createAppOnlyAuthorization(input), field);
  }
  const input = fixture(), authorization = createAppOnlyAuthorization(input);
  assert.throws(() => createAppOnlyAuthorization({ ...input, now: input.now + APP_ONLY.maxEvidenceAgeMs + 1 }));
  assert.throws(() => assertAppOnlyAuthorization({ ...input, authorization, phase: "DEPLOY" }));
  const { preparationSha256: ignored, ...substituted } = input.preparation; void ignored;
  substituted.candidateDigest = `sha256:${"d".repeat(64)}`;
  assert.throws(() => assertAppOnlyAuthorization({ ...input, authorization,
    preparation: { ...substituted, preparationSha256: canonicalSha256(substituted) } }));
  const { actualApproval: omitted, evidenceSha256: unused, ...configOnly } = input.approval; void omitted; void unused;
  configOnly.schemaVersion = 2;
  assert.throws(() => createAppOnlyAuthorization({ ...input, approval: { ...configOnly, evidenceSha256: canonicalSha256(configOnly) } }), /actual approval/i);
  assert.throws(() => assertAppOnlyAuthorization({ ...input, authorization: { ...authorization, approvedBy: "operator" } }));
});
