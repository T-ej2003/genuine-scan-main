import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";

const phases = Object.freeze({
  BOOTSTRAP: ["APP_ONLY_BOOTSTRAP_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyBootstrapWorkflowRef],
  VERIFIER: ["APP_ONLY_VERIFIER_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef],
  PROVISION_DEPLOYER: ["APP_ONLY_PERMISSION_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyProvisioningWorkflowRef],
  DEPLOY: ["APP_ONLY_DEPLOYMENT_PREPARATION", PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyDeploymentWorkflowRef],
});

// Callers must authenticate the preparation's canonical producer artifact first.
// This is not a local-JSON approval mechanism: the exact protected job must also
// authenticate GitHub's actual review event using the existing environment contract.
export function createAppOnlyAuthorization({ phase, preparation, approval, env, now = Date.now() }) {
  assert.ok(Object.hasOwn(phases, phase), "Unknown app-only approval phase");
  const [kind, workflowRef] = phases[phase];
  const { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, kind);
  assert.match(body.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(env.GITHUB_SHA, body.sourceSha); assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1", "Ambiguous executions must not be retried through workflow reruns");
  assert.equal(env.GITHUB_WORKFLOW_REF, workflowRef);
  const age = now - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale approval subject");
  if (phase === "VERIFIER") assert.equal(body.eligible, false);
  if (phase === "DEPLOY") assert.equal(body.eligible, true);
  if (phase === "PROVISION_DEPLOYER") {
    assert.equal(body.phase, "DEPLOYER"); assert.match(body.eligibilitySha256 || "", /^[a-f0-9]{64}$/);
  }
  const context = { sourceSha: body.sourceSha, repository: env.GITHUB_REPOSITORY, environment: "production", workflowRef,
    eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS, now: new Date(now) };
  assertProductionEnvironmentApprovalEvidence(approval, context);
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, context);
  const authorization = { schemaVersion: 1, kind: "APP_ONLY_PROTECTED_AUTHORIZATION", phase,
    sourceSha: body.sourceSha, preparationSha256, approvalSha256: approval.evidenceSha256,
    workflowRef, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    approvedBy, generatedAt: new Date(now).toISOString() };
  return { ...authorization, authorizationSha256: canonicalSha256(authorization) };
}

export function assertAppOnlyAuthorization({ authorization, phase, preparation, approval, env, now = Date.now() }) {
  const { authorizationSha256, ...body } = authorization;
  assert.equal(authorizationSha256, canonicalSha256(body));
  const age = now - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale app-only authorization");
  const expected = createAppOnlyAuthorization({ phase, preparation, approval, env, now });
  // The creation timestamp is fixed; all security bindings must still match now.
  expected.generatedAt = body.generatedAt;
  delete expected.authorizationSha256;
  assert.deepEqual(body, expected, "Authorization belongs to another approval, phase or preparation");
  return true;
}
