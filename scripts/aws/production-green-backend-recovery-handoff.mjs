import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

const SHA = /^[a-f0-9]{64}$/;
export const GREEN_RECOVERY_PREPARED_PHASE = "BACKEND:HANDOFF:PREPARED";

export function prepareGreenRecoveryHandoff({ input, operationId, registeredTaskDefinitionArn, githubContext, livePolicyIdentity, componentState, now }) {
  assert.match(operationId || "", SHA);
  assert.match(registeredTaskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/);
  assert.ok(livePolicyIdentity && typeof livePolicyIdentity === "object");
  assert.ok(Number.isSafeInteger(componentState?.generation) && componentState.generation > 0);
  assert.equal(componentState.components?.backend?.taskDefinitionArn, input.taskDefinitionArn);
  const body = { schemaVersion: 1, kind: "GREEN_BACKEND_RECOVERY_HANDOFF", operationId,
    sourceSha: input.sourceSha, ticket: input.approval.ticket, taskDefinitionArn: input.taskDefinitionArn,
    imageDigest: input.recoveryImageDigest, registeredTaskDefinitionArn, candidateFingerprint: input.candidateFingerprint,
    deploymentId: input.deploymentId, serviceConfigurationSha256: input.serviceConfigurationSha256,
    approvalSha256: input.approval.authorizationSha256,
    environmentApprovalSha256: input.environmentApproval.evidenceSha256,
    imageAuthorizationSha256: input.imageAuthorization.evidenceSha256,
    runtimeConsumabilitySha256: input.runtimeConsumabilitySha256,
    databaseCompatibilitySha256: input.databaseCompatibility.resultSha256,
    componentGeneration: componentState.generation,
    componentBackendSha256: canonicalSha256(componentState.components.backend),
    livePolicyIdentity, githubContext, preparedAt: new Date(now).toISOString() };
  return { ...body, handoffSha256: canonicalSha256(body) };
}

export function assertGreenRecoveryHandoff(handoff, { input, operationId, registeredTaskDefinitionArn, githubContext, componentState, now }) {
  assert.ok(handoff && handoff.schemaVersion === 1 && handoff.kind === "GREEN_BACKEND_RECOVERY_HANDOFF");
  const { handoffSha256, livePolicyIdentity, preparedAt, ...body } = handoff;
  assert.match(handoffSha256 || "", SHA);
  assert.equal(handoffSha256, canonicalSha256({ ...body, livePolicyIdentity, preparedAt }));
  const preparedAtMs = Date.parse(preparedAt);
  assert.ok(Number.isFinite(preparedAtMs) && preparedAtMs <= now && now - preparedAtMs <= 10 * 60_000,
    "Green recovery preparation is stale");
  assert.deepEqual(handoff, prepareGreenRecoveryHandoff({ input, operationId, registeredTaskDefinitionArn, githubContext,
    livePolicyIdentity, componentState, now: preparedAtMs }), "Green recovery handoff binding changed");
  return handoff;
}
