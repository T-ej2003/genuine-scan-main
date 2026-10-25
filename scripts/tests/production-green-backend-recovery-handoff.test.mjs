import assert from "node:assert/strict";
import test from "node:test";
import { prepareGreenRecoveryHandoff, assertGreenRecoveryHandoff } from "../aws/production-green-backend-recovery-handoff.mjs";

const now = Date.parse("2026-10-25T20:00:00.000Z");
const input = { sourceSha: "a".repeat(40), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:24",
  recoveryImageDigest: `sha256:${"b".repeat(64)}`, candidateFingerprint: "c".repeat(64), deploymentId: "ecs-svc/1",
  serviceConfigurationSha256: "d".repeat(64), runtimeConsumabilitySha256: "e".repeat(64),
  approval: { ticket: "CHG-20261025-007", authorizationSha256: "f".repeat(64) },
  environmentApproval: { evidenceSha256: "1".repeat(64) }, imageAuthorization: { evidenceSha256: "2".repeat(64) },
  databaseCompatibility: { resultSha256: "3".repeat(64) } };
const componentState = { generation: 1, components: { backend: { taskDefinitionArn: input.taskDefinitionArn } } };
const githubContext = { repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1" };
const context = { input, componentState, githubContext, operationId: "4".repeat(64),
  registeredTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:35", now };

test("handoff binds source, ticket, digest, predecessor, component state and exact run", () => {
  const handoff = prepareGreenRecoveryHandoff({ ...context, livePolicyIdentity: { task: "5".repeat(64) } });
  assert.equal(assertGreenRecoveryHandoff(handoff, context), handoff);
  for (const changed of [
    { input: { ...input, sourceSha: "6".repeat(40) } },
    { input: { ...input, recoveryImageDigest: `sha256:${"7".repeat(64)}` } },
    { input: { ...input, approval: { ...input.approval, ticket: "CHG-OTHER" } } },
    { input: { ...input, deploymentId: "ecs-svc/2" } },
    { input: { ...input, serviceConfigurationSha256: "8".repeat(64) } },
    { componentState: { ...componentState, generation: 2 } },
    { githubContext: { ...githubContext, workflowRunAttempt: "2" } },
    { registeredTaskDefinitionArn: context.registeredTaskDefinitionArn.replace(":35", ":36") },
  ]) assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, ...changed }));
  assert.throws(() => assertGreenRecoveryHandoff({ ...handoff, ticket: "forged" }, context));
  assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, now: now + 10 * 60_000 + 1 }), /stale/);
  assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, now: now - 1 }), /stale/);
});
