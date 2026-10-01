import assert from "node:assert/strict";
import test from "node:test";
import { assertArchivedFailedInventoryTask, assertFailedPreDeploymentPredecessor, assertPreDeploymentReplayRow, createPreDeploymentOperationIdentity, preDeploymentOperationKey, preDeploymentRecoveryTransaction } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
const source = "2f296dfe5546765a4b762568cbaa7fc26af97660";
const identity = createPreDeploymentOperationIdentity({ approvalId: `APR-STAGE-B-${source}`, releaseSha: source, imageReleaseSha: source, rotationId: "rotation-20260913011819-98b062c4", taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:3", imageDigest: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:3cbf8683f4072db322e4d09be9783e1804353fbc50a5b55020988665d2e3ef6e" });
// Exact persisted production shape and identity; the private nonce is replaced.
const row = { ...identity, identityVersion: 2, approvalMode: "production-predeployment-rotation-inventory#0c14f7f9eab1481da87a58e0fe8445e882653437d3a13f7f535782e0b7e3794c", operationIdentitySha256: "ec5a6d279abf3c754d4418242a4d89d083190d795a34497bf92633e8e7ff1a0d", approvalNonce: "fixture-private-nonce", expiresAt: 1790812875, launchState: "launch-uncertain", taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fa5ad8eb6aa9443cad6ec600bfa8e82c" };
const task = { taskArn: row.taskArn, taskDefinitionArn: identity.taskDefinitionArn, clusterArn: STAGE_B.clusterArn, lastStatus: "STOPPED", stopCode: "EssentialContainerExited", containers: [{ name: "inventory", exitCode: 1, image: identity.imageDigest }], tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: source }, { key: "RotationId", value: identity.rotationId }] };
const logs = [{ message: "Error: read-only rotation inventory query failed" }];
const successorIdentity = createPreDeploymentOperationIdentity({ ...identity, releaseSha: "a".repeat(40), approvalId: `APR-STAGE-B-${"a".repeat(40)}`, taskDefinitionArn: identity.taskDefinitionArn.replace(/:3$/, ":4") });
const successor = { ...successorIdentity, operationKey: preDeploymentOperationKey(successorIdentity), nonce: "successor-private-nonce", expiresAt: "2026-10-02T12:00:00.000Z" };
test("exact preserved launch-uncertain row authenticates and creates an atomic forward-only successor", () => {
  assert.equal(assertPreDeploymentReplayRow(row, identity).launchState, "launch-uncertain");
  const proof = assertFailedPreDeploymentPredecessor({ row, identity, task, logEvents: logs }); assert.equal(proof.taskArn, row.taskArn);
  const tx = preDeploymentRecoveryTransaction({ table: "reviewed-replay-table", predecessor: { row, identity }, successor, recoveryEvidenceSha256: "b".repeat(64) });
  assert.equal(tx.TransactItems.length, 3);
  assert.match(tx.TransactItems[2].ConditionCheck.Key.approvalMode.S, /^absent-inventory-recovery#/);
  assert.match(tx.TransactItems[0].Update.ConditionExpression, /attribute_not_exists\(successorOperationKey\)/);
  assert.equal(tx.TransactItems[1].Put.ConditionExpression, "attribute_not_exists(approvalMode)");
  assert.equal(tx.TransactItems[1].Put.Item.predecessorOperationKey.S, row.approvalMode);
  assert.equal(tx.TransactItems[0].Update.ExpressionAttributeValues[":identity"].S, row.operationIdentitySha256);
});
test("successful, unknown, substituted, or output-producing predecessors fail closed", () => {
  for (const changed of [{ ...task, lastStatus: "RUNNING" }, { ...task, containers: [{ ...task.containers[0], exitCode: 0 }] }, { ...task, taskArn: row.taskArn.replace(/82c$/, "82d") }, { ...task, tags: [] }]) assert.throws(() => assertFailedPreDeploymentPredecessor({ row, identity, task: changed, logEvents: logs }));
  for (const logEvents of [[], [{ message: "unknown failure" }], [...logs, { message: '{"refreshSessions":{"count":0}}' }]]) assert.throws(() => assertFailedPreDeploymentPredecessor({ row, identity, task, logEvents }));
  assert.throws(() => assertFailedPreDeploymentPredecessor({ row: { ...row, launchState: "succeeded" }, identity, task, logEvents: logs }));
});
test("recovered predecessor cannot authorize a second successor and identity substitution fails", () => {
  const recovered = { ...row, launchState: "failed-recovered", successorOperationKey: successor.operationKey, recoveryEvidenceSha256: "b".repeat(64) };
  assert.doesNotThrow(() => assertPreDeploymentReplayRow(recovered, identity));
  assert.throws(() => preDeploymentRecoveryTransaction({ table: "reviewed-replay-table", predecessor: { row: recovered, identity }, successor, recoveryEvidenceSha256: "b".repeat(64) }));
  assert.throws(() => preDeploymentRecoveryTransaction({ table: "reviewed-replay-table", predecessor: { row, identity: { ...identity, imageReleaseSha: "f".repeat(40) } }, successor, recoveryEvidenceSha256: "b".repeat(64) }));
});

test("actual AWS archived StopTask shape plus uncaught fixed CLI failure remains recoverable after ECS forgets the task", () => {
  const event = { eventSource: "ecs.amazonaws.com", eventName: "StopTask", recipientAccountId: "368992683803", awsRegion: "eu-west-2", eventID: "56033bd5-383f-4ed1-8655-fa67dcbe78d6", eventTime: "2026-09-30T22:40:08Z", userIdentity: { sessionContext: { sessionIssuer: { arn: STAGE_B.brokerRoleArn } } }, requestParameters: { task: row.taskArn, cluster: STAGE_B.clusterArn }, responseElements: { task: { taskArn: row.taskArn, taskDefinitionArn: identity.taskDefinitionArn, clusterArn: STAGE_B.clusterArn, lastStatus: "STOPPED", stopCode: "EssentialContainerExited", stoppedAt: "2026-09-30T22:40:06Z", containers: [], tags: [] } } };
  const logEvents = [...logs, { message: "    at executeProductionRotationInventory (file:///app/scripts/production-rotation-state-inventory.mjs:30:34)" }];
  assert.equal(assertArchivedFailedInventoryTask({ row, identity, cloudTrailEvent: event, logEvents }).cloudTrailEventId, event.eventID);
  for (const changed of [{ ...event, eventSource: "untrusted" }, { ...event, errorCode: "AccessDenied" }, { ...event, eventTime: "2026-10-02T00:00:00Z" }, { ...event, userIdentity: {} }]) assert.throws(() => assertArchivedFailedInventoryTask({ row, identity, cloudTrailEvent: changed, logEvents }));
  assert.throws(() => assertArchivedFailedInventoryTask({ row, identity, cloudTrailEvent: event, logEvents: [...logEvents, { message: "{}" }] }));
  assert.throws(() => assertArchivedFailedInventoryTask({ row: { ...row, launchState: "succeeded" }, identity, cloudTrailEvent: event, logEvents }));
});
