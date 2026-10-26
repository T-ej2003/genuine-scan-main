import assert from "node:assert/strict";
import { APP_ONLY, appOnlyServiceConfigurationSha256 } from "./production-app-only-contract.mjs";
import { GREEN_BACKEND_RECOVERY_KIND, GREEN_BACKEND_TASK_ARN } from "./production-green-backend-health-recovery.mjs";
import { journalEcsServiceUpdate } from "./production-release-gate-ecs-journal.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { GREEN_RECOVERY_PREPARED_PHASE } from "./production-green-backend-recovery-handoff.mjs";

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const HEX = /^[a-f0-9]{64}$/;
const NORMAL_DEPLOYER = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-normal-deployer\/GitHubActions$/;

export function assertHistoricalGreenUpdateEvent(event, { eventId, dispatchAt, predecessor, targetArn, deploymentId }) {
  const at = Date.parse(event?.eventTime);
  assert.equal(event?.eventID, eventId, "CloudTrail event ID differs from the authorized update");
  assert.equal(event?.eventName, "UpdateService");
  assert.equal(event?.eventSource, "ecs.amazonaws.com");
  assert.equal(event?.awsRegion, APP_ONLY.region);
  assert.equal(String(event?.recipientAccountId), APP_ONLY.account);
  assert.match(event?.userIdentity?.arn || "", NORMAL_DEPLOYER);
  assert.equal(event?.userIdentity?.type, "AssumedRole");
  assert.equal(event?.errorCode, undefined, "Historical ECS update failed");
  assert.equal(event?.requestParameters?.cluster, APP_ONLY.clusterArn);
  assert.equal(event?.requestParameters?.service, APP_ONLY.serviceArn);
  assert.equal(event?.requestParameters?.taskDefinition, targetArn, "CloudTrail task definition differs from the authorized update");
  assert.equal(event?.responseElements?.service?.serviceArn, APP_ONLY.serviceArn);
  assert.equal(event?.responseElements?.service?.taskDefinition, targetArn);
  assert.equal(event?.responseElements?.service?.desiredCount, predecessor.failureProof.desiredCount);
  assert.ok(event?.responseElements?.service?.deployments?.some((deployment) => deployment.id === deploymentId
    && deployment.taskDefinition === targetArn), "CloudTrail update did not create the live deployment");
  assert.ok(Number.isFinite(at) && at >= Date.parse(dispatchAt) - 1000 && at <= Date.parse(dispatchAt) + 120_000,
    "CloudTrail update is outside the claimed dispatch window");
  return true;
}

export async function completeHistoricalGreenBackendRecovery(input, adapters) {
  for (const key of ["store", "verifyOriginalSource", "verifyOriginalAuthorization", "verifyFreshApproval", "readCloudTrailEvent",
    "readService", "verifyCurrent", "verifyRegisteredRevision", "readComponentState", "commitComponentState"])
    assert.ok(adapters?.[key], `Historical completion requires ${key}`);
  const { operationId, originalSourceSha, originalRunId, ticket, originalTaskDefinitionArn,
    targetTaskDefinitionArn, imageDigest, cloudTrailEventId } = input;
  assert.match(originalSourceSha || "", SHA);
  assert.match(operationId || "", HEX);
  assert.match(imageDigest || "", DIGEST);
  assert.match(originalTaskDefinitionArn || "", GREEN_BACKEND_TASK_ARN);
  assert.match(targetTaskDefinitionArn || "", GREEN_BACKEND_TASK_ARN);
  assert.match(String(originalRunId || ""), /^[1-9][0-9]*$/);
  assert.match(ticket || "", /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
  assert.match(cloudTrailEventId || "", /^[a-f0-9-]{36}$/);
  assert.equal(operationId, canonicalSha256({ kind: GREEN_BACKEND_RECOVERY_KIND, sourceSha: originalSourceSha,
    taskDefinitionArn: originalTaskDefinitionArn, imageDigest }));
  await adapters.verifyOriginalSource(originalSourceSha);

  const store = adapters.store;
  const predecessor = await store.readOperation(operationId, "BACKEND:PREDECESSOR");
  const registrationDispatch = await store.readOperation(operationId, "BACKEND:REGISTER:DISPATCH");
  const registration = await store.readOperation(operationId, "BACKEND:REGISTER:COMPLETED");
  const intent = await store.readOperation(operationId, "BACKEND:UPDATE:INTENT");
  const dispatch = await store.readOperation(operationId, "BACKEND:UPDATE:DISPATCH");
  assert.ok(predecessor && registrationDispatch && registration && intent && dispatch,
    "Historical operation lacks immutable predecessor, registration, intent or dispatch");
  assert.equal(predecessor.sourceSha, originalSourceSha);
  assert.equal(predecessor.taskDefinitionArn, originalTaskDefinitionArn);
  assert.equal(predecessor.recoveryImageDigest, imageDigest);
  assert.equal(predecessor.failureProofSha256, canonicalSha256(predecessor.failureProof));
  assert.equal(predecessor.failureProof.desiredCount, 2);
  assert.equal(registration.taskDefinitionArn, targetTaskDefinitionArn);
  assert.equal(registration.intent?.operationId, operationId);
  assert.equal(registration.intent?.sourceSha, originalSourceSha);
  assert.equal(registration.intent?.imageDigest, imageDigest);
  assert.equal(registrationDispatch.operationId, operationId);
  assert.equal(registrationDispatch.sourceSha, originalSourceSha);
  assert.equal(registrationDispatch.imageDigest, imageDigest);
  assert.match(registrationDispatch.authorizationSha256 || "", HEX);
  assert.equal(intent.operationId, operationId);
  assert.equal(intent.sourceSha, originalSourceSha);
  assert.equal(intent.sourceTaskDefinitionArn, originalTaskDefinitionArn);
  assert.equal(intent.targetTaskDefinitionArn, targetTaskDefinitionArn);
  assert.equal(intent.imageDigest, imageDigest);
  assert.equal(intent.candidateFingerprint, predecessor.candidateFingerprint);
  assert.equal(intent.serviceConfigurationSha256, predecessor.serviceConfigurationSha256);
  assert.deepEqual(Object.fromEntries(Object.entries(dispatch).filter(([key]) => key !== "phase" && key !== "authorizationSha256")), intent);
  assert.equal(dispatch.phase, "BACKEND:UPDATE");
  assert.match(dispatch.authorizationSha256 || "", HEX);
  const authorization = await store.readOperation(operationId, `BACKEND:AUTHORIZATION:BACKEND:UPDATE:${dispatch.authorizationSha256}`);
  assert.equal(authorization?.phase, "BACKEND:UPDATE");
  assert.equal(authorization?.input?.approval?.authorizationSha256, dispatch.authorizationSha256);
  assert.equal(authorization?.input?.approval?.ticket, ticket);
  assert.equal(String(authorization?.githubContext?.workflowRunId), String(originalRunId));
  const handoff = await store.readOperation(operationId, `${GREEN_RECOVERY_PREPARED_PHASE}:${dispatch.authorizationSha256}`);
  assert.ok(handoff, "Original recovery handoff is missing");
  const { handoffSha256, ...handoffBody } = handoff;
  assert.equal(handoffSha256, canonicalSha256(handoffBody));
  assert.equal(handoff.operationId, operationId);
  assert.equal(handoff.sourceSha, originalSourceSha);
  assert.equal(handoff.ticket, ticket);
  assert.equal(handoff.registeredTaskDefinitionArn, targetTaskDefinitionArn);
  assert.equal(handoff.imageDigest, imageDigest);
  assert.equal(handoff.approvalSha256, dispatch.authorizationSha256);
  assert.equal(String(handoff.githubContext?.workflowRunId), String(originalRunId));
  assert.equal(handoff.componentGeneration, input.expectedComponentGeneration);
  const registerAuthorization = await store.readOperation(operationId,
    `BACKEND:AUTHORIZATION:BACKEND:REGISTER:${registrationDispatch.authorizationSha256}`);
  assert.equal(registerAuthorization?.phase, "BACKEND:REGISTER");
  assert.equal(registerAuthorization?.input?.approval?.authorizationSha256, registrationDispatch.authorizationSha256);
  assert.equal(registerAuthorization?.input?.approval?.ticket, ticket);
  assert.match(String(registerAuthorization?.githubContext?.workflowRunId || ""), /^[1-9][0-9]*$/);
  const registrationDispatchAt = await store.readOperationCommittedAt(operationId, "BACKEND:REGISTER:DISPATCH");
  const registrationAuthorizationAt = await store.readOperationCommittedAt(operationId,
    `BACKEND:AUTHORIZATION:BACKEND:REGISTER:${registrationDispatch.authorizationSha256}`);
  assert.ok(Date.parse(registrationAuthorizationAt) <= Date.parse(registrationDispatchAt));
  await adapters.verifyOriginalAuthorization(registerAuthorization, Date.parse(registrationDispatchAt));
  const dispatchAt = await store.readOperationCommittedAt(operationId, "BACKEND:UPDATE:DISPATCH");
  assert.ok(Date.parse(registrationDispatchAt) <= Date.parse(dispatchAt), "Registration occurred after UpdateService dispatch");
  const handoffAt = await store.readOperationCommittedAt(operationId, `${GREEN_RECOVERY_PREPARED_PHASE}:${dispatch.authorizationSha256}`);
  assert.ok(Date.parse(handoffAt) <= Date.parse(dispatchAt), "Original handoff was committed after UpdateService dispatch");
  const authorizationAt = await store.readOperationCommittedAt(operationId, `BACKEND:AUTHORIZATION:BACKEND:UPDATE:${dispatch.authorizationSha256}`);
  assert.ok(Date.parse(authorizationAt) <= Date.parse(dispatchAt));
  await adapters.verifyOriginalAuthorization(authorization, Date.parse(dispatchAt));
  await adapters.verifyRegisteredRevision(registration, predecessor);
  await adapters.verifyFreshApproval(input);

  const service = await adapters.readService();
  assert.equal(service.serviceArn, APP_ONLY.serviceArn);
  assert.equal(service.taskDefinition, targetTaskDefinitionArn, "Live ECS task definition differs from the historical target");
  assert.equal(service.desiredCount, 2);
  assert.equal(service.deployments?.length, 1);
  const deploymentId = service.deployments[0]?.id;
  const event = await adapters.readCloudTrailEvent(cloudTrailEventId);
  assertHistoricalGreenUpdateEvent(event, { eventId: cloudTrailEventId, dispatchAt, predecessor, targetArn: targetTaskDefinitionArn, deploymentId });
  const expectedGeneration = handoff.componentGeneration;
  const stateBefore = await adapters.readComponentState();
  const alreadyCommitted = stateBefore.generation === expectedGeneration + 1;
  if (alreadyCommitted) {
    const priorUpdate = await store.readOperation(operationId, "BACKEND:UPDATE:COMPLETED");
    const priorRecovery = await store.readOperation(operationId, "BACKEND:RECOVERY:COMPLETE");
    assert.ok(priorUpdate && priorRecovery, "Component state advanced without complete historical journal");
    const priorEvidence = { schemaVersion: 1, kind: "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha: originalSourceSha,
      imageDigest, originalTaskDefinitionArn, targetTaskDefinitionArn, operationId,
      candidateFingerprint: predecessor.candidateFingerprint, completionSha256: canonicalSha256(priorRecovery), completion: priorRecovery };
    assert.equal(stateBefore.components.backend.taskDefinitionArn, targetTaskDefinitionArn);
    assert.equal(stateBefore.components.backend.imageDigest, imageDigest);
    assert.equal(stateBefore.components.backend.establishedThroughSha, originalSourceSha);
    assert.deepEqual(stateBefore.completedEmergencyWork?.["backend-health-recovery"],
      { sourceSha: originalSourceSha, evidenceSha256: canonicalSha256(priorEvidence) });
  }
  const assertState = async () => {
    const state = await adapters.readComponentState();
    assert.equal(state.generation, alreadyCommitted ? expectedGeneration + 1 : expectedGeneration,
      "Component state generation changed");
    if (!alreadyCommitted) {
      assert.equal(state.components.backend.taskDefinitionArn, originalTaskDefinitionArn);
      assert.equal(canonicalSha256(state.components.backend), handoff.componentBackendSha256);
    }
    return state;
  };
  await assertState();
  const verify = async (current) => {
    await adapters.verifyFreshApproval(input);
    assert.equal(current.serviceArn, APP_ONLY.serviceArn);
    assert.equal(current.taskDefinition, targetTaskDefinitionArn);
    assert.equal(appOnlyServiceConfigurationSha256(current), predecessor.serviceConfigurationSha256);
    assert.equal(current.deployments?.length, 1);
    assert.equal(current.deployments[0]?.id, deploymentId, "Historical deployment changed");
    assert.equal(current.deployments[0]?.rolloutState, "COMPLETED");
    assert.equal(current.desiredCount, 2);
    assert.equal(current.runningCount, 2);
    assert.equal(current.pendingCount, 0);
    await adapters.verifyCurrent(input, current);
    await assertState();
  };
  await verify(service);
  await journalEcsServiceUpdate({ store, operationId, phase: "BACKEND:UPDATE", intent,
    dispatchIntent: dispatch, verifyDispatch: async (record) => assert.deepEqual(record, dispatch),
    read: adapters.readService, verify,
    update: () => { throw new Error("Historical completion cannot invoke ECS UpdateService"); } });
  const nativeCompletion = await store.readOperation(operationId, "BACKEND:UPDATE:COMPLETED");
  assert.equal(nativeCompletion?.nativeResult?.deploymentId, deploymentId);
  await verify(await adapters.readService());
  const health = await adapters.verifyCurrent(input, await adapters.readService());
  assert.equal(health?.healthy, true);
  assert.equal(health?.dependencies?.database, "ready");
  await adapters.verifyFreshApproval(input);
  const existing = await store.readOperation(operationId, "BACKEND:RECOVERY:COMPLETE");
  if (existing) {
    assert.deepEqual(Object.fromEntries(Object.entries(existing).filter(([key]) => !["health", "completedAt"].includes(key))),
      { ...intent, taskDefinitionArn: targetTaskDefinitionArn });
    assert.equal(existing.health?.healthy, true);
    assert.equal(existing.health?.dependencies?.database, "ready");
    assert.ok(Date.parse(existing.completedAt) >= Date.parse(event.eventTime));
  }
  const completion = existing || { ...intent, taskDefinitionArn: targetTaskDefinitionArn, health,
    completedAt: new Date(adapters.now?.() ?? Date.now()).toISOString() };
  if (!existing) await store.writeOperation(operationId, "BACKEND:RECOVERY:COMPLETE", completion);
  assert.deepEqual(await store.readOperation(operationId, "BACKEND:RECOVERY:COMPLETE"), completion);
  await verify(await adapters.readService());
  await adapters.verifyFreshApproval(input);
  const evidence = { schemaVersion: 1, kind: "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha: originalSourceSha,
    imageDigest, originalTaskDefinitionArn, targetTaskDefinitionArn, operationId,
    candidateFingerprint: predecessor.candidateFingerprint, completionSha256: canonicalSha256(completion), completion };
  evidence.evidenceSha256 = canonicalSha256(evidence);
  const committed = await adapters.commitComponentState(evidence);
  assert.equal(committed.state.components.backend.taskDefinitionArn, targetTaskDefinitionArn);
  assert.equal(committed.state.components.backend.imageDigest, imageDigest);
  assert.equal(committed.state.generation, expectedGeneration + 1);
  return { operationId, taskDefinitionArn: targetTaskDefinitionArn, evidence, componentState: committed.state };
}
