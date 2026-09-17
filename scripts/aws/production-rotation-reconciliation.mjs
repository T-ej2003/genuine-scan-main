import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { APP_ONLY, captureAppOnlyPredecessor, captureBackendServiceSnapshot } from "./production-app-only-contract.mjs";

export const assertRotationBackendTaskArn = (arn) => assert.match(arn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/(mscqr-backend|mscqr-production-rls-green-backend-candidate):[1-9][0-9]*$/);

export function authenticateRotationReconciliation({ readiness, current, readers, expectedCurrentTaskDefinitionArn, taskDefinitionArn, imageDigest, releaseIdentity, mode, isProtectedMainAncestor }) {
  assert.ok(current?.components?.backend, "Production component state is not bootstrapped.");
  const bindings = readiness.overlapTaskDefinition.identityBindings;
  assert.equal(bindings.taskDefinitionArn, taskDefinitionArn, "Rotation target differs from readiness.");
  assertRotationBackendTaskArn(expectedCurrentTaskDefinitionArn);
  assert.notEqual(expectedCurrentTaskDefinitionArn, taskDefinitionArn, "Rotation predecessor must differ from target.");
  if (bindings.imageDigest !== undefined) assert.equal(bindings.imageDigest, imageDigest, "Rotation digest differs from readiness.");
  assert.equal(isProtectedMainAncestor(readiness.sourceSha), true, "Rotation source is not protected-main history.");
  const snapshot = readers.readLive();
  const containers = snapshot.definition.containerDefinitions.filter(({ name }) => name === APP_ONLY.container);
  assert.equal(containers.length, 1);
  const digest = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/.exec(containers[0].image);
  assert.ok(digest, "Rotation image must be immutable.");
  assert.equal(snapshot.definition.status, "ACTIVE");
  const live = captureBackendServiceSnapshot(snapshot, digest[1]);
  const sourceSha = readers.readBackendImageSource(live.backendDigest);
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Rotation image source is not protected-main history.");
  const backend = { sourceSha, establishedThroughSha: readiness.sourceSha, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: live.desiredCount };
  const predecessor = current.components.backend.taskDefinitionArn === expectedCurrentTaskDefinitionArn;
  const committed = canonicalSha256(current.components.backend) === canonicalSha256(backend)
    && current.components.security?.releaseIdentity === releaseIdentity
    && current.components.security?.sourceSha === readiness.sourceSha
    && current.completedEmergencyWork?.[mode]?.sourceSha === readiness.sourceSha
    && current.completedEmergencyWork?.[mode]?.evidenceSha256 === releaseIdentity;
  assert.ok(predecessor || committed, "Rotation durable predecessor or completed transition mismatch.");
  assert.equal(live.desiredCount, current.components.backend.desiredCount, "Rotation desired count differs from predecessor state.");
  if (predecessor) {
    const definition = readers.readDefinition(expectedCurrentTaskDefinitionArn);
    const images = definition.containerDefinitions.filter(({ name }) => name === APP_ONLY.container);
    assert.equal(definition.taskDefinitionArn, expectedCurrentTaskDefinitionArn);
    assert.equal(images.length, 1);
    assert.equal(images[0].image, `${APP_ONLY.backendRepository}@${current.components.backend.imageDigest}`, "Rotation recorded predecessor digest mismatch.");
    assert.equal(readers.readBackendImageSource(current.components.backend.imageDigest), current.components.backend.sourceSha, "Rotation recorded predecessor source mismatch.");
  }
  if (live.taskDefinitionArn === expectedCurrentTaskDefinitionArn) {
    assert.ok(predecessor, "Committed rotation cannot regress to its predecessor.");
    assert.equal(live.backendDigest, current.components.backend.imageDigest);
    assert.equal(sourceSha, current.components.backend.sourceSha);
    return { disposition: "PRE_SWITCH", backend };
  }
  assert.equal(live.taskDefinitionArn, taskDefinitionArn, "Unknown live rotation task definition.");
  assert.equal(live.backendDigest, imageDigest, "Rotation live digest mismatch.");
  captureAppOnlyPredecessor(snapshot);
  assert.equal(snapshot.definition.tags?.filter(({ key, value }) => key === "MSCQRExecTarget" && value === "production-backend").length, 1, "Rotation execution-target marker mismatch.");
  for (const entry of containers[0].environment || []) {
    if (["GIT_SHA", "RELEASE_GIT_SHA"].includes(entry.name)) assert.equal(entry.value, readiness.sourceSha, "Rotation runtime source mismatch.");
  }
  assert.equal(snapshot.service.enableExecuteCommand, true, "Rotation ECS Exec setting mismatch.");
  assert.equal(snapshot.service.propagateTags, "TASK_DEFINITION", "Rotation task-tag propagation mismatch.");
  return { disposition: "ALREADY_APPLIED", backend, metadata: {
    mode: "existing-task-definition", clusterName: APP_ONLY.cluster, serviceName: APP_ONLY.service, containerName: APP_ONLY.container,
    previousTaskDefinitionArn: expectedCurrentTaskDefinitionArn, newTaskDefinitionArn: taskDefinitionArn,
    expectedImageDigest: imageDigest, observedTaskDefinitionArn: taskDefinitionArn, observedImageDigest: imageDigest,
    observedTaskArns: snapshot.tasks.map(({ taskArn }) => taskArn).sort(),
    desiredCount: live.desiredCount, runningCount: live.desiredCount, pendingCount: 0, serviceStable: true,
  } };
}

export async function runReconciledRotationDeployment({ deploy, verifyApplied, ...input }) {
  const checked = authenticateRotationReconciliation(input);
  if (checked.disposition === "PRE_SWITCH") return deploy();
  await verifyApplied();
  return { disposition: "ALREADY_APPLIED", updateServiceCount: 0, propagateTags: "TASK_DEFINITION", taskDefinitionArn: input.taskDefinitionArn, metadata: checked.metadata };
}
