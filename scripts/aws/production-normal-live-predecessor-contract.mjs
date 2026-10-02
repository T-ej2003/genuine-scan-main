import assert from "node:assert/strict";
import { APP_ONLY, assertAppOnlyDefinition } from "./production-app-only-contract.mjs";
import { assertProductionComponentDeploymentState, componentDeploymentProvenance, stateHash } from "./production-component-deployment-state.mjs";
import { NORMAL_RECEIPT_WORKFLOW } from "./production-normal-receipt-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;

export function assertNormalDeploymentLivePredecessor({ componentState, service, taskDefinition, repository, imageDetails } = {}) {
  assertProductionComponentDeploymentState(componentState);
  const backendProvenance = componentDeploymentProvenance(componentState, "backend");
  assert.equal(backendProvenance.lane, "NORMAL_APPLICATION");
  assert.equal(backendProvenance.workflow, NORMAL_RECEIPT_WORKFLOW);
  assert.match(String(backendProvenance.githubRunId), /^[1-9][0-9]*$/, "Normal deployment evidence requires a GitHub run identity");
  assert.equal(componentState.normalDeploymentReceipt, undefined, "Normal deployment receipt must be atomically committed into component state");
  const backend = componentState.components.backend;
  assert.ok(backend, "Normal deployment backend state is missing");
  assert.equal(backend.sourceSha, backend.establishedThroughSha);
  assert.match(backend.sourceSha, SHA);

  assert.equal(service?.clusterArn, APP_ONLY.clusterArn);
  assert.equal(service?.serviceArn, APP_ONLY.serviceArn);
  assert.equal(service?.serviceName, APP_ONLY.service);
  assert.equal(service?.status, "ACTIVE");
  assert.equal(service?.taskDefinition, backend.taskDefinitionArn);
  assert.equal(service?.desiredCount, backend.desiredCount);
  assert.equal(service?.runningCount, backend.desiredCount);
  assert.equal(service?.pendingCount, 0);
  assert.equal(service?.deployments?.length, 1, "Normal deployment live predecessor requires one completed deployment");
  const primary = service.deployments.filter((deployment) => deployment.status === "PRIMARY");
  assert.equal(primary.length, 1, "Normal deployment live predecessor requires one primary deployment");
  assert.equal(primary[0].rolloutState, "COMPLETED");
  assert.equal(primary[0].taskDefinition, backend.taskDefinitionArn);

  assert.equal(taskDefinition?.taskDefinitionArn, backend.taskDefinitionArn);
  const container = assertAppOnlyDefinition(taskDefinition);
  assert.equal(container.image, `${APP_ONLY.backendRepository}@${backend.imageDigest}`);
  const environment = new Map((container.environment || []).map(({ name, value }) => [name, value]));
  assert.equal(environment.get("RELEASE_GIT_SHA"), backend.sourceSha);
  if (environment.has("GIT_SHA")) assert.equal(environment.get("GIT_SHA"), backend.sourceSha);

  assert.equal(repository?.repositoryName, "mscqr-backend");
  assert.equal(String(repository?.registryId), APP_ONLY.account);
  assert.equal(repository?.imageTagMutability, "IMMUTABLE");
  assert.equal(imageDetails?.length, 1);
  assert.equal(imageDetails[0]?.imageDigest, backend.imageDigest);
  const sourceTags = (imageDetails[0]?.imageTags || []).filter((tag) => SHA.test(tag));
  assert.deepEqual(sourceTags, [backend.sourceSha], "Normal deployment image source identity is ambiguous or mismatched");
  return Object.freeze({ backend, backendProvenance, componentStateSha256: stateHash(componentState) });
}
