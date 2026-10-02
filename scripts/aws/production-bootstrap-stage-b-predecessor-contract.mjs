import assert from "node:assert/strict";
import crypto from "node:crypto";
import { APP_ONLY, assertAppOnlyDefinition } from "./production-app-only-contract.mjs";
import { assertProductionComponentDeploymentState, componentDeploymentProvenance, stateHash } from "./production-component-deployment-state.mjs";
import { classifyProductionChanges, PRODUCTION_RELEASE_CLASS } from "./production-deployment-classification.mjs";
import { NORMAL_DEPLOYABLE_COMPONENTS } from "./production-normal-receipt-contract.mjs";
import { WEB_RELEASE } from "./production-web-release-contract.mjs";

export const COMPONENT_STATE_BOOTSTRAP_WORKFLOW = "T-ej2003/genuine-scan-main/.github/workflows/bootstrap-production-component-deployment-state.yml@refs/heads/main";
export const BOOTSTRAP_STAGE_B_REFERENCE_KIND = "STAGE_B_BOOTSTRAP_FORWARD_LIVE_PREDECESSOR_REFERENCE";
const SHA = /^[a-f0-9]{40}$/;
const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");

function assertExactLiveComponent({ component, service, taskDefinition, contract }) {
  assert.equal(service?.clusterArn, contract.clusterArn);
  assert.equal(service?.serviceArn, contract.serviceArn);
  assert.equal(service?.serviceName, contract.serviceName);
  assert.equal(service?.status, "ACTIVE");
  assert.equal(service?.taskDefinition, component.taskDefinitionArn);
  assert.equal(service?.desiredCount, component.desiredCount);
  assert.equal(service?.runningCount, component.desiredCount);
  assert.equal(service?.pendingCount, 0);
  const primary = (service?.deployments || []).filter((deployment) => deployment.status === "PRIMARY");
  assert.equal(service?.deployments?.length, 1, `${contract.name} bootstrap predecessor requires one completed deployment`);
  assert.equal(primary.length, 1); assert.equal(primary[0].rolloutState, "COMPLETED"); assert.equal(primary[0].taskDefinition, component.taskDefinitionArn);

  assert.equal(taskDefinition?.taskDefinitionArn, component.taskDefinitionArn);
  assert.equal(taskDefinition?.family, contract.family); assert.equal(taskDefinition?.status, "ACTIVE");
  const containers = (taskDefinition?.containerDefinitions || []).filter(({ name }) => name === contract.container);
  assert.equal(containers.length, 1); assert.equal(containers[0].image, `${contract.repositoryUri}@${component.imageDigest}`);
  if (contract.name === "backend") {
    assertAppOnlyDefinition(taskDefinition);
    const environment = new Map((containers[0].environment || []).map(({ name, value }) => [name, value]));
    assert.equal(environment.get("RELEASE_GIT_SHA"), component.sourceSha);
    if (environment.has("GIT_SHA")) assert.equal(environment.get("GIT_SHA"), component.sourceSha);
  }

}

function assertRange(range, component, toolingSha) {
  assert.deepEqual(Object.keys(range || {}).sort(), ["component", "files", "filesSha256", "fromSha", "releaseClass", "toSha"].sort());
  assert.equal(range.component, component.name); assert.equal(range.fromSha, component.state.establishedThroughSha); assert.equal(range.toSha, toolingSha);
  assert.ok(Array.isArray(range.files)); assert.deepEqual(range.files, [...new Set(range.files)].sort());
  assert.equal(range.filesSha256, digest(range.files));
  const classification = classifyProductionChanges(range.files);
  assert.equal(range.releaseClass, classification.releaseClass);
  return classification;
}

export function assertBootstrapStageBLivePredecessor({ componentState, toolingSha, backend, frontend, sourceRanges } = {}) {
  assertProductionComponentDeploymentState(componentState); assert.match(toolingSha || "", SHA);
  assert.equal(componentState.schemaVersion, 2); assert.equal(componentState.generation, 1); assert.equal(componentState.updatedByLane, "BOOTSTRAP");
  assert.equal(componentState.updatedByWorkflow, COMPONENT_STATE_BOOTSTRAP_WORKFLOW); assert.match(String(componentState.githubRunId), /^[1-9][0-9]*$/);
  assert.equal(componentState.normalDeploymentReceipt, undefined); assert.equal(componentState.components.database, null); assert.equal(componentState.components.security, null);
  assert.deepEqual(Object.keys(sourceRanges || {}).sort(), [...NORMAL_DEPLOYABLE_COMPONENTS].sort());

  const contracts = {
    backend: { name: "backend", clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service, family: APP_ONLY.family, container: APP_ONLY.container, repositoryUri: APP_ONLY.backendRepository },
    frontend: { name: "frontend", clusterArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`, serviceArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:service/${WEB_RELEASE.cluster}/${WEB_RELEASE.serviceName}`, serviceName: WEB_RELEASE.serviceName, family: WEB_RELEASE.family, container: WEB_RELEASE.container, repositoryUri: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}` },
  };
  const evidence = { backend, frontend };
  const classifications = {};
  for (const name of NORMAL_DEPLOYABLE_COMPONENTS) {
    const state = componentState.components[name]; assert.ok(state, `${name} bootstrap component is missing`);
    assert.equal(state.sourceSha, state.establishedThroughSha);
    const provenance = componentDeploymentProvenance(componentState, name);
    assert.deepEqual(provenance, { lane: "BOOTSTRAP", workflow: COMPONENT_STATE_BOOTSTRAP_WORKFLOW, githubRunId: String(componentState.githubRunId), generation: 1, updatedAt: componentState.updatedAt });
    assertExactLiveComponent({ component: state, ...evidence[name], contract: contracts[name] });
    classifications[name] = assertRange(sourceRanges[name], { name, state }, toolingSha);
  }
  assert.ok(Object.values(classifications).some(({ releaseClass }) => [PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE, PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY].includes(releaseClass)), "Bootstrap bridge requires accumulated stronger-lane work");
  return Object.freeze({ componentStateSha256: stateHash(componentState), components: structuredClone(componentState.components), classifications: Object.freeze(classifications) });
}

export function bootstrapStageBSourceRange({ component, fromSha, toSha, files } = {}) {
  assert.ok(NORMAL_DEPLOYABLE_COMPONENTS.includes(component)); assert.match(fromSha || "", SHA); assert.match(toSha || "", SHA);
  const normalized = [...new Set(files || [])].sort();
  const releaseClass = classifyProductionChanges(normalized).releaseClass;
  return Object.freeze({ component, fromSha, toSha, files: normalized, filesSha256: digest(normalized), releaseClass });
}
