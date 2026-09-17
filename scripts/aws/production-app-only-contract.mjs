import assert from "node:assert/strict";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { NORMAL_ACTIVATION, NORMAL_CANDIDATE_ARN } from "./production-normal-backend-activation-policy.mjs";
import { normalizeEcsTaskDefinitionReadback, assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";

export const APP_ONLY_DOMAINS = Object.freeze([
  "DATABASE_SCHEMA", "MIGRATIONS", "RLS", "IAM",
  "TERRAFORM_MANAGED_RUNTIME_CONFIGURATION", "KMS", "NETWORK",
]);
export const APP_ONLY = Object.freeze({
  account: NORMAL_ACTIVATION.account, region: NORMAL_ACTIVATION.region,
  cluster: NORMAL_ACTIVATION.cluster, clusterArn: NORMAL_ACTIVATION.clusterArn,
  service: NORMAL_ACTIVATION.service, serviceArn: NORMAL_ACTIVATION.serviceArn,
  family: NORMAL_ACTIVATION.family, container: NORMAL_ACTIVATION.container,
  roleArn: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-app-only-deployer`,
  schemaVersion: 1,
  maxEvidenceAgeMs: 15 * 60 * 1000,
  backendRepository: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/mscqr-backend`,
  taskRoleArn: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-green-backend-task`,
  executionRoleArn: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-green-backend-execution`,
});
const sha = (value) => assert.match(value || "", /^[a-f0-9]{40}$/);
const digest = (value) => assert.match(value || "", /^sha256:[a-f0-9]{64}$/);
const exact = (actual, expected, label) => assert.equal(canonicalJson(actual), canonicalJson(expected), label);
export function assertAppOnlyDeploymentId(value) {
  // Opaque AWS string: preserve leading zeros and require the absolute end (not a final newline).
  assert.match(value, /^ecs-svc\/[0-9]+(?![\s\S])/, "Invalid ECS deployment identity");
}
const tags = (value) => {
  assert.ok(Array.isArray(value));
  assert.equal(new Set(value.map(({ key }) => key)).size, value.length, "Duplicate task-definition tag");
  return [...value].sort((a, b) => a.key.localeCompare(b.key));
};
export const appOnlyDefinitionSha256 = (definition) => canonicalSha256({ definition: normalizeEcsTaskDefinitionReadback(definition), tags: tags(definition.tags || []) });
export const appOnlyServiceConfigurationSha256 = (service) => {
  const configuration = structuredClone(service);
  // Exclude only AWS observations and identities separately bound by CAS.
  // Unknown/new service settings remain bound, rather than silently ignored.
  for (const field of ["serviceArn", "serviceName", "clusterArn", "status", "taskDefinition",
    "desiredCount", "runningCount", "pendingCount", "deployments", "events", "createdAt", "createdBy",
    "currentServiceDeployment", "currentServiceRevisions", "taskSets"])
    delete configuration[field];
  if (Object.hasOwn(configuration, "tags")) configuration.tags = tags(configuration.tags);
  return canonicalSha256(configuration);
};

// Only these AWS response fields are non-registration metadata. Unknown fields
// remain in the request and fail AWS validation rather than being silently lost.
const READBACK_FIELDS = Object.freeze([
  "taskDefinitionArn", "revision", "status", "registeredAt", "registeredBy",
  "deregisteredAt", "deleteRequestedAt", "requiresAttributes", "compatibilities",
]);

export function assertAppOnlyDefinition(definition) {
  assert.ok(NORMAL_CANDIDATE_ARN.test(definition?.taskDefinitionArn || ""), "Unexpected predecessor family");
  assert.equal(definition.family, APP_ONLY.family);
  assert.equal(definition.status, "ACTIVE");
  assert.equal(definition.taskRoleArn, APP_ONLY.taskRoleArn);
  assert.equal(definition.executionRoleArn, APP_ONLY.executionRoleArn);
  assert.equal(definition.networkMode, "awsvpc");
  exact(definition.runtimePlatform, STAGE_B.taskRuntimePlatform, "Unexpected runtime platform");
  assert.ok(Array.isArray(definition.containerDefinitions) && definition.containerDefinitions.length > 0);
  const names = definition.containerDefinitions.map(({ name }) => name);
  assert.equal(new Set(names).size, names.length, "Duplicate container name");
  const backend = definition.containerDefinitions.filter(({ name }) => name === APP_ONLY.container);
  assert.equal(backend.length, 1);
  assert.ok(backend[0].image.startsWith(`${APP_ONLY.backendRepository}@`));
  digest(backend[0].image.split("@")[1]);
  return backend[0];
}

export function buildAppOnlyCandidate(predecessor, candidateDigest) {
  const backend = assertAppOnlyDefinition(predecessor);
  digest(candidateDigest);
  assert.notEqual(backend.image, `${APP_ONLY.backendRepository}@${candidateDigest}`, "Already deployed");
  const candidate = structuredClone(predecessor);
  for (const field of READBACK_FIELDS) delete candidate[field];
  candidate.containerDefinitions.find(({ name }) => name === APP_ONLY.container).image = `${APP_ONLY.backendRepository}@${candidateDigest}`;
  return candidate;
}

export function assertAppOnlyCandidate(predecessor, candidate, candidateDigest) {
  const expected = buildAppOnlyCandidate(predecessor, candidateDigest);
  exact(normalizeEcsTaskDefinitionReadback(candidate), normalizeEcsTaskDefinitionReadback(expected), "Candidate changes more than the backend image");
  // The shared normalizer removes tags as response metadata; this lane binds
  // them separately so cloning cannot silently grant a new tag-based privilege.
  exact(tags(candidate.tags || []), tags(predecessor.tags || []), "Candidate tags changed");
  return true;
}

export function assertRegisteredAppOnlyCandidate(predecessor, candidate, candidateDigest) {
  assert.ok(NORMAL_CANDIDATE_ARN.test(candidate?.taskDefinitionArn || ""));
  assert.notEqual(candidate.taskDefinitionArn, predecessor.taskDefinitionArn);
  assertEcsTaskDefinitionReadback({ definition: candidate, taskDefinitionArn: candidate.taskDefinitionArn,
    expected: buildAppOnlyCandidate(predecessor, candidateDigest), label: "Registered app-only candidate" });
  return assertAppOnlyCandidate(predecessor, candidate, candidateDigest);
}

export function captureAppOnlyPredecessor({ service, definition, tasks }) {
  const backend = assertAppOnlyDefinition(definition);
  assert.equal(service?.desiredCount, 2);
  return captureBackendServiceSnapshot({ service, definition, tasks }, backend.image.split("@")[1]);
}

// Service/task readback shared with recovery; each caller authenticates its own
// task-definition family and privileges before capturing this snapshot.
export function captureBackendServiceSnapshot({ service, definition, tasks }, backendDigest) {
  digest(backendDigest);
  assert.equal(service?.clusterArn, APP_ONLY.clusterArn);
  assert.equal(service?.serviceArn, APP_ONLY.serviceArn);
  assert.equal(service?.serviceName, APP_ONLY.service);
  assert.equal(service?.status, "ACTIVE");
  assert.equal(service.taskDefinition, definition.taskDefinitionArn);
  assert.ok(Number.isSafeInteger(service.desiredCount) && service.desiredCount > 0);
  assert.equal(service.runningCount, service.desiredCount);
  assert.equal(service.pendingCount, 0);
  assert.equal(service.deployments?.length, 1, "Concurrent deployment");
  const deployment = service.deployments[0];
  assertAppOnlyDeploymentId(deployment.id);
  assert.equal(deployment.status, "PRIMARY");
  assert.equal(deployment.rolloutState, "COMPLETED");
  assert.equal(deployment.taskDefinition, service.taskDefinition);
  assert.equal(tasks?.length, service.desiredCount);
  assert.equal(new Set(tasks.map(({ taskArn }) => taskArn)).size, service.desiredCount);
  for (const task of tasks) {
    assert.equal(task.clusterArn, APP_ONLY.clusterArn);
    assert.equal(task.group, `service:${APP_ONLY.service}`);
    assert.equal(task.taskDefinitionArn, service.taskDefinition);
    assert.equal(task.lastStatus, "RUNNING");
    assert.equal(task.healthStatus, "HEALTHY");
    assert.equal(task.startedBy, deployment.id);
    const containers = task.containers?.filter(({ name }) => name === APP_ONLY.container);
    assert.equal(containers?.length, 1);
    assert.equal(containers[0].imageDigest, backendDigest);
  }
  return {
    clusterArn: service.clusterArn, serviceArn: service.serviceArn,
    taskDefinitionArn: service.taskDefinition, backendDigest,
    desiredCount: service.desiredCount, deploymentId: deployment.id,
    deploymentStatus: deployment.rolloutState,
    definitionSha256: appOnlyDefinitionSha256(definition),
    serviceConfigurationSha256: appOnlyServiceConfigurationSha256(service),
  };
}

export function assertAppOnlyCas(expected, current) {
  exact(current, expected, "STALE_PREPARATION: live predecessor changed");
}

export function assertAppOnlySessionRiskConfiguration(definition) {
  const backend = assertAppOnlyDefinition(definition);
  assert.equal((backend.environmentFiles || []).length, 0, "Session-risk configuration from environment files is unproven");
  assert.ok(!(backend.secrets || []).some(({ name }) => name === "AUTH_RISK_BLOCK_THRESHOLD"), "Secret-backed risk threshold requires independent verification");
  const entries = (backend.environment || []).filter(({ name }) => name === "AUTH_RISK_BLOCK_THRESHOLD");
  assert.ok(entries.length <= 1, "Duplicate risk threshold override");
  if (entries.length) {
    const value = entries[0].value;
    assert.equal(typeof value, "string");
    assert.ok(value === "" || value === "85", "Unreviewed risk threshold override");
  }
  return { overridePresent: entries.length === 1, effectiveThreshold: 85 };
}

// Match backend/src/observability/release.ts immutable image-source.json.
// Runtime deployment metadata is not proof of the running image:
// immutable digest/publication authentication remains independently required.
export function appOnlyExpectedHealthSourceSha(definition, imageSourceSha) {
  sha(imageSourceSha);
  const backend = assertAppOnlyDefinition(definition);
  const fields = ["RELEASE_GIT_SHA", "GITHUB_SHA", "COMMIT_SHA", "GIT_SHA", "RENDER_GIT_COMMIT", "VERCEL_GIT_COMMIT_SHA"];
  assert.equal((backend.environmentFiles || []).length, 0, "Release metadata from external environment files is unproven");
  assert.ok(!(backend.secrets || []).some(({ name }) => fields.includes(name)), "Secret-backed release metadata is unproven");
  for (const name of fields) {
    const entries = (backend.environment || []).filter((entry) => entry.name === name);
    assert.ok(entries.length <= 1, "Duplicate release metadata variable");
    if (entries.length) assert.equal(typeof entries[0].value, "string");
  }
  return imageSourceSha;
}

export function assertAppOnlyEvidenceIdentity(actual, expected, now = Date.now()) {
  sha(expected.sourceSha); sha(expected.candidateSourceSha);
  digest(expected.candidateDigest); digest(expected.predecessorBackendDigest);
  assert.equal(expected.account, APP_ONLY.account);
  assert.equal(expected.region, APP_ONLY.region);
  assert.equal(expected.clusterArn, APP_ONLY.clusterArn);
  assert.equal(expected.serviceArn, APP_ONLY.serviceArn);
  assert.ok(NORMAL_CANDIDATE_ARN.test(expected.predecessorTaskDefinition || ""));
  exact(actual.identity, expected, "Compatibility evidence belongs to another deployment");
  const age = now - Date.parse(actual.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale compatibility evidence");
  const { evidenceSha256, ...payload } = actual;
  assert.equal(evidenceSha256, canonicalSha256(payload), "Compatibility evidence hash mismatch");
  // Hashes are integrity, NOT provenance. The production consumer must first
  // authenticate the exact producing workflow/run/artifact and live readbacks.
  return true;
}

export function evaluateAppOnlyDomains(domainEvidence) {
  exact(Object.keys(domainEvidence).sort(), [...APP_ONLY_DOMAINS].sort(), "Domain closure incomplete");
  const domains = {};
  for (const domain of APP_ONLY_DOMAINS) {
    const proof = domainEvidence[domain];
    assert.equal(typeof proof.changed, "boolean");
    domains[domain] = !proof.changed ? "UNCHANGED"
      : proof.status === "COMPATIBLE" ? "ALREADY_APPLIED_COMPATIBLE" : "INCOMPATIBLE_OR_UNPROVEN";
  }
  return { domains, eligible: Object.values(domains).every((value) => value !== "INCOMPATIBLE_OR_UNPROVEN") };
}

export function assertAppOnlyRollbackOwnership({ service, candidateArn, candidateDeploymentId, predecessor }) {
  assertAppOnlyDeploymentId(candidateDeploymentId);
  assertAppOnlyDeploymentId(predecessor?.deploymentId);
  assert.ok(NORMAL_CANDIDATE_ARN.test(candidateArn || ""));
  assert.ok(NORMAL_CANDIDATE_ARN.test(predecessor?.taskDefinitionArn || ""));
  assert.notEqual(candidateArn, predecessor.taskDefinitionArn);
  assert.equal(service.serviceArn, predecessor.serviceArn);
  assert.equal(service.clusterArn, predecessor.clusterArn);
  assert.equal(service.taskDefinition, candidateArn, "Rollback ownership lost");
  assert.equal(service.desiredCount, predecessor.desiredCount);
  assert.equal(appOnlyServiceConfigurationSha256(service), predecessor.serviceConfigurationSha256, "Rollback service configuration changed");
  const primary = service.deployments?.filter(({ status }) => status === "PRIMARY");
  assert.equal(primary?.length, 1);
  assert.equal(primary[0].id, candidateDeploymentId);
  assert.equal(primary[0].taskDefinition, candidateArn);
  assert.ok(service.deployments.every((entry) => entry.id === candidateDeploymentId
    || entry.id === predecessor.deploymentId && entry.taskDefinition === predecessor.taskDefinitionArn), "Competing deployment");
  return predecessor.taskDefinitionArn;
}
