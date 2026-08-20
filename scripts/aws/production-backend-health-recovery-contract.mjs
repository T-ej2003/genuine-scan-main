import { canonicalSha256, taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";

export const BACKEND_HEALTH_RECOVERY = Object.freeze({
  kind: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  schemaVersion: 1,
  account: "368992683803",
  region: "eu-west-2",
  cluster: "mscqr-prod-euw2-main",
  service: "mscqr-backend-servi-euw2",
  family: "mscqr-backend",
  container: "backend",
  repository: "mscqr-backend",
});

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const HEX256 = /^[a-f0-9]{64}$/;
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:([1-9][0-9]*)$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/;
const IDENTITY_ENV = new Set(["GIT_SHA", "RELEASE_GIT_SHA"]);
const AUTHORIZATION_FIELDS = new Set(["schemaVersion", "kind", "environment", "account", "region", "cluster", "service", "family", "sourceSha", "imageReleaseSha", "currentTaskDefinitionArn", "recoveryImageDigest", "imageAuthorizationSha256", "reasonCode", "allowedDeltaProfile", "approval", "authorizationSha256"]);
const APPROVAL_FIELDS = new Set(["ticket", "approvedBy", "approverRole", "reason", "verificationRef", "sourceSha", "currentTaskDefinitionArn", "recoveryImageDigest"]);

const requiredText = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};

export function createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, approval } = {}) {
  const body = {
    schemaVersion: BACKEND_HEALTH_RECOVERY.schemaVersion,
    kind: BACKEND_HEALTH_RECOVERY.kind,
    environment: "production",
    account: BACKEND_HEALTH_RECOVERY.account,
    region: BACKEND_HEALTH_RECOVERY.region,
    cluster: BACKEND_HEALTH_RECOVERY.cluster,
    service: BACKEND_HEALTH_RECOVERY.service,
    family: BACKEND_HEALTH_RECOVERY.family,
    sourceSha,
    imageReleaseSha: imageAuthorization?.imageReleaseSha,
    currentTaskDefinitionArn,
    recoveryImageDigest,
    imageAuthorizationSha256: imageAuthorization?.evidenceSha256,
    reasonCode: "CURRENT_IMAGE_DIGEST_MISSING",
    allowedDeltaProfile: "IMAGE_AND_SOURCE_IDENTITY_ONLY",
    approval: structuredClone(approval),
  };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

function definition(value) {
  const source = value?.taskDefinition || value;
  if (!source || typeof source !== "object" || Array.isArray(source)) throw new Error("ECS task definition is malformed.");
  return source;
}

function backendContainer(value) {
  const matches = (definition(value).containerDefinitions || []).filter(({ name }) => name === BACKEND_HEALTH_RECOVERY.container);
  if (matches.length !== 1) throw new Error("Legacy task definition must contain exactly one backend container.");
  return matches[0];
}

function registrationPayload(readback) {
  const task = structuredClone(definition(readback));
  const payload = Object.fromEntries([
    "family", "taskRoleArn", "executionRoleArn", "networkMode", "containerDefinitions", "volumes",
    "placementConstraints", "requiresCompatibilities", "cpu", "memory", "pidMode", "ipcMode",
    "proxyConfiguration", "inferenceAccelerators", "ephemeralStorage", "runtimePlatform", "enableFaultInjection",
  ].filter((key) => task[key] !== undefined).map((key) => [key, task[key]]));
  if (Array.isArray(readback?.tags) && readback.tags.length) payload.tags = structuredClone(readback.tags);
  return payload;
}

export function buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha } = {}) {
  if (!SHA.test(imageReleaseSha || "") || !SHA256.test(recoveryImageDigest || "")) throw new Error("Recovery image release SHA or image digest is invalid.");
  const current = definition(currentTaskDefinition);
  if (current.status !== "ACTIVE" || current.family !== BACKEND_HEALTH_RECOVERY.family || !TASK_ARN.test(current.taskDefinitionArn || "")) throw new Error("Current task definition is outside the exact active legacy backend family.");
  const payload = registrationPayload(currentTaskDefinition);
  const container = backendContainer(payload);
  const image = `${BACKEND_HEALTH_RECOVERY.account}.dkr.ecr.${BACKEND_HEALTH_RECOVERY.region}.amazonaws.com/${BACKEND_HEALTH_RECOVERY.repository}@${recoveryImageDigest}`;
  container.image = image;
  const environment = Array.isArray(container.environment) ? container.environment : [];
  for (const name of IDENTITY_ENV) if (environment.filter((entry) => entry?.name === name).length !== 1) throw new Error(`Legacy backend must contain exactly one ${name} identity field.`);
  container.environment = environment.map((entry) => IDENTITY_ENV.has(entry?.name) ? { ...entry, value: imageReleaseSha } : entry);
  return payload;
}

export function assertLegacyBackendRecoveryCandidate({ currentTaskDefinition, candidate, recoveryImageDigest, imageReleaseSha } = {}) {
  const expected = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha });
  const tags = expected.tags || [];
  if (taskDefinitionFingerprint(candidate, candidate?.tags || []) !== taskDefinitionFingerprint(expected, tags)
    || canonicalSha256(candidate) !== canonicalSha256(expected)) {
    throw new Error("Legacy backend recovery candidate changes fields outside the image and source identity contract.");
  }
  return Object.freeze({ fingerprint: taskDefinitionFingerprint(expected, tags), candidate: expected });
}

export function assertLegacyBackendRecoveryAuthorization(authorization, {
  sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, imageValidation, executionActor,
} = {}) {
  if (!authorization || Object.keys(authorization).some((field) => !AUTHORIZATION_FIELDS.has(field)) || Object.keys(authorization).length !== AUTHORIZATION_FIELDS.size) throw new Error("Backend health recovery authorization schema is invalid.");
  if (authorization?.schemaVersion !== BACKEND_HEALTH_RECOVERY.schemaVersion || authorization?.kind !== BACKEND_HEALTH_RECOVERY.kind
    || authorization?.environment !== "production" || authorization?.account !== BACKEND_HEALTH_RECOVERY.account
    || authorization?.region !== BACKEND_HEALTH_RECOVERY.region || authorization?.cluster !== BACKEND_HEALTH_RECOVERY.cluster
    || authorization?.service !== BACKEND_HEALTH_RECOVERY.service || authorization?.family !== BACKEND_HEALTH_RECOVERY.family
    || authorization?.currentTaskDefinitionArn !== currentTaskDefinitionArn || !TASK_ARN.test(currentTaskDefinitionArn || "")
    || authorization?.recoveryImageDigest !== recoveryImageDigest || !SHA256.test(recoveryImageDigest || "")
    || authorization?.reasonCode !== "CURRENT_IMAGE_DIGEST_MISSING" || authorization?.allowedDeltaProfile !== "IMAGE_AND_SOURCE_IDENTITY_ONLY"
    || authorization?.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || authorization?.imageReleaseSha !== imageAuthorization?.imageReleaseSha || !SHA.test(authorization?.imageReleaseSha || "")
    || !HEX256.test(authorization?.imageAuthorizationSha256 || "") || authorization.imageAuthorizationSha256 !== imageAuthorization?.evidenceSha256) {
    throw new Error("Backend health recovery authorization is incomplete or bound to a different incident.");
  }
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (authorizedBackendDigest(imageAuthorization) !== recoveryImageDigest) throw new Error("Recovery digest differs from canonical image authorization.");
  const approval = authorization.approval;
  if (!approval || Object.keys(approval).some((field) => !APPROVAL_FIELDS.has(field)) || Object.keys(approval).length !== APPROVAL_FIELDS.size) throw new Error("Backend health recovery approval schema is invalid.");
  for (const field of ["ticket", "approvedBy", "approverRole", "reason", "verificationRef"]) requiredText(approval?.[field], `approval.${field}`);
  if (approval.sourceSha !== sourceSha || approval.currentTaskDefinitionArn !== currentTaskDefinitionArn || approval.recoveryImageDigest !== recoveryImageDigest) throw new Error("Human approval is bound to a different recovery.");
  const actor = requiredText(executionActor, "executionActor");
  if (approval.approvedBy.toLowerCase() === actor.toLowerCase()) throw new Error("Backend health recovery cannot be self-approved.");
  if (/(BEGIN [A-Z ]+PRIVATE KEY|SecretString|AccessKeyId|SecretAccessKey|SessionToken|DATABASE_URL=|password|token)/i.test(JSON.stringify(approval))) throw new Error("Backend health recovery approval contains prohibited secret material.");
  const { authorizationSha256, ...body } = authorization;
  if (!HEX256.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256) throw new Error("Backend health recovery authorization hash is invalid.");
  return authorization;
}

export function assertLegacyBackendRecoveryEligibility(input = {}) {
  const { sourceSha, service, currentTaskDefinition, currentImageExists, replacementImage, stoppedReasons = [], authorization, imageAuthorization, imageValidation, executionActor } = input;
  const current = definition(currentTaskDefinition);
  const currentArn = current.taskDefinitionArn;
  const imageMatch = IMAGE.exec(backendContainer(current).image || "");
  if (service?.clusterArn !== `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`
    || service?.serviceName !== BACKEND_HEALTH_RECOVERY.service || !TASK_ARN.test(service?.taskDefinition || "")
    || !Number.isInteger(service?.desiredCount) || service.desiredCount < 1) throw new Error("Live ECS service is outside the exact backend recovery boundary.");
  if (!TASK_ARN.test(currentArn || "") || current.family !== BACKEND_HEALTH_RECOVERY.family || !imageMatch) throw new Error("Current legacy backend task definition identity is invalid.");
  if (currentImageExists !== false) throw new Error("Backend health recovery requires the current immutable digest to be absent from ECR.");
  if (!stoppedReasons.some((reason) => /CannotPullContainerError/i.test(reason) && /not found|does not exist/i.test(reason) && reason.includes(imageMatch[1]))) throw new Error("Backend degradation is not authenticated as the current digest's missing-image pull failure.");
  if (replacementImage?.exists !== true || replacementImage?.immutable !== true || replacementImage?.signatureValid !== true
    || replacementImage?.attestationValid !== true || replacementImage?.provenanceValid !== true || replacementImage?.criticalFindings !== 0
    || replacementImage?.repository !== BACKEND_HEALTH_RECOVERY.repository || !SHA256.test(replacementImage?.digest || "")) throw new Error("Replacement image does not satisfy the recovery evidence contract.");
  assertLegacyBackendRecoveryAuthorization(authorization, { sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: replacementImage.digest, imageAuthorization, imageValidation, executionActor });
  const checked = assertLegacyBackendRecoveryCandidate({ currentTaskDefinition, candidate: input.candidate, recoveryImageDigest: replacementImage.digest, imageReleaseSha: authorization.imageReleaseSha });
  return Object.freeze({ ...checked, currentTaskDefinitionArn: currentArn, observedServiceTaskDefinitionArn: service.taskDefinition, currentImageDigest: imageMatch[1], recoveryImageDigest: replacementImage.digest, desiredCount: service.desiredCount, networkConfigurationSha256: canonicalSha256(service.networkConfiguration), loadBalancersSha256: canonicalSha256(service.loadBalancers) });
}

export async function runLegacyBackendHealthRecovery(input, adapters = {}) {
  for (const name of ["census", "register", "describe", "readService", "updateService", "waitStable", "readRunningTasks", "verifyHealth"]) if (typeof adapters[name] !== "function") throw new Error(`Recovery adapter ${name} is required.`);
  const eligible = assertLegacyBackendRecoveryEligibility(input);
  const revisions = await adapters.census();
  if (!Array.isArray(revisions)) throw new Error("Legacy backend revision census is incomplete.");
  const matches = revisions.filter((item) => taskDefinitionFingerprint(item, item.tags || []) === eligible.fingerprint);
  if (matches.length > 1) throw new Error("Multiple matching recovery revisions make replay ambiguous.");
  let targetArn = matches[0]?.taskDefinition?.taskDefinitionArn || matches[0]?.taskDefinitionArn;
  let registrations = 0;
  if (!targetArn) {
    try {
      const result = await adapters.register(eligible.candidate);
      targetArn = result?.taskDefinition?.taskDefinitionArn || result?.taskDefinitionArn;
      registrations = 1;
    } catch (error) {
      const after = await adapters.census();
      const reconciled = after.filter((item) => taskDefinitionFingerprint(item, item.tags || []) === eligible.fingerprint);
      if (reconciled.length !== 1) throw error;
      targetArn = reconciled[0]?.taskDefinition?.taskDefinitionArn || reconciled[0]?.taskDefinitionArn;
      registrations = 1;
    }
  }
  if (!TASK_ARN.test(targetArn || "")) throw new Error("Recovery registration did not resolve one exact legacy backend revision.");
  const target = await adapters.describe(targetArn);
  if (taskDefinitionFingerprint(target, target?.tags || []) !== eligible.fingerprint) throw new Error("Recovery target readback does not match the exact authorized candidate.");
  let live = await adapters.readService();
  let updates = 0;
  if (live.taskDefinition !== targetArn) {
    if (live.taskDefinition !== eligible.currentTaskDefinitionArn || eligible.observedServiceTaskDefinitionArn !== eligible.currentTaskDefinitionArn
      || live.desiredCount !== eligible.desiredCount || canonicalSha256(live.networkConfiguration) !== eligible.networkConfigurationSha256
      || canonicalSha256(live.loadBalancers) !== eligible.loadBalancersSha256) throw new Error("Backend service changed concurrently before recovery update.");
    try { await adapters.updateService(targetArn); updates = 1; }
    catch (error) {
      live = await adapters.readService();
      if (live.taskDefinition !== targetArn) throw error;
      updates = 1;
    }
  }
  await adapters.waitStable(targetArn);
  live = await adapters.readService();
  if (live.taskDefinition !== targetArn || live.desiredCount !== eligible.desiredCount || live.runningCount !== eligible.desiredCount || live.pendingCount !== 0) throw new Error("Backend service did not converge on the recovery revision.");
  const tasks = await adapters.readRunningTasks();
  if (!Array.isArray(tasks) || tasks.length !== eligible.desiredCount || tasks.some((task) => task.taskDefinitionArn !== targetArn || task.imageDigest !== eligible.recoveryImageDigest)) throw new Error("Running backend tasks do not match the approved recovery digest.");
  if (await adapters.verifyHealth() !== true) throw new Error("Backend health did not recover after the governed image replacement.");
  return Object.freeze({ mode: BACKEND_HEALTH_RECOVERY.kind, targetArn, recoveryImageDigest: eligible.recoveryImageDigest, registrations, updates, backendHealthy: true, rotationRequired: true, stageBApplied: false, frontendDeployed: false });
}
