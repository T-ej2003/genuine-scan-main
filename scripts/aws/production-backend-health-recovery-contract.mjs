import { canonicalSha256, taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentReviewer } from "./production-github-environment-approval.mjs";
import { ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { loadArtifactSigningBootstrapContract } from "./production-artifact-signing-bootstrap.mjs";
import { ROLLBACK_VIABILITY, assertFreshRollbackEquivalence, assertRollbackSupersessionProof } from "./production-ecs-rollback-viability.mjs";

export const BACKEND_HEALTH_RECOVERY = Object.freeze({
  kind: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  schemaVersion: 2,
  account: "368992683803",
  region: "eu-west-2",
  cluster: "mscqr-prod-euw2-main",
  service: "mscqr-backend-servi-euw2",
  family: "mscqr-backend",
  container: "backend",
  repository: "mscqr-backend",
});

export const BACKEND_HEALTH_RECOVERY_STATUS = Object.freeze({
  NO_MUTATION_FAILURE: "NO_MUTATION_FAILURE",
  TASK_DEFINITION_REGISTRATION_ATTEMPTED: "TASK_DEFINITION_REGISTRATION_ATTEMPTED",
  TASK_DEFINITION_REGISTERED_ONLY: "TASK_DEFINITION_REGISTERED_ONLY",
  SERVICE_UPDATE_ATTEMPTED: "SERVICE_UPDATE_ATTEMPTED",
  SERVICE_UPDATE_CONFIRMED: "SERVICE_UPDATE_CONFIRMED",
  SERVICE_STABILIZATION_FAILED: "SERVICE_STABILIZATION_FAILED",
  RUNNING_DIGEST_VERIFICATION_FAILED: "RUNNING_DIGEST_VERIFICATION_FAILED",
  HEALTH_VERIFICATION_FAILED: "HEALTH_VERIFICATION_FAILED",
  RECOVERY_COMPLETE: "RECOVERY_COMPLETE",
});
export const ARTIFACT_SIGNING_VERIFICATION = Object.freeze({
  PENDING: "PENDING",
  VERIFIED: "VERIFIED",
  FAILED: "FAILED",
});
export const ARTIFACT_SIGNING_DISCOVERY_FAILURE = Object.freeze({
  CALLER_IDENTITY: "CALLER_IDENTITY_DISCOVERY_FAILED",
  SECRET_REFERENCE: "SECRET_REFERENCE_DISCOVERY_FAILED",
  SECRET_VALUE: "SECRET_VALUE_VERIFICATION_FAILED",
  LIVE_BINDING: "LIVE_BINDING_VALIDATION_FAILED",
});
const RECOVERY_STATUSES = new Set(Object.values(BACKEND_HEALTH_RECOVERY_STATUS));
const ARTIFACT_SIGNING_VERIFICATION_STATES = new Set(Object.values(ARTIFACT_SIGNING_VERIFICATION));
const ARTIFACT_SIGNING_DISCOVERY_FAILURES = new Set(Object.values(ARTIFACT_SIGNING_DISCOVERY_FAILURE));

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const HEX256 = /^[a-f0-9]{64}$/;
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:([1-9][0-9]*)$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/;
const IDENTITY_ENV = new Set(["GIT_SHA", "RELEASE_GIT_SHA"]);
const SIGNING_BINDINGS = new Set(ARTIFACT_SIGNING_BINDINGS);
const ARTIFACT_SIGNING_SECRET_NAMES = loadArtifactSigningBootstrapContract().names;
const ARTIFACT_SIGNING_SECRET_ARNS = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, new RegExp(`^arn:aws:secretsmanager:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:secret:${ARTIFACT_SIGNING_SECRET_NAMES[name].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-[A-Za-z0-9]{6}$`)]));
const AUTHORIZATION_FIELDS = new Set(["schemaVersion", "kind", "environment", "account", "region", "cluster", "service", "family", "sourceSha", "imageReleaseSha", "currentTaskDefinitionArn", "recoveryImageDigest", "imageAuthorizationSha256", "environmentApprovalSha256", "artifactSigningBindingSha256", "rollbackProof", "reasonCode", "allowedDeltaProfile", "approval", "authorizationSha256"]);
const BASE_APPROVAL_FIELDS = ["ticket", "approvedBy", "approverRole", "reason", "verificationRef", "sourceSha", "currentTaskDefinitionArn", "recoveryImageDigest"];
const ROLLBACK_APPROVAL_FIELDS = ["rollbackDeploymentArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest"];

const requiredText = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};

export function assertLegacyBackendRecoveryEvidence(evidence, {
  sourceSha, currentTaskDefinitionArn, recoveryImageDigest, authorizationFileSha256, authorizationSha256,
  environmentApprovalFileSha256, environmentApprovalSha256, imageAuthorizationFileSha256, imageAuthorizationSha256,
  artifactSigningBindingSha256, imageReleaseSha,
  rollbackProofSha256,
  account = BACKEND_HEALTH_RECOVERY.account, region = BACKEND_HEALTH_RECOVERY.region,
} = {}) {
  const { evidenceSha256, ...body } = evidence || {};
  if (evidence?.schemaVersion !== 3 || evidence?.kind !== "BACKEND_HEALTH_RECOVERY_EVIDENCE"
    || evidence.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || evidence.currentTaskDefinitionArn !== currentTaskDefinitionArn || !TASK_ARN.test(currentTaskDefinitionArn || "")
    || evidence.recoveryImageDigest !== recoveryImageDigest || !SHA256.test(recoveryImageDigest || "")
    || evidence.imageReleaseSha !== imageReleaseSha || !SHA.test(imageReleaseSha || "")
    || evidence.account !== account || evidence.region !== region
    || ![authorizationFileSha256, authorizationSha256, environmentApprovalFileSha256, environmentApprovalSha256,
      imageAuthorizationFileSha256, imageAuthorizationSha256].every((expected) => HEX256.test(expected || ""))
    || evidence.authorizationFileSha256 !== authorizationFileSha256 || evidence.authorizationSha256 !== authorizationSha256
    || evidence.environmentApprovalFileSha256 !== environmentApprovalFileSha256 || evidence.environmentApprovalSha256 !== environmentApprovalSha256
    || evidence.imageAuthorizationFileSha256 !== imageAuthorizationFileSha256 || evidence.imageAuthorizationSha256 !== imageAuthorizationSha256
    || !HEX256.test(artifactSigningBindingSha256 || "") || evidence.artifactSigningBindingSha256 !== artifactSigningBindingSha256
    || evidence.rollbackProofSha256 !== (rollbackProofSha256 || null)
    || !RECOVERY_STATUSES.has(evidence.status)
    || !ARTIFACT_SIGNING_VERIFICATION_STATES.has(evidence.artifactSigningVerification)
    || (evidence.artifactSigningVerification === ARTIFACT_SIGNING_VERIFICATION.FAILED
      ? !ARTIFACT_SIGNING_DISCOVERY_FAILURES.has(evidence.artifactSigningFailure)
      : evidence.artifactSigningFailure !== null)
    || !Number.isSafeInteger(evidence.registrations) || evidence.registrations < 0 || evidence.registrations > 1
    || !Number.isSafeInteger(evidence.updates) || evidence.updates < 0 || evidence.updates > 1
    || !Number.isFinite(Date.parse(evidence.generatedAt))
    || !HEX256.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) {
    throw new Error("Backend health recovery evidence is malformed, stale, or tampered.");
  }
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE && (evidence.registrations !== 0 || evidence.updates !== 0)) throw new Error("No-mutation recovery evidence records a mutation.");
  if (evidence.status !== BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE
    && evidence.artifactSigningVerification !== ARTIFACT_SIGNING_VERIFICATION.VERIFIED) {
    throw new Error("Mutation-capable recovery evidence lacks authenticated artifact-signing verification.");
  }
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED && (evidence.registrations !== 0 || evidence.updates !== 0)) throw new Error("Registration-attempt evidence records a confirmed mutation.");
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY && (evidence.registrations !== 1 || evidence.updates !== 0)) throw new Error("Registered-only evidence has inconsistent mutation counts.");
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED && evidence.updates !== 0) throw new Error("Service-update-attempt evidence records a confirmed update.");
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED && evidence.updates !== 1) throw new Error("Service-update confirmation lacks its mutation count.");
  if ([BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE, BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED].includes(evidence.status) && evidence.targetArn !== null) throw new Error("Pre-registration recovery evidence records a target revision.");
  if (![BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE, BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED].includes(evidence.status) && !TASK_ARN.test(evidence.targetArn || "")) throw new Error("Post-registration recovery evidence lacks the authenticated target revision.");
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.RECOVERY_COMPLETE
    && (evidence.backendHealthy !== true || evidence.health?.healthy !== true || evidence.health?.success !== true || evidence.health?.status !== "ready"
      || evidence.health?.dependencies?.database !== "ready" || evidence.health?.dependencies?.redis !== "ready" || evidence.health?.dependencies?.objectStorage !== "ready"
      || evidence.health?.release?.gitSha !== imageReleaseSha || !Number.isFinite(Date.parse(evidence.health?.timestamp))
      || evidence.rotationRequired !== true)) {
    throw new Error("Completed backend recovery evidence lacks final readiness proof.");
  }
  return evidence;
}

export function createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, environmentApproval, artifactSigningBindingSha256, rollbackProof = null, approval } = {}) {
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
    environmentApprovalSha256: environmentApproval?.evidenceSha256,
    artifactSigningBindingSha256,
    rollbackProof: rollbackProof ? structuredClone(rollbackProof) : null,
    reasonCode: "CURRENT_IMAGE_DIGEST_MISSING",
    allowedDeltaProfile: "IMAGE_SOURCE_IDENTITY_AND_EXACT_ARTIFACT_SIGNING_BINDINGS",
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

function assertArtifactSigningBindings(bindings) {
  if (!bindings || Object.keys(bindings).sort().join(",") !== [...ARTIFACT_SIGNING_BINDINGS].sort().join(",")
    || ARTIFACT_SIGNING_BINDINGS.some((name) => typeof bindings[name] !== "string" || !ARTIFACT_SIGNING_SECRET_ARNS[name].test(bindings[name]))
    || new Set(Object.values(bindings)).size !== ARTIFACT_SIGNING_BINDINGS.length) {
    throw new Error("Authenticated artifact-signing bindings are incomplete or outside the exact production namespace.");
  }
  return bindings;
}

function buildLegacyImageIdentityOnlyCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha } = {}) {
  if (!SHA.test(imageReleaseSha || "") || !SHA256.test(recoveryImageDigest || "")) throw new Error("Recovery image release SHA or image digest is invalid.");
  const current = definition(currentTaskDefinition);
  if (current.status !== "ACTIVE" || current.family !== BACKEND_HEALTH_RECOVERY.family || !TASK_ARN.test(current.taskDefinitionArn || "")) throw new Error("Current task definition is outside the exact active legacy backend family.");
  const payload = registrationPayload(currentTaskDefinition);
  const container = backendContainer(payload);
  const image = `${BACKEND_HEALTH_RECOVERY.account}.dkr.ecr.${BACKEND_HEALTH_RECOVERY.region}.amazonaws.com/${BACKEND_HEALTH_RECOVERY.repository}@${recoveryImageDigest}`;
  container.image = image;
  const environment = Array.isArray(container.environment) ? container.environment : [];
  for (const name of IDENTITY_ENV) if (environment.filter((entry) => entry?.name === name).length !== 1) throw new Error(`Legacy backend must contain exactly one ${name} identity field.`);
  if (environment.some(({ name }) => SIGNING_BINDINGS.has(name))) throw new Error("Artifact-signing bindings must not be plaintext environment variables.");
  const secrets = Array.isArray(container.secrets) ? container.secrets : [];
  if (secrets.some(({ name }) => SIGNING_BINDINGS.has(name))) throw new Error("Legacy backend source must not contain partial or duplicate artifact-signing bindings.");
  container.environment = environment.map((entry) => IDENTITY_ENV.has(entry?.name) ? { ...entry, value: imageReleaseSha } : entry);
  return payload;
}

export function buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha, artifactSigningBindings } = {}) {
  const payload = buildLegacyImageIdentityOnlyCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha });
  const container = backendContainer(payload);
  const checkedBindings = assertArtifactSigningBindings(artifactSigningBindings);
  const legacySecrets = Array.isArray(container.secrets) ? container.secrets : [];
  container.secrets = [...legacySecrets, ...ARTIFACT_SIGNING_BINDINGS.map((name) => ({ name, valueFrom: checkedBindings[name] }))];
  return payload;
}

export function assertLegacyBackendRecoveryCandidate({ currentTaskDefinition, candidate, recoveryImageDigest, imageReleaseSha, artifactSigningBindings } = {}) {
  const expected = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest, imageReleaseSha, artifactSigningBindings });
  const tags = expected.tags || [];
  if (taskDefinitionFingerprint(candidate, candidate?.tags || []) !== taskDefinitionFingerprint(expected, tags)
    || canonicalSha256(candidate) !== canonicalSha256(expected)) {
    throw new Error("Legacy backend recovery candidate changes fields outside the exact image, source identity, and artifact-signing contract.");
  }
  return Object.freeze({ fingerprint: taskDefinitionFingerprint(expected, tags), candidate: expected });
}

export function assertLegacyBackendRecoveryAuthorization(authorization, {
  sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindingSha256, githubContext, executionActor,
} = {}) {
  if (!authorization || Object.keys(authorization).some((field) => !AUTHORIZATION_FIELDS.has(field)) || Object.keys(authorization).length !== AUTHORIZATION_FIELDS.size) throw new Error("Backend health recovery authorization schema is invalid.");
  if (authorization?.schemaVersion !== BACKEND_HEALTH_RECOVERY.schemaVersion || authorization?.kind !== BACKEND_HEALTH_RECOVERY.kind
    || authorization?.environment !== "production" || authorization?.account !== BACKEND_HEALTH_RECOVERY.account
    || authorization?.region !== BACKEND_HEALTH_RECOVERY.region || authorization?.cluster !== BACKEND_HEALTH_RECOVERY.cluster
    || authorization?.service !== BACKEND_HEALTH_RECOVERY.service || authorization?.family !== BACKEND_HEALTH_RECOVERY.family
    || authorization?.currentTaskDefinitionArn !== currentTaskDefinitionArn || !TASK_ARN.test(currentTaskDefinitionArn || "")
    || authorization?.recoveryImageDigest !== recoveryImageDigest || !SHA256.test(recoveryImageDigest || "")
    || authorization?.reasonCode !== "CURRENT_IMAGE_DIGEST_MISSING" || authorization?.allowedDeltaProfile !== "IMAGE_SOURCE_IDENTITY_AND_EXACT_ARTIFACT_SIGNING_BINDINGS"
    || authorization?.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || authorization?.imageReleaseSha !== imageAuthorization?.imageReleaseSha || !SHA.test(authorization?.imageReleaseSha || "")
    || !HEX256.test(authorization?.imageAuthorizationSha256 || "") || authorization.imageAuthorizationSha256 !== imageAuthorization?.evidenceSha256
    || !HEX256.test(authorization?.environmentApprovalSha256 || "") || authorization.environmentApprovalSha256 !== environmentApproval?.evidenceSha256) {
    throw new Error("Backend health recovery authorization is incomplete or bound to a different incident.");
  }
  if (!HEX256.test(artifactSigningBindingSha256 || "") || authorization.artifactSigningBindingSha256 !== artifactSigningBindingSha256) throw new Error("Backend health recovery artifact-signing binding is stale or unauthenticated.");
  assertProductionEnvironmentApprovalEvidence(environmentApproval, { sourceSha, repository: githubContext?.repository, environment: "production", workflowRef: githubContext?.workflowRef, eventName: githubContext?.eventName, workflowRunId: githubContext?.workflowRunId, workflowRunAttempt: githubContext?.workflowRunAttempt, executionActor, githubActions: githubContext?.githubActions, now: githubContext?.now });
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (authorizedBackendDigest(imageAuthorization) !== recoveryImageDigest) throw new Error("Recovery digest differs from canonical image authorization.");
  const approval = authorization.approval;
  const approvalFields = Object.keys(approval || {}).sort().join(",");
  const baseApprovalFields = [...BASE_APPROVAL_FIELDS].sort().join(",");
  const rollbackApprovalFields = [...BASE_APPROVAL_FIELDS, ...ROLLBACK_APPROVAL_FIELDS].sort().join(",");
  if (!approval || (approvalFields !== baseApprovalFields && approvalFields !== rollbackApprovalFields)) throw new Error("Backend health recovery approval schema is invalid.");
  for (const field of ["ticket", "approvedBy", "approverRole", "reason", "verificationRef"]) requiredText(approval?.[field], `approval.${field}`);
  if (approval.sourceSha !== sourceSha || approval.currentTaskDefinitionArn !== currentTaskDefinitionArn || approval.recoveryImageDigest !== recoveryImageDigest) throw new Error("Human approval is bound to a different recovery.");
  if (authorization.rollbackProof) {
    assertRollbackSupersessionProof(authorization.rollbackProof, {
      serviceArn: `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:service/${BACKEND_HEALTH_RECOVERY.cluster}/${BACKEND_HEALTH_RECOVERY.service}`,
      rollbackDeploymentArn: approval.rollbackDeploymentArn,
      rollbackTargetTaskDefinitionArn: approval.rollbackTargetTaskDefinitionArn,
      rollbackTargetDigest: approval.rollbackTargetDigest,
    });
  } else if (ROLLBACK_APPROVAL_FIELDS.some((field) => field in approval)) throw new Error("Human rollback approval lacks authenticated live rollback proof.");
  assertProductionEnvironmentReviewer(environmentApproval, { approvedBy: approval.approvedBy, executionActor });
  if (/(BEGIN [A-Z ]+PRIVATE KEY|SecretString|AccessKeyId|SecretAccessKey|SessionToken|DATABASE_URL=|password|token)/i.test(JSON.stringify(approval))) throw new Error("Backend health recovery approval contains prohibited secret material.");
  const { authorizationSha256, ...body } = authorization;
  if (!HEX256.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256) throw new Error("Backend health recovery authorization hash is invalid.");
  return authorization;
}

export function assertLegacyBackendRecoveryEligibility(input = {}) {
  const { sourceSha, service, currentTaskDefinition, currentImageExists, replacementImage, stoppedReasons = [], authorization, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindings, artifactSigningBindingSha256, githubContext, executionActor } = input;
  const current = definition(currentTaskDefinition);
  const currentArn = current.taskDefinitionArn;
  const imageMatch = IMAGE.exec(backendContainer(current).image || "");
  if (service?.clusterArn !== `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`
    || service?.serviceName !== BACKEND_HEALTH_RECOVERY.service || !TASK_ARN.test(service?.taskDefinition || "")
    || !Number.isInteger(service?.desiredCount) || service.desiredCount < 1) throw new Error("Live ECS service is outside the exact backend recovery boundary.");
  const deployments = Array.isArray(service.deployments) ? service.deployments : [];
  const inProgress = deployments.some((deployment) => deployment?.rolloutState === "IN_PROGRESS"
    || (deployment?.taskDefinition !== service.taskDefinition && [deployment?.desiredCount, deployment?.runningCount, deployment?.pendingCount].some((count) => Number(count) > 0)));
  if (inProgress && authorization?.rollbackProof?.classification !== ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE) throw new Error("Backend service rollback or deployment remains in progress and requires reconciliation.");
  if (!TASK_ARN.test(currentArn || "") || current.family !== BACKEND_HEALTH_RECOVERY.family || !imageMatch) throw new Error("Current legacy backend task definition identity is invalid.");
  if (currentImageExists !== false) throw new Error("Backend health recovery requires the current immutable digest to be absent from ECR.");
  if (!stoppedReasons.some((reason) => /CannotPullContainerError/i.test(reason) && /not found|does not exist/i.test(reason) && reason.includes(imageMatch[1]))) throw new Error("Backend degradation is not authenticated as the current digest's missing-image pull failure.");
  if (replacementImage?.exists !== true || replacementImage?.immutable !== true || replacementImage?.signatureValid !== true
    || replacementImage?.attestationValid !== true || replacementImage?.provenanceValid !== true || replacementImage?.criticalFindings !== 0
    || replacementImage?.repository !== BACKEND_HEALTH_RECOVERY.repository || !SHA256.test(replacementImage?.digest || "")) throw new Error("Replacement image does not satisfy the recovery evidence contract.");
  assertLegacyBackendRecoveryAuthorization(authorization, { sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: replacementImage.digest, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindingSha256, githubContext, executionActor });
  const checked = assertLegacyBackendRecoveryCandidate({ currentTaskDefinition, candidate: input.candidate, recoveryImageDigest: replacementImage.digest, imageReleaseSha: authorization.imageReleaseSha, artifactSigningBindings });
  return Object.freeze({ ...checked, currentTaskDefinitionArn: currentArn, observedServiceTaskDefinitionArn: service.taskDefinition, currentImageDigest: imageMatch[1], recoveryImageDigest: replacementImage.digest, desiredCount: service.desiredCount, networkConfigurationSha256: canonicalSha256(service.networkConfiguration), loadBalancersSha256: canonicalSha256(service.loadBalancers), rollbackProof: authorization.rollbackProof });
}

export async function runLegacyBackendHealthRecovery(input, adapters = {}) {
  for (const name of ["census", "register", "describe", "readService", "updateService", "waitStable", "readRunningTasks", "verifyHealth", "record"]) if (typeof adapters[name] !== "function") throw new Error(`Recovery adapter ${name} is required.`);
  const eligible = assertLegacyBackendRecoveryEligibility(input);
  if (eligible.rollbackProof) {
    if (typeof adapters.readRollbackViability !== "function") throw new Error("Recovery rollback viability adapter is required.");
    assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
  }
  const revisions = await adapters.census();
  if (!Array.isArray(revisions)) throw new Error("Legacy backend revision census is incomplete.");
  const matches = revisions.filter((item) => taskDefinitionFingerprint(item, item.tags || []) === eligible.fingerprint);
  if (matches.length > 1) throw new Error("Multiple matching recovery revisions make replay ambiguous.");
  const failedForwardTaskDefinitionArn = eligible.rollbackProof?.forwardTargetTaskDefinitionArn;
  if (failedForwardTaskDefinitionArn && matches.some((item) => (item?.taskDefinition?.taskDefinitionArn || item?.taskDefinitionArn) === failedForwardTaskDefinitionArn)) {
    throw new Error("The failed forward task definition cannot be reused as a corrected recovery revision.");
  }
  const sourceRevision = Number(TASK_ARN.exec(eligible.currentTaskDefinitionArn)?.[1]);
  const failedPredecessor = buildLegacyImageIdentityOnlyCandidate({ currentTaskDefinition: input.currentTaskDefinition, recoveryImageDigest: eligible.recoveryImageDigest, imageReleaseSha: input.authorization.imageReleaseSha });
  const failedPredecessorFingerprint = taskDefinitionFingerprint(failedPredecessor, failedPredecessor.tags || []);
  const newerUnknown = revisions.filter((item) => {
    const task = definition(item);
    const revision = Number(TASK_ARN.exec(task.taskDefinitionArn || "")?.[1]);
    const fingerprint = taskDefinitionFingerprint(item, item.tags || []);
    return revision > sourceRevision && fingerprint !== eligible.fingerprint && fingerprint !== failedPredecessorFingerprint;
  });
  if (newerUnknown.length) throw new Error("A newer unknown legacy backend revision requires reconciliation before recovery.");
  let targetArn = matches[0]?.taskDefinition?.taskDefinitionArn || matches[0]?.taskDefinitionArn;
  if (targetArn && !TASK_ARN.test(targetArn)) throw new Error("Recovery census returned an invalid legacy backend revision.");
  if (eligible.observedServiceTaskDefinitionArn !== eligible.currentTaskDefinitionArn
    && eligible.observedServiceTaskDefinitionArn !== targetArn) {
    throw new Error("Backend service current task definition is stale and does not match an authenticated completed recovery.");
  }
  let registrations = 0;
  if (!targetArn) {
    if (eligible.rollbackProof) assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED, targetArn: null, registrations: 0, updates: 0 });
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
  if (targetArn === failedForwardTaskDefinitionArn) throw new Error("Recovery registration reused the failed forward task definition.");
  if (registrations) await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY, targetArn, registrations, updates: 0 });
  const target = await adapters.describe(targetArn);
  if (taskDefinitionFingerprint(target, target?.tags || []) !== eligible.fingerprint) throw new Error("Recovery target readback does not match the exact authorized candidate.");
  let live = await adapters.readService();
  let updates = 0;
  if (live.taskDefinition !== targetArn) {
    if (live.taskDefinition !== eligible.currentTaskDefinitionArn || eligible.observedServiceTaskDefinitionArn !== eligible.currentTaskDefinitionArn
      || live.desiredCount !== eligible.desiredCount || canonicalSha256(live.networkConfiguration) !== eligible.networkConfigurationSha256
      || canonicalSha256(live.loadBalancers) !== eligible.loadBalancersSha256) throw new Error("Backend service changed concurrently before recovery update.");
    if (eligible.rollbackProof) assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, targetArn, registrations, updates: 0 });
    try { await adapters.updateService(targetArn); updates = 1; }
    catch (error) {
      live = await adapters.readService();
      if (live.taskDefinition !== targetArn) {
        await adapters.record({ status: registrations
          ? BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY
          : BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, targetArn, registrations, updates: 0 });
        throw error;
      }
      updates = 1;
    }
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED, targetArn, registrations, updates });
  }
  try { await adapters.waitStable(targetArn); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates });
    throw error;
  }
  try { live = await adapters.readService(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates });
    throw error;
  }
  if (live.taskDefinition !== targetArn || live.desiredCount !== eligible.desiredCount || live.runningCount !== eligible.desiredCount || live.pendingCount !== 0) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates });
    throw new Error("Backend service did not converge on the recovery revision.");
  }
  let tasks;
  try { tasks = await adapters.readRunningTasks(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED, targetArn, registrations, updates });
    throw error;
  }
  if (!Array.isArray(tasks) || tasks.length !== eligible.desiredCount || tasks.some((task) => task.taskDefinitionArn !== targetArn || task.imageDigest !== eligible.recoveryImageDigest)) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED, targetArn, registrations, updates });
    throw new Error("Running backend tasks do not match the approved recovery digest.");
  }
  if (tasks.some((task) => task.healthStatus !== "HEALTHY")) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates });
    throw new Error("Every running backend task must report HEALTHY before recovery completion.");
  }
  let health;
  try { health = await adapters.verifyHealth(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED, targetArn, registrations, updates });
    throw error;
  }
  if (health?.healthy !== true || health?.success !== true || health?.status !== "ready") {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED, targetArn, registrations, updates });
    throw new Error("Backend health did not recover after the governed image replacement.");
  }
  const result = Object.freeze({ mode: BACKEND_HEALTH_RECOVERY.kind, targetArn, recoveryImageDigest: eligible.recoveryImageDigest, registrations, updates, backendHealthy: true, health, rotationRequired: true, stageBApplied: false, frontendDeployed: false });
  await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RECOVERY_COMPLETE, ...result });
  return result;
}
