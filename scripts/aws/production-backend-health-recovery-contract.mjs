import { canonicalSha256, taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentReviewer } from "./production-github-environment-approval.mjs";
import { ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { loadArtifactSigningBootstrapContract } from "./production-artifact-signing-bootstrap.mjs";
import { ROLLBACK_VIABILITY, assertFreshRollbackEquivalence, assertRollbackSupersessionProof } from "./production-ecs-rollback-viability.mjs";
import { assertFreshRuntimeConsumabilityVerification } from "./production-ecs-runtime-consumability.mjs";

export const BACKEND_HEALTH_RECOVERY = Object.freeze({
  kind: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  schemaVersion: 4,
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
export const INTERRUPTED_RECOVERY_STATE = Object.freeze({
  NO_EFFECT: "NO_EFFECT",
  RESUMABLE: "RESUMABLE",
  PROGRESSING: "PROGRESSING",
  FAILED: "FAILED",
  SUCCEEDED: "SUCCEEDED",
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
const TASK_INSTANCE_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/;
const SERVICE_DEPLOYMENT_ID = /^ecs-svc\/[1-9][0-9]*$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/;
const IDENTITY_ENV = new Set(["GIT_SHA", "RELEASE_GIT_SHA"]);
const SIGNING_BINDINGS = new Set(ARTIFACT_SIGNING_BINDINGS);
const ARTIFACT_SIGNING_SECRET_NAMES = loadArtifactSigningBootstrapContract().names;
const ARTIFACT_SIGNING_SECRET_ARNS = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, new RegExp(`^arn:aws:secretsmanager:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:secret:${ARTIFACT_SIGNING_SECRET_NAMES[name].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-[A-Za-z0-9]{6}$`)]));
const AUTHORIZATION_FIELDS = new Set(["schemaVersion", "kind", "environment", "account", "region", "cluster", "service", "family", "sourceSha", "imageReleaseSha", "currentTaskDefinitionArn", "recoveryImageDigest", "imageAuthorizationSha256", "environmentApprovalSha256", "artifactSigningBindingSha256", "runtimeConsumabilitySha256", "failedRecoveryEvidenceSha256", "failedRecoveryEvidenceReferenceSha256", "rollbackProof", "reasonCode", "allowedDeltaProfile", "approval", "authorizationSha256"]);
const BASE_APPROVAL_FIELDS = ["ticket", "approvedBy", "approverRole", "reason", "verificationRef", "sourceSha", "currentTaskDefinitionArn", "recoveryImageDigest", "runtimeConsumabilitySha256"];
const ROLLBACK_APPROVAL_FIELDS = ["rollbackDeploymentArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest"];
const FAILED_HISTORY_APPROVAL_FIELD = "failedRecoveryEvidenceSha256";
const FAILED_HISTORY_REFERENCE_APPROVAL_FIELD = "failedRecoveryEvidenceReferenceSha256";

const requiredText = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};

export function assertLegacyBackendRecoveryEvidence(evidence, {
  sourceSha, currentTaskDefinitionArn, recoveryImageDigest, authorizationFileSha256, authorizationSha256,
  environmentApprovalFileSha256, environmentApprovalSha256, imageAuthorizationFileSha256, imageAuthorizationSha256,
  artifactSigningBindingSha256, runtimeConsumabilitySha256, imageReleaseSha,
  rollbackProofSha256, failedRecoveryEvidenceReferenceSha256 = null,
  account = BACKEND_HEALTH_RECOVERY.account, region = BACKEND_HEALTH_RECOVERY.region,
} = {}) {
  const { evidenceSha256, ...body } = evidence || {};
  const preRuntimeClosureLegacy = evidence?.schemaVersion === 3;
  const crashConsistent = [6, 7].includes(evidence?.schemaVersion);
  if (![3, 5, 6, 7].includes(evidence?.schemaVersion) || evidence?.kind !== "BACKEND_HEALTH_RECOVERY_EVIDENCE"
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
    || (preRuntimeClosureLegacy
      ? "runtimeConsumabilitySha256" in evidence || runtimeConsumabilitySha256 !== null
      : !HEX256.test(runtimeConsumabilitySha256 || "") || evidence.runtimeConsumabilitySha256 !== runtimeConsumabilitySha256)
    || evidence.rollbackProofSha256 !== (rollbackProofSha256 || null)
    || ("failedRecoveryEvidenceReferenceSha256" in evidence ? evidence.failedRecoveryEvidenceReferenceSha256 !== failedRecoveryEvidenceReferenceSha256 : failedRecoveryEvidenceReferenceSha256 !== null)
    || !RECOVERY_STATUSES.has(evidence.status)
    || !ARTIFACT_SIGNING_VERIFICATION_STATES.has(evidence.artifactSigningVerification)
    || (evidence.artifactSigningVerification === ARTIFACT_SIGNING_VERIFICATION.FAILED
      ? !ARTIFACT_SIGNING_DISCOVERY_FAILURES.has(evidence.artifactSigningFailure)
      : evidence.artifactSigningFailure !== null)
    || !Array.isArray(evidence.knownFailedRevisions)
    || evidence.knownFailedRevisions.some((item) => !TASK_ARN.test(item?.taskDefinitionArn || "") || !HEX256.test(item?.taskDefinitionFingerprint || ""))
    || new Set(evidence.knownFailedRevisions.map(({ taskDefinitionArn: arn }) => arn)).size !== evidence.knownFailedRevisions.length
    || !Number.isSafeInteger(evidence.registrations) || evidence.registrations < 0 || evidence.registrations > 1
    || !Number.isSafeInteger(evidence.updates) || evidence.updates < 0 || evidence.updates > 1
    || !Number.isFinite(Date.parse(evidence.generatedAt))
    || !HEX256.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) {
    throw new Error("Backend health recovery evidence is malformed, stale, or tampered.");
  }
  if (crashConsistent && (!HEX256.test(evidence.candidateFingerprint || "")
    || ![null, undefined].includes(evidence.initialRevisionCensusSha256) && !HEX256.test(evidence.initialRevisionCensusSha256)
    || ![null, undefined].includes(evidence.expectedRevisionCensusSha256) && !HEX256.test(evidence.expectedRevisionCensusSha256))) {
    throw new Error("Backend health recovery crash-reconciliation identity is malformed.");
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
  if (crashConsistent && evidence.status !== BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE && !HEX256.test(evidence.initialRevisionCensusSha256 || "")) throw new Error("Mutation-capable recovery evidence lacks its initial revision census.");
  if (crashConsistent && evidence.targetArn && !HEX256.test(evidence.expectedRevisionCensusSha256 || "")) throw new Error("Post-registration recovery evidence lacks its expected revision census.");
  if (evidence.schemaVersion === 7 && evidence.status !== BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE && !HEX256.test(evidence.predecessorHistoryLineageSha256 || "")) throw new Error("Mutation-capable recovery evidence lacks its authenticated predecessor history lineage.");
  if (evidence.status === BACKEND_HEALTH_RECOVERY_STATUS.RECOVERY_COMPLETE
    && (evidence.backendHealthy !== true || evidence.health?.healthy !== true || evidence.health?.success !== true || evidence.health?.status !== "ready"
      || evidence.health?.dependencies?.database !== "ready" || evidence.health?.dependencies?.redis !== "ready" || evidence.health?.dependencies?.objectStorage !== "ready"
      || evidence.health?.release?.gitSha !== imageReleaseSha || !Number.isFinite(Date.parse(evidence.health?.timestamp))
      || evidence.rotationRequired !== true)) {
    throw new Error("Completed backend recovery evidence lacks final readiness proof.");
  }
  return evidence;
}

export function createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256 = null, failedRecoveryEvidenceReferenceSha256 = null, rollbackProof = null, approval } = {}) {
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
    runtimeConsumabilitySha256,
    failedRecoveryEvidenceSha256,
    failedRecoveryEvidenceReferenceSha256,
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

const taskDefinitionArn = (value) => definition(value).taskDefinitionArn;

const historyOf = (eligible) => eligible.recoveryHistory || [];
const historyKey = (item) => `${item.workflowRunId}:${item.evidenceFileSha256}`;
const identityHash = (identities) => canonicalSha256([...identities].sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn)));
export function openInterruptedRecoveryHistory(history) {
  if (!Array.isArray(history)) throw new Error("Recovery history is malformed.");
  const current = history.at(-1);
  return current?.classification === "INTERRUPTED_MUTATION" ? [current] : [];
}
export const EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256 = canonicalSha256([]);
export const RECOVERY_HISTORY_LINEAGE_PROJECTION_VERSION = 1;
export function recoveryHistoryLineageRecord(record) {
  return {
    repository: record.repository,
    workflowRunId: record.workflowRunId,
    sourceSha: record.sourceSha,
    service: record.service,
    releaseMode: record.releaseMode,
    currentTaskDefinitionArn: record.currentTaskDefinitionArn,
    taskDefinitionArn: record.taskDefinitionArn,
    candidateFingerprint: record.candidateFingerprint,
    taskDefinitionFingerprint: record.taskDefinitionFingerprint,
    recoveryImageDigest: record.recoveryImageDigest,
    artifactSigningBindingSha256: record.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: record.runtimeConsumabilitySha256,
    predecessorHistoryReferenceSha256: record.predecessorHistoryReferenceSha256,
    predecessorHistoryLineageSha256: record.predecessorHistoryLineageSha256,
    status: record.status,
    classification: record.classification,
    failureClassification: record.failureClassification,
    initialRevisionCensusSha256: record.initialRevisionCensusSha256,
    expectedRevisionCensusSha256: record.expectedRevisionCensusSha256,
    registrations: record.registrations,
    updates: record.updates,
    evidenceFileSha256: record.evidenceFileSha256,
  };
}
export function recoveryHistoryLineageSha256(history) {
  if (!Array.isArray(history)) throw new Error("Recovery history lineage is malformed.");
  let lineageSha256 = EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256;
  let strengthened = false;
  for (const record of history) {
    const bound = record.predecessorHistoryLineageSha256;
    if (bound !== null && bound !== undefined) {
      if (!HEX256.test(bound) || bound !== lineageSha256) throw new Error("Recovery history lineage predecessor hash is missing, reordered, or forked.");
      strengthened = true;
    } else if (strengthened) throw new Error("Recovery history lineage cannot downgrade after a bound generation.");
    lineageSha256 = canonicalSha256({ predecessorLineageSha256: lineageSha256, record: recoveryHistoryLineageRecord(record) });
  }
  return lineageSha256;
}

function revisionEntries(revisions) {
  if (!Array.isArray(revisions)) throw new Error("Legacy backend revision census is incomplete.");
  const entries = revisions.map((item) => {
    const arn = taskDefinitionArn(item);
    const revision = Number(TASK_ARN.exec(arn || "")?.[1]);
    if (!Number.isSafeInteger(revision)) throw new Error("Recovery census returned an invalid legacy backend revision.");
    return { item, taskDefinitionArn: arn, revision, fingerprint: taskDefinitionFingerprint(item, item.tags || []) };
  });
  if (new Set(entries.map(({ taskDefinitionArn: arn }) => arn)).size !== entries.length) throw new Error("Recovery census contains duplicate task-definition identities.");
  return entries;
}

export function reconcileAuthenticatedRevisionLineage(revisions, eligible, { allowedRevision = null } = {}) {
  const entries = revisionEntries(revisions).sort((a, b) => a.revision - b.revision);
  const sourceRevision = Number(TASK_ARN.exec(eligible.currentTaskDefinitionArn || "")?.[1]);
  if (!Number.isSafeInteger(sourceRevision)) throw new Error("Recovery lineage source task definition is invalid.");
  const history = historyOf(eligible);
  recoveryHistoryLineageSha256(history);
  const rollbackForwardArn = eligible.rollbackProof?.forwardTargetTaskDefinitionArn || null;
  let root;
  if (history[0]?.initialRevisionCensusSha256) {
    const roots = Array.from({ length: entries.length + 1 }, (_, length) => entries.slice(0, length))
      .filter((candidate) => identityHash(candidate.map(({ taskDefinitionArn: arn, fingerprint }) => ({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint }))) === history[0].initialRevisionCensusSha256);
    if (roots.length !== 1) throw new Error("Recovery history cannot derive one authenticated base census.");
    [root] = roots;
  } else if (history.length) {
    const legacySourceRevision = Number(TASK_ARN.exec(history[0].currentTaskDefinitionArn || "")?.[1]);
    if (!Number.isSafeInteger(legacySourceRevision)) throw new Error("Legacy recovery history cannot derive its base census.");
    root = entries.filter(({ revision, taskDefinitionArn: arn }) => revision <= legacySourceRevision || arn === rollbackForwardArn);
  } else {
    root = entries.filter(({ revision, taskDefinitionArn: arn }) => revision <= sourceRevision || arn === rollbackForwardArn);
  }
  if (rollbackForwardArn && !history.some(({ taskDefinitionArn: arn }) => arn === rollbackForwardArn)) {
    const rollback = root.find(({ taskDefinitionArn: arn }) => arn === rollbackForwardArn);
    if (!rollback || rollback.fingerprint !== eligible.rollbackProof.forwardTargetTaskDefinitionFingerprint) throw new Error("Authenticated failed forward task definition is absent or differs from live rollback history.");
  }
  const lineage = root.map(({ taskDefinitionArn: arn, fingerprint }) => ({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint }));
  const resolutions = [];
  const finalIdentities = entries.map(({ taskDefinitionArn: arn, fingerprint }) => ({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint }));
  const historicalFinalIdentities = allowedRevision
    ? finalIdentities.filter(({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint }) => arn !== allowedRevision.taskDefinitionArn || fingerprint !== allowedRevision.taskDefinitionFingerprint)
    : finalIdentities;
  const entryByArn = new Map(entries.map((entry) => [entry.taskDefinitionArn, entry]));
  const addCandidate = (record, targetArn, expectedHash) => {
    const target = entryByArn.get(targetArn);
    if (!target || target.fingerprint !== record.taskDefinitionFingerprint || target.fingerprint !== record.candidateFingerprint) throw new Error("Recovery lineage candidate differs from authenticated historical evidence.");
    const next = entries.find(({ taskDefinitionArn: arn }) => !lineage.some((item) => item.taskDefinitionArn === arn));
    if (next?.taskDefinitionArn !== targetArn) throw new Error("Recovery history has a missing, reordered, or concurrently inserted revision.");
    lineage.push({ taskDefinitionArn: targetArn, taskDefinitionFingerprint: target.fingerprint });
    if (expectedHash && identityHash(lineage) !== expectedHash) throw new Error("Recovery history candidate does not produce its authenticated successor lineage.");
  };
  for (let index = 0; index < history.length; index += 1) {
    const record = history[index];
    const legacyContinuation = index > 0 && record.evidenceContract === "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE"
      && history[index - 1]?.evidenceContract === "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE"
      && record.predecessorHistoryReferenceSha256 === null
      && Date.parse(record.workflowCreatedAt) > Date.parse(history[index - 1].workflowCreatedAt);
    if (index === 0 ? record.predecessorHistoryReferenceSha256 !== null : !legacyContinuation && !HEX256.test(record.predecessorHistoryReferenceSha256 || "")) throw new Error("Recovery history predecessor reference chain is missing, reordered, or substituted.");
    if (record.taskDefinitionFingerprint !== record.candidateFingerprint || !lineage.some(({ taskDefinitionArn: arn }) => arn === record.currentTaskDefinitionArn)) throw new Error("Recovery history is bound to a different predecessor lineage or candidate identity.");
    const predecessorSha256 = identityHash(lineage);
    let targetArn = record.taskDefinitionArn;
    let introduced = false;
    if (record.initialRevisionCensusSha256 === null) {
      if (!targetArn || record.registrations !== 1) throw new Error("Legacy recovery history cannot establish predecessor continuity.");
      if (!lineage.some(({ taskDefinitionArn: arn }) => arn === targetArn)) {
        addCandidate(record, targetArn, null); introduced = true;
      } else if (targetArn !== rollbackForwardArn) throw new Error("Legacy recovery history conflicts with its authenticated lineage.");
    } else {
      if (record.initialRevisionCensusSha256 !== predecessorSha256) throw new Error("Recovery history predecessor lineage is missing, reordered, or forked.");
      if (record.registrations === 1) {
        if (!targetArn) throw new Error("Registered recovery generation lacks its candidate revision.");
        addCandidate(record, targetArn, record.expectedRevisionCensusSha256); introduced = true;
      } else if (targetArn === null) {
        const successorSha256 = history[index + 1]?.initialRevisionCensusSha256 || identityHash(historicalFinalIdentities);
        if (successorSha256 !== predecessorSha256) {
          const candidates = entries.filter(({ taskDefinitionArn: arn, fingerprint }) => !lineage.some((item) => item.taskDefinitionArn === arn) && fingerprint === record.candidateFingerprint
            && identityHash([...lineage, { taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint }]) === successorSha256);
          if (candidates.length !== 1) throw new Error("Ambiguous registration response cannot establish one authenticated lineage extension.");
          targetArn = candidates[0].taskDefinitionArn; addCandidate(record, targetArn, successorSha256); introduced = true;
        }
      } else {
        const target = lineage.find(({ taskDefinitionArn: arn }) => arn === targetArn);
        if (!target || target.taskDefinitionFingerprint !== record.taskDefinitionFingerprint || record.expectedRevisionCensusSha256 !== predecessorSha256) throw new Error("Recovery history reuse does not match its authenticated predecessor lineage.");
      }
    }
    resolutions.push(Object.freeze({ key: historyKey(record), index, targetArn, introduced, predecessorSha256, successorSha256: identityHash(lineage) }));
  }
  const historicalIdentitySha256 = identityHash(lineage);
  const remaining = entries.filter(({ taskDefinitionArn: arn }) => !lineage.some((item) => item.taskDefinitionArn === arn));
  const expectedCurrent = allowedRevision
    ? remaining.filter(({ taskDefinitionArn: arn, fingerprint }) => arn === allowedRevision.taskDefinitionArn && fingerprint === allowedRevision.taskDefinitionFingerprint)
    : remaining.filter(({ fingerprint }) => fingerprint === eligible.fingerprint);
  if (remaining.length > 1 || remaining.length !== expectedCurrent.length) throw new Error("Authoritative revision census contains a newer unknown or concurrent lineage revision.");
  if (remaining.length) lineage.push({ taskDefinitionArn: remaining[0].taskDefinitionArn, taskDefinitionFingerprint: remaining[0].fingerprint });
  const currentSha256 = identityHash(finalIdentities);
  if (identityHash(lineage) !== currentSha256) throw new Error("Authoritative revision census differs from its authenticated lineage.");
  return Object.freeze({ identities: Object.freeze(finalIdentities.sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn))), identitySha256: currentSha256, historicalIdentitySha256, historyResolutions: Object.freeze(resolutions) });
}

export function classifyRevisionCensus(revisions, eligible, options = {}) {
  const entries = revisionEntries(revisions);
  const lineage = reconcileAuthenticatedRevisionLineage(revisions, eligible, options);
  const approvedFailed = new Map((eligible.knownFailedRevisions || []).map((item) => [item.taskDefinitionArn, item]));
  const resolutionByKey = new Map(lineage.historyResolutions.map((item) => [item.key, item]));
  const approvedInterrupted = new Map((eligible.interruptedRecoveries || []).map((item) => [resolutionByKey.get(historyKey(item))?.targetArn, item]).filter(([arn]) => arn));
  const failedArn = eligible.rollbackProof?.forwardTargetTaskDefinitionArn;
  if (failedArn) approvedFailed.set(failedArn, { taskDefinitionArn: failedArn, taskDefinitionFingerprint: eligible.rollbackProof.forwardTargetTaskDefinitionFingerprint });
  const matches = entries.filter(({ taskDefinitionArn: arn, fingerprint }) => fingerprint === eligible.fingerprint && !approvedFailed.has(arn));
  if (matches.length > 1) throw new Error("Multiple matching recovery revisions make replay ambiguous.");
  const knownFailed = entries.filter(({ taskDefinitionArn: arn }) => approvedFailed.has(arn));
  if (knownFailed.length !== approvedFailed.size || knownFailed.some(({ taskDefinitionArn: arn, fingerprint }) => approvedFailed.get(arn).taskDefinitionFingerprint !== fingerprint)) throw new Error("An authenticated failed forward task definition or failed recovery revision is absent or differs from live revision history.");
  const interrupted = entries.filter(({ taskDefinitionArn: arn }) => approvedInterrupted.has(arn));
  if (interrupted.length !== approvedInterrupted.size || interrupted.some(({ taskDefinitionArn: arn, fingerprint }) => approvedInterrupted.get(arn).taskDefinitionFingerprint !== fingerprint)) throw new Error("An authenticated interrupted recovery revision is absent or differs from live revision history.");
  if (matches.some(({ taskDefinitionArn: arn }) => approvedFailed.has(arn))) throw new Error("A failed recovery task definition cannot be reused as a corrected recovery revision.");
  const identities = lineage.identities;
  return Object.freeze({
    matches,
    knownFailedRevisions: knownFailed.map(({ taskDefinitionArn: arn, fingerprint }) => ({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint })),
    interruptedRevisions: interrupted.map(({ taskDefinitionArn: arn, fingerprint }) => ({ taskDefinitionArn: arn, taskDefinitionFingerprint: fingerprint })),
    identities,
    identitySha256: lineage.identitySha256,
    historyResolutions: lineage.historyResolutions,
  });
}

const taskFailureReason = (task) => [task?.stoppedReason, ...(task?.containers || []).map(({ reason }) => reason)].filter(Boolean).join("\n");
const interruptedResult = (classification, targetArn, identitySha256, snapshot, extra = {}) => Object.freeze({
  classification, targetArn, identitySha256, ...extra,
  serviceTaskDefinitionArn: snapshot.service.taskDefinition,
  desiredCount: snapshot.service.desiredCount,
  runningCount: snapshot.service.runningCount,
  pendingCount: snapshot.service.pendingCount,
  networkConfigurationSha256: canonicalSha256(snapshot.service.networkConfiguration),
  loadBalancersSha256: canonicalSha256(snapshot.service.loadBalancers),
  proofSha256: canonicalSha256({ classification, targetArn, identitySha256, taskDefinition: snapshot.service.taskDefinition,
    desiredCount: snapshot.service.desiredCount, runningCount: snapshot.service.runningCount, pendingCount: snapshot.service.pendingCount,
    deployments: (snapshot.service.deployments || []).map(({ id, taskDefinition, rolloutState, desiredCount, runningCount, pendingCount, createdAt }) => ({ id, taskDefinition, rolloutState, desiredCount, runningCount, pendingCount, createdAt })).sort((a, b) => String(a.id).localeCompare(String(b.id))),
    evidence: extra }),
});

export function classifyInterruptedRecoveryState(interruption, snapshot, { lineage } = {}) {
  if (interruption?.classification !== "INTERRUPTED_MUTATION" || !HEX256.test(interruption?.taskDefinitionFingerprint || "")
    || !snapshot?.service || !lineage) throw new Error("Interrupted recovery evidence, lineage, or live snapshot is incomplete.");
  const resolution = lineage.historyResolutions.find(({ key }) => key === historyKey(interruption));
  if (!resolution) throw new Error("Interrupted recovery is absent from the authenticated revision lineage.");
  const targetArn = resolution.targetArn;
  if (targetArn === null) return interruptedResult(INTERRUPTED_RECOVERY_STATE.NO_EFFECT, null, lineage.historicalIdentitySha256, snapshot);
  const service = snapshot.service;
  if (service.serviceName !== BACKEND_HEALTH_RECOVERY.service || service.taskDefinition === interruption.currentTaskDefinitionArn) {
    if (service.serviceName !== BACKEND_HEALTH_RECOVERY.service || interruption.status === BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED) throw new Error("Confirmed interrupted service update disagrees with authoritative ECS state.");
    return interruptedResult(INTERRUPTED_RECOVERY_STATE.RESUMABLE, targetArn, lineage.historicalIdentitySha256, snapshot);
  }
  if (service.taskDefinition !== targetArn) throw new Error("Interrupted recovery service moved to an unauthenticated revision.");
  if (![BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED].includes(interruption.status)) throw new Error("Pre-update interruption cannot authenticate a service mutation.");
  if (!Number.isInteger(service.desiredCount) || service.desiredCount < 1 || !Number.isInteger(service.runningCount) || !Number.isInteger(service.pendingCount)) throw new Error("Interrupted recovery service counts are malformed.");
  const deployments = (service.deployments || []).filter(({ taskDefinition }) => taskDefinition === targetArn);
  if (deployments.length !== 1 || !/^ecs-svc\/[1-9][0-9]*$/.test(deployments[0]?.id || "") || !Number.isFinite(Date.parse(deployments[0]?.createdAt))) throw new Error("Interrupted recovery current deployment identity is ambiguous.");
  const deployment = deployments[0];
  const runningTasks = Array.isArray(snapshot.runningTasks) ? snapshot.runningTasks : [];
  const healthy = service.runningCount === service.desiredCount && service.pendingCount === 0 && runningTasks.length === service.desiredCount
    && runningTasks.every((task) => task.taskDefinitionArn === targetArn && task.imageDigest === interruption.recoveryImageDigest && task.healthStatus === "HEALTHY")
    && snapshot.health?.healthy === true && snapshot.health?.success === true && snapshot.health?.status === "ready";
  if (healthy) return interruptedResult(INTERRUPTED_RECOVERY_STATE.SUCCEEDED, targetArn, lineage.historicalIdentitySha256, snapshot, { health: snapshot.health });
  const seen = new Set();
  const failures = (Array.isArray(snapshot.stoppedTasks) ? snapshot.stoppedTasks : []).filter((task) => {
    const containers = (task?.containers || []).filter(({ name }) => name === BACKEND_HEALTH_RECOVERY.container);
    if (!/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/.test(task?.taskArn || "") || seen.has(task.taskArn)
      || task.startedBy !== deployment.id || task.taskDefinitionArn !== targetArn || !Number.isFinite(Date.parse(task.createdAt))
      || !Number.isFinite(Date.parse(task.stoppedAt)) || Date.parse(task.createdAt) < Date.parse(deployment.createdAt) || Date.parse(task.stoppedAt) < Date.parse(task.createdAt)
      || containers.length !== 1 || containers[0].image !== `${BACKEND_HEALTH_RECOVERY.account}.dkr.ecr.${BACKEND_HEALTH_RECOVERY.region}.amazonaws.com/${BACKEND_HEALTH_RECOVERY.repository}@${interruption.recoveryImageDigest}`
      || (containers[0].imageDigest != null && containers[0].imageDigest !== interruption.recoveryImageDigest)
      || !/(CannotPullContainerError|ResourceInitializationError|EssentialContainerExited|essential container.*exited)/i.test(taskFailureReason(task))) return false;
    seen.add(task.taskArn); return true;
  });
  if (failures.length >= 2 && service.runningCount === 0 && service.pendingCount === 0) {
    const failureEvidenceSha256 = canonicalSha256(failures.map((task) => ({
      taskArn: task.taskArn, startedBy: task.startedBy, taskDefinitionArn: task.taskDefinitionArn,
      createdAt: task.createdAt, stoppedAt: task.stoppedAt, reason: taskFailureReason(task),
      image: task.containers.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container).image,
      imageDigest: task.containers.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container).imageDigest || null,
    })).sort((a, b) => a.taskArn.localeCompare(b.taskArn)));
    return interruptedResult(INTERRUPTED_RECOVERY_STATE.FAILED, targetArn, lineage.historicalIdentitySha256, snapshot, { failures: failures.length, failureEvidenceSha256 });
  }
  if (deployment.rolloutState === "IN_PROGRESS" || service.pendingCount > 0 || service.runningCount > 0) return interruptedResult(INTERRUPTED_RECOVERY_STATE.PROGRESSING, targetArn, lineage.historicalIdentitySha256, snapshot);
  throw new Error("Interrupted recovery live outcome is ambiguous.");
}

function expectedRevisionCensusSha256(initialCensus, targetArn, fingerprint, registered) {
  const identities = registered
    ? [...initialCensus.identities, { taskDefinitionArn: targetArn, taskDefinitionFingerprint: fingerprint }]
    : [...initialCensus.identities];
  if (new Set(identities.map(({ taskDefinitionArn: arn }) => arn)).size !== identities.length) throw new Error("Recovery registration reused an existing task-definition identity.");
  return canonicalSha256(identities.sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn)));
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
  sourceSha, currentTaskDefinitionArn, recoveryImageDigest, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256 = null, failedRecoveryEvidenceReferenceSha256 = null, recoveryHistory = [], knownFailedRevisions = [], interruptedRecoveries = [], githubContext, executionActor,
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
  if (!HEX256.test(runtimeConsumabilitySha256 || "") || authorization.runtimeConsumabilitySha256 !== runtimeConsumabilitySha256) throw new Error("Backend health recovery runtime-consumability evidence is stale or unauthenticated.");
  const history = recoveryHistory;
  const historyViewsMatch = canonicalSha256(history.filter(({ classification }) => classification === "TERMINAL_FAILURE")) === canonicalSha256(knownFailedRevisions)
    && canonicalSha256(history.filter(({ classification }) => classification === "INTERRUPTED_MUTATION")) === canonicalSha256(interruptedRecoveries);
  const invalidFailedHistory = !Array.isArray(knownFailedRevisions) || knownFailedRevisions.some((item) => {
    const legacy = item?.evidenceContract === "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE";
    return item?.repository !== "T-ej2003/genuine-scan-main" || !TASK_ARN.test(item?.taskDefinitionArn || "")
    || !HEX256.test(item?.taskDefinitionFingerprint || "") || !HEX256.test(item?.evidenceFileSha256 || "") || !/^[1-9][0-9]*$/.test(String(item?.workflowRunId || ""))
    || ![BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED, BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED].includes(item?.status)
    || item?.classification !== "TERMINAL_FAILURE" || item?.failureClassification !== item.status || !SHA.test(item?.sourceSha || "") || item?.service !== BACKEND_HEALTH_RECOVERY.service
    || item?.releaseMode !== BACKEND_HEALTH_RECOVERY.kind || !SHA256.test(item?.recoveryImageDigest || "") || !HEX256.test(item?.candidateFingerprint || "")
    || item.candidateFingerprint !== item.taskDefinitionFingerprint || !HEX256.test(item?.artifactSigningBindingSha256 || "")
    || (legacy ? item.runtimeConsumabilitySha256 !== null || item.requiresLiveFailureReconciliation !== true : !HEX256.test(item?.runtimeConsumabilitySha256 || ""))
    || ![null, undefined].includes(item?.predecessorHistoryReferenceSha256) && !HEX256.test(item.predecessorHistoryReferenceSha256)
    || ![null, undefined].includes(item?.predecessorHistoryLineageSha256) && !HEX256.test(item.predecessorHistoryLineageSha256)
    || !TASK_ARN.test(item?.currentTaskDefinitionArn || "") || ![0, 1].includes(item?.registrations) || ![0, 1].includes(item?.updates);
  });
  if (!Array.isArray(recoveryHistory) || !Array.isArray(knownFailedRevisions) || !Array.isArray(interruptedRecoveries) || !historyViewsMatch || invalidFailedHistory
    || interruptedRecoveries.some((item) => item?.repository !== "T-ej2003/genuine-scan-main" || item?.classification !== "INTERRUPTED_MUTATION"
      || ![BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED, BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY, BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED].includes(item?.status)
      || item.failureClassification !== null || !SHA.test(item?.sourceSha || "") || item.service !== BACKEND_HEALTH_RECOVERY.service || item.releaseMode !== BACKEND_HEALTH_RECOVERY.kind
      || !HEX256.test(item?.taskDefinitionFingerprint || "") || item.taskDefinitionFingerprint !== item.candidateFingerprint || !HEX256.test(item?.initialRevisionCensusSha256 || "") || !HEX256.test(item?.evidenceFileSha256 || "")
      || !/^[1-9][0-9]*$/.test(String(item?.workflowRunId || "")) || !SHA256.test(item?.recoveryImageDigest || "") || !HEX256.test(item?.artifactSigningBindingSha256 || "") || !HEX256.test(item?.runtimeConsumabilitySha256 || "") || !TASK_ARN.test(item?.currentTaskDefinitionArn || "")
      || ![null, undefined].includes(item?.predecessorHistoryReferenceSha256) && !HEX256.test(item.predecessorHistoryReferenceSha256)
      || ![null, undefined].includes(item?.predecessorHistoryLineageSha256) && !HEX256.test(item.predecessorHistoryLineageSha256)
      || (item.taskDefinitionArn === null ? item.status !== BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED || item.expectedRevisionCensusSha256 !== null : !TASK_ARN.test(item.taskDefinitionArn) || !HEX256.test(item.expectedRevisionCensusSha256 || "")))
    || new Set(history.map(({ workflowRunId }) => workflowRunId)).size !== history.length
    || new Set(history.map(({ taskDefinitionArn, taskDefinitionFingerprint }) => taskDefinitionArn || `pending:${taskDefinitionFingerprint}`)).size !== history.length
    || (history.length ? !HEX256.test(failedRecoveryEvidenceSha256 || "") || !HEX256.test(failedRecoveryEvidenceReferenceSha256 || "") || authorization.failedRecoveryEvidenceSha256 !== failedRecoveryEvidenceSha256 || authorization.failedRecoveryEvidenceReferenceSha256 !== failedRecoveryEvidenceReferenceSha256 : authorization.failedRecoveryEvidenceSha256 !== null || authorization.failedRecoveryEvidenceReferenceSha256 !== null)) throw new Error("Authenticated recovery history is malformed, missing, or duplicated.");
  recoveryHistoryLineageSha256(history);
  assertProductionEnvironmentApprovalEvidence(environmentApproval, { sourceSha, repository: githubContext?.repository, environment: "production", workflowRef: githubContext?.workflowRef, eventName: githubContext?.eventName, workflowRunId: githubContext?.workflowRunId, workflowRunAttempt: githubContext?.workflowRunAttempt, executionActor, githubActions: githubContext?.githubActions, now: githubContext?.now });
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (authorizedBackendDigest(imageAuthorization) !== recoveryImageDigest) throw new Error("Recovery digest differs from canonical image authorization.");
  const approval = authorization.approval;
  const approvalFields = Object.keys(approval || {}).sort().join(",");
  const baseApprovalFields = [...BASE_APPROVAL_FIELDS].sort().join(",");
  const failedHistoryApprovalFields = [...BASE_APPROVAL_FIELDS, FAILED_HISTORY_APPROVAL_FIELD, FAILED_HISTORY_REFERENCE_APPROVAL_FIELD].sort().join(",");
  const rollbackApprovalFields = [...BASE_APPROVAL_FIELDS, ...ROLLBACK_APPROVAL_FIELDS].sort().join(",");
  const rollbackHistoryApprovalFields = [...BASE_APPROVAL_FIELDS, ...ROLLBACK_APPROVAL_FIELDS, FAILED_HISTORY_APPROVAL_FIELD, FAILED_HISTORY_REFERENCE_APPROVAL_FIELD].sort().join(",");
  if (!approval || ![baseApprovalFields, failedHistoryApprovalFields, rollbackApprovalFields, rollbackHistoryApprovalFields].includes(approvalFields)) throw new Error("Backend health recovery approval schema is invalid.");
  for (const field of ["ticket", "approvedBy", "approverRole", "reason", "verificationRef"]) requiredText(approval?.[field], `approval.${field}`);
  if (approval.sourceSha !== sourceSha || approval.currentTaskDefinitionArn !== currentTaskDefinitionArn || approval.recoveryImageDigest !== recoveryImageDigest || approval.runtimeConsumabilitySha256 !== runtimeConsumabilitySha256) throw new Error("Human approval is bound to a different recovery.");
  if (history.length ? approval[FAILED_HISTORY_APPROVAL_FIELD] !== failedRecoveryEvidenceSha256 : FAILED_HISTORY_APPROVAL_FIELD in approval) throw new Error("Human approval is not bound to the exact authenticated recovery history.");
  if (history.length ? approval[FAILED_HISTORY_REFERENCE_APPROVAL_FIELD] !== failedRecoveryEvidenceReferenceSha256 : FAILED_HISTORY_REFERENCE_APPROVAL_FIELD in approval) throw new Error("Human approval is not bound to the immutable recovery-history reference.");
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

function legacyFailedDeploymentProof(service, stoppedTaskFailures, taskDefinitionArn) {
  const expectedServiceArn = `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:service/${BACKEND_HEALTH_RECOVERY.cluster}/${BACKEND_HEALTH_RECOVERY.service}`;
  if (service?.serviceArn !== expectedServiceArn
    || service?.clusterArn !== `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`
    || service?.serviceName !== BACKEND_HEALTH_RECOVERY.service || service?.taskDefinition !== taskDefinitionArn || service.runningCount !== 0 || service.pendingCount !== 0) return null;
  const deployments = (service.deployments || []).filter((deployment) => deployment?.status === "PRIMARY" && deployment?.taskDefinition === taskDefinitionArn && deployment?.rolloutState === "FAILED"
    && SERVICE_DEPLOYMENT_ID.test(deployment?.id || "") && Number(deployment?.failedTasks) > 0 && Number.isFinite(Date.parse(deployment?.createdAt)));
  if (deployments.length !== 1 || !Array.isArray(stoppedTaskFailures)) return null;
  const deployment = deployments[0];
  const failures = stoppedTaskFailures.filter((task) => {
    const createdAt = Date.parse(task?.createdAt); const startedAt = task?.startedAt == null ? createdAt : Date.parse(task.startedAt); const stoppedAt = Date.parse(task?.stoppedAt);
    return TASK_INSTANCE_ARN.test(task?.taskArn || "") && task.taskDefinitionArn === taskDefinitionArn && task.startedBy === deployment.id
      && task.desiredStatus === "STOPPED" && task.lastStatus === "STOPPED" && typeof task.stopCode === "string"
      && typeof task.stoppedReason === "string" && Array.isArray(task.containerReasons) && task.containerReasons.every((reason) => typeof reason === "string")
      && Number.isFinite(createdAt) && Number.isFinite(startedAt) && Number.isFinite(stoppedAt) && createdAt >= Date.parse(deployment.createdAt)
      && startedAt >= createdAt && stoppedAt >= startedAt;
  });
  if (!failures.flatMap((task) => [task.stoppedReason, ...task.containerReasons]).some((reason) => /ResourceInitializationError|CannotPullContainerError|TaskFailedToStart/i.test(reason))) return null;
  return Object.freeze({
    serviceArn: service.serviceArn,
    clusterArn: service.clusterArn, serviceName: service.serviceName, taskDefinitionArn, deploymentId: deployment.id,
    rolloutState: deployment.rolloutState, failedTasks: deployment.failedTasks, deploymentCreatedAt: deployment.createdAt,
    deployments: service.deployments.map(({ id, status, taskDefinition, rolloutState, failedTasks, desiredCount, runningCount, pendingCount, createdAt, updatedAt }) => ({ id, status, taskDefinition, rolloutState, failedTasks, desiredCount, runningCount, pendingCount, createdAt, updatedAt })).sort((a, b) => String(a.id).localeCompare(String(b.id))),
    stoppedTasks: failures.map(({ taskArn, taskDefinitionArn: arn, startedBy, desiredStatus, lastStatus, stopCode, stoppedReason, containerReasons, createdAt, startedAt, stoppedAt }) => ({ taskArn, taskDefinitionArn: arn, startedBy, desiredStatus, lastStatus, stopCode, stoppedReason, containerReasons, createdAt, startedAt, stoppedAt })).sort((a, b) => a.taskArn.localeCompare(b.taskArn)),
  });
}

export function assertLegacyBackendRecoveryEligibility(input = {}) {
  const { sourceSha, service, currentTaskDefinition, currentImageExists, replacementImage, stoppedTaskFailures = [], authorization, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindings, artifactSigningBindingSha256, runtimeConsumabilitySha256, authenticatedFailedRecoveryEvidence, githubContext, executionActor } = input;
  const knownFailedRevisions = authenticatedFailedRecoveryEvidence?.knownFailedRevisions || [];
  const interruptedRecoveries = authenticatedFailedRecoveryEvidence?.interruptedRecoveries || [];
  const recoveryHistory = authenticatedFailedRecoveryEvidence?.recoveryHistory || [];
  const openInterruptions = openInterruptedRecoveryHistory(recoveryHistory);
  const interruptionReconciliations = input.interruptionReconciliations || [];
  const current = definition(currentTaskDefinition);
  const currentArn = current.taskDefinitionArn;
  const imageMatch = IMAGE.exec(backendContainer(current).image || "");
  if (service?.clusterArn !== `arn:aws:ecs:${BACKEND_HEALTH_RECOVERY.region}:${BACKEND_HEALTH_RECOVERY.account}:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`
    || service?.serviceName !== BACKEND_HEALTH_RECOVERY.service || !TASK_ARN.test(service?.taskDefinition || "")
    || !Number.isInteger(service?.desiredCount) || service.desiredCount < 1 || !Number.isInteger(service?.runningCount) || service.runningCount < 0
    || !Number.isInteger(service?.pendingCount) || service.pendingCount < 0) throw new Error("Live ECS service is outside the exact backend recovery boundary.");
  const deployments = Array.isArray(service.deployments) ? service.deployments : [];
  const inProgress = deployments.some((deployment) => deployment?.rolloutState === "IN_PROGRESS"
    || (deployment?.taskDefinition !== service.taskDefinition && [deployment?.desiredCount, deployment?.runningCount, deployment?.pendingCount].some((count) => Number(count) > 0)));
  if (inProgress && authorization?.rollbackProof?.classification !== ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE) throw new Error("Backend service rollback or deployment remains in progress and requires reconciliation.");
  if (!TASK_ARN.test(currentArn || "") || current.family !== BACKEND_HEALTH_RECOVERY.family || !imageMatch) throw new Error("Current legacy backend task definition identity is invalid.");
  if (!Array.isArray(interruptionReconciliations) || interruptionReconciliations.length !== openInterruptions.length) throw new Error("The current authenticated interrupted recovery requires authoritative live reconciliation.");
  if (interruptionReconciliations.some(({ result }) => result.serviceTaskDefinitionArn !== service.taskDefinition || result.desiredCount !== service.desiredCount
    || result.runningCount !== service.runningCount || result.pendingCount !== service.pendingCount
    || result.networkConfigurationSha256 !== canonicalSha256(service.networkConfiguration) || result.loadBalancersSha256 !== canonicalSha256(service.loadBalancers))) throw new Error("Interrupted recovery live reconciliation changed from the execution service snapshot.");
  const currentInterruption = interruptionReconciliations.find(({ result }) => result.targetArn === service.taskDefinition);
  if (currentInterruption?.result.classification === INTERRUPTED_RECOVERY_STATE.PROGRESSING) throw new Error("Interrupted backend recovery is still progressing and must not be superseded.");
  const currentFailedRevision = knownFailedRevisions.find(({ taskDefinitionArn: arn }) => arn === service.taskDefinition)
    || (currentInterruption?.result.classification === INTERRUPTED_RECOVERY_STATE.FAILED ? currentInterruption.interruption : null);
  const unavailable = service.runningCount === 0 && service.pendingCount === 0;
  const exactFailedDeployments = (taskDefinitionArn) => deployments.filter((deployment) => deployment?.taskDefinition === taskDefinitionArn && deployment?.rolloutState === "FAILED"
    && SERVICE_DEPLOYMENT_ID.test(deployment?.id || "") && Number(deployment?.failedTasks) > 0 && Number.isFinite(Date.parse(deployment?.createdAt)));
  const exactFailures = (taskDefinitionArn, matchingDeployments) => matchingDeployments.length === 1 && Array.isArray(stoppedTaskFailures) ? stoppedTaskFailures.filter((task) => {
    const createdAt = Date.parse(task?.createdAt); const startedAt = task?.startedAt == null ? createdAt : Date.parse(task.startedAt); const stoppedAt = Date.parse(task?.stoppedAt);
    return TASK_INSTANCE_ARN.test(task?.taskArn || "") && task.taskDefinitionArn === taskDefinitionArn && task.startedBy === matchingDeployments[0].id
      && task.desiredStatus === "STOPPED" && task.lastStatus === "STOPPED" && typeof task.stopCode === "string"
      && typeof task.stoppedReason === "string" && Array.isArray(task.containerReasons) && task.containerReasons.every((reason) => typeof reason === "string")
      && Number.isFinite(createdAt) && Number.isFinite(startedAt) && Number.isFinite(stoppedAt) && createdAt >= Date.parse(matchingDeployments[0].createdAt)
      && startedAt >= createdAt && stoppedAt >= startedAt;
  }) : [];
  const sourceFailureReasons = exactFailures(currentArn, exactFailedDeployments(currentArn)).flatMap((task) => [task.stoppedReason, ...task.containerReasons]);
  const historicalLegacyFailureProof = currentFailedRevision?.requiresLiveFailureReconciliation === true ? legacyFailedDeploymentProof(service, stoppedTaskFailures, service.taskDefinition) : null;
  const legacyFailureLive = !currentFailedRevision?.requiresLiveFailureReconciliation || historicalLegacyFailureProof !== null;
  const unavailableKnownFailure = unavailable && currentFailedRevision && legacyFailureLive;
  const unavailableMissingImage = unavailable && currentImageExists === false && sourceFailureReasons.some((reason) => /CannotPullContainerError/i.test(reason) && /not found|does not exist/i.test(reason) && reason.includes(imageMatch[1]));
  const missingImageFailureProof = unavailableMissingImage && service.taskDefinition === currentArn ? legacyFailedDeploymentProof(service, stoppedTaskFailures, currentArn) : null;
  if (unavailableMissingImage && service.taskDefinition === currentArn && !missingImageFailureProof) throw new Error("Missing-image recovery lacks an exact mutation-bound deployment failure proof.");
  const reconciledInterruption = currentInterruption?.result.classification === INTERRUPTED_RECOVERY_STATE.SUCCEEDED
    || unavailable && interruptionReconciliations.some(({ result }) => [INTERRUPTED_RECOVERY_STATE.NO_EFFECT, INTERRUPTED_RECOVERY_STATE.RESUMABLE].includes(result.classification));
  const stalledRollback = authorization?.rollbackProof?.classification === ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE;
  if (!reconciledInterruption && !stalledRollback && !unavailableKnownFailure && !unavailableMissingImage) throw new Error("Backend degradation is not authenticated as the current digest's missing-image pull failure or an unavailable approved terminal recovery failure.");
  if (replacementImage?.exists !== true || replacementImage?.immutable !== true || replacementImage?.signatureValid !== true
    || replacementImage?.attestationValid !== true || replacementImage?.provenanceValid !== true || replacementImage?.criticalFindings !== 0
    || replacementImage?.repository !== BACKEND_HEALTH_RECOVERY.repository || !SHA256.test(replacementImage?.digest || "")) throw new Error("Replacement image does not satisfy the recovery evidence contract.");
  assertLegacyBackendRecoveryAuthorization(authorization, { sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: replacementImage.digest, imageAuthorization, imageValidation, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence?.envelopeSha256 || null, failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence?.referenceSha256 || null, recoveryHistory, knownFailedRevisions, interruptedRecoveries, githubContext, executionActor });
  const checked = assertLegacyBackendRecoveryCandidate({ currentTaskDefinition, candidate: input.candidate, recoveryImageDigest: replacementImage.digest, imageReleaseSha: authorization.imageReleaseSha, artifactSigningBindings });
  const reconciledFailedRevisions = interruptionReconciliations.filter(({ result }) => result.classification === INTERRUPTED_RECOVERY_STATE.FAILED).map(({ interruption }) => interruption);
  return Object.freeze({ ...checked, currentTaskDefinitionArn: currentArn, observedServiceTaskDefinitionArn: service.taskDefinition, currentImageDigest: imageMatch[1], recoveryImageDigest: replacementImage.digest, desiredCount: service.desiredCount, networkConfigurationSha256: canonicalSha256(service.networkConfiguration), loadBalancersSha256: canonicalSha256(service.loadBalancers), rollbackProof: authorization.rollbackProof, recoveryHistory, knownFailedRevisions: [...knownFailedRevisions, ...reconciledFailedRevisions], interruptedRecoveries, interruptionReconciliations, currentInterruption, legacyFailureProof: historicalLegacyFailureProof, legacyFailureProofSha256: historicalLegacyFailureProof ? canonicalSha256(historicalLegacyFailureProof) : null, missingImageFailureProof, missingImageFailureProofSha256: missingImageFailureProof ? canonicalSha256(missingImageFailureProof) : null });
}

export async function runLegacyBackendHealthRecovery(input, adapters = {}) {
  for (const name of ["census", "verifyRuntimeClosure", "register", "describe", "readService", "updateService", "waitStable", "readRunningTasks", "verifyHealth", "record"]) if (typeof adapters[name] !== "function") throw new Error(`Recovery adapter ${name} is required.`);
  const recoveryHistory = input.authenticatedFailedRecoveryEvidence?.recoveryHistory || [];
  const authenticatedInterruptions = input.authenticatedFailedRecoveryEvidence?.interruptedRecoveries || [];
  const interruptions = openInterruptedRecoveryHistory(recoveryHistory);
  if (interruptions.length && typeof adapters.readInterruptedRecoveryState !== "function") throw new Error("Interrupted recovery live reconciliation adapter is required.");
  const candidateIdentity = assertLegacyBackendRecoveryCandidate({ currentTaskDefinition: input.currentTaskDefinition, candidate: input.candidate, recoveryImageDigest: input.replacementImage?.digest, imageReleaseSha: input.authorization?.imageReleaseSha, artifactSigningBindings: input.artifactSigningBindings });
  const lineageEligible = { currentTaskDefinitionArn: input.authorization?.currentTaskDefinitionArn, fingerprint: candidateIdentity.fingerprint, rollbackProof: input.authorization?.rollbackProof, recoveryHistory, knownFailedRevisions: input.authenticatedFailedRecoveryEvidence?.knownFailedRevisions || [], interruptedRecoveries: authenticatedInterruptions };
  assertLegacyBackendRecoveryAuthorization(input.authorization, { sourceSha: input.sourceSha, currentTaskDefinitionArn: input.authorization?.currentTaskDefinitionArn, recoveryImageDigest: input.replacementImage?.digest, imageAuthorization: input.imageAuthorization, imageValidation: input.imageValidation, environmentApproval: input.environmentApproval, artifactSigningBindingSha256: input.artifactSigningBindingSha256, runtimeConsumabilitySha256: input.runtimeConsumabilitySha256, failedRecoveryEvidenceSha256: input.authenticatedFailedRecoveryEvidence?.envelopeSha256 || null, failedRecoveryEvidenceReferenceSha256: input.authenticatedFailedRecoveryEvidence?.referenceSha256 || null, recoveryHistory, knownFailedRevisions: lineageEligible.knownFailedRevisions, interruptedRecoveries: authenticatedInterruptions, githubContext: input.githubContext, executionActor: input.executionActor });
  const revisions = await adapters.census();
  reconcileAuthenticatedRevisionLineage(revisions, lineageEligible);
  const reconcileInterruptions = async (allowedRevision = null) => Promise.all(interruptions.map(async (interruption) => {
    const snapshot = await adapters.readInterruptedRecoveryState(interruption);
    const lineage = reconcileAuthenticatedRevisionLineage(snapshot.census, lineageEligible, { allowedRevision });
    return { interruption, result: classifyInterruptedRecoveryState(interruption, snapshot, { lineage }) };
  }));
  const interruptionReconciliations = await reconcileInterruptions();
  const eligible = assertLegacyBackendRecoveryEligibility({ ...input, interruptionReconciliations });
  const initialCensus = classifyRevisionCensus(revisions, eligible);
  const assertFreshInterruptions = async (allowedRevision = null) => {
    if (!interruptions.length) return;
    const fresh = await reconcileInterruptions(allowedRevision);
    if (fresh.some(({ result }, index) => result.proofSha256 !== interruptionReconciliations[index].result.proofSha256)) throw new Error("Interrupted recovery live state changed before mutation.");
  };
  const assertFreshLegacyFailure = async (expectedCensusSha256, allowedRevision = null) => {
    const expectedProof = eligible.legacyFailureProof || eligible.missingImageFailureProof;
    const expectedProofSha256 = eligible.legacyFailureProofSha256 || eligible.missingImageFailureProofSha256;
    if (!expectedProof) return null;
    if (typeof adapters.readLegacyFailureState !== "function") throw new Error("Legacy failed-revision mutation-bound reconciliation adapter is required.");
    const snapshot = await adapters.readLegacyFailureState();
    const lineage = classifyRevisionCensus(snapshot?.census, eligible);
    if (lineage.identitySha256 !== expectedCensusSha256) throw new Error("Legacy backend revision census changed at the failed-deployment mutation boundary.");
    const freshProof = legacyFailedDeploymentProof(snapshot?.service, snapshot?.stoppedTaskFailures, eligible.observedServiceTaskDefinitionArn);
    if (!freshProof || canonicalSha256(freshProof) !== expectedProofSha256) throw new Error("Legacy failed backend deployment proof changed before mutation.");
    if (allowedRevision && !lineage.matches.some(({ taskDefinitionArn, fingerprint }) => taskDefinitionArn === allowedRevision.taskDefinitionArn && fingerprint === allowedRevision.taskDefinitionFingerprint)) throw new Error("Recovery registration is absent from the authenticated mutation-bound census.");
    return snapshot.service;
  };
  if (eligible.currentInterruption?.result.classification === INTERRUPTED_RECOVERY_STATE.SUCCEEDED) {
    const result = Object.freeze({ mode: BACKEND_HEALTH_RECOVERY.kind, targetArn: eligible.currentInterruption.result.targetArn, recoveryImageDigest: eligible.recoveryImageDigest, registrations: 0, updates: 0, backendHealthy: true, health: eligible.currentInterruption.result.health, rotationRequired: true, stageBApplied: false, frontendDeployed: false, reconciledInterruption: true });
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RECOVERY_COMPLETE, ...result,
      initialRevisionCensusSha256: eligible.currentInterruption.interruption.initialRevisionCensusSha256,
      expectedRevisionCensusSha256: eligible.currentInterruption.interruption.expectedRevisionCensusSha256 });
    return result;
  }
  if (eligible.rollbackProof) {
    if (typeof adapters.readRollbackViability !== "function") throw new Error("Recovery rollback viability adapter is required.");
    assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
  }
  if (eligible.fingerprint !== candidateIdentity.fingerprint) throw new Error("Recovery candidate identity changed during eligibility validation.");
  const initialRuntimeClosure = await adapters.verifyRuntimeClosure(eligible.candidate);
  const now = () => typeof adapters.now === "function" ? adapters.now() : adapters.now ?? Date.now();
  assertFreshRuntimeConsumabilityVerification(initialRuntimeClosure, { evidenceSha256: input.runtimeConsumabilitySha256, now: now() });
  const matches = initialCensus.matches;
  if (initialCensus.knownFailedRevisions.length) await adapters.record({ knownFailedRevisions: initialCensus.knownFailedRevisions });
  const failedRevisionArns = new Set(initialCensus.knownFailedRevisions.map(({ taskDefinitionArn }) => taskDefinitionArn));
  let targetArn = matches[0]?.taskDefinitionArn;
  if (targetArn && !TASK_ARN.test(targetArn)) throw new Error("Recovery census returned an invalid legacy backend revision.");
  if (eligible.observedServiceTaskDefinitionArn !== eligible.currentTaskDefinitionArn && !failedRevisionArns.has(eligible.observedServiceTaskDefinitionArn)
    && eligible.observedServiceTaskDefinitionArn !== targetArn) {
    throw new Error("Backend service current task definition is stale and does not match an authenticated completed recovery.");
  }
  let registrations = 0;
  if (!targetArn) {
    if (eligible.rollbackProof) assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
    const freshRuntimeClosure = await adapters.verifyRuntimeClosure(eligible.candidate);
    if (freshRuntimeClosure?.evidenceSha256 !== initialRuntimeClosure.evidenceSha256) throw new Error("Recovery candidate runtime dependency closure changed before registration.");
    if (!eligible.legacyFailureProof && !eligible.missingImageFailureProof && classifyRevisionCensus(await adapters.census(), eligible).identitySha256 !== initialCensus.identitySha256) throw new Error("Legacy backend revision census changed before recovery registration.");
    await assertFreshInterruptions();
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED, targetArn: null, registrations: 0, updates: 0, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: null });
    assertFreshRuntimeConsumabilityVerification(freshRuntimeClosure, { evidenceSha256: initialRuntimeClosure.evidenceSha256, now: now() });
    await assertFreshLegacyFailure(initialCensus.identitySha256);
    try {
      const result = await adapters.register(eligible.candidate);
      targetArn = result?.taskDefinition?.taskDefinitionArn || result?.taskDefinitionArn;
      registrations = 1;
    } catch (error) {
      const reconciled = classifyRevisionCensus(await adapters.census(), eligible).matches;
      if (reconciled.length !== 1) throw error;
      targetArn = reconciled[0].taskDefinitionArn;
      registrations = 1;
    }
  }
  if (!TASK_ARN.test(targetArn || "")) throw new Error("Recovery registration did not resolve one exact legacy backend revision.");
  if (failedRevisionArns.has(targetArn)) throw new Error("Recovery registration reused a failed recovery task definition.");
  const target = await adapters.describe(targetArn);
  if (taskDefinitionFingerprint(target, target?.tags || []) !== eligible.fingerprint) throw new Error("Recovery target readback does not match the exact authorized candidate.");
  const expectedCensusSha256 = expectedRevisionCensusSha256(initialCensus, targetArn, eligible.fingerprint, registrations === 1);
  if (registrations) await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY, targetArn, registrations, updates: 0, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
  if (classifyRevisionCensus(await adapters.census(), eligible).identitySha256 !== expectedCensusSha256) throw new Error("Legacy backend revision census changed after recovery registration.");
  let live = await adapters.readService();
  let updates = 0;
  if (live.taskDefinition !== targetArn) {
    if (live.taskDefinition !== eligible.observedServiceTaskDefinitionArn || (eligible.observedServiceTaskDefinitionArn !== eligible.currentTaskDefinitionArn && !failedRevisionArns.has(eligible.observedServiceTaskDefinitionArn))
      || live.desiredCount !== eligible.desiredCount || canonicalSha256(live.networkConfiguration) !== eligible.networkConfigurationSha256
      || canonicalSha256(live.loadBalancers) !== eligible.loadBalancersSha256) throw new Error("Backend service changed concurrently before recovery update.");
    if (eligible.rollbackProof) assertFreshRollbackEquivalence(eligible.rollbackProof, await adapters.readRollbackViability());
    const freshRuntimeClosure = await adapters.verifyRuntimeClosure(eligible.candidate);
    if (freshRuntimeClosure?.status !== "PASS" || freshRuntimeClosure.evidenceSha256 !== initialRuntimeClosure.evidenceSha256) throw new Error("Recovery candidate runtime dependency closure changed before service update.");
    if (!eligible.legacyFailureProof && !eligible.missingImageFailureProof && classifyRevisionCensus(await adapters.census(), eligible).identitySha256 !== expectedCensusSha256) throw new Error("Legacy backend revision census changed before recovery service update.");
    await assertFreshInterruptions(registrations ? { taskDefinitionArn: targetArn, taskDefinitionFingerprint: eligible.fingerprint } : null);
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, targetArn, registrations, updates: 0, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    assertFreshRuntimeConsumabilityVerification(freshRuntimeClosure, { evidenceSha256: initialRuntimeClosure.evidenceSha256, now: now() });
    live = await assertFreshLegacyFailure(expectedCensusSha256, registrations ? { taskDefinitionArn: targetArn, taskDefinitionFingerprint: eligible.fingerprint } : null) || await adapters.readService();
    if (live.taskDefinition !== eligible.observedServiceTaskDefinitionArn || live.desiredCount !== eligible.desiredCount
      || canonicalSha256(live.networkConfiguration) !== eligible.networkConfigurationSha256 || canonicalSha256(live.loadBalancers) !== eligible.loadBalancersSha256) throw new Error("Backend service changed concurrently at the recovery update boundary.");
    try { await adapters.updateService(targetArn); updates = 1; }
    catch (error) {
      live = await adapters.readService();
      if (live.taskDefinition !== targetArn) {
        await adapters.record({ status: registrations
          ? BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY
          : BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED, targetArn, registrations, updates: 0, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
        throw error;
      }
      updates = 1;
    }
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
  }
  try { await adapters.waitStable(targetArn); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw error;
  }
  try { live = await adapters.readService(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw error;
  }
  if (live.taskDefinition !== targetArn || live.desiredCount !== eligible.desiredCount || live.runningCount !== eligible.desiredCount || live.pendingCount !== 0) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw new Error("Backend service did not converge on the recovery revision.");
  }
  let tasks;
  try { tasks = await adapters.readRunningTasks(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw error;
  }
  if (!Array.isArray(tasks) || tasks.length !== eligible.desiredCount || tasks.some((task) => task.taskDefinitionArn !== targetArn || task.imageDigest !== eligible.recoveryImageDigest)) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw new Error("Running backend tasks do not match the approved recovery digest.");
  }
  if (tasks.some((task) => task.healthStatus !== "HEALTHY")) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw new Error("Every running backend task must report HEALTHY before recovery completion.");
  }
  let health;
  try { health = await adapters.verifyHealth(); }
  catch (error) {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw error;
  }
  if (health?.healthy !== true || health?.success !== true || health?.status !== "ready") {
    await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED, targetArn, registrations, updates, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
    throw new Error("Backend health did not recover after the governed image replacement.");
  }
  const result = Object.freeze({ mode: BACKEND_HEALTH_RECOVERY.kind, targetArn, recoveryImageDigest: eligible.recoveryImageDigest, registrations, updates, backendHealthy: true, health, rotationRequired: true, stageBApplied: false, frontendDeployed: false });
  await adapters.record({ status: BACKEND_HEALTH_RECOVERY_STATUS.RECOVERY_COMPLETE, ...result, initialRevisionCensusSha256: initialCensus.identitySha256, expectedRevisionCensusSha256: expectedCensusSha256 });
  return result;
}
