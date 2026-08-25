import crypto from "node:crypto";
import { BACKEND_HEALTH_RECOVERY, BACKEND_HEALTH_RECOVERY_STATUS, assertLegacyBackendRecoveryEvidence, recoveryHistoryLineageSha256 } from "./production-backend-health-recovery-contract.mjs";
import { assertRuntimeConsumabilityEnvelopeSignature } from "./production-ecs-runtime-consumability.mjs";
import { assertProductionEnvironmentApprovalIdentity, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

const KIND = "AUTHENTICATED_BACKEND_FAILED_RECOVERY_EVIDENCE";
const REPOSITORY = "T-ej2003/genuine-scan-main";
export const PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE = "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE";
const LEGACY_WORKFLOW_PATH = ".github/workflows/release-gate.yml";
const LEGACY_ARTIFACT_NAME = "backend-health-recovery-evidence";
const NOT_PART_OF_SCHEMA = "NOT_PART_OF_SCHEMA";
const LEGACY_APPROVAL_PROOF = "AUTHENTICATED_GITHUB_PRODUCTION_ENVIRONMENT_APPROVAL_HISTORY";
const HEX = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{40}$/;
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:[1-9][0-9]*$/;
const RUN_ID = /^[1-9][0-9]*$/;
const MAX_HISTORY_RECORDS = 32;
const MAX_HISTORY_BYTES = 8 * 1024 * 1024;
const TERMINAL_FAILURES = new Set([
  BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_STABILIZATION_FAILED,
  BACKEND_HEALTH_RECOVERY_STATUS.RUNNING_DIGEST_VERIFICATION_FAILED,
  BACKEND_HEALTH_RECOVERY_STATUS.HEALTH_VERIFICATION_FAILED,
]);
const INTERRUPTED_MUTATIONS = new Set([
  BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTRATION_ATTEMPTED,
  BACKEND_HEALTH_RECOVERY_STATUS.TASK_DEFINITION_REGISTERED_ONLY,
  BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_ATTEMPTED,
  BACKEND_HEALTH_RECOVERY_STATUS.SERVICE_UPDATE_CONFIRMED,
]);
const TERMINAL_MUTATION_COUNTS = new Set(["0/0", "0/1", "1/0", "1/1"]);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const exactFields = (value, fields) => value && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
const LEGACY_RECORD_FIELDS = ["legacyIdentity", "recoveryEvidence", "repository", "workflowRunId"];
const LEGACY_IDENTITY_FIELDS = ["schemaVersion", "kind", "evidenceContract", "repository", "workflowRunId", "workflowRunAttempt", "workflowPath", "workflowEvent", "workflowHeadSha", "workflowHeadBranch", "workflowConclusion", "workflowCreatedAt", "workflowDefinitionSha256", "productionJobId", "productionJobName", "productionJobConclusion", "productionJobProofSha256", "productionEnvironmentId", "productionDeploymentId", "productionDeploymentProofSha256", "productionApprovalProofSha256", "productionApproverId", "productionApprover", "artifactId", "artifactName", "artifactCreatedAt", "artifactArchiveSizeInBytes", "artifactArchiveDigest", "evidenceByteSize", "evidenceByteSha256", "environmentApprovalEvidence", "runtimeConsumabilityEvidence", "candidateFingerprintEvidence", "sourceSha", "service", "releaseMode", "taskDefinitionArn", "taskDefinitionFingerprint", "recoveryImageDigest", "imageReleaseSha"];
const LEGACY_EVIDENCE_FIELDS = ["account", "artifactSigningBindingSha256", "artifactSigningFailure", "artifactSigningVerification", "authorizationFileSha256", "authorizationSha256", "currentTaskDefinitionArn", "environmentApprovalFileSha256", "environmentApprovalSha256", "evidenceSha256", "generatedAt", "imageAuthorizationFileSha256", "imageAuthorizationSha256", "imageReleaseSha", "kind", "knownFailedRevisions", "recoveryImageDigest", "region", "registrations", "rollbackProofSha256", "schemaVersion", "sourceSha", "status", "targetArn", "updates"];

function artifact(bytes, label) {
  if (!Buffer.isBuffer(bytes) || !bytes.length) throw new Error(`${label} bytes are required.`);
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error(`${label} is malformed.`); }
  return { bytesBase64: bytes.toString("base64"), byteSha256: hash(bytes), value };
}

function readArtifact(component, label) {
  if (!component || Object.keys(component).sort().join(",") !== "byteSha256,bytesBase64" || !HEX.test(component.byteSha256 || "")
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(component.bytesBase64 || "")) throw new Error(`${label} envelope is malformed.`);
  const bytes = Buffer.from(component.bytesBase64, "base64");
  if (!bytes.length || hash(bytes) !== component.byteSha256 || bytes.toString("base64") !== component.bytesBase64) throw new Error(`${label} byte hash does not match.`);
  return artifact(bytes, label);
}

function validateLegacyRecord(record) {
  if (!exactFields(record, LEGACY_RECORD_FIELDS) || record.repository !== REPOSITORY || !RUN_ID.test(record.workflowRunId || "")) throw new Error("Legacy historical recovery record schema is invalid.");
  const recovery = readArtifact(record.recoveryEvidence, "Legacy historical recovery evidence");
  const evidence = recovery.value;
  const identity = record.legacyIdentity;
  if (!exactFields(evidence, LEGACY_EVIDENCE_FIELDS) || !exactFields(identity, LEGACY_IDENTITY_FIELDS)
    || identity.schemaVersion !== 1 || identity.kind !== "BACKEND_FAILED_RECOVERY_LEGACY_IDENTITY" || identity.evidenceContract !== PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE
    || identity.repository !== REPOSITORY || identity.workflowRunId !== record.workflowRunId || identity.workflowRunAttempt !== "1"
    || identity.workflowPath !== LEGACY_WORKFLOW_PATH || identity.workflowEvent !== "workflow_dispatch" || identity.workflowHeadSha !== evidence.sourceSha || identity.workflowHeadBranch !== "main"
    || identity.workflowConclusion !== "failure" || !Number.isFinite(Date.parse(identity.workflowCreatedAt)) || !HEX.test(identity.workflowDefinitionSha256 || "")
    || !Number.isSafeInteger(identity.productionJobId) || identity.productionJobId < 1 || identity.productionJobName !== "Deploy production ECS" || identity.productionJobConclusion !== "failure" || !HEX.test(identity.productionJobProofSha256 || "")
    || !Number.isSafeInteger(identity.productionEnvironmentId) || identity.productionEnvironmentId < 1 || !Number.isSafeInteger(identity.productionDeploymentId) || identity.productionDeploymentId < 1
    || !HEX.test(identity.productionDeploymentProofSha256 || "") || !HEX.test(identity.productionApprovalProofSha256 || "") || !Number.isSafeInteger(identity.productionApproverId) || identity.productionApproverId < 1 || typeof identity.productionApprover !== "string" || !identity.productionApprover
    || !Number.isSafeInteger(identity.artifactId) || identity.artifactId < 1 || identity.artifactName !== LEGACY_ARTIFACT_NAME
    || !Number.isSafeInteger(identity.artifactArchiveSizeInBytes) || identity.artifactArchiveSizeInBytes < 1 || identity.artifactArchiveDigest !== `sha256:${identity.artifactArchiveDigest?.slice(7)}` || !HEX.test(identity.artifactArchiveDigest?.slice(7) || "")
    || !Number.isFinite(Date.parse(identity.artifactCreatedAt)) || identity.evidenceByteSize !== Buffer.from(recovery.bytesBase64, "base64").length || identity.evidenceByteSha256 !== recovery.byteSha256 || identity.environmentApprovalEvidence !== LEGACY_APPROVAL_PROOF
    || identity.runtimeConsumabilityEvidence !== NOT_PART_OF_SCHEMA || identity.candidateFingerprintEvidence !== NOT_PART_OF_SCHEMA
    || identity.sourceSha !== evidence.sourceSha || !SHA.test(identity.sourceSha || "") || identity.service !== BACKEND_HEALTH_RECOVERY.service
    || identity.releaseMode !== BACKEND_HEALTH_RECOVERY.kind || identity.taskDefinitionArn !== evidence.targetArn || !TASK_ARN.test(identity.taskDefinitionArn || "")
    || !HEX.test(identity.taskDefinitionFingerprint || "") || identity.recoveryImageDigest !== evidence.recoveryImageDigest
    || identity.imageReleaseSha !== evidence.imageReleaseSha || !SHA.test(identity.imageReleaseSha || "")) throw new Error("Legacy historical recovery identity is malformed or unbound.");
  assertLegacyBackendRecoveryEvidence(evidence, {
    sourceSha: evidence.sourceSha, currentTaskDefinitionArn: evidence.currentTaskDefinitionArn, recoveryImageDigest: evidence.recoveryImageDigest,
    imageReleaseSha: evidence.imageReleaseSha, authorizationFileSha256: evidence.authorizationFileSha256, authorizationSha256: evidence.authorizationSha256,
    environmentApprovalFileSha256: evidence.environmentApprovalFileSha256, environmentApprovalSha256: evidence.environmentApprovalSha256,
    imageAuthorizationFileSha256: evidence.imageAuthorizationFileSha256, imageAuthorizationSha256: evidence.imageAuthorizationSha256,
    artifactSigningBindingSha256: evidence.artifactSigningBindingSha256, runtimeConsumabilitySha256: null, rollbackProofSha256: evidence.rollbackProofSha256,
  });
  if (!TERMINAL_FAILURES.has(evidence.status) || evidence.registrations !== 1 || evidence.updates !== 1 || evidence.backendHealthy === true)
    throw new Error("Legacy historical recovery evidence is not an authenticated terminal failure.");
  return Object.freeze({
    repository: REPOSITORY, workflowRunId: identity.workflowRunId, workflowCreatedAt: identity.workflowCreatedAt,
    sourceSha: evidence.sourceSha, service: BACKEND_HEALTH_RECOVERY.service, releaseMode: BACKEND_HEALTH_RECOVERY.kind,
    taskDefinitionArn: evidence.targetArn, candidateFingerprint: identity.taskDefinitionFingerprint, taskDefinitionFingerprint: identity.taskDefinitionFingerprint,
    recoveryImageDigest: evidence.recoveryImageDigest, imageReleaseSha: evidence.imageReleaseSha, artifactSigningBindingSha256: evidence.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: null, predecessorHistoryReferenceSha256: null, predecessorHistoryLineageSha256: null,
    status: evidence.status, classification: "TERMINAL_FAILURE", failureClassification: evidence.status,
    currentTaskDefinitionArn: evidence.currentTaskDefinitionArn, initialRevisionCensusSha256: null, expectedRevisionCensusSha256: null,
    registrations: evidence.registrations, updates: evidence.updates, evidenceFileSha256: recovery.byteSha256,
    evidenceContract: PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE, requiresLiveFailureReconciliation: true,
  });
}

function validateRecord(record, verifyRuntime) {
  if (exactFields(record, LEGACY_RECORD_FIELDS)) return validateLegacyRecord(record);
  if (!record || Object.keys(record).sort().join(",") !== "environmentApproval,recoveryEvidence,repository,runtimeConsumability,workflowRunId") throw new Error("Historical recovery evidence record schema is invalid.");
  const recovery = readArtifact(record.recoveryEvidence, "Historical recovery evidence");
  const environment = readArtifact(record.environmentApproval, "Historical environment approval evidence");
  const runtime = readArtifact(record.runtimeConsumability, "Historical runtime consumability evidence");
  const evidence = recovery.value;
  assertProductionEnvironmentApprovalIdentity(environment.value, { sourceSha: evidence.sourceSha, repository: REPOSITORY });
  assertRuntimeConsumabilityEnvelopeSignature(runtime.value, { verify: verifyRuntime });
  assertLegacyBackendRecoveryEvidence(evidence, {
    sourceSha: evidence.sourceSha,
    currentTaskDefinitionArn: evidence.currentTaskDefinitionArn,
    recoveryImageDigest: evidence.recoveryImageDigest,
    imageReleaseSha: evidence.imageReleaseSha,
    authorizationFileSha256: evidence.authorizationFileSha256,
    authorizationSha256: evidence.authorizationSha256,
    environmentApprovalFileSha256: evidence.environmentApprovalFileSha256,
    environmentApprovalSha256: evidence.environmentApprovalSha256,
    imageAuthorizationFileSha256: evidence.imageAuthorizationFileSha256,
    imageAuthorizationSha256: evidence.imageAuthorizationSha256,
    artifactSigningBindingSha256: evidence.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: evidence.runtimeConsumabilitySha256,
    rollbackProofSha256: evidence.rollbackProofSha256,
    failedRecoveryEvidenceReferenceSha256: evidence.failedRecoveryEvidenceReferenceSha256 || null,
  });
  const terminalFailure = TERMINAL_FAILURES.has(evidence.status);
  const interruptedMutation = INTERRUPTED_MUTATIONS.has(evidence.status);
  if (record.repository !== environment.value.repository || record.workflowRunId !== environment.value.workflowRunId
    || (!terminalFailure && !interruptedMutation) || (terminalFailure && !TERMINAL_MUTATION_COUNTS.has(`${evidence.registrations}/${evidence.updates}`)) || evidence.backendHealthy === true
    || evidence.environmentApprovalFileSha256 !== environment.byteSha256 || evidence.environmentApprovalSha256 !== environment.value.evidenceSha256
    || evidence.runtimeConsumabilitySha256 !== runtime.value?.evidence?.evidenceSha256
    || runtime.value?.evidence?.sourceSha !== evidence.sourceSha || !HEX.test(runtime.value?.evidence?.candidateFingerprint || "")
    || (interruptedMutation && (![6, 7].includes(evidence.schemaVersion) || evidence.candidateFingerprint !== runtime.value.evidence.candidateFingerprint
      || !HEX.test(evidence.initialRevisionCensusSha256 || "") || (evidence.targetArn && !HEX.test(evidence.expectedRevisionCensusSha256 || ""))))) {
    throw new Error("Historical recovery evidence is not an authenticated terminal failure or crash-reconcilable interruption.");
  }
  return Object.freeze({
    repository: environment.value.repository,
    workflowRunId: environment.value.workflowRunId,
    sourceSha: evidence.sourceSha,
    service: BACKEND_HEALTH_RECOVERY.service,
    releaseMode: BACKEND_HEALTH_RECOVERY.kind,
    taskDefinitionArn: evidence.targetArn,
    candidateFingerprint: runtime.value.evidence.candidateFingerprint,
    taskDefinitionFingerprint: runtime.value.evidence.candidateFingerprint,
    recoveryImageDigest: evidence.recoveryImageDigest,
    imageReleaseSha: evidence.imageReleaseSha,
    artifactSigningBindingSha256: evidence.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: evidence.runtimeConsumabilitySha256,
    predecessorHistoryReferenceSha256: evidence.failedRecoveryEvidenceReferenceSha256 || null,
    predecessorHistoryLineageSha256: evidence.predecessorHistoryLineageSha256 || null,
    status: evidence.status,
    classification: terminalFailure ? "TERMINAL_FAILURE" : "INTERRUPTED_MUTATION",
    failureClassification: terminalFailure ? evidence.status : null,
    currentTaskDefinitionArn: evidence.currentTaskDefinitionArn,
    initialRevisionCensusSha256: evidence.initialRevisionCensusSha256 || null,
    expectedRevisionCensusSha256: evidence.expectedRevisionCensusSha256 || null,
    registrations: evidence.registrations,
    updates: evidence.updates,
    evidenceFileSha256: recovery.byteSha256,
  });
}

function assertOrderedHistory(summaries) {
  for (let index = 0; index < summaries.length; index += 1) {
    const record = summaries[index];
    const previous = summaries[index - 1];
    const unreferencedLegacyContinuation = index > 0 && record.evidenceContract === PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE
      && previous?.evidenceContract === PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE && record.predecessorHistoryReferenceSha256 === null
      && Date.parse(record.workflowCreatedAt) > Date.parse(previous.workflowCreatedAt);
    if (index === 0 ? record.predecessorHistoryReferenceSha256 !== null : !unreferencedLegacyContinuation && !HEX.test(record.predecessorHistoryReferenceSha256 || "")) throw new Error("Historical recovery evidence predecessor reference chain is missing or reordered.");
    if (previous?.expectedRevisionCensusSha256 && record.initialRevisionCensusSha256 !== previous.expectedRevisionCensusSha256) throw new Error("Historical recovery evidence census lineage is missing, reordered, or forked.");
  }
}

export function createAuthenticatedFailedRecoveryEvidence({ records, verifyRuntime, sign, signedAt = new Date().toISOString() } = {}) {
  if (!Array.isArray(records) || !records.length || records.length > MAX_HISTORY_RECORDS || typeof verifyRuntime !== "function" || typeof sign !== "function") throw new Error("Historical failed recovery evidence inputs are incomplete or exceed the bounded history limit.");
  const encoded = records.map((record) => {
    const recoveryEvidence = artifact(record.recoveryEvidenceBytes, "Historical recovery evidence");
    if (record.legacyIdentity) return { repository: REPOSITORY, workflowRunId: record.legacyIdentity.workflowRunId,
      recoveryEvidence: { bytesBase64: recoveryEvidence.bytesBase64, byteSha256: recoveryEvidence.byteSha256 }, legacyIdentity: structuredClone(record.legacyIdentity) };
    const environmentApproval = artifact(record.environmentApprovalBytes, "Historical environment approval evidence");
    const runtimeConsumability = artifact(record.runtimeConsumabilityBytes, "Historical runtime consumability evidence");
    return { repository: environmentApproval.value.repository, workflowRunId: environmentApproval.value.workflowRunId,
      recoveryEvidence: { bytesBase64: recoveryEvidence.bytesBase64, byteSha256: recoveryEvidence.byteSha256 },
      environmentApproval: { bytesBase64: environmentApproval.bytesBase64, byteSha256: environmentApproval.byteSha256 },
      runtimeConsumability: { bytesBase64: runtimeConsumability.bytesBase64, byteSha256: runtimeConsumability.byteSha256 } };
  });
  const summaries = encoded.map((record) => validateRecord(record, verifyRuntime));
  assertOrderedHistory(summaries);
  recoveryHistoryLineageSha256(summaries);
  const identities = summaries.map(({ taskDefinitionArn, taskDefinitionFingerprint }) => taskDefinitionArn || `pending:${taskDefinitionFingerprint}`);
  if (new Set(identities).size !== identities.length
    || new Set(summaries.map(({ workflowRunId }) => workflowRunId)).size !== summaries.length) throw new Error("Historical failed recovery evidence is duplicated or conflicting.");
  const body = { schemaVersion: 1, kind: KIND, repository: REPOSITORY, records: encoded, signedAt, keyArn: STAGE_B.approvalKmsKeyArn, signingAlgorithm: STAGE_B_APPROVAL_ALGORITHM };
  const signedPayloadSha256 = canonicalSha256(body);
  const signatureBase64 = sign({ digest: Buffer.from(signedPayloadSha256, "hex"), keyArn: body.keyArn, signingAlgorithm: body.signingAlgorithm });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64 || "")) throw new Error("Historical failed recovery evidence signature is invalid.");
  const envelope = { ...body, signedPayloadSha256, signatureBase64 };
  const result = { ...envelope, envelopeSha256: canonicalSha256(envelope) };
  if (Buffer.byteLength(`${JSON.stringify(result, null, 2)}\n`) > MAX_HISTORY_BYTES) throw new Error("Historical failed recovery evidence exceeds the bounded byte limit.");
  return Object.freeze(result);
}

export function assertAuthenticatedFailedRecoveryEvidence(envelope, { verify, now = Date.now() } = {}) {
  const { envelopeSha256, ...body } = envelope || {};
  const unsigned = { schemaVersion: envelope?.schemaVersion, kind: envelope?.kind, repository: envelope?.repository, records: envelope?.records, signedAt: envelope?.signedAt, keyArn: envelope?.keyArn, signingAlgorithm: envelope?.signingAlgorithm };
  const nowMs = Number(now); const signedAtMs = Date.parse(envelope?.signedAt);
  if (envelope?.schemaVersion !== 1 || envelope.kind !== KIND || envelope.repository !== REPOSITORY || !Array.isArray(envelope.records) || !envelope.records.length || envelope.records.length > MAX_HISTORY_RECORDS
    || Buffer.byteLength(JSON.stringify(envelope)) > MAX_HISTORY_BYTES
    || envelope.keyArn !== STAGE_B.approvalKmsKeyArn || envelope.signingAlgorithm !== STAGE_B_APPROVAL_ALGORITHM
    || !HEX.test(envelope.signedPayloadSha256 || "") || canonicalSha256(unsigned) !== envelope.signedPayloadSha256
    || !HEX.test(envelopeSha256 || "") || canonicalSha256(body) !== envelopeSha256
    || !Number.isFinite(nowMs) || !Number.isFinite(signedAtMs) || signedAtMs > nowMs + 5 * 60 * 1000
    || typeof verify !== "function" || verify({ digest: Buffer.from(envelope.signedPayloadSha256, "hex"), signature: Buffer.from(envelope.signatureBase64 || "", "base64"), keyArn: envelope.keyArn, signingAlgorithm: envelope.signingAlgorithm }) !== true) {
    throw new Error("Historical failed recovery evidence signature is invalid, stale, or tampered.");
  }
  const summaries = envelope.records.map((record) => validateRecord(record, verify));
  assertOrderedHistory(summaries);
  const lineageSha256 = recoveryHistoryLineageSha256(summaries);
  const identities = summaries.map(({ taskDefinitionArn, taskDefinitionFingerprint }) => taskDefinitionArn || `pending:${taskDefinitionFingerprint}`);
  if (new Set(identities).size !== identities.length
    || new Set(summaries.map(({ workflowRunId }) => workflowRunId)).size !== summaries.length) throw new Error("Historical failed recovery evidence is duplicated or conflicting.");
  return Object.freeze({
    envelopeSha256,
    lineageSha256,
    recoveryHistory: Object.freeze(summaries),
    knownFailedRevisions: Object.freeze(summaries.filter(({ classification }) => classification === "TERMINAL_FAILURE")),
    interruptedRecoveries: Object.freeze(summaries.filter(({ classification }) => classification === "INTERRUPTED_MUTATION")),
  });
}

export const FAILED_RECOVERY_EVIDENCE = Object.freeze({ kind: KIND, repository: REPOSITORY, retention: "IMMUTABLE_RELEASE_NO_AUTOMATIC_EXPIRY", maxHistoryRecords: MAX_HISTORY_RECORDS, maxHistoryBytes: MAX_HISTORY_BYTES, terminalMutationCounts: Object.freeze([...TERMINAL_MUTATION_COUNTS]), interruptedMutationStatuses: Object.freeze([...INTERRUPTED_MUTATIONS]), environmentKind: PRODUCTION_ENVIRONMENT_APPROVAL.kind });
