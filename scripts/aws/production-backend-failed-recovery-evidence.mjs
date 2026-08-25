import crypto from "node:crypto";
import { BACKEND_HEALTH_RECOVERY, BACKEND_HEALTH_RECOVERY_STATUS, assertLegacyBackendRecoveryEvidence, recoveryHistoryLineageSha256 } from "./production-backend-health-recovery-contract.mjs";
import { assertRuntimeConsumabilityEnvelopeSignature } from "./production-ecs-runtime-consumability.mjs";
import { assertProductionEnvironmentApprovalIdentity, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

const KIND = "AUTHENTICATED_BACKEND_FAILED_RECOVERY_EVIDENCE";
const REPOSITORY = "T-ej2003/genuine-scan-main";
const HEX = /^[a-f0-9]{64}$/;
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

function validateRecord(record, verifyRuntime) {
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
    authorizationFileSha256: evidence.authorizationFileSha256,
    authorizationSha256: evidence.authorizationSha256,
    environmentApprovalFileSha256: evidence.environmentApprovalFileSha256,
    environmentApprovalSha256: evidence.environmentApprovalSha256,
    imageAuthorizationFileSha256: evidence.imageAuthorizationFileSha256,
    imageAuthorizationSha256: evidence.imageAuthorizationSha256,
    artifactSigningBindingSha256: evidence.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: evidence.runtimeConsumabilitySha256,
    imageReleaseSha: evidence.imageReleaseSha,
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
    if (index === 0 ? record.predecessorHistoryReferenceSha256 !== null : !HEX.test(record.predecessorHistoryReferenceSha256 || "")) throw new Error("Historical recovery evidence predecessor reference chain is missing or reordered.");
    const previous = summaries[index - 1];
    if (previous?.expectedRevisionCensusSha256 && record.initialRevisionCensusSha256 !== previous.expectedRevisionCensusSha256) throw new Error("Historical recovery evidence census lineage is missing, reordered, or forked.");
  }
}

export function createAuthenticatedFailedRecoveryEvidence({ records, verifyRuntime, sign, signedAt = new Date().toISOString() } = {}) {
  if (!Array.isArray(records) || !records.length || records.length > MAX_HISTORY_RECORDS || typeof verifyRuntime !== "function" || typeof sign !== "function") throw new Error("Historical failed recovery evidence inputs are incomplete or exceed the bounded history limit.");
  const encoded = records.map(({ recoveryEvidenceBytes, environmentApprovalBytes, runtimeConsumabilityBytes }) => ({
    recoveryEvidence: artifact(recoveryEvidenceBytes, "Historical recovery evidence"),
    environmentApproval: artifact(environmentApprovalBytes, "Historical environment approval evidence"),
    runtimeConsumability: artifact(runtimeConsumabilityBytes, "Historical runtime consumability evidence"),
  })).map(({ recoveryEvidence, environmentApproval, runtimeConsumability }) => ({
    repository: environmentApproval.value.repository,
    workflowRunId: environmentApproval.value.workflowRunId,
    recoveryEvidence: { bytesBase64: recoveryEvidence.bytesBase64, byteSha256: recoveryEvidence.byteSha256 },
    environmentApproval: { bytesBase64: environmentApproval.bytesBase64, byteSha256: environmentApproval.byteSha256 },
    runtimeConsumability: { bytesBase64: runtimeConsumability.bytesBase64, byteSha256: runtimeConsumability.byteSha256 },
  }));
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
