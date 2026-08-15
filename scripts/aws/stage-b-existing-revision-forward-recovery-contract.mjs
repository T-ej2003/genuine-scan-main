import crypto from "node:crypto";
import { assertImageAuthorizationEnvelope, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { imageAuthorizationSha256 } from "./production-image-authorization.mjs";
import { assertProductionImageReuseResult } from "./validate-stage-b-image-reuse.mjs";
import {
  STAGE_B_BACKEND_RECOVERY,
  assertCanonicalBackendRecoveryCensus,
  buildCanonicalBackendRecoveryTaskDefinition,
  canonicalJson,
  canonicalSha256,
  stateSnapshotSha256,
  taskDefinitionFingerprint,
} from "./stage-b-task-definition-recovery-contract.mjs";

export const STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY = Object.freeze({
  schemaVersion: 2,
  kind: "STAGE_B_EXISTING_REVISION_ZERO_REGISTRATION_ADOPTION",
  mode: "EXISTING_REVISION_ZERO_REGISTRATION_ADOPTION",
  address: STAGE_B_BACKEND_RECOVERY.address,
  family: STAGE_B_BACKEND_RECOVERY.family,
  existingRevisionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9",
  lineage: STAGE_B_BACKEND_RECOVERY.lineage,
  startSerial: 94,
});

export const STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION = Object.freeze({
  schemaVersion: 1,
  kind: "STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION",
  mode: "AMBIGUOUS_IMPORT_SUPERSESSION",
  supersessionReason: "AMBIGUOUS_IMPORT_OUTCOME_CURRENT_STATE_UNRECONCILED",
  address: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.address,
  family: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.family,
  existingRevisionArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn,
  lineage: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage,
  startSerial: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial,
});

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;

export function journalSha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function backendInstance(state) {
  const resources = (state?.resources || []).filter(({ type, name }) => type === "aws_ecs_task_definition" && name === "candidate");
  if (resources.length !== 1 || !Array.isArray(resources[0].instances)) throw new Error("Forward recovery requires the canonical candidate resource collection.");
  return resources[0].instances.find(({ index_key: key }) => key === "backend") || null;
}

function stateWithoutBackend(state) {
  const value = structuredClone(state);
  value.resources = value.resources.flatMap((resource) => {
    if (resource.type !== "aws_ecs_task_definition" || resource.name !== "candidate") return [resource];
    const instances = resource.instances.filter(({ index_key: key }) => key !== "backend");
    return [{ ...resource, instances }];
  });
  return value;
}

function backendInstances(state) {
  const resources = (state?.resources || []).filter(({ type, name }) => type === "aws_ecs_task_definition" && name === "candidate");
  if (resources.length !== 1 || !Array.isArray(resources[0].instances)) throw new Error("Forward recovery requires the canonical candidate resource collection.");
  return resources[0].instances.filter(({ index_key: key }) => key === "backend");
}

export function assertForwardStateBeforeImport(state) {
  if (state?.lineage !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage || state?.serial !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial) throw new Error("Forward recovery requires the exact current Terraform lineage and serial.");
  if (backendInstances(state).length !== 0) throw new Error("Forward recovery requires the backend candidate to be absent before import.");
  return { lineage: state.lineage, serial: state.serial, stateSha256: stateSnapshotSha256(state) };
}

export function assertForwardImportRetryState({ journalState, state } = {}) {
  if (!journalState || journalState.phase !== "IMPORTING" || journalState.importCalls !== 1 || journalState.importMayHaveOccurred !== true) throw new Error("Forward import retry requires an authenticated importing incident.");
  const attemptCount = journalState.importAttemptCount ?? 1;
  if (attemptCount !== 1 || journalState.importAttemptOutcome !== "FAILED_BEFORE_STATE_MUTATION" || journalState.importFailureStateSha256 !== journalState.stateBeforeSha256) throw new Error("Forward import retry outcome is ambiguous; durable proof that the prior invocation failed before state mutation is required.");
  const before = assertForwardStateBeforeImport(state);
  if (before.stateSha256 !== journalState.stateBeforeSha256) throw new Error("Forward import outcome is ambiguous; authoritative state is not the authenticated pre-import state.");
  return Object.freeze({ stateSha256: before.stateSha256, retryAuthorized: true });
}

export function assertLegacyAmbiguousImportJournalIsImmutable(journalState) {
  if (journalState?.schemaVersion === STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion
    && journalState.phase === "IMPORTING" && journalState.importAttemptCount === undefined
    && journalState.importAttemptOutcome === undefined && journalState.importFailureStateSha256 === undefined) throw new Error("Legacy ambiguous IMPORTING recovery is permanently non-resumable; use the current-state supersession contract.");
  return journalState;
}

export function assertForwardImportedState({ beforeStateSha256, after } = {}) {
  if (after?.lineage !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage || after?.serial !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial + 1) throw new Error("Forward recovery import changed Terraform lineage or serial unexpectedly.");
  if (backendInstances(after).length !== 1) throw new Error("Forward recovery import must add exactly one backend candidate instance.");
  const imported = backendInstances(after)[0];
  const importedArn = imported?.attributes?.arn || imported?.attributes?.id;
  if (importedArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn) throw new Error("Forward recovery import did not bind the exact canonical :9 ARN.");
  const comparableAfter = stateWithoutBackend(after);
  comparableAfter.serial = STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial;
  if (stateSnapshotSha256(comparableAfter) !== beforeStateSha256) throw new Error("Forward recovery import changed Terraform state outside the exact backend candidate address.");
  return { lineage: after.lineage, serial: after.serial, stateSha256: stateSnapshotSha256(after), backendArn: importedArn };
}

export function assertForwardStateAfterImport(before, after) {
  const beforeBinding = assertForwardStateBeforeImport(before);
  const result = assertForwardImportedState({ beforeStateSha256: beforeBinding.stateSha256, after });
  const comparableBefore = stateWithoutBackend(before);
  const comparableAfter = stateWithoutBackend(after);
  comparableAfter.serial = comparableBefore.serial;
  if (stateSnapshotSha256(comparableBefore) !== stateSnapshotSha256(comparableAfter)) throw new Error("Forward recovery import changed Terraform state outside the exact backend candidate address.");
  return result;
}

export function assertForwardCensus({ census } = {}) {
  const supplied = census?.complete === true && Array.isArray(census.revisions) ? census.revisions : null;
  const entries = assertCanonicalBackendRecoveryCensus({ census });
  const target = entries.find(({ arn }) => arn === STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn);
  if (!target || entries[0].arn !== target.arn) throw new Error("Forward recovery requires the exact canonical :9 revision to be newest.");
  if (entries.some(({ revision }) => revision > 9)) throw new Error("Forward recovery refuses an unexpected newer backend revision.");
  const byArn = new Map(entries.map((entry) => [entry.arn, entry]));
  const orderedEntries = supplied.map((entry) => byArn.get(entry?.arn || entry?.readback?.taskDefinition?.taskDefinitionArn));
  if (orderedEntries.some((entry) => !entry)) throw new Error("Forward recovery census ordering cannot be authenticated.");
  return Object.freeze({ entries, newestArn: target.arn, censusSha256: canonicalSha256(orderedEntries) });
}

export function assertForwardRevisionReadback({ readback, expectedFingerprint, imageReleaseSha, backendImage } = {}) {
  const taskDefinition = readback?.taskDefinition || readback;
  if (taskDefinition?.taskDefinitionArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn
    || taskDefinition.family !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.family || taskDefinition.status !== "ACTIVE"
    || Number(taskDefinition.revision) !== 9 || taskDefinitionFingerprint(taskDefinition, readback?.tags) !== expectedFingerprint) throw new Error("Canonical :9 readback does not match the protected task-definition fingerprint.");
  const container = taskDefinition.containerDefinitions?.find(({ name }) => name === "backend");
  const release = container?.environment?.find(({ name }) => name === "RELEASE_GIT_SHA")?.value;
  if (container?.image !== backendImage || release !== imageReleaseSha) throw new Error("Canonical :9 image or RELEASE_GIT_SHA binding does not match the authorized image release.");
  return { arn: taskDefinition.taskDefinitionArn, fingerprint: expectedFingerprint, image: container.image, imageReleaseSha: release };
}

export function assertForwardSourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, deriveImageReuse, proveDescendant } = {}) {
  if (!SHA.test(sourceSha || "") || !protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.originMainHead !== sourceSha || protectedCheckout.toolingSha !== sourceSha || protectedCheckout.porcelainStatus) throw new Error("Forward recovery requires the exact clean protected-main executor checkout.");
  if (!bindings || bindings.toolingSha !== sourceSha || bindings.sourceSha !== sourceSha || !SHA256.test(bindings.toolingTreeSha256 || "") || !SHA256.test(bindings.sourceContractSha256 || "") || !SHA.test(bindings.imageReleaseSha || "") || !IMAGE.test(bindings.backendImage || "")) throw new Error("Forward recovery source and image bindings are incomplete.");
  const authorization = imageAuthorization || bindings.imageAuthorization;
  if (!authorization || authorization.imageReleaseSha !== bindings.imageReleaseSha || !SHA.test(authorization.sourceSha || "") || !SHA256.test(authorization.evidenceSha256 || "")) throw new Error("Forward recovery image authorization does not bind the requested image release.");
  if (!imageAuthorizationValidation?.verifyImageEvidence) throw new Error("Forward recovery image authorization verifier is required.");
  assertImageAuthorizationEnvelope(authorization, imageAuthorizationValidation);
  const digest = authorizedBackendDigest(authorization);
  if (bindings.backendImage !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`) throw new Error("Forward recovery backend image does not match authorization.");
  const derived = deriveProvenance?.({ sourceSha, protectedCheckout });
  if (!derived || derived.toolingTreeSha256 !== bindings.toolingTreeSha256 || derived.sourceContractSha256 !== bindings.sourceContractSha256) throw new Error("Forward recovery current source provenance is not derived from protected main.");
  if (authorization.sourceSha !== sourceSha && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: authorization.sourceSha, descendantSha: sourceSha }) !== true)) throw new Error("Forward recovery image authorization source is not an authenticated protected-main ancestor.");
  const authorizationSourceReuse = deriveImageReuse?.({ imageReleaseSha: authorization.sourceSha, toolingSha: sourceSha });
  assertProductionImageReuseResult(authorizationSourceReuse);
  if (authorizationSourceReuse.toolingSha !== sourceSha || authorizationSourceReuse.imageReleaseSha !== authorization.sourceSha || authorizationSourceReuse.imageAffectingFiles.length !== 0) throw new Error("Forward recovery authorization-source reuse is not explicitly compatible with current protected main.");
  const reuse = deriveImageReuse?.({ imageReleaseSha: bindings.imageReleaseSha, toolingSha: sourceSha });
  assertProductionImageReuseResult(reuse);
  if (reuse.toolingSha !== sourceSha || reuse.imageReleaseSha !== bindings.imageReleaseSha || reuse.imageAffectingFiles.length !== 0) throw new Error("Forward recovery image reuse is not explicitly compatible with current protected main.");
  return Object.freeze({ authorization, authorizedBackendDigest: digest, derived, authorizationSourceReuse, reuse });
}

export function assertForwardConsumedImportResume({ sourceSha, bindings, protectedCheckout, journalState, imageAuthorization, deriveProvenance, deriveImageReuse, proveDescendant } = {}) {
  if (!journalState || journalState.phase !== "IMPORTING" || journalState.schemaVersion !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion
    || journalState.kind !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind || journalState.mode !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode) throw new Error("Forward consumed-import replay requires an importing zero-registration incident journal.");
  const expectedIncidentIdentity = canonicalForwardRecoveryIncidentIdentity(journalState);
  if (journalState.incidentIdentity !== expectedIncidentIdentity || journalState.registrationCalls !== 0 || journalState.registrationCapability !== "NONE" || journalState.importCalls !== 1 || journalState.importMayHaveOccurred !== true
    || journalState.existingRevisionArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn) throw new Error("Forward consumed-import replay journal identity or import budget is invalid.");
  validateExistingRevisionForwardJournal(journalState, expectedFieldsFromJournal(journalState));
  if (!SHA.test(sourceSha || "") || !SHA.test(journalState.sourceSha || "")
    || !protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.originMainHead !== sourceSha || protectedCheckout.toolingSha !== sourceSha || protectedCheckout.porcelainStatus) throw new Error("Forward descendant resume requires the exact clean protected-main executor checkout.");
  if (sourceSha !== journalState.sourceSha
    && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: journalState.sourceSha, descendantSha: sourceSha }) !== true)) throw new Error("Forward consumed-import replay requires the original incident source to be an ancestor of the executor.");
  if (!bindings || bindings.sourceSha !== journalState.sourceSha || bindings.toolingSha !== journalState.sourceSha || bindings.toolingTreeSha256 !== journalState.toolingTreeSha256
    || bindings.sourceContractSha256 !== journalState.sourceContractSha256 || bindings.imageReleaseSha !== journalState.imageReleaseSha
    || bindings.imageAuthorizationSha256 !== undefined && bindings.imageAuthorizationSha256 !== journalState.imageAuthorizationSha256
    || bindings.backendImage !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${journalState.authorizedBackendDigest}`) throw new Error("Forward consumed-import replay bindings do not preserve the original incident.");
  const authorization = imageAuthorization || bindings.imageAuthorization;
  if (!SHA.test(journalState.imageAuthorizationSourceSha || "") || !authorization || authorization.sourceSha !== journalState.imageAuthorizationSourceSha || authorization.imageReleaseSha !== journalState.imageReleaseSha
    || authorization.evidenceSha256 !== journalState.imageAuthorizationSha256 || authorization.authorizationSha256 !== authorization.evidenceSha256
    || imageAuthorizationSha256(authorization) !== authorization.evidenceSha256) throw new Error("Forward consumed-import replay authorization does not preserve the original incident identity.");
  if (authorizedBackendDigest(authorization) !== journalState.authorizedBackendDigest) throw new Error("Forward consumed-import replay image digest does not preserve the original incident.");
  if (authorization.sourceSha !== journalState.sourceSha
    && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: authorization.sourceSha, descendantSha: journalState.sourceSha }) !== true)) throw new Error("Forward consumed-import replay authorization source is not the authenticated original incident ancestor.");
  const authorizationSourceReuse = deriveImageReuse?.({ imageReleaseSha: authorization.sourceSha, toolingSha: journalState.sourceSha });
  assertProductionImageReuseResult(authorizationSourceReuse);
  if (authorizationSourceReuse.toolingSha !== journalState.sourceSha || authorizationSourceReuse.imageReleaseSha !== authorization.sourceSha || authorizationSourceReuse.imageAffectingFiles.length !== 0 || authorizationSourceReuse.imageBuildInputsChanged === true) throw new Error("Forward consumed-import replay original authorization-source reuse is not explicitly compatible with the incident source.");
  const incidentProvenance = deriveProvenance?.({ sourceSha: journalState.sourceSha, protectedCheckout });
  const executorProvenance = deriveProvenance?.({ sourceSha, protectedCheckout });
  if (!incidentProvenance || incidentProvenance.toolingTreeSha256 !== journalState.toolingTreeSha256 || incidentProvenance.sourceContractSha256 !== journalState.sourceContractSha256
    || !executorProvenance || !SHA256.test(executorProvenance.toolingTreeSha256 || "") || executorProvenance.sourceContractSha256 !== journalState.sourceContractSha256) throw new Error("Forward consumed-import replay provenance is not bound to the original incident and protected executor.");
  const reuse = deriveImageReuse?.({ imageReleaseSha: journalState.imageReleaseSha, toolingSha: sourceSha });
  assertProductionImageReuseResult(reuse);
  if (reuse.toolingSha !== sourceSha || reuse.imageReleaseSha !== journalState.imageReleaseSha || reuse.imageAffectingFiles.length !== 0 || reuse.imageBuildInputsChanged === true) throw new Error("Forward consumed-import replay image reuse is not explicitly compatible with the protected executor.");
  return Object.freeze({ incidentSourceSha: journalState.sourceSha, authorizationSourceSha: authorization.sourceSha, authorizedBackendDigest: journalState.authorizedBackendDigest, fingerprint: journalState.fingerprint, incidentProvenance, executorProvenance, authorizationSourceReuse, reuse });
}

export function assertForwardCompletedResume({ sourceSha, protectedCheckout, journalState, proveDescendant } = {}) {
  if (!journalState || !["COMPLETED", "RECONCILED"].includes(journalState.phase)
    || journalState.schemaVersion !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion
    || journalState.kind !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind
    || journalState.mode !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode) throw new Error("Forward completed replay requires a terminal zero-registration incident journal.");
  const expectedIncidentIdentity = canonicalForwardRecoveryIncidentIdentity(journalState);
  if (journalState.incidentIdentity !== expectedIncidentIdentity || journalState.registrationCalls !== 0 || journalState.registrationCapability !== "NONE"
    || journalState.importCalls !== 1 || journalState.existingRevisionArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn) throw new Error("Forward completed replay journal identity or import budget is invalid.");
  if (!SHA.test(sourceSha || "") || !SHA.test(journalState.sourceSha || "")
    || !protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.originMainHead !== sourceSha
    || protectedCheckout.toolingSha !== sourceSha || protectedCheckout.porcelainStatus) throw new Error("Forward completed replay requires the exact clean protected-main executor checkout.");
  if (sourceSha !== journalState.sourceSha
    && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: journalState.sourceSha, descendantSha: sourceSha }) !== true)) throw new Error("Forward completed replay requires the executor to descend from the original incident source.");
  return Object.freeze({ incidentSourceSha: journalState.sourceSha, authorizedBackendDigest: journalState.authorizedBackendDigest, fingerprint: journalState.fingerprint });
}

export function assertForwardPreparedResume({ sourceSha, protectedCheckout, journalState, proveDescendant } = {}) {
  if (!journalState || journalState.phase !== "PREPARED" || journalState.importCalls !== 0 || journalState.importMayHaveOccurred === true) throw new Error("Forward prepared resume requires an unconsumed PREPARED journal.");
  const expected = expectedFieldsFromJournal(journalState);
  if (journalState.incidentIdentity !== canonicalForwardRecoveryIncidentIdentity(journalState)) throw new Error("Forward prepared resume journal identity is invalid.");
  validateExistingRevisionForwardJournal(journalState, expected);
  if (!SHA.test(sourceSha || "") || !SHA.test(journalState.sourceSha || "")
    || !protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.originMainHead !== sourceSha
    || protectedCheckout.toolingSha !== sourceSha || protectedCheckout.porcelainStatus) throw new Error("Forward prepared resume requires the exact clean protected-main executor checkout.");
  if (sourceSha !== journalState.sourceSha
    && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: journalState.sourceSha, descendantSha: sourceSha }) !== true)) throw new Error("Forward prepared resume requires the original source to be an ancestor of the executor.");
  return Object.freeze({ incidentIdentity: journalState.incidentIdentity, sourceSha: journalState.sourceSha, stateBeforeSha256: journalState.stateBeforeSha256 });
}

export function canonicalForwardRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, authorizedBackendDigest, imageAuthorizationSha256, imageAuthorizationSourceSha, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn, censusSha256, fingerprint } = {}) {
  if (!SHA.test(sourceSha || "") || !SHA256.test(toolingTreeSha256 || "") || !SHA256.test(sourceContractSha256 || "") || !SHA.test(imageReleaseSha || "")
    || !/^sha256:[a-f0-9]{64}$/.test(authorizedBackendDigest || "") || !SHA256.test(imageAuthorizationSha256 || "") || !SHA.test(imageAuthorizationSourceSha || "") || stateLineage !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage
    || stateSerial !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial || !SHA256.test(stateBeforeSha256 || "") || existingRevisionArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn || !SHA256.test(censusSha256 || "") || !SHA256.test(fingerprint || "")) throw new Error("Forward recovery incident identity is incomplete.");
  return canonicalSha256({ schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, authorizedBackendDigest, imageAuthorizationSha256, imageAuthorizationSourceSha, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn, censusSha256, fingerprint });
}

export function validateExistingRevisionForwardJournal(journal, expected) {
  if (!journal || journal.schemaVersion !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion || journal.kind !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind || journal.mode !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode || journal.incidentIdentity !== expected.incidentIdentity || journal.registrationCalls !== 0 || journal.registrationCapability !== "NONE" || journal.sourceSha !== expected.sourceSha || journal.toolingTreeSha256 !== expected.toolingTreeSha256 || journal.sourceContractSha256 !== expected.sourceContractSha256 || journal.imageReleaseSha !== expected.imageReleaseSha || journal.authorizedBackendDigest !== expected.authorizedBackendDigest || journal.imageAuthorizationSha256 !== expected.imageAuthorizationSha256 || journal.imageAuthorizationSourceSha !== expected.imageAuthorizationSourceSha || journal.stateLineage !== expected.stateLineage || journal.stateSerial !== expected.stateSerial || journal.stateBeforeSha256 !== expected.stateBeforeSha256 || journal.existingRevisionArn !== expected.existingRevisionArn || journal.censusSha256 !== expected.censusSha256 || journal.fingerprint !== expected.fingerprint || !["PREPARED", "IMPORTING", "RECONCILED", "COMPLETED"].includes(journal.phase)) throw new Error("Forward recovery journal is not the exact zero-registration incident.");
  if (["IMPORTING", "RECONCILED", "COMPLETED"].includes(journal.phase) && !SHA256.test(journal.stateBeforeSha256 || "")) throw new Error("Forward recovery journal is missing its authenticated pre-import state hash.");
  if (journal.phase === "IMPORTING" && journal.stateAfterImportSha256 !== undefined && !SHA256.test(journal.stateAfterImportSha256 || "")) throw new Error("Forward recovery importing checkpoint hash is malformed.");
  if (["RECONCILED", "COMPLETED"].includes(journal.phase) && !SHA256.test(journal.stateAfterImportSha256 || "")) throw new Error("Forward recovery journal is missing its authenticated post-import state hash.");
  if (journal.phase === "IMPORTING" && journal.importMayHaveOccurred !== true) throw new Error("Forward recovery importing phase must fail closed as potentially ambiguous.");
  if (journal.phase === "IMPORTING" && journal.importCalls !== 1) throw new Error("Forward recovery importing phase must have exactly one reserved import call.");
  if (["IMPORTING", "RECONCILED", "COMPLETED"].includes(journal.phase) && journal.importAttemptCount !== undefined && ![1, 2].includes(journal.importAttemptCount)) throw new Error("Forward recovery import attempt count is malformed.");
  if (journal.phase === "IMPORTING" && journal.importAttemptCount === 2 && journal.importRetryAuthorized !== true) throw new Error("Forward recovery retry authorization is incomplete.");
  if (["RECONCILED", "COMPLETED"].includes(journal.phase) && (!SHA256.test(journal.evidenceSha256 || "") || journal.registrationCalls !== 0 || journal.importCalls !== 1 || !SHA256.test(journal.stateAfterImportSha256 || ""))) throw new Error("Forward recovery completed evidence bindings are incomplete.");
  return journal;
}

export function buildForwardRecoveryEvidence(expected, stateAfterImportSha256) {
  const body = { schemaVersion: 1, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, ...expected, stateAfterImportSha256, registrationCalls: 0, importCalls: 1 };
  return { ...body, evidenceSha256: canonicalSha256(body) };
}

function expectedFieldsFromJournal(journal) {
  return { incidentIdentity: journal.incidentIdentity, sourceSha: journal.sourceSha, toolingTreeSha256: journal.toolingTreeSha256, sourceContractSha256: journal.sourceContractSha256, imageReleaseSha: journal.imageReleaseSha, authorizedBackendDigest: journal.authorizedBackendDigest, imageAuthorizationSha256: journal.imageAuthorizationSha256, imageAuthorizationSourceSha: journal.imageAuthorizationSourceSha, stateLineage: journal.stateLineage, stateSerial: journal.stateSerial, stateBeforeSha256: journal.stateBeforeSha256, existingRevisionArn: journal.existingRevisionArn, censusSha256: journal.censusSha256, fingerprint: journal.fingerprint };
}

export function validateForwardRecoveryEvidence(evidence, journal, expected) {
  const expectedEvidence = buildForwardRecoveryEvidence(expected, journal.stateAfterImportSha256);
  if (!evidence || canonicalJson(evidence) !== canonicalJson(expectedEvidence) || journal.evidenceSha256 !== expectedEvidence.evidenceSha256) throw new Error("Forward recovery evidence is not the exact authenticated completed incident result.");
  return evidence;
}

function supersessionFields(journal) {
  return {
    incidentIdentity: journal.incidentIdentity,
    supersedesJournalSha256: journal.supersedesJournalSha256,
    supersedesIncidentIdentity: journal.supersedesIncidentIdentity,
    supersededSourceSha: journal.supersededSourceSha,
    supersessionReason: journal.supersessionReason,
    sourceSha: journal.sourceSha,
    toolingTreeSha256: journal.toolingTreeSha256,
    sourceContractSha256: journal.sourceContractSha256,
    imageReleaseSha: journal.imageReleaseSha,
    authorizedBackendDigest: journal.authorizedBackendDigest,
    imageAuthorizationSha256: journal.imageAuthorizationSha256,
    imageAuthorizationSourceSha: journal.imageAuthorizationSourceSha,
    stateLineage: journal.stateLineage,
    stateSerial: journal.stateSerial,
    stateBeforeSha256: journal.stateBeforeSha256,
    existingRevisionArn: journal.existingRevisionArn,
    censusSha256: journal.censusSha256,
    fingerprint: journal.fingerprint,
  };
}

export function canonicalAmbiguousImportSupersessionIdentity(fields = {}) {
  const required = [fields.sourceSha, fields.toolingTreeSha256, fields.sourceContractSha256, fields.imageReleaseSha,
    fields.imageAuthorizationSha256, fields.stateBeforeSha256, fields.censusSha256, fields.fingerprint,
    fields.supersedesJournalSha256, fields.supersedesIncidentIdentity];
  if (required.some((value) => typeof value !== "string" || !value)
    || !SHA.test(fields.sourceSha) || !SHA256.test(fields.toolingTreeSha256) || !SHA256.test(fields.sourceContractSha256)
    || !SHA.test(fields.imageReleaseSha) || !/^sha256:[a-f0-9]{64}$/.test(fields.authorizedBackendDigest || "")
    || !SHA256.test(fields.imageAuthorizationSha256) || !SHA.test(fields.imageAuthorizationSourceSha)
    || fields.stateLineage !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.lineage
    || fields.stateSerial !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.startSerial || !SHA256.test(fields.stateBeforeSha256)
    || fields.existingRevisionArn !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn || !SHA256.test(fields.censusSha256)
    || !SHA256.test(fields.fingerprint) || !SHA256.test(fields.supersedesJournalSha256)
    || !SHA256.test(fields.supersedesIncidentIdentity) || !SHA.test(fields.supersededSourceSha)
    || fields.supersessionReason !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.supersessionReason) throw new Error("Ambiguous import supersession identity is incomplete.");
  return canonicalSha256({ schemaVersion: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.schemaVersion, kind: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.kind, mode: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.mode,
    supersedesJournalSha256: fields.supersedesJournalSha256, supersedesIncidentIdentity: fields.supersedesIncidentIdentity, supersededSourceSha: fields.supersededSourceSha,
    supersessionReason: fields.supersessionReason, sourceSha: fields.sourceSha, toolingTreeSha256: fields.toolingTreeSha256, sourceContractSha256: fields.sourceContractSha256,
    imageReleaseSha: fields.imageReleaseSha, authorizedBackendDigest: fields.authorizedBackendDigest, imageAuthorizationSha256: fields.imageAuthorizationSha256,
    imageAuthorizationSourceSha: fields.imageAuthorizationSourceSha, stateLineage: fields.stateLineage, stateSerial: fields.stateSerial, stateBeforeSha256: fields.stateBeforeSha256,
    existingRevisionArn: fields.existingRevisionArn, censusSha256: fields.censusSha256, fingerprint: fields.fingerprint });
}

export function validateAmbiguousImportSupersededJournal(journal, { journalSha256: expectedJournalSha256, journalBytes, state, censusEvidence, fingerprint, sourceSha, proveDescendant } = {}) {
  if (!journal || journal.schemaVersion !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion
    || journal.kind !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind || journal.mode !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode
    || journal.phase !== "IMPORTING" || journal.importCalls !== 1 || journal.importMayHaveOccurred !== true
    || journal.registrationCalls !== 0 || journal.registrationCapability !== "NONE"
    || journal.existingRevisionArn !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn
    || journal.stateLineage !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.lineage
    || journal.stateSerial !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.startSerial
    || journal.stateAfterImportSha256 !== undefined || journal.evidenceSha256 !== undefined) throw new Error("Ambiguous import supersession requires the unchanged, incomplete historical IMPORTING journal.");
  if (!SHA256.test(expectedJournalSha256 || "") || !journalBytes || journalSha256(journalBytes) !== expectedJournalSha256 || !SHA.test(journal.sourceSha || "") || journal.incidentIdentity !== canonicalForwardRecoveryIncidentIdentity(journal)) throw new Error("Ambiguous import supersession historical journal identity is invalid.");
  if (journal.sourceSha !== sourceSha && (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: journal.sourceSha, descendantSha: sourceSha }) !== true)) throw new Error("Ambiguous import supersession executor is not a protected descendant of the historical incident.");
  const current = assertForwardStateBeforeImport(state);
  if (current.stateSha256 !== journal.stateBeforeSha256) throw new Error("Ambiguous import supersession current state does not match the historical incident checkpoint.");
  if (!censusEvidence || censusEvidence.censusSha256 !== journal.censusSha256 || fingerprint !== journal.fingerprint) throw new Error("Ambiguous import supersession historical ECS evidence does not match current canonical :9.");
  return Object.freeze({ journalSha256: expectedJournalSha256, supersededSourceSha: journal.sourceSha, supersedesIncidentIdentity: journal.incidentIdentity });
}

export function validateAmbiguousImportSupersessionJournal(journal, expected) {
  if (!journal || journal.schemaVersion !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.schemaVersion
    || journal.kind !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.kind || journal.mode !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.mode
    || !["PREPARED", "IMPORTING", "COMPLETED"].includes(journal.phase)) throw new Error("Ambiguous import supersession journal is invalid.");
  const expectedIdentity = canonicalAmbiguousImportSupersessionIdentity(expected);
  if (journal.incidentIdentity !== expectedIdentity || canonicalJson(supersessionFields(journal)) !== canonicalJson(supersessionFields(expected))
    || journal.registrationCalls !== 0 || journal.registrationCapability !== "NONE" || ![0, 1].includes(journal.importCalls)
    || journal.existingRevisionArn !== STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn) throw new Error("Ambiguous import supersession journal identity or capability budget is invalid.");
  if (journal.phase === "PREPARED" && journal.importCalls !== 0) throw new Error("Ambiguous import supersession PREPARED phase cannot consume import budget.");
  if (journal.phase !== "PREPARED" && (journal.importCalls !== 1 || journal.importMayHaveOccurred !== true)) throw new Error("Ambiguous import supersession consumed phase has an invalid import budget.");
  if (journal.phase === "COMPLETED" && !SHA256.test(journal.stateAfterImportSha256 || "") || journal.phase === "IMPORTING" && journal.stateAfterImportSha256 !== undefined) throw new Error("Ambiguous import supersession checkpoint is invalid.");
  return journal;
}

function buildAmbiguousImportSupersessionEvidence(expected, stateAfterImportSha256) {
  const body = { schemaVersion: 1, kind: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.kind, mode: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.mode, ...expected, stateAfterImportSha256, registrationCalls: 0, importCalls: 1 };
  return { ...body, evidenceSha256: canonicalSha256(body) };
}

function validateAmbiguousImportSupersessionEvidence(evidence, journal, expected) {
  const expectedEvidence = buildAmbiguousImportSupersessionEvidence(expected, journal.stateAfterImportSha256);
  if (!evidence || canonicalJson(evidence) !== canonicalJson(expectedEvidence) || journal.evidenceSha256 !== expectedEvidence.evidenceSha256) throw new Error("Ambiguous import supersession evidence is not the exact immutable completed result.");
  return evidence;
}

export function assertAmbiguousImportSupersessionAuthority({ oldJournal, oldJournalSha256, oldJournalBytes, state, census, readback, sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, deriveImageReuse, proveDescendant } = {}) {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const fingerprint = taskDefinitionFingerprint(payload.taskDefinition, payload.tags);
  const censusEvidence = assertForwardCensus({ census });
  const authorization = assertForwardSourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, deriveImageReuse, proveDescendant });
  const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authorization.authorizedBackendDigest}`;
  assertForwardRevisionReadback({ readback, expectedFingerprint: fingerprint, imageReleaseSha: bindings.imageReleaseSha, backendImage });
  const superseded = validateAmbiguousImportSupersededJournal(oldJournal, { journalSha256: oldJournalSha256, journalBytes: oldJournalBytes, state, censusEvidence, fingerprint, sourceSha, proveDescendant });
  const stateBefore = assertForwardStateBeforeImport(state);
  const fields = {
    supersedesJournalSha256: superseded.journalSha256,
    supersedesIncidentIdentity: superseded.supersedesIncidentIdentity,
    supersededSourceSha: superseded.supersededSourceSha,
    supersessionReason: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.supersessionReason,
    sourceSha, toolingTreeSha256: authorization.derived.toolingTreeSha256, sourceContractSha256: authorization.derived.sourceContractSha256,
    imageReleaseSha: bindings.imageReleaseSha, authorizedBackendDigest: authorization.authorizedBackendDigest,
    imageAuthorizationSha256: authorization.authorization.evidenceSha256, imageAuthorizationSourceSha: authorization.authorization.sourceSha,
    stateLineage: stateBefore.lineage, stateSerial: stateBefore.serial, stateBeforeSha256: stateBefore.stateSha256,
    existingRevisionArn: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn, censusSha256: censusEvidence.censusSha256, fingerprint,
  };
  return Object.freeze({ ...fields, incidentIdentity: canonicalAmbiguousImportSupersessionIdentity(fields), authorization, censusEvidence, fingerprint, stateBeforeSha256: stateBefore.stateSha256 });
}

export async function runAmbiguousImportSupersession({ oldJournal, oldJournalSha256, oldJournalBytes, bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse, validateImportBindings, readState, census, describe, importState, evidence, journal, interruptAt } = {}) {
  if (!oldJournal || typeof readState !== "function" || typeof census !== "function" || typeof describe !== "function" || typeof importState !== "function" || !journal?.read || !journal?.write || !evidence?.read || !evidence?.write) throw new Error("Ambiguous import supersession requires the immutable historical journal and durable adapters.");
  const existing = journal.read();
  const state = await readState();
  if (existing?.phase === "IMPORTING") {
    const expected = supersessionFields(existing);
    validateAmbiguousImportSupersessionJournal(existing, expected);
    if (existing.supersedesJournalSha256 !== oldJournalSha256 || journalSha256(oldJournalBytes || Buffer.alloc(0)) !== oldJournalSha256 || existing.supersedesIncidentIdentity !== oldJournal.incidentIdentity) throw new Error("Ambiguous import supersession historical journal link changed during consumed-mutation replay.");
    const censusEvidence = assertForwardCensus({ census: await census() });
    const readback = await describe(STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn);
    assertForwardRevisionReadback({ readback, expectedFingerprint: existing.fingerprint, imageReleaseSha: existing.imageReleaseSha, backendImage: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${existing.authorizedBackendDigest}` });
    const afterBinding = assertForwardImportedState({ beforeStateSha256: existing.stateBeforeSha256, after: state });
    if (censusEvidence.censusSha256 !== existing.censusSha256) throw new Error("Ambiguous import supersession consumed replay census drifted.");
    const completedEvidence = persistForwardRecoveryEvidence(buildAmbiguousImportSupersessionEvidence(expected, afterBinding.stateSha256), evidence);
    journal.write({ ...existing, ...completedEvidence, phase: "COMPLETED", stateAfterImportSha256: afterBinding.stateSha256 });
    return { incidentIdentity: existing.incidentIdentity, imported: false, phase: "COMPLETED", recoveredFromPhase: "IMPORTING", registrationCalls: 0, importCalls: 0, state, readback, census: censusEvidence, evidence: completedEvidence };
  }
  if (existing?.phase === "COMPLETED") {
    const expected = supersessionFields(existing);
    validateAmbiguousImportSupersessionJournal(existing, expected);
    const censusEvidence = assertForwardCensus({ census: await census() });
    const readback = await describe(STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn);
    assertForwardRevisionReadback({ readback, expectedFingerprint: existing.fingerprint, imageReleaseSha: existing.imageReleaseSha, backendImage: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${existing.authorizedBackendDigest}` });
    validateAmbiguousImportSupersessionEvidence(evidence.read(), existing, expected);
    assertForwardImportedState({ beforeStateSha256: existing.stateBeforeSha256, after: state });
    if (censusEvidence.censusSha256 !== existing.censusSha256) throw new Error("Ambiguous import supersession completed replay census drifted.");
    return { incidentIdentity: existing.incidentIdentity, imported: false, phase: "COMPLETED", registrationCalls: 0, importCalls: 0, state, readback, census: censusEvidence };
  }
  const authority = assertAmbiguousImportSupersessionAuthority({ oldJournal, oldJournalSha256, oldJournalBytes, state, census: await census(), readback: await describe(STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn), sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, deriveImageReuse, proveDescendant });
  const expected = { ...authority };
  delete expected.authorization; delete expected.censusEvidence;
  if (existing) {
    validateAmbiguousImportSupersessionJournal(existing, expected);
    if (existing.phase === "IMPORTING") throw new Error("Ambiguous import supersession import outcome is still ambiguous; no second import is authorized.");
  } else {
    if (typeof validateImportBindings === "function") validateImportBindings();
    journal.write({ schemaVersion: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.schemaVersion, kind: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.kind, mode: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.mode, phase: "PREPARED", ...expected, registrationCalls: 0, registrationCapability: "NONE", importCalls: 0 });
  }
  const latestState = await readState();
  if (stateSnapshotSha256(latestState) !== authority.stateBeforeSha256) throw new Error("Ambiguous import supersession state changed before the governed import boundary.");
  const latestCensus = assertForwardCensus({ census: await census() });
  if (latestCensus.censusSha256 !== authority.censusEvidence.censusSha256) throw new Error("Ambiguous import supersession ECS census changed before the governed import boundary.");
  const latestReadback = assertForwardRevisionReadback({ readback: await describe(STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn), expectedFingerprint: authority.fingerprint, imageReleaseSha: bindings.imageReleaseSha, backendImage: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authority.authorization.authorizedBackendDigest}` });
  if (latestReadback.fingerprint !== authority.fingerprint) throw new Error("Ambiguous import supersession canonical :9 changed before the governed import boundary.");
  if (typeof validateImportBindings === "function") validateImportBindings();
  journal.write({ ...journal.read(), ...expected, phase: "IMPORTING", importCalls: 1, importMayHaveOccurred: true });
  await importState({ address: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.address, arn: STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn });
  interruptAt?.("AFTER_IMPORT");
  const after = await readState();
  const afterBinding = assertForwardStateAfterImport(state, after);
  interruptAt?.("AFTER_POST_IMPORT_VERIFICATION");
  const completedEvidence = persistForwardRecoveryEvidence(buildAmbiguousImportSupersessionEvidence(expected, afterBinding.stateSha256), evidence);
  interruptAt?.("AFTER_EVIDENCE_PERSISTED");
  journal.write({ ...journal.read(), ...completedEvidence, phase: "COMPLETED", stateAfterImportSha256: afterBinding.stateSha256 });
  return { incidentIdentity: authority.incidentIdentity, imported: true, phase: "COMPLETED", registrationCalls: 0, importCalls: 1, state: after, readback: latestReadback, census: latestCensus, evidence: completedEvidence };
}

function persistForwardRecoveryEvidence(evidence, evidenceAdapter) {
  if (!evidenceAdapter?.read || !evidenceAdapter?.write) throw new Error("Forward recovery requires a durable evidence adapter before completion.");
  const existing = evidenceAdapter.read();
  if (existing !== null && canonicalJson(existing) !== canonicalJson(evidence)) throw new Error("Forward recovery evidence already exists with contradictory contents.");
  if (existing === null) evidenceAdapter.write(evidence);
  const persisted = evidenceAdapter.read();
  if (canonicalJson(persisted) !== canonicalJson(evidence)) throw new Error("Forward recovery evidence was not durably verified before completion.");
  return persisted;
}

function expectedFields({ sourceSha, authorization, bindings, censusEvidence, fingerprint, incidentIdentity, stateBeforeSha256 }) {
  return { incidentIdentity, sourceSha, toolingTreeSha256: authorization.derived.toolingTreeSha256, sourceContractSha256: authorization.derived.sourceContractSha256, imageReleaseSha: bindings.imageReleaseSha, authorizedBackendDigest: authorization.authorizedBackendDigest, imageAuthorizationSha256: authorization.authorization.evidenceSha256, imageAuthorizationSourceSha: authorization.authorization.sourceSha, stateLineage: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage, stateSerial: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial, stateBeforeSha256, existingRevisionArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn, censusSha256: censusEvidence.censusSha256, fingerprint };
}

export async function runExistingRevisionForwardRecovery({ bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse, validateImportBindings, readState, census, describe, importState, evidence, journal, interruptAt } = {}) {
  if (typeof readState !== "function" || typeof census !== "function" || typeof describe !== "function" || typeof importState !== "function" || !journal?.read || !journal?.write || !evidence?.read || !evidence?.write) throw new Error("Forward recovery requires read, census, describe, import, journal, and durable evidence adapters.");
  const existing = journal.read();
  assertLegacyAmbiguousImportJournalIsImmutable(existing);
  const observedState = await readState();
  const completedResume = existing && ["COMPLETED", "RECONCILED"].includes(existing.phase)
    ? assertForwardCompletedResume({ sourceSha, protectedCheckout, journalState: existing, proveDescendant })
    : null;
  const preparedResume = existing?.phase === "PREPARED"
    ? assertForwardPreparedResume({ sourceSha, protectedCheckout, journalState: existing, proveDescendant })
    : null;
  const consumedImportResume = existing?.phase === "IMPORTING"
    ? assertForwardConsumedImportResume({ sourceSha, bindings, protectedCheckout, journalState: existing, imageAuthorization, deriveProvenance, deriveImageReuse, proveDescendant })
    : null;
  const importRetryState = existing?.phase === "IMPORTING" && (observedState?.resources || []).some(({ type, name, instances }) => type === "aws_ecs_task_definition" && name === "candidate" && Array.isArray(instances) && instances.every(({ index_key: key }) => key !== "backend"))
    ? assertForwardImportRetryState({ journalState: existing, state: observedState })
    : null;
  const importAuthorizationRequired = !completedResume && (!existing || preparedResume || importRetryState);
  if (importAuthorizationRequired && typeof validateImportBindings === "function") validateImportBindings();
  const authorization = completedResume || (consumedImportResume && !importRetryState) ? null : assertForwardSourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse });
  const payload = completedResume || consumedImportResume ? null : buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const fingerprint = completedResume?.fingerprint || consumedImportResume?.fingerprint || taskDefinitionFingerprint(payload.taskDefinition, payload.tags);
  const censusEvidence = assertForwardCensus({ census: await census() });
  if (completedResume && censusEvidence.censusSha256 !== existing.censusSha256) throw new Error("Forward completed replay census no longer matches the authenticated incident.");
  const incidentSourceSha = completedResume?.incidentSourceSha || consumedImportResume?.incidentSourceSha || sourceSha;
  const authorizedBackendDigestValue = completedResume?.authorizedBackendDigest || consumedImportResume?.authorizedBackendDigest || authorization.authorizedBackendDigest;
  const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authorizedBackendDigestValue}`;
  const readback = assertForwardRevisionReadback({ readback: await describe(STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn), expectedFingerprint: fingerprint, imageReleaseSha: existing?.imageReleaseSha || bindings.imageReleaseSha, backendImage });
  const stateLineage = existing?.stateLineage || observedState.lineage;
  const stateSerial = existing?.stateSerial ?? observedState.serial;
  const stateBeforeSha256 = existing?.stateBeforeSha256 || stateSnapshotSha256(observedState);
  const incidentIdentity = completedResume || consumedImportResume ? existing.incidentIdentity : canonicalForwardRecoveryIncidentIdentity({ sourceSha: incidentSourceSha, toolingTreeSha256: authorization.derived.toolingTreeSha256, sourceContractSha256: authorization.derived.sourceContractSha256, imageReleaseSha: bindings.imageReleaseSha, authorizedBackendDigest: authorization.authorizedBackendDigest, imageAuthorizationSha256: authorization.authorization.evidenceSha256, imageAuthorizationSourceSha: authorization.authorization.sourceSha, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn: readback.arn, censusSha256: censusEvidence.censusSha256, fingerprint });
  const expected = completedResume || consumedImportResume ? expectedFieldsFromJournal(existing) : expectedFields({ sourceSha: incidentSourceSha, authorization, bindings, censusEvidence, fingerprint, incidentIdentity, stateBeforeSha256 });
  const preparedDescendantRestart = preparedResume && preparedResume.sourceSha !== sourceSha;
  if (existing) {
    if (!preparedDescendantRestart) validateExistingRevisionForwardJournal(existing, expected);
    if (["COMPLETED", "RECONCILED"].includes(existing.phase)) {
      validateForwardRecoveryEvidence(evidence.read(), existing, expected);
      if (stateSnapshotSha256(observedState) !== existing.stateAfterImportSha256 || observedState.lineage !== existing.stateLineage || observedState.serial !== existing.stateSerial + 1 || (backendInstance(observedState)?.attributes?.arn || backendInstance(observedState)?.attributes?.id) !== existing.existingRevisionArn) throw new Error("Forward recovery replay observed state drift after reconciliation.");
      return { incidentIdentity, imported: false, phase: existing.phase, registrationCalls: 0, importCalls: 0, state: observedState, readback, census: censusEvidence };
    }
    if (existing.phase === "IMPORTING") {
      if (!importRetryState) {
        const afterBinding = assertForwardImportedState({ beforeStateSha256: existing.stateBeforeSha256, after: observedState });
        if (existing.stateAfterImportSha256 !== undefined && existing.stateAfterImportSha256 !== afterBinding.stateSha256) throw new Error("Forward recovery importing checkpoint hash does not match the authenticated imported state.");
        const recoveredEvidence = persistForwardRecoveryEvidence(buildForwardRecoveryEvidence(expected, afterBinding.stateSha256), evidence);
        journal.write({ ...existing, ...recoveredEvidence, schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, stateAfterImportSha256: afterBinding.stateSha256, phase: "COMPLETED" });
        return { incidentIdentity, imported: false, phase: "COMPLETED", recoveredFromPhase: "IMPORTING", registrationCalls: 0, importCalls: 0, state: observedState, readback, census: censusEvidence, evidence: recoveredEvidence };
      }
    }
  }
  const beforeState = observedState;
  const before = assertForwardStateBeforeImport(beforeState);
  if (existing?.stateBeforeSha256 !== undefined && existing.stateBeforeSha256 !== before.stateSha256) throw new Error("Forward recovery current state no longer matches the prepared incident.");
  if (preparedDescendantRestart) journal.write({ schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, phase: "PREPARED", ...expected, stateBeforeSha256: before.stateSha256, registrationCalls: 0, registrationCapability: "NONE", importCalls: 0 });
  else if (!existing) journal.write({ schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, phase: "PREPARED", ...expected, stateBeforeSha256: before.stateSha256, registrationCalls: 0, registrationCapability: "NONE", importCalls: 0 });
  if (preparedDescendantRestart) return { incidentIdentity, imported: false, reauthorized: true, phase: "PREPARED", registrationCalls: 0, importCalls: 0, state: beforeState, readback, census: censusEvidence };
  const latestBeforeImportState = await readState();
  const latestBeforeImport = assertForwardStateBeforeImport(latestBeforeImportState);
  if (latestBeforeImport.stateSha256 !== before.stateSha256) throw new Error("Forward recovery state changed before the governed import boundary.");
  const latestCensusEvidence = assertForwardCensus({ census: await census() });
  if (latestCensusEvidence.censusSha256 !== censusEvidence.censusSha256) throw new Error("Forward recovery ECS census changed before the governed import boundary.");
  const latestReadback = assertForwardRevisionReadback({ readback: await describe(STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn), expectedFingerprint: fingerprint, imageReleaseSha: existing?.imageReleaseSha || bindings.imageReleaseSha, backendImage });
  if (latestReadback.fingerprint !== readback.fingerprint) throw new Error("Forward recovery canonical :9 readback changed before the governed import boundary.");
  if (typeof validateImportBindings === "function") validateImportBindings();
  const prepared = journal.read();
  journal.write({ ...prepared, ...expected, phase: "IMPORTING", importCalls: 1, importMayHaveOccurred: true, importAttemptCount: importRetryState ? 2 : 1, ...(importRetryState ? { importRetryAuthorized: true } : {}) });
  try {
    await importState({ address: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.address, arn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn });
  } catch (error) {
    if (!importRetryState) {
      const failedState = await readState();
      const failedBefore = assertForwardStateBeforeImport(failedState);
      const currentJournal = journal.read();
      if (currentJournal?.phase === "IMPORTING" && currentJournal.importAttemptCount === 1 && failedBefore.stateSha256 === currentJournal.stateBeforeSha256) {
        journal.write({ ...currentJournal, importAttemptOutcome: "FAILED_BEFORE_STATE_MUTATION", importFailureStateSha256: failedBefore.stateSha256 });
      }
    }
    throw error;
  }
  interruptAt?.("AFTER_IMPORT");
  const after = await readState();
  const afterBinding = assertForwardStateAfterImport(beforeState, after);
  interruptAt?.("AFTER_POST_IMPORT_VERIFICATION");
  const completedEvidence = persistForwardRecoveryEvidence(buildForwardRecoveryEvidence(expected, afterBinding.stateSha256), evidence);
  interruptAt?.("AFTER_EVIDENCE_PERSISTED");
  journal.write({ ...journal.read(), ...completedEvidence, schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, phase: "COMPLETED" });
  interruptAt?.("AFTER_COMPLETED");
  return { incidentIdentity, imported: true, phase: "COMPLETED", registrationCalls: 0, importCalls: 1, state: after, readback, census: censusEvidence, evidence: completedEvidence };
}
