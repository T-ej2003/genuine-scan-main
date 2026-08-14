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
  schemaVersion: 1,
  kind: "STAGE_B_EXISTING_REVISION_ZERO_REGISTRATION_ADOPTION",
  mode: "EXISTING_REVISION_ZERO_REGISTRATION_ADOPTION",
  address: STAGE_B_BACKEND_RECOVERY.address,
  family: STAGE_B_BACKEND_RECOVERY.family,
  existingRevisionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9",
  lineage: STAGE_B_BACKEND_RECOVERY.lineage,
  startSerial: 94,
});

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;

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
  const entries = assertCanonicalBackendRecoveryCensus({ census });
  const target = entries.find(({ arn }) => arn === STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn);
  if (!target || entries[0].arn !== target.arn) throw new Error("Forward recovery requires the exact canonical :9 revision to be newest.");
  if (entries.some(({ revision }) => revision > 9)) throw new Error("Forward recovery refuses an unexpected newer backend revision.");
  return Object.freeze({ entries, newestArn: target.arn, censusSha256: canonicalSha256(entries) });
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
  if (!authorization || authorization.sourceSha !== journalState.sourceSha || authorization.imageReleaseSha !== journalState.imageReleaseSha
    || authorization.evidenceSha256 !== journalState.imageAuthorizationSha256 || authorization.authorizationSha256 !== authorization.evidenceSha256
    || imageAuthorizationSha256(authorization) !== authorization.evidenceSha256) throw new Error("Forward consumed-import replay authorization does not preserve the original incident identity.");
  if (authorizedBackendDigest(authorization) !== journalState.authorizedBackendDigest) throw new Error("Forward consumed-import replay image digest does not preserve the original incident.");
  const incidentProvenance = deriveProvenance?.({ sourceSha: journalState.sourceSha, protectedCheckout });
  const executorProvenance = deriveProvenance?.({ sourceSha, protectedCheckout });
  if (!incidentProvenance || incidentProvenance.toolingTreeSha256 !== journalState.toolingTreeSha256 || incidentProvenance.sourceContractSha256 !== journalState.sourceContractSha256
    || !executorProvenance || !SHA256.test(executorProvenance.toolingTreeSha256 || "") || executorProvenance.sourceContractSha256 !== journalState.sourceContractSha256) throw new Error("Forward consumed-import replay provenance is not bound to the original incident and protected executor.");
  const reuse = deriveImageReuse?.({ imageReleaseSha: journalState.imageReleaseSha, toolingSha: sourceSha });
  assertProductionImageReuseResult(reuse);
  if (reuse.toolingSha !== sourceSha || reuse.imageReleaseSha !== journalState.imageReleaseSha || reuse.imageAffectingFiles.length !== 0 || reuse.imageBuildInputsChanged === true) throw new Error("Forward consumed-import replay image reuse is not explicitly compatible with the protected executor.");
  return Object.freeze({ incidentSourceSha: journalState.sourceSha, authorizedBackendDigest: journalState.authorizedBackendDigest, fingerprint: journalState.fingerprint, incidentProvenance, executorProvenance, reuse });
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

export function canonicalForwardRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, authorizedBackendDigest, imageAuthorizationSha256, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn, censusSha256, fingerprint } = {}) {
  if (!SHA.test(sourceSha || "") || !SHA256.test(toolingTreeSha256 || "") || !SHA256.test(sourceContractSha256 || "") || !SHA.test(imageReleaseSha || "")
    || !/^sha256:[a-f0-9]{64}$/.test(authorizedBackendDigest || "") || !SHA256.test(imageAuthorizationSha256 || "") || stateLineage !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage
    || stateSerial !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial || !SHA256.test(stateBeforeSha256 || "") || existingRevisionArn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn || !SHA256.test(censusSha256 || "") || !SHA256.test(fingerprint || "")) throw new Error("Forward recovery incident identity is incomplete.");
  return canonicalSha256({ schemaVersion: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, authorizedBackendDigest, imageAuthorizationSha256, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn, censusSha256, fingerprint });
}

export function validateExistingRevisionForwardJournal(journal, expected) {
  if (!journal || journal.schemaVersion !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.schemaVersion || journal.kind !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind || journal.mode !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode || journal.incidentIdentity !== expected.incidentIdentity || journal.registrationCalls !== 0 || journal.registrationCapability !== "NONE" || journal.sourceSha !== expected.sourceSha || journal.toolingTreeSha256 !== expected.toolingTreeSha256 || journal.sourceContractSha256 !== expected.sourceContractSha256 || journal.imageReleaseSha !== expected.imageReleaseSha || journal.authorizedBackendDigest !== expected.authorizedBackendDigest || journal.imageAuthorizationSha256 !== expected.imageAuthorizationSha256 || journal.stateLineage !== expected.stateLineage || journal.stateSerial !== expected.stateSerial || journal.stateBeforeSha256 !== expected.stateBeforeSha256 || journal.existingRevisionArn !== expected.existingRevisionArn || journal.censusSha256 !== expected.censusSha256 || journal.fingerprint !== expected.fingerprint || !["PREPARED", "IMPORTING", "RECONCILED", "COMPLETED"].includes(journal.phase)) throw new Error("Forward recovery journal is not the exact zero-registration incident.");
  if (["IMPORTING", "RECONCILED", "COMPLETED"].includes(journal.phase) && !SHA256.test(journal.stateBeforeSha256 || "")) throw new Error("Forward recovery journal is missing its authenticated pre-import state hash.");
  if (journal.phase === "IMPORTING" && journal.stateAfterImportSha256 !== undefined && !SHA256.test(journal.stateAfterImportSha256 || "")) throw new Error("Forward recovery importing checkpoint hash is malformed.");
  if (["RECONCILED", "COMPLETED"].includes(journal.phase) && !SHA256.test(journal.stateAfterImportSha256 || "")) throw new Error("Forward recovery journal is missing its authenticated post-import state hash.");
  if (journal.phase === "IMPORTING" && journal.importMayHaveOccurred !== true) throw new Error("Forward recovery importing phase must fail closed as potentially ambiguous.");
  if (journal.phase === "IMPORTING" && journal.importCalls !== 1) throw new Error("Forward recovery importing phase must have exactly one reserved import call.");
  if (["RECONCILED", "COMPLETED"].includes(journal.phase) && (!SHA256.test(journal.evidenceSha256 || "") || journal.registrationCalls !== 0 || journal.importCalls !== 1 || !SHA256.test(journal.stateAfterImportSha256 || ""))) throw new Error("Forward recovery completed evidence bindings are incomplete.");
  return journal;
}

export function buildForwardRecoveryEvidence(expected, stateAfterImportSha256) {
  const body = { schemaVersion: 1, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, ...expected, stateAfterImportSha256, registrationCalls: 0, importCalls: 1 };
  return { ...body, evidenceSha256: canonicalSha256(body) };
}

function expectedFieldsFromJournal(journal) {
  return { incidentIdentity: journal.incidentIdentity, sourceSha: journal.sourceSha, toolingTreeSha256: journal.toolingTreeSha256, sourceContractSha256: journal.sourceContractSha256, imageReleaseSha: journal.imageReleaseSha, authorizedBackendDigest: journal.authorizedBackendDigest, imageAuthorizationSha256: journal.imageAuthorizationSha256, stateLineage: journal.stateLineage, stateSerial: journal.stateSerial, stateBeforeSha256: journal.stateBeforeSha256, existingRevisionArn: journal.existingRevisionArn, censusSha256: journal.censusSha256, fingerprint: journal.fingerprint };
}

export function validateForwardRecoveryEvidence(evidence, journal, expected) {
  const expectedEvidence = buildForwardRecoveryEvidence(expected, journal.stateAfterImportSha256);
  if (!evidence || canonicalJson(evidence) !== canonicalJson(expectedEvidence) || journal.evidenceSha256 !== expectedEvidence.evidenceSha256) throw new Error("Forward recovery evidence is not the exact authenticated completed incident result.");
  return evidence;
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
  return { incidentIdentity, sourceSha, toolingTreeSha256: authorization.derived.toolingTreeSha256, sourceContractSha256: authorization.derived.sourceContractSha256, imageReleaseSha: bindings.imageReleaseSha, authorizedBackendDigest: authorization.authorizedBackendDigest, imageAuthorizationSha256: authorization.authorization.evidenceSha256, stateLineage: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.lineage, stateSerial: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.startSerial, stateBeforeSha256, existingRevisionArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn, censusSha256: censusEvidence.censusSha256, fingerprint };
}

export async function runExistingRevisionForwardRecovery({ bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse, readState, census, describe, importState, evidence, journal, interruptAt } = {}) {
  if (typeof readState !== "function" || typeof census !== "function" || typeof describe !== "function" || typeof importState !== "function" || !journal?.read || !journal?.write || !evidence?.read || !evidence?.write) throw new Error("Forward recovery requires read, census, describe, import, journal, and durable evidence adapters.");
  const existing = journal.read();
  const observedState = await readState();
  const completedResume = existing && ["COMPLETED", "RECONCILED"].includes(existing.phase)
    ? assertForwardCompletedResume({ sourceSha, protectedCheckout, journalState: existing, proveDescendant })
    : null;
  const consumedImportResume = existing?.phase === "IMPORTING"
    ? assertForwardConsumedImportResume({ sourceSha, bindings, protectedCheckout, journalState: existing, imageAuthorization, deriveProvenance, deriveImageReuse, proveDescendant })
    : null;
  const authorization = completedResume || consumedImportResume ? null : assertForwardSourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse });
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
  const incidentIdentity = completedResume || consumedImportResume ? existing.incidentIdentity : canonicalForwardRecoveryIncidentIdentity({ sourceSha: incidentSourceSha, toolingTreeSha256: authorization.derived.toolingTreeSha256, sourceContractSha256: authorization.derived.sourceContractSha256, imageReleaseSha: bindings.imageReleaseSha, authorizedBackendDigest: authorization.authorizedBackendDigest, imageAuthorizationSha256: authorization.authorization.evidenceSha256, stateLineage, stateSerial, stateBeforeSha256, existingRevisionArn: readback.arn, censusSha256: censusEvidence.censusSha256, fingerprint });
  const expected = completedResume || consumedImportResume ? expectedFieldsFromJournal(existing) : expectedFields({ sourceSha: incidentSourceSha, authorization, bindings, censusEvidence, fingerprint, incidentIdentity, stateBeforeSha256 });
  if (existing) {
    validateExistingRevisionForwardJournal(existing, expected);
    if (["COMPLETED", "RECONCILED"].includes(existing.phase)) {
      validateForwardRecoveryEvidence(evidence.read(), existing, expected);
      if (stateSnapshotSha256(observedState) !== existing.stateAfterImportSha256 || observedState.lineage !== existing.stateLineage || observedState.serial !== existing.stateSerial + 1 || (backendInstance(observedState)?.attributes?.arn || backendInstance(observedState)?.attributes?.id) !== existing.existingRevisionArn) throw new Error("Forward recovery replay observed state drift after reconciliation.");
      return { incidentIdentity, imported: false, registrationCalls: 0, importCalls: 0, state: observedState, readback, census: censusEvidence };
    }
    if (existing.phase === "IMPORTING") {
      const afterBinding = assertForwardImportedState({ beforeStateSha256: existing.stateBeforeSha256, after: observedState });
      if (existing.stateAfterImportSha256 !== undefined && existing.stateAfterImportSha256 !== afterBinding.stateSha256) throw new Error("Forward recovery importing checkpoint hash does not match the authenticated imported state.");
      const recoveredEvidence = persistForwardRecoveryEvidence(buildForwardRecoveryEvidence(expected, afterBinding.stateSha256), evidence);
      journal.write({ ...existing, ...recoveredEvidence, stateAfterImportSha256: afterBinding.stateSha256, phase: "COMPLETED" });
      return { incidentIdentity, imported: false, registrationCalls: 0, importCalls: 0, state: observedState, readback, census: censusEvidence, evidence: recoveredEvidence };
    }
  }
  const beforeState = observedState;
  const before = assertForwardStateBeforeImport(beforeState);
  if (existing?.stateBeforeSha256 !== undefined && existing.stateBeforeSha256 !== before.stateSha256) throw new Error("Forward recovery current state no longer matches the prepared incident.");
  if (!existing) journal.write({ schemaVersion: 1, kind: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.kind, mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, phase: "PREPARED", ...expected, stateBeforeSha256: before.stateSha256, registrationCalls: 0, registrationCapability: "NONE", importCalls: 0 });
  const latestBeforeImportState = await readState();
  const latestBeforeImport = assertForwardStateBeforeImport(latestBeforeImportState);
  if (latestBeforeImport.stateSha256 !== before.stateSha256) throw new Error("Forward recovery state changed before the governed import boundary.");
  const prepared = journal.read();
  journal.write({ ...prepared, ...expected, phase: "IMPORTING", importCalls: 1, importMayHaveOccurred: true });
  await importState({ address: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.address, arn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn });
  interruptAt?.("AFTER_IMPORT");
  const after = await readState();
  const afterBinding = assertForwardStateAfterImport(beforeState, after);
  interruptAt?.("AFTER_POST_IMPORT_VERIFICATION");
  const completedEvidence = persistForwardRecoveryEvidence(buildForwardRecoveryEvidence(expected, afterBinding.stateSha256), evidence);
  interruptAt?.("AFTER_EVIDENCE_PERSISTED");
  journal.write({ ...journal.read(), ...completedEvidence, phase: "COMPLETED" });
  interruptAt?.("AFTER_COMPLETED");
  return { incidentIdentity, imported: true, registrationCalls: 0, importCalls: 1, state: after, readback, census: censusEvidence, evidence: completedEvidence };
}
