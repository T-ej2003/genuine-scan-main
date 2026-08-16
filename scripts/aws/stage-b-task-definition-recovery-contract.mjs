import crypto from "node:crypto";
import { renderStageBTaskDefinition, assertFixedTaskDefinition } from "./production-green-stage-b-task-definitions.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertStageBImageReuseResult, deriveStageBImageImpactReport, STAGE_B_IMAGE_REUSE_RULES_VERSION } from "./validate-stage-b-image-reuse.mjs";

export const STAGE_B_BACKEND_RECOVERY = Object.freeze({
  address: 'aws_ecs_task_definition.candidate["backend"]',
  family: "mscqr-production-rls-green-backend-candidate",
  predecessorArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:5",
  historicalRevisionArns: Object.freeze([
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:6",
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7",
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8",
  ]),
  newestHistoricalArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8",
  lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a",
  serial: 93,
  tags: Object.freeze([
    { key: "Component", value: "full-rls-green-stage-b" },
    { key: "Environment", value: "production" },
    { key: "MSCQRExecTarget", value: "production-backend" },
    { key: "ManagedBy", value: "Terraform" },
  ]),
});

const ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:([1-9][0-9]*)$/;
const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const LINEAGE = /^[a-f0-9-]{36}$/;
const DIGEST = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const RECOVERY_SCHEMA_VERSION = 4;
const RECOVERY_KIND = "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY";
const CHECKPOINT_HASH_DOMAIN = "stage-b-recovery-checkpoint-v2";
const REGISTERED_RESUME_PHASES = new Set(["REGISTERED", "READBACK_VERIFIED", "STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED"]);
const CROSS_DESCENDANT_REUSE_CATEGORIES = new Set(["toolingOnly", "testOnly", "documentationOnly", "ciOnly"]);

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function canonicalSha256(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function imageDigest(value) {
  const digest = String(value || "").split("@").at(-1);
  if (!IMAGE_DIGEST.test(digest)) throw new Error("Canonical recovery backend image digest is invalid.");
  return digest;
}

export function canonicalRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageDigest: backendImageDigest, imageAuthorizationSha256, stateLineage, stateSerial, predecessorArn, newestHistoricalArn, fingerprint, stateBeforeBindingReportSha256 } = {}) {
  if (!SHA.test(sourceSha || "") || !SHA256.test(toolingTreeSha256 || "") || !SHA256.test(sourceContractSha256 || "")
    || !SHA.test(imageReleaseSha || "") || !IMAGE_DIGEST.test(backendImageDigest || "") || !SHA256.test(imageAuthorizationSha256 || "")
    || !LINEAGE.test(stateLineage || "") || !Number.isInteger(stateSerial) || predecessorArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn
    || !ARN.test(newestHistoricalArn || "") || !SHA256.test(fingerprint || "")
    || stateBeforeBindingReportSha256 !== undefined && !SHA256.test(stateBeforeBindingReportSha256)) throw new Error("Canonical recovery incident identity inputs are incomplete.");
  return canonicalSha256({ schemaVersion: RECOVERY_SCHEMA_VERSION, kind: RECOVERY_KIND, sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageDigest: backendImageDigest, imageAuthorizationSha256, stateLineage, stateSerial, predecessorArn, newestHistoricalArn, fingerprint, ...(stateBeforeBindingReportSha256 === undefined ? {} : { stateBeforeBindingReportSha256 }) });
}

export function assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is required for backend recovery.");
  assertCanonicalRecoveryExecutorCheckout({ sourceSha, protectedCheckout });
  if (!bindings || bindings.toolingSha !== sourceSha || bindings.sourceSha !== sourceSha || !SHA.test(bindings.imageReleaseSha || "")
    || !SHA256.test(bindings.toolingTreeSha256 || "") || !SHA256.test(bindings.sourceContractSha256 || "")) throw new Error("Canonical recovery tooling, source-content, and image-release identities are incomplete.");
  const authorization = imageAuthorization || bindings.imageAuthorization;
  if (!authorization || bindings.imageReleaseSha !== authorization.imageReleaseSha) throw new Error("Canonical recovery image-release identity does not match image authorization.");
  const authorizationValidation = imageAuthorizationValidation || bindings.imageAuthorizationValidation;
  if (!authorizationValidation || typeof authorizationValidation.verifyImageEvidence !== "function") throw new Error("Canonical recovery image authorization verifier context is required.");
  assertImageAuthorization(authorization, sourceSha, authorizationValidation);
  const authorizedDigest = authorizedBackendDigest(authorization);
  if (!IMAGE_DIGEST.test(authorizedDigest || "") || bindings.backendImage !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authorizedDigest}`) throw new Error("Canonical recovery backend image does not match image authorization.");
  const derived = typeof deriveProvenance === "function" ? deriveProvenance({ sourceSha, protectedCheckout }) : null;
  if (!derived || derived.toolingTreeSha256 !== bindings.toolingTreeSha256 || derived.sourceContractSha256 !== bindings.sourceContractSha256
    || !SHA256.test(derived.toolingTreeSha256 || "") || !SHA256.test(derived.sourceContractSha256 || "")) throw new Error("Canonical recovery source provenance was not derived from the protected source.");
  return derived;
}

function assertCanonicalRecoveryExecutorCheckout({ sourceSha, protectedCheckout } = {}) {
  if (!protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.toolingSha !== sourceSha
    || protectedCheckout.originMainHead !== sourceSha || protectedCheckout.isAncestor !== true || protectedCheckout.porcelainStatus) {
    throw new Error("Canonical recovery requires the exact clean protected-main checkout.");
  }
  return protectedCheckout;
}

export function assertCanonicalRecoveryDescendantResume({ sourceSha, bindings, protectedCheckout, journalState, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse = ({ imageReleaseSha, toolingSha }) => { const report = deriveStageBImageImpactReport({ imageReleaseSha, toolingSha }); return { ...report, imageBuildInputsChanged: report.newImagesRequired }; } } = {}) {
  if (!journalState || journalState.schemaVersion !== RECOVERY_SCHEMA_VERSION || journalState.kind !== RECOVERY_KIND) throw new Error("Cross-descendant recovery resume requires a schema-v4 incident journal.");
  if (journalState.checkpointHashDomain !== undefined && journalState.checkpointHashDomain !== CHECKPOINT_HASH_DOMAIN) throw new Error("Canonical recovery journal has an unreviewed checkpoint hash domain.");
  const completed = journalState.phase === "COMPLETED";
  if ((!REGISTERED_RESUME_PHASES.has(journalState.phase) && !completed) || journalState.registrationCalls !== 1 || journalState.registrationMayHaveOccurred !== true
    || !ARN.test(journalState.replacementArn || "") || STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(journalState.replacementArn)) {
    throw new Error("Cross-descendant recovery resume requires an already-registered canonical replacement and consumed registration budget.");
  }
  if (!SHA.test(sourceSha || "") || !SHA.test(journalState.sourceSha || "") || sourceSha === journalState.sourceSha) throw new Error("Cross-descendant recovery resume requires a different protected executor SHA.");
  assertCanonicalRecoveryExecutorCheckout({ sourceSha, protectedCheckout });
  if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: journalState.sourceSha, descendantSha: sourceSha }) !== true) throw new Error("Current protected main is not a proven descendant of the original recovery incident source.");
  if (!bindings || bindings.sourceSha !== journalState.sourceSha || bindings.toolingSha !== journalState.toolingSha
    || bindings.imageReleaseSha !== journalState.imageReleaseSha || bindings.sourceContractSha256 !== journalState.sourceContractSha256
    || bindings.imageAuthorizationSha256 !== undefined && bindings.imageAuthorizationSha256 !== journalState.imageAuthorizationSha256) {
    throw new Error("Cross-descendant recovery bindings do not preserve the original incident identity.");
  }
  const expectedIncidentIdentity = canonicalRecoveryIncidentIdentity({ sourceSha: journalState.sourceSha, toolingTreeSha256: journalState.toolingTreeSha256, sourceContractSha256: journalState.sourceContractSha256, imageReleaseSha: journalState.imageReleaseSha, imageDigest: imageDigest(journalState.imageDigest), imageAuthorizationSha256: journalState.imageAuthorizationSha256, stateLineage: journalState.stateLineage, stateSerial: journalState.stateSerial, predecessorArn: journalState.predecessorArn, newestHistoricalArn: journalState.newestHistoricalArn, fingerprint: journalState.protectedSourceFingerprint, stateBeforeBindingReportSha256: journalState.stateBeforeBindingReportSha256 });
  if (journalState.incidentIdentity !== expectedIncidentIdentity) throw new Error("Cross-descendant recovery journal incident identity is not deterministic for its original bindings.");
  const incidentProvenance = typeof deriveProvenance === "function" ? deriveProvenance({ sourceSha: journalState.sourceSha, protectedCheckout }) : null;
  if (!incidentProvenance || incidentProvenance.toolingTreeSha256 !== journalState.toolingTreeSha256 || incidentProvenance.sourceContractSha256 !== journalState.sourceContractSha256) throw new Error("Original recovery incident provenance cannot be re-derived from the protected checkout history.");
  const executorProvenance = typeof deriveProvenance === "function" ? deriveProvenance({ sourceSha, protectedCheckout }) : null;
  if (!executorProvenance || !SHA256.test(executorProvenance.toolingTreeSha256 || "") || !SHA256.test(executorProvenance.sourceContractSha256 || "")
    || executorProvenance.sourceContractSha256 !== journalState.sourceContractSha256) throw new Error("Current protected executor provenance is not compatible with the original recovery incident.");
  const authorization = imageAuthorization || bindings.imageAuthorization;
  if (!authorization || authorization.evidenceSha256 !== journalState.imageAuthorizationSha256 || authorization.imageReleaseSha !== journalState.imageReleaseSha) throw new Error("Cross-descendant recovery image authorization does not preserve the original incident authorization.");
  if (!imageAuthorizationValidation || typeof imageAuthorizationValidation.verifyImageEvidence !== "function") throw new Error("Canonical recovery image authorization verifier context is required.");
  assertImageAuthorization(authorization, journalState.sourceSha, imageAuthorizationValidation);
  const authorizedDigest = authorizedBackendDigest(authorization);
  if (!IMAGE_DIGEST.test(authorizedDigest || "") || authorizedDigest !== journalState.authorizedBackendImageDigest
    || bindings.backendImage !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authorizedDigest}`) throw new Error("Cross-descendant recovery backend image does not preserve the original authorized digest.");
  let reuse;
  try { reuse = deriveImageReuse({ imageReleaseSha: journalState.imageReleaseSha, toolingSha: sourceSha }); } catch (error) { throw new Error(`Cross-descendant image reuse proof failed: ${error.message}`); }
  assertStageBImageReuseResult(reuse);
  if (reuse.toolingSha !== sourceSha || reuse.imageReleaseSha !== journalState.imageReleaseSha || reuse.comparisonBaseSha !== journalState.imageReleaseSha
    || reuse.comparisonHeadIdentity !== "tooling-input-tree-sha256" || reuse.comparisonHeadSha256 !== reuse.toolingInputTreeSha256 || reuse.classificationRulesVersion !== STAGE_B_IMAGE_REUSE_RULES_VERSION
    || !SHA256.test(reuse.toolingInputTreeSha256 || "") || !Array.isArray(reuse.classifiedChangedFiles) || !Array.isArray(reuse.imageAffectingFiles)
    || reuse.imageAffectingFiles.length !== 0) throw new Error("Cross-descendant image reuse proof contains a runtime, image-affecting, or unreviewed change.");
  const hasTrustedToolingOnly = reuse.classifiedChangedFiles.some(({ category }) => category === "trustedToolingOnly");
  if (reuse.classifiedChangedFiles.some(({ category }) => category !== "trustedToolingOnly" && !CROSS_DESCENDANT_REUSE_CATEGORIES.has(category))) throw new Error("Cross-descendant image reuse proof contains an unreviewed change category.");
  if (completed) throw new Error("Completed cross-descendant recovery incidents are terminal and cannot be resumed.");
  return Object.freeze({ incidentSourceSha: journalState.sourceSha, incidentProvenance, executorToolingSha: sourceSha, executorProvenance, imageReuse: reuse });
}

const sortBy = (items, key) => Array.isArray(items) ? [...items].sort((a, b) => String(a?.[key] ?? "").localeCompare(String(b?.[key] ?? ""))) : items;

function semanticDefinition(value, tags = value?.tags) {
  const source = value?.taskDefinition || value;
  if (!source || typeof source !== "object" || Array.isArray(source)) throw new Error("Task-definition readback is malformed.");
  const definition = structuredClone(source);
  delete definition.taskDefinitionArn;
  delete definition.revision;
  delete definition.status;
  delete definition.registeredAt;
  delete definition.registeredBy;
  delete definition.requiresAttributes;
  delete definition.compatibilities;
  delete definition.tags;
  if (Array.isArray(definition.placementConstraints) && definition.placementConstraints.length === 0) delete definition.placementConstraints;
  if (Array.isArray(definition.volumes)) {
    definition.volumes = definition.volumes.map((volume) => {
      const keys = Object.keys(volume || {}).filter((key) => !["name", "host", "configureAtLaunch"].includes(key));
      if (keys.length || typeof volume?.name !== "string" || (volume.configureAtLaunch !== undefined && volume.configureAtLaunch !== false)
        || (volume.host !== undefined && (!volume.host || typeof volume.host !== "object" || Object.keys(volume.host).length))) throw new Error("Task-definition volume contains an unreviewed provider field.");
      return { name: volume.name };
    });
  }
  definition.containerDefinitions = sortBy(definition.containerDefinitions, "name")?.map((container) => {
    const normalized = {
      ...container,
      environment: sortBy(container.environment, "name"),
      secrets: sortBy(container.secrets, "name"),
      portMappings: sortBy(container.portMappings, "name"),
      mountPoints: sortBy(container.mountPoints, "containerPath"),
      ulimits: sortBy(container.ulimits, "name"),
      systemControls: sortBy(container.systemControls, "namespace"),
      dependsOn: sortBy(container.dependsOn, "containerName"),
    };
    if (normalized.cpu === 0) delete normalized.cpu;
    if (Array.isArray(normalized.volumesFrom) && normalized.volumesFrom.length === 0) delete normalized.volumesFrom;
    if (Array.isArray(normalized.systemControls) && normalized.systemControls.length === 0) normalized.systemControls = undefined;
    return normalized;
  });
  definition.volumes = sortBy(definition.volumes, "name");
  const normalizedTags = sortBy(tags, "key");
  if (!Array.isArray(normalizedTags)) throw new Error("Task-definition tags are required for recovery fingerprinting.");
  return { taskDefinition: definition, tags: normalizedTags };
}

export function taskDefinitionFingerprint(value, tags = value?.tags) {
  return canonicalSha256(semanticDefinition(value, tags));
}

export function buildCanonicalBackendRecoveryTaskDefinition(bindings) {
  if (!bindings || typeof bindings !== "object" || Array.isArray(bindings)) throw new Error("Canonical backend recovery bindings are required.");
  if (!DIGEST.test(bindings.backendImage || "")) throw new Error("Canonical backend recovery image must be an immutable backend digest.");
  if (!SHA.test(bindings.imageReleaseSha || "")) throw new Error("Canonical backend recovery release SHA is invalid.");
  const taskDefinition = renderStageBTaskDefinition("backend", bindings);
  taskDefinition.runtimePlatform = { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" };
  assertFixedTaskDefinition(taskDefinition);
  return { taskDefinition, tags: structuredClone(STAGE_B_BACKEND_RECOVERY.tags) };
}

function stateBackendCandidate(state) {
  const resources = Array.isArray(state?.resources) ? state.resources : [];
  const matches = resources.filter((resource) => resource?.type === "aws_ecs_task_definition" && resource?.name === "candidate");
  if (matches.length !== 1 || !Array.isArray(matches[0].instances)) throw new Error("Terraform state does not contain one candidate resource collection.");
  const instances = matches[0].instances.filter((instance) => instance?.index_key === "backend");
  if (instances.length !== 1) throw new Error("Terraform state does not contain exactly one backend candidate instance.");
  const arn = instances[0].attributes?.arn || instances[0].attributes?.id;
  if (!ARN.test(arn || "")) throw new Error("Terraform state backend candidate ARN is malformed.");
  return { resource: matches[0], instance: instances[0], arn };
}

export function assertBackendRecoveryPreconditions({ state, sourceSha, expectedLineage = STAGE_B_BACKEND_RECOVERY.lineage, expectedSerial = STAGE_B_BACKEND_RECOVERY.serial, expectedNewestArn = STAGE_B_BACKEND_RECOVERY.newestHistoricalArn } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is required for backend recovery.");
  if (state?.lineage !== expectedLineage || state?.serial !== expectedSerial) throw new Error("Terraform state lineage or serial is not the reviewed recovery predecessor.");
  if (expectedNewestArn !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn) throw new Error("Live newest backend revision is not the reviewed recovery predecessor.");
  const current = stateBackendCandidate(state);
  if (current.arn !== STAGE_B_BACKEND_RECOVERY.predecessorArn) throw new Error("Terraform state backend candidate is not the exact reviewed :5 predecessor.");
  return { address: STAGE_B_BACKEND_RECOVERY.address, family: STAGE_B_BACKEND_RECOVERY.family, predecessorArn: current.arn, sourceSha, lineage: state.lineage, serial: state.serial, newestHistoricalArn: expectedNewestArn };
}

function replacementArn(value) {
  const match = ARN.exec(value || "");
  if (!match) throw new Error("Canonical recovery replacement ARN is outside the exact backend family.");
  return { arn: value, revision: Number(match[1]) };
}

export function assertCanonicalBackendRecoveryCensus({ census } = {}) {
  const revisions = census?.complete === true && Array.isArray(census.revisions) ? census.revisions : null;
  if (!Array.isArray(revisions) || revisions.length === 0) throw new Error("Canonical recovery requires a complete ACTIVE backend revision census.");
  const entries = revisions.map((entry) => {
    const readback = entry?.readback || entry;
    const taskDefinition = readback?.taskDefinition || readback;
    const arn = entry?.arn || taskDefinition?.taskDefinitionArn;
    const parsed = replacementArn(arn);
    if (taskDefinition?.taskDefinitionArn !== parsed.arn || taskDefinition.family !== STAGE_B_BACKEND_RECOVERY.family || taskDefinition.status !== "ACTIVE" || Number(taskDefinition.revision) !== parsed.revision) {
      throw new Error("Canonical recovery census contains an unfaithful backend revision readback.");
    }
    return { arn: parsed.arn, revision: parsed.revision, readback };
  }).sort((a, b) => b.revision - a.revision);
  if (new Set(entries.map(({ arn }) => arn)).size !== entries.length) throw new Error("Canonical recovery census contains duplicate backend revisions.");
  return entries;
}

export function assertCanonicalBackendRecoveryReadback({ readback, expectedArn, expectedFingerprint, expectedNewestArn = STAGE_B_BACKEND_RECOVERY.newestHistoricalArn } = {}) {
  const expected = replacementArn(expectedArn);
  const newest = replacementArn(expectedNewestArn);
  if (STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(expected.arn) || expected.revision <= newest.revision) throw new Error("Recovery replacement must be a new revision, never a historical or non-newest revision.");
  const taskDefinition = readback?.taskDefinition || readback;
  if (taskDefinition?.taskDefinitionArn !== expected.arn || taskDefinition.family !== STAGE_B_BACKEND_RECOVERY.family || taskDefinition.status !== "ACTIVE") throw new Error("Recovery replacement is not the exact ACTIVE backend family revision.");
  if (Number(taskDefinition.revision) !== expected.revision) throw new Error("Recovery replacement revision metadata does not match its ARN.");
  if (taskDefinitionFingerprint(taskDefinition, readback?.tags) !== expectedFingerprint) throw new Error("Recovery replacement semantic fingerprint differs from protected source.");
  return { arn: expected.arn, revision: expected.revision, fingerprint: expectedFingerprint, active: true, newest: true };
}

function stateWithoutBackend(state) {
  return {
    ...state,
    resources: (state?.resources || []).flatMap((resource) => {
      if (resource.type !== "aws_ecs_task_definition" || resource.name !== "candidate") return [resource];
      const instances = (resource.instances || []).filter((instance) => instance.index_key !== "backend");
      return instances.length ? [{ ...resource, instances }] : [];
    }),
  };
}

const TERRAFORM_VERSION = /^\d+\.\d+\.\d+$/;
const REVIEWED_TERRAFORM_VERSIONS = new Set(["1.15.7", "1.15.8"]);

export function normalizeTerraformRecoveryCheckpointState(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) throw new Error("Terraform recovery checkpoint state is malformed.");
  const normalized = structuredClone(state);
  if (Object.hasOwn(normalized, "terraform_version")) {
    if (!TERRAFORM_VERSION.test(normalized.terraform_version || "")) throw new Error("Terraform recovery checkpoint version is malformed.");
    if (REVIEWED_TERRAFORM_VERSIONS.has(normalized.terraform_version)) normalized.terraform_version = "<terraform-generated-version>";
  }
  if (Object.hasOwn(normalized, "check_results")) {
    if (!Array.isArray(normalized.check_results)) throw new Error("Terraform recovery checkpoint check results are malformed.");
    normalized.check_results = [...normalized.check_results].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  }
  return normalized;
}

export function stateSnapshotSha256(state) {
  return canonicalSha256(normalizeTerraformRecoveryCheckpointState(state));
}

function legacyStateSnapshotSha256(state) {
  return canonicalSha256(state);
}

function checkpointStateSha256(journalState, state) {
  if (journalState.checkpointHashDomain === undefined) return legacyStateSnapshotSha256(state);
  if (journalState.checkpointHashDomain !== CHECKPOINT_HASH_DOMAIN) throw new Error("Canonical recovery journal has an unreviewed checkpoint hash domain.");
  return stateSnapshotSha256(state);
}

const LEGACY_CHECKPOINT_COMPATIBILITY = Object.freeze({
  domain: "stage-b-recovery-legacy-semantic-v1",
  terraformVersions: Object.freeze(["1.15.7", "1.15.8"]),
  normalizedFields: Object.freeze(["terraform_version", "check_results"]),
});

function expectedStateAfterRemove(state) {
  return { ...stateWithoutBackend(state), serial: state.serial + 1 };
}

function requireJournal(journal) {
  if (!journal || typeof journal.read !== "function" || typeof journal.write !== "function") throw new Error("Canonical recovery requires a persistent recovery journal.");
  return journal;
}

function validateJournal(journalState, { sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest: backendImageDigest, newestHistoricalArn, incidentIdentity, stateBeforeBindingReportSha256 } = {}) {
  if (!journalState || journalState.schemaVersion !== RECOVERY_SCHEMA_VERSION || journalState.kind !== RECOVERY_KIND
    || journalState.incidentIdentity !== incidentIdentity || journalState.sourceSha !== sourceSha || journalState.toolingSha !== sourceSha
    || journalState.toolingTreeSha256 !== toolingTreeSha256 || journalState.sourceContractSha256 !== sourceContractSha256 || journalState.address !== STAGE_B_BACKEND_RECOVERY.address
    || journalState.family !== STAGE_B_BACKEND_RECOVERY.family || journalState.predecessorArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn
    || journalState.newestHistoricalArn !== newestHistoricalArn || !STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(journalState.newestHistoricalArn)
    || journalState.stateLineage !== STAGE_B_BACKEND_RECOVERY.lineage || journalState.stateSerial !== STAGE_B_BACKEND_RECOVERY.serial
    || journalState.predecessorSerial !== STAGE_B_BACKEND_RECOVERY.serial || journalState.protectedSourceFingerprint !== fingerprint || journalState.imageDigest !== backendImageDigest
    || journalState.authorizedBackendImageDigest !== imageDigest(backendImageDigest)
    || journalState.imageReleaseSha !== imageReleaseSha || journalState.imageAuthorizationSha256 !== imageAuthorizationSha256
    || (journalState.stateBeforeBindingReportSha256 !== undefined && !SHA256.test(journalState.stateBeforeBindingReportSha256))
    || journalState.stateBeforeBindingReportSha256 !== stateBeforeBindingReportSha256
    || (journalState.checkpointHashDomain !== undefined && journalState.checkpointHashDomain !== CHECKPOINT_HASH_DOMAIN)
    || !["DISCOVERY", "PREPARED", "REGISTERING", "REGISTERED", "READBACK_VERIFIED", "STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)
    || !Number.isInteger(journalState.registrationCalls) || journalState.registrationCalls < 0 || journalState.registrationCalls > 1
    || typeof journalState.registrationMayHaveOccurred !== "boolean") {
    throw new Error("Canonical recovery journal does not match the reviewed incident and protected source.");
  }
  if (journalState.registrationMayHaveOccurred === false && journalState.registrationCalls !== 0) throw new Error("Canonical recovery journal has an impossible registration budget state.");
  if (["REGISTERED", "READBACK_VERIFIED", "STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)
    && !ARN.test(journalState.replacementArn || "")) throw new Error("Canonical recovery journal is missing its persisted replacement ARN.");
  if (journalState.replacementArn && STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(journalState.replacementArn)) throw new Error("Canonical recovery journal cannot adopt a historical revision.");
  return journalState;
}

export function buildCanonicalRecoveryJournal(state, { sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest: backendImageDigest, newestHistoricalArn, incidentIdentity, stateBeforeBindingReportSha256 } = {}) {
  const expectedIncidentIdentity = canonicalRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageDigest: imageDigest(backendImageDigest), imageAuthorizationSha256, stateLineage: state.lineage, stateSerial: state.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn, fingerprint, stateBeforeBindingReportSha256 });
  if (incidentIdentity !== expectedIncidentIdentity) throw new Error("Canonical recovery incident identity is not deterministic for the reviewed bindings.");
  return {
    schemaVersion: RECOVERY_SCHEMA_VERSION,
    kind: RECOVERY_KIND,
    incidentIdentity,
    phase: "DISCOVERY",
    sourceSha,
    toolingSha: sourceSha,
    toolingTreeSha256,
    sourceContractSha256,
    imageReleaseSha,
    imageAuthorizationSha256,
    authorizedBackendImageDigest: imageDigest(backendImageDigest),
    address: STAGE_B_BACKEND_RECOVERY.address,
    family: STAGE_B_BACKEND_RECOVERY.family,
    predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn,
    newestHistoricalArn,
    stateLineage: state.lineage,
    stateSerial: state.serial,
    predecessorSerial: state.serial,
    stateBeforeSha256: stateSnapshotSha256(state),
    stateAfterRemoveSha256: stateSnapshotSha256(expectedStateAfterRemove(state)),
    ...(stateBeforeBindingReportSha256 === undefined ? {} : { stateBeforeBindingReportSha256 }),
    expectedStateAfterRemoveSerial: state.serial + 1,
    expectedStateAfterImportSerial: state.serial + 2,
    checkpointHashDomain: CHECKPOINT_HASH_DOMAIN,
    protectedSourceFingerprint: fingerprint,
    imageDigest: backendImageDigest,
    registrationCalls: 0,
    registrationMayHaveOccurred: false,
  };
}

function assertLegacyPreRemovalStateAnchor(journalState, stateBefore, stateBeforeAnchor) {
  if (!stateBeforeAnchor || stateBeforeAnchor.schemaVersion !== 2 || stateBeforeAnchor.tfvarsSchemaVersion !== 1
    || stateBeforeAnchor.tfvarsFormat !== "hcl" || stateBeforeAnchor.tfvarsExtension !== ".tfvars"
    || stateBeforeAnchor.generator !== "scripts/aws/generate-production-green-stage-b-tfvars.mjs"
    || stateBeforeAnchor.recoveryOnly !== false || !SHA256.test(stateBeforeAnchor.bindingReportSha256 || "")
    || !SHA256.test(stateBeforeAnchor.stateBackupSha256 || "") || !SHA256.test(stateBeforeAnchor.stateBeforeBytesSha256 || "")
    || stateBeforeAnchor.stateBackupSha256 !== stateBeforeAnchor.stateBeforeBytesSha256
    || stateBeforeAnchor.bindingReportSha256 !== journalState.stateBeforeBindingReportSha256
    || stateBeforeAnchor.toolingSha !== journalState.toolingSha || stateBeforeAnchor.toolingTreeSha256 !== journalState.toolingTreeSha256
    || stateBeforeAnchor.sourceContractSha256 !== journalState.sourceContractSha256 || stateBeforeAnchor.imageReleaseSha !== journalState.imageReleaseSha
    || stateBeforeAnchor.stateLineage !== journalState.stateLineage || stateBeforeAnchor.stateSerial !== journalState.stateSerial) {
    throw new Error("Legacy recovery pre-removal state is not cryptographically bound to the canonical Stage-B binding artifact.");
  }
  return stateBeforeAnchor;
}

export function assertLegacyPostRemoveCheckpointCompatibility(journalState, state, stateBefore, stateBeforeAnchor) {
  if (journalState?.checkpointHashDomain !== undefined) return false;
  if (!SHA256.test(journalState?.stateBeforeSha256 || "") || !SHA256.test(journalState?.stateAfterRemoveSha256 || "")) {
    throw new Error("Legacy recovery checkpoint hashes are malformed.");
  }
  if (!stateBefore || stateBefore.lineage !== journalState.stateLineage || stateBefore.serial !== journalState.stateSerial
    || stateBackendCandidateFromOptional(stateBefore) !== STAGE_B_BACKEND_RECOVERY.predecessorArn) {
    throw new Error("Legacy recovery requires the reviewed pre-removal state snapshot.");
  }
  if (state.lineage !== journalState.stateLineage || state.serial !== journalState.expectedStateAfterRemoveSerial
    || stateBackendCandidateFromOptional(state) !== null) {
    throw new Error("Legacy recovery post-removal state has unexpected lineage, serial, or candidate state.");
  }
  if (!LEGACY_CHECKPOINT_COMPATIBILITY.terraformVersions.includes(stateBefore.terraform_version)
    || !LEGACY_CHECKPOINT_COMPATIBILITY.terraformVersions.includes(state.terraform_version)) {
    throw new Error("Legacy recovery checkpoint uses an unreviewed Terraform version.");
  }
  const expected = expectedStateAfterRemove(stateBefore);
  if (stateSnapshotSha256(expected) !== stateSnapshotSha256(state)) {
    throw new Error(`Legacy recovery checkpoint is outside ${LEGACY_CHECKPOINT_COMPATIBILITY.domain}.`);
  }
  const beforeHashMatches = legacyStateSnapshotSha256(stateBefore) === journalState.stateBeforeSha256;
  const afterHashMatches = legacyStateSnapshotSha256(expected) === journalState.stateAfterRemoveSha256;
  if (!beforeHashMatches) assertLegacyPreRemovalStateAnchor(journalState, stateBefore, stateBeforeAnchor);
  return Object.freeze({ domain: LEGACY_CHECKPOINT_COMPATIBILITY.domain, normalizedFields: LEGACY_CHECKPOINT_COMPATIBILITY.normalizedFields, exactLegacyHashes: beforeHashMatches && afterHashMatches, anchored: !beforeHashMatches });
}

function assertJournalState(journalState, state, expectedArn, stateBefore, stateBeforeAnchor) {
  if (state.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const candidate = stateBackendCandidateFromOptional(state);
  const checkpointHash = checkpointStateSha256(journalState, state);
  const normalizedCheckpointHash = stateSnapshotSha256(state);
  const expectedPostRemoveHash = stateBefore ? stateSnapshotSha256(expectedStateAfterRemove(stateBefore)) : null;
  if (journalState.phase === "STATE_RECONCILING_POST_REMOVE") {
    const postRemoveCheckpointValid = checkpointHash === journalState.stateAfterRemoveSha256
      || (journalState.checkpointHashDomain === undefined
        ? assertLegacyPostRemoveCheckpointCompatibility(journalState, state, stateBefore, stateBeforeAnchor)
        : normalizedCheckpointHash === expectedPostRemoveHash);
    if (state.serial !== journalState.expectedStateAfterRemoveSerial || candidate !== null
      || !postRemoveCheckpointValid) {
      throw new Error("Terraform state is not the exact reviewed post-removal recovery state.");
    }
  } else if (["STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)) {
    if (state.serial !== journalState.expectedStateAfterImportSerial || candidate !== expectedArn) throw new Error("Terraform state is not the exact reviewed imported recovery state.");
  }
}

function recoveryStateCheckpoint(journalState, state, expectedArn, stateBefore, stateBeforeAnchor) {
  if (state.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  if (stateBefore) {
    const validSnapshot = stateBefore.lineage === journalState.stateLineage && stateBefore.serial === journalState.stateSerial
      && stateBackendCandidateFromOptional(stateBefore) === STAGE_B_BACKEND_RECOVERY.predecessorArn;
    const exactSnapshot = validSnapshot && checkpointStateSha256(journalState, stateBefore) === journalState.stateBeforeSha256;
    const legacyPostRemoveSnapshot = journalState.checkpointHashDomain === undefined && state.serial === journalState.expectedStateAfterRemoveSerial
      && stateBackendCandidateFromOptional(state) === null && (checkpointStateSha256(journalState, state) === journalState.stateAfterRemoveSha256 || (() => {
        try { return assertLegacyPostRemoveCheckpointCompatibility(journalState, state, stateBefore, stateBeforeAnchor); }
        catch (error) { throw new Error("Recovery pre-removal state snapshot does not match the durable journal.", { cause: error }); }
      })());
    if (!exactSnapshot && !legacyPostRemoveSnapshot) {
      throw new Error("Recovery pre-removal state snapshot does not match the durable journal.");
    }
  }
  const candidate = stateBackendCandidateFromOptional(state);
  const checkpointHash = checkpointStateSha256(journalState, state);
  const normalizedCheckpointHash = stateSnapshotSha256(state);
  const expectedBeforeHash = journalState.stateBeforeSha256;
  const expectedPostRemoveHash = stateBefore ? stateSnapshotSha256(expectedStateAfterRemove(stateBefore)) : null;
  const original = state.serial === journalState.stateSerial && candidate === STAGE_B_BACKEND_RECOVERY.predecessorArn && checkpointHash === expectedBeforeHash;
  const removed = state.serial === journalState.expectedStateAfterRemoveSerial && candidate === null
    && (checkpointHash === journalState.stateAfterRemoveSha256
      || (journalState.checkpointHashDomain === undefined
        ? assertLegacyPostRemoveCheckpointCompatibility(journalState, state, stateBefore, stateBeforeAnchor)
        : normalizedCheckpointHash === expectedPostRemoveHash));
  const imported = state.serial === journalState.expectedStateAfterImportSerial && candidate === expectedArn;
  if (journalState.phase === "STATE_RECONCILING_PRE_REMOVE" && (original || removed || imported)) return original ? "PRE_REMOVE" : removed ? "POST_REMOVE" : "IMPORTED";
  if (journalState.phase === "STATE_RECONCILING_POST_REMOVE" && (removed || imported)) return removed ? "POST_REMOVE" : "IMPORTED";
  if (["STATE_RECONCILED", "COMPLETED"].includes(journalState.phase) && imported) return "IMPORTED";
  throw new Error("Recovery journal and Terraform state do not form an exact resumable checkpoint.");
}

function recoveryCensusDecision(entries, fingerprint) {
  const matches = entries.filter(({ readback }) => taskDefinitionFingerprint(readback.taskDefinition || readback, readback.tags) === fingerprint);
  if (matches.length > 1) throw new Error("Canonical recovery census found multiple current-source matching revisions.");
  const newest = entries[0];
  if (matches[0] && matches[0].arn !== newest.arn) throw new Error("Canonical recovery census found an unexpected newer revision above the current-source match.");
  const historical = entries.find(({ arn }) => arn === STAGE_B_BACKEND_RECOVERY.newestHistoricalArn);
  if (!historical) throw new Error("Fresh canonical recovery requires the exact reviewed newest historical revision.");
  if (!matches[0] && newest.arn !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn) throw new Error("Fresh canonical recovery refuses an unreviewed newer live revision.");
  return { newest, matching: matches[0] || null, newestHistoricalArn: historical.arn };
}

export async function runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance = ({ protectedCheckout: checkout }) => checkout?.derivedProvenance, proveDescendant, deriveImageReuse, readState, register, describe, census, removeState, importState, journal, stateBefore, stateBeforeAnchor } = {}) {
  if (typeof readState !== "function") throw new Error("Canonical backend recovery requires a Terraform state reader.");
  if (typeof census !== "function") throw new Error("Canonical backend recovery requires a complete live revision census adapter.");
  const recoveryJournal = requireJournal(journal);
  const existingJournal = recoveryJournal.read();
  if (existingJournal && existingJournal.schemaVersion !== RECOVERY_SCHEMA_VERSION) throw new Error("Legacy recovery journal is historical evidence and cannot authorize the current source-bound incident.");
  const descendantResume = existingJournal && existingJournal.sourceSha !== sourceSha
    ? assertCanonicalRecoveryDescendantResume({ sourceSha, bindings, protectedCheckout, journalState: existingJournal, imageAuthorization, imageAuthorizationValidation, deriveProvenance, proveDescendant, deriveImageReuse })
    : null;
  if (!descendantResume) assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation, deriveProvenance });
  const before = await readState();
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const fingerprint = taskDefinitionFingerprint(payload.taskDefinition, payload.tags);
  const authorization = imageAuthorization || bindings.imageAuthorization;
  const imageAuthorizationSha256 = authorization.evidenceSha256;
  const backendImageDigest = imageDigest(bindings.backendImage);
  const censusResult = assertCanonicalBackendRecoveryCensus({ census: await census() });
  const decision = recoveryCensusDecision(censusResult, fingerprint);
  if (!existingJournal) assertBackendRecoveryPreconditions({ state: before, sourceSha });
  else if (before.lineage !== existingJournal.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const incidentSourceSha = existingJournal?.sourceSha || sourceSha;
  const incidentToolingTreeSha256 = existingJournal?.toolingTreeSha256 || bindings.toolingTreeSha256;
  const incidentSourceContractSha256 = existingJournal?.sourceContractSha256 || bindings.sourceContractSha256;
  const incidentImageReleaseSha = existingJournal?.imageReleaseSha || bindings.imageReleaseSha;
  const incidentImageAuthorizationSha256 = existingJournal?.imageAuthorizationSha256 || imageAuthorizationSha256;
  const stateBeforeBindingReportSha256 = existingJournal ? existingJournal.stateBeforeBindingReportSha256 : stateBeforeAnchor?.bindingReportSha256;
  const incidentIdentity = canonicalRecoveryIncidentIdentity({ sourceSha: incidentSourceSha, toolingTreeSha256: incidentToolingTreeSha256, sourceContractSha256: incidentSourceContractSha256, imageReleaseSha: incidentImageReleaseSha, imageDigest: backendImageDigest, imageAuthorizationSha256: incidentImageAuthorizationSha256, stateLineage: existingJournal?.stateLineage || before.lineage, stateSerial: existingJournal?.stateSerial ?? before.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn: decision.newestHistoricalArn, fingerprint, stateBeforeBindingReportSha256 });
  const prepared = existingJournal ? validateJournal(existingJournal, { sourceSha: incidentSourceSha, toolingTreeSha256: incidentToolingTreeSha256, sourceContractSha256: incidentSourceContractSha256, imageReleaseSha: incidentImageReleaseSha, imageAuthorizationSha256: incidentImageAuthorizationSha256, fingerprint, imageDigest: bindings.backendImage, newestHistoricalArn: decision.newestHistoricalArn, incidentIdentity, stateBeforeBindingReportSha256 }) : buildCanonicalRecoveryJournal(before, { sourceSha: incidentSourceSha, toolingTreeSha256: incidentToolingTreeSha256, sourceContractSha256: incidentSourceContractSha256, imageReleaseSha: incidentImageReleaseSha, imageAuthorizationSha256: incidentImageAuthorizationSha256, fingerprint, imageDigest: bindings.backendImage, newestHistoricalArn: decision.newestHistoricalArn, incidentIdentity, stateBeforeBindingReportSha256 });
  if (existingJournal?.replacementArn && decision.matching?.arn !== existingJournal.replacementArn && ["REGISTERED", "READBACK_VERIFIED", "STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(existingJournal.phase)) {
    throw new Error("Canonical recovery journal replacement does not match the current-source revision.");
  }
  if (!existingJournal) journal.write(prepared);
  else if (prepared.stateBeforeSha256 !== checkpointStateSha256(prepared, before) && ["DISCOVERY", "PREPARED"].includes(prepared.phase)) throw new Error("Terraform state changed before canonical recovery resumed.");
  if (["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase)) recoveryStateCheckpoint(prepared, before, prepared.replacementArn, stateBefore, stateBeforeAnchor);
  let registration;
  if (prepared.replacementArn && ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase)) {
    if (decision.newest.arn !== prepared.replacementArn) throw new Error("Canonical recovery resume requires its exact replacement to remain newest.");
    const readback = await describe(decision.newest.arn);
    const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: decision.newest.arn, expectedFingerprint: fingerprint, expectedNewestArn: prepared.newestHistoricalArn });
    registration = { ...verified, payload, registrationCalls: 0, resumed: true };
  } else {
    const ready = prepared.phase === "DISCOVERY" ? { ...prepared, phase: "PREPARED" } : prepared;
    if (ready !== prepared) journal.write(ready);
    if (decision.matching) {
      const verified = assertCanonicalBackendRecoveryReadback({ readback: decision.matching.readback, expectedArn: decision.matching.arn, expectedFingerprint: fingerprint, expectedNewestArn: ready.newestHistoricalArn });
      registration = { ...verified, payload, registrationCalls: 0, resumed: true };
    } else {
      if (ready.registrationMayHaveOccurred || ready.registrationCalls !== 0) throw new Error("Canonical recovery cannot prove a prior registration was not sent; newest revision must be read back before any retry.");
      if (decision.newest.arn !== ready.newestHistoricalArn) throw new Error("Canonical recovery census changed after the incident was prepared; perform a fresh census before registration.");
      const registering = { ...ready, phase: "REGISTERING", registrationMayHaveOccurred: true };
      journal.write(registering);
      let response;
      try {
        response = await register(payload);
      } catch (error) {
        journal.write({ ...registering, registrationCalls: 1 });
        throw error;
      }
      const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
      if (!ARN.test(arn || "")) {
        journal.write({ ...registering, registrationCalls: 1 });
        throw new Error("Canonical recovery registration returned no valid backend task-definition ARN.");
      }
      journal.write({ ...registering, phase: "REGISTERED", registrationCalls: 1, replacementArn: arn });
      const readback = await describe(arn);
      const postRegistrationCensus = assertCanonicalBackendRecoveryCensus({ census: await census() });
      if (postRegistrationCensus[0].arn !== arn) throw new Error("Canonical recovery replacement is not the newest retained backend revision.");
      const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: arn, expectedFingerprint: fingerprint, expectedNewestArn: ready.newestHistoricalArn });
      registration = { ...verified, payload, registrationCalls: 1, resumed: false };
    }
  }
  const reconciliationResume = ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase);
  const registered = { ...prepared, phase: reconciliationResume ? prepared.phase : "READBACK_VERIFIED", replacementArn: registration.arn, replacementFingerprint: registration.fingerprint, registrationCalls: Math.max(prepared.registrationCalls, registration.registrationCalls), registrationMayHaveOccurred: prepared.registrationMayHaveOccurred || registration.registrationCalls === 1 };
  journal.write(registered);
  const reconciliation = await reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: registration.arn, sourceSha: incidentSourceSha, journal, stateBefore, stateBeforeAnchor });
  const evidence = recoveryEvidence({ sourceSha: incidentSourceSha, toolingTreeSha256: incidentToolingTreeSha256, sourceContractSha256: incidentSourceContractSha256, imageReleaseSha: incidentImageReleaseSha, imageAuthorizationSha256: incidentImageAuthorizationSha256, state: before, stateBinding: prepared, imageDigest: bindings.backendImage, newestHistoricalArn: prepared.newestHistoricalArn, incidentIdentity: prepared.incidentIdentity, stateBeforeBindingReportSha256: prepared.stateBeforeBindingReportSha256, replacement: { arn: registration.arn, fingerprint: registration.fingerprint, protectedSourceFingerprint: fingerprint }, ...(descendantResume ? { resumeExecutorToolingSha: descendantResume.executorToolingSha, resumeExecutorToolingTreeSha256: descendantResume.executorProvenance.toolingTreeSha256 } : {}) });
  journal.write({ ...registered, phase: "COMPLETED", evidenceSha256: evidence.evidenceSha256 });
  return { registration, evidence, reconciliation };
}

export function createAwsCanonicalBackendRecoveryRegistrationAdapter({ run } = {}) {
  if (typeof run !== "function") throw new Error("AWS recovery registration runner is required.");
  return async ({ taskDefinition, tags }) => {
    const response = await run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...taskDefinition, tags }), "--output", "json"]);
    return typeof response === "string" ? JSON.parse(response) : response;
  };
}

function assertOnlyBackendStateChange(before, after, expectedArn) {
  const strip = (state) => ({ ...state, serial: undefined, resources: (state.resources || []).map((resource) => resource.type === "aws_ecs_task_definition" && resource.name === "candidate" ? { ...resource, instances: (resource.instances || []).filter((instance) => instance.index_key !== "backend") } : resource) });
  if (stateSnapshotSha256(strip(before)) !== stateSnapshotSha256(strip(after))) throw new Error("Recovery changed Terraform state outside the backend candidate resource.");
  const current = stateBackendCandidate(after);
  if (current.arn !== expectedArn) throw new Error("Terraform state backend candidate does not point to the canonical replacement.");
}

export async function reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: targetArn, sourceSha, journal, stateBefore, stateBeforeAnchor } = {}) {
  if (typeof readState !== "function" || typeof removeState !== "function" || typeof importState !== "function") throw new Error("Canonical backend state reconciliation adapters are required.");
  const recoveryJournal = requireJournal(journal);
  const journalState = recoveryJournal.read();
  const before = await readState();
  const target = replacementArn(targetArn);
  if (STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(target.arn)) throw new Error("Historical backend revisions cannot be adopted.");
  if (journalState.replacementArn !== target.arn) throw new Error("Recovery replacement does not match the persistent recovery journal.");
  if (before.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const checkpoint = ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)
    ? recoveryStateCheckpoint(journalState, before, target.arn, stateBefore, stateBeforeAnchor)
    : (assertBackendRecoveryPreconditions({ state: before, sourceSha }), "PRE_REMOVE");
  if (checkpoint === "IMPORTED") {
    recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILED" });
    return { stateLineageBefore: journalState.stateLineage, stateLineageAfter: before.lineage, stateSerialBefore: journalState.stateSerial, stateSerialAfter: before.serial, stateBackendCandidate: target.arn, liveBackendCandidate: target.arn, stateLivePredecessorMatch: true, removeCalls: 0, importCalls: 0 };
  }
  if (checkpoint === "POST_REMOVE") {
    assertJournalState({ ...journalState, phase: "STATE_RECONCILING_POST_REMOVE" }, before, target.arn, stateBefore, stateBeforeAnchor);
    await importState({ address: STAGE_B_BACKEND_RECOVERY.address, arn: target.arn });
    const imported = await readState();
    if (imported.lineage !== journalState.stateLineage || imported.serial !== journalState.expectedStateAfterImportSerial || stateBackendCandidateFromOptional(imported) !== target.arn) throw new Error("Terraform state import did not produce the exact canonical recovery state.");
    recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILED" });
    return { stateLineageBefore: journalState.stateLineage, stateLineageAfter: imported.lineage, stateSerialBefore: journalState.stateSerial, stateSerialAfter: imported.serial, stateBackendCandidate: target.arn, liveBackendCandidate: target.arn, stateLivePredecessorMatch: true, removeCalls: 0, importCalls: 1 };
  }
  assertBackendRecoveryPreconditions({ state: before, sourceSha });
  recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILING_PRE_REMOVE" });
  await removeState({ address: STAGE_B_BACKEND_RECOVERY.address, expectedArn: STAGE_B_BACKEND_RECOVERY.predecessorArn });
  const removed = await readState();
  assertJournalState({ ...journalState, phase: "STATE_RECONCILING_POST_REMOVE" }, removed, target.arn, stateBefore, stateBeforeAnchor);
  recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILING_POST_REMOVE" });
  await importState({ address: STAGE_B_BACKEND_RECOVERY.address, arn: target.arn });
  const after = await readState();
  if (after.lineage !== journalState.stateLineage || after.serial !== journalState.expectedStateAfterImportSerial || stateBackendCandidateFromOptional(after) !== target.arn) throw new Error("Terraform state import did not produce the exact canonical recovery state.");
  assertOnlyBackendStateChange(before, after, target.arn);
  recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILED" });
  return { stateLineageBefore: journalState.stateLineage, stateLineageAfter: after.lineage, stateSerialBefore: journalState.stateSerial, stateSerialAfter: after.serial, stateBackendCandidate: target.arn, liveBackendCandidate: target.arn, stateLivePredecessorMatch: true, removeCalls: 1, importCalls: 1 };
}

function stateBackendCandidateFromOptional(state) {
  try { return stateBackendCandidate(state).arn; } catch { return null; }
}

export function recoveryEvidence({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageAuthorizationSha256, state, stateBinding, replacement, imageDigest: backendImageDigest, newestHistoricalArn, incidentIdentity, registrationEvent = null, resumeExecutorToolingSha, resumeExecutorToolingTreeSha256, stateBeforeBindingReportSha256 } = {}) {
  if (stateBinding) {
    if (stateBinding.stateLineage !== STAGE_B_BACKEND_RECOVERY.lineage || stateBinding.stateSerial !== STAGE_B_BACKEND_RECOVERY.serial
      || stateBinding.predecessorArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn) throw new Error("Recovery evidence state binding is not the reviewed predecessor.");
  } else assertBackendRecoveryPreconditions({ state, sourceSha });
  const verifiedReplacement = replacement && replacementArn(replacement.arn);
  if (!verifiedReplacement || STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(verifiedReplacement.arn) || replacement.fingerprint !== replacement.protectedSourceFingerprint) throw new Error("Recovery evidence does not bind the replacement to the protected fingerprint.");
  if (!DIGEST.test(backendImageDigest || "") || !SHA256.test(toolingTreeSha256 || "") || !SHA256.test(sourceContractSha256 || "") || !SHA.test(imageReleaseSha || "") || !SHA256.test(imageAuthorizationSha256 || "") || !ARN.test(newestHistoricalArn || "") || !SHA256.test(incidentIdentity || "")) throw new Error("Recovery evidence provenance binding is invalid.");
  if ((resumeExecutorToolingSha === undefined) !== (resumeExecutorToolingTreeSha256 === undefined)
    || (resumeExecutorToolingSha !== undefined && (!SHA.test(resumeExecutorToolingSha) || !SHA256.test(resumeExecutorToolingTreeSha256)))) throw new Error("Recovery evidence resume-executor provenance is incomplete.");
  const expectedIncidentIdentity = canonicalRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageDigest: imageDigest(backendImageDigest), imageAuthorizationSha256, stateLineage: stateBinding?.stateLineage || state.lineage, stateSerial: stateBinding?.stateSerial || state.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn, fingerprint: replacement.protectedSourceFingerprint, stateBeforeBindingReportSha256 });
  if (incidentIdentity !== expectedIncidentIdentity) throw new Error("Recovery evidence incident identity is not deterministic for its bindings.");
  const evidence = { schemaVersion: 2, kind: RECOVERY_KIND, incidentIdentity, sourceSha, toolingSha: sourceSha, toolingTreeSha256, sourceContractSha256, imageReleaseSha, imageAuthorizationSha256, ...(resumeExecutorToolingSha ? { resumeExecutorToolingSha, resumeExecutorToolingTreeSha256 } : {}), ...(stateBeforeBindingReportSha256 === undefined ? {} : { stateBeforeBindingReportSha256 }), address: STAGE_B_BACKEND_RECOVERY.address, family: STAGE_B_BACKEND_RECOVERY.family, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, predecessorSerial: STAGE_B_BACKEND_RECOVERY.serial, newestHistoricalArn, historicalRevisionArns: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns, replacementArn: replacement.arn, protectedSourceFingerprint: replacement.protectedSourceFingerprint, replacementFingerprint: replacement.fingerprint, imageDigest: backendImageDigest, authorizedBackendImageDigest: imageDigest(backendImageDigest), stateLineage: stateBinding?.stateLineage || state.lineage, stateSerial: stateBinding?.stateSerial || state.serial, registrationEvent };
  return { ...evidence, evidenceSha256: canonicalSha256(evidence) };
}
