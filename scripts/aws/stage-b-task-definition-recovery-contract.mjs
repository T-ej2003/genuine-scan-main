import crypto from "node:crypto";
import { renderStageBTaskDefinition, assertFixedTaskDefinition } from "./production-green-stage-b-task-definitions.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";

export const STAGE_B_BACKEND_RECOVERY = Object.freeze({
  address: 'aws_ecs_task_definition.candidate["backend"]',
  family: "mscqr-production-rls-green-backend-candidate",
  predecessorArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:5",
  historicalRevisionArns: Object.freeze([
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:6",
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7",
  ]),
  newestHistoricalArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7",
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
const DIGEST = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const exact = (a, b) => canonicalJson(a) === canonicalJson(b);

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function canonicalSha256(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is required for backend recovery.");
  if (!protectedCheckout || protectedCheckout.currentHead !== sourceSha || protectedCheckout.toolingSha !== sourceSha
    || protectedCheckout.originMainHead !== sourceSha || protectedCheckout.isAncestor !== true || protectedCheckout.porcelainStatus) {
    throw new Error("Canonical recovery requires the exact clean protected-main checkout.");
  }
  if (!bindings || bindings.toolingSha !== sourceSha || bindings.sourceSha !== sourceSha || !SHA.test(bindings.imageReleaseSha || "")) throw new Error("Canonical recovery tooling and image-release identities are incomplete.");
  const authorization = imageAuthorization || bindings.imageAuthorization;
  if (!authorization || bindings.imageReleaseSha !== authorization.imageReleaseSha) throw new Error("Canonical recovery image-release identity does not match image authorization.");
  assertImageAuthorization(authorization, sourceSha, imageAuthorizationValidation || bindings.imageAuthorizationValidation);
  const authorizedDigest = authorizedBackendDigest(authorization);
  if (!IMAGE_DIGEST.test(authorizedDigest || "") || bindings.backendImage !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${authorizedDigest}`) throw new Error("Canonical recovery backend image does not match image authorization.");
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

export async function registerCanonicalBackendRecovery({ bindings, state, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, expectedFingerprint, register, describe, newest = null } = {}) {
  assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation });
  assertBackendRecoveryPreconditions({ state, sourceSha });
  if (typeof register !== "function" || typeof describe !== "function") throw new Error("Canonical backend recovery requires registration and readback adapters.");
  const newestBefore = typeof newest === "function" ? await newest() : STAGE_B_BACKEND_RECOVERY.newestHistoricalArn;
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  if (newestBefore !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn) {
    const readback = await describe(newestBefore);
    const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: newestBefore, expectedFingerprint });
    return { ...verified, payload, registrationCalls: 0, resumed: true };
  }
  const response = await register(payload);
  const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
  const readback = await describe(arn);
  const newestAfter = typeof newest === "function" ? await newest() : arn;
  if (newestAfter !== arn) throw new Error("Canonical recovery replacement is not the newest retained backend revision.");
  const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: arn, expectedFingerprint, expectedNewestArn: newestBefore });
  return { ...verified, payload, registrationCalls: 1, resumed: false };
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

function stateSnapshotSha256(state) {
  return canonicalSha256(state);
}

function expectedStateAfterRemove(state) {
  return { ...stateWithoutBackend(state), serial: state.serial + 1 };
}

function requireJournal(journal) {
  if (!journal || typeof journal.read !== "function" || typeof journal.write !== "function") throw new Error("Canonical recovery requires a persistent recovery journal.");
  return journal;
}

function validateJournal(journalState, { sourceSha, imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest } = {}) {
  if (!journalState || journalState.schemaVersion !== 4 || journalState.kind !== "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY"
    || journalState.sourceSha !== sourceSha || journalState.address !== STAGE_B_BACKEND_RECOVERY.address
    || journalState.family !== STAGE_B_BACKEND_RECOVERY.family || journalState.predecessorArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn
    || journalState.newestHistoricalArn !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn
    || journalState.stateLineage !== STAGE_B_BACKEND_RECOVERY.lineage || journalState.stateSerial !== STAGE_B_BACKEND_RECOVERY.serial
    || journalState.protectedSourceFingerprint !== fingerprint || journalState.imageDigest !== imageDigest
    || journalState.imageReleaseSha !== imageReleaseSha || journalState.imageAuthorizationSha256 !== imageAuthorizationSha256
    || !["DISCOVERY", "PREPARED", "REGISTERING", "REGISTERED", "READBACK_VERIFIED", "STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)
    || !Number.isInteger(journalState.registrationCalls) || journalState.registrationCalls < 0 || journalState.registrationCalls > 1
    || typeof journalState.registrationMayHaveOccurred !== "boolean") {
    throw new Error("Canonical recovery journal does not match the reviewed incident and protected source.");
  }
  return journalState;
}

export function buildCanonicalRecoveryJournal(state, { sourceSha, imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest } = {}) {
  return {
    schemaVersion: 4,
    kind: "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY",
    phase: "DISCOVERY",
    sourceSha,
    toolingSha: sourceSha,
    imageReleaseSha,
    imageAuthorizationSha256,
    address: STAGE_B_BACKEND_RECOVERY.address,
    family: STAGE_B_BACKEND_RECOVERY.family,
    predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn,
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    stateLineage: state.lineage,
    stateSerial: state.serial,
    stateBeforeSha256: stateSnapshotSha256(state),
    stateAfterRemoveSha256: stateSnapshotSha256(expectedStateAfterRemove(state)),
    expectedStateAfterRemoveSerial: state.serial + 1,
    expectedStateAfterImportSerial: state.serial + 2,
    protectedSourceFingerprint: fingerprint,
    imageDigest,
    registrationCalls: 0,
    registrationMayHaveOccurred: false,
  };
}

function assertJournalState(journalState, state, expectedArn) {
  if (state.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const candidate = stateBackendCandidateFromOptional(state);
  if (journalState.phase === "STATE_RECONCILING_POST_REMOVE") {
    if (state.serial !== journalState.expectedStateAfterRemoveSerial || candidate !== null || stateSnapshotSha256(state) !== journalState.stateAfterRemoveSha256) {
      throw new Error("Terraform state is not the exact reviewed post-removal recovery state.");
    }
  } else if (["STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)) {
    if (state.serial !== journalState.expectedStateAfterImportSerial || candidate !== expectedArn) throw new Error("Terraform state is not the exact reviewed imported recovery state.");
  }
}

function recoveryStateCheckpoint(journalState, state, expectedArn) {
  if (state.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const candidate = stateBackendCandidateFromOptional(state);
  const original = state.serial === journalState.stateSerial && candidate === STAGE_B_BACKEND_RECOVERY.predecessorArn && stateSnapshotSha256(state) === journalState.stateBeforeSha256;
  const removed = state.serial === journalState.expectedStateAfterRemoveSerial && candidate === null && stateSnapshotSha256(state) === journalState.stateAfterRemoveSha256;
  const imported = state.serial === journalState.expectedStateAfterImportSerial && candidate === expectedArn;
  if (journalState.phase === "STATE_RECONCILING_PRE_REMOVE" && (original || removed || imported)) return original ? "PRE_REMOVE" : removed ? "POST_REMOVE" : "IMPORTED";
  if (journalState.phase === "STATE_RECONCILING_POST_REMOVE" && (removed || imported)) return removed ? "POST_REMOVE" : "IMPORTED";
  if (["STATE_RECONCILED", "COMPLETED"].includes(journalState.phase) && imported) return "IMPORTED";
  throw new Error("Recovery journal and Terraform state do not form an exact resumable checkpoint.");
}

export async function runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, readState, register, describe, newest, removeState, importState, journal } = {}) {
  if (typeof readState !== "function") throw new Error("Canonical backend recovery requires a Terraform state reader.");
  requireJournal(journal);
  assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation });
  const before = await readState();
  const existingJournal = journal.read();
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const fingerprint = taskDefinitionFingerprint(payload.taskDefinition, payload.tags);
  if (existingJournal?.schemaVersion === 1 && existingJournal.phase === "REGISTERING" && existingJournal.registrationCalls === 1 && !existingJournal.replacementArn) {
    throw new Error("Legacy recovery journal records a pre-discovery registration count; preserve it as failed evidence and start a new reviewed recovery incident after live revalidation.");
  }
  const imageAuthorizationSha256 = (imageAuthorization || bindings.imageAuthorization).evidenceSha256;
  const prepared = existingJournal ? validateJournal(existingJournal, { sourceSha, imageReleaseSha: bindings.imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest: bindings.backendImage }) : buildCanonicalRecoveryJournal(before, { sourceSha, imageReleaseSha: bindings.imageReleaseSha, imageAuthorizationSha256, fingerprint, imageDigest: bindings.backendImage });
  if (!existingJournal) journal.write(prepared);
  else if (prepared.stateBeforeSha256 !== stateSnapshotSha256(before) && ["DISCOVERY", "PREPARED"].includes(prepared.phase)) throw new Error("Terraform state changed before canonical recovery resumed.");
  if (["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase)) recoveryStateCheckpoint(prepared, before, prepared.replacementArn);
  let registration;
  if (prepared.replacementArn && ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase)) {
    const newestArn = await newest();
    if (newestArn !== prepared.replacementArn) throw new Error("Canonical recovery resume requires its exact replacement to remain newest.");
    const readback = await describe(newestArn);
    const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: newestArn, expectedFingerprint: fingerprint });
    registration = { ...verified, payload, registrationCalls: 0, resumed: true };
  } else {
    assertBackendRecoveryPreconditions({ state: before, sourceSha });
    const newestArn = await newest();
    const ready = prepared.phase === "DISCOVERY" ? { ...prepared, phase: "PREPARED" } : prepared;
    if (ready !== prepared) journal.write(ready);
    if (newestArn !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn) {
      const readback = await describe(newestArn);
      const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: newestArn, expectedFingerprint: fingerprint });
      registration = { ...verified, payload, registrationCalls: 0, resumed: true };
    } else {
      if (ready.registrationMayHaveOccurred || ready.registrationCalls !== 0) throw new Error("Canonical recovery cannot prove a prior registration was not sent; newest revision must be read back before any retry.");
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
      journal.write({ ...registering, phase: "REGISTERED", registrationCalls: 1, replacementArn: arn });
      const readback = await describe(arn);
      if (await newest() !== arn) throw new Error("Canonical recovery replacement is not the newest retained backend revision.");
      const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: arn, expectedFingerprint: fingerprint });
      registration = { ...verified, payload, registrationCalls: 1, resumed: false };
    }
  }
  const reconciliationResume = ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(prepared.phase);
  const registered = { ...prepared, phase: reconciliationResume ? prepared.phase : "READBACK_VERIFIED", replacementArn: registration.arn, replacementFingerprint: registration.fingerprint, registrationCalls: Math.max(prepared.registrationCalls, registration.registrationCalls), registrationMayHaveOccurred: prepared.registrationMayHaveOccurred || registration.registrationCalls === 1 };
  journal.write(registered);
  const reconciliation = await reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: registration.arn, sourceSha, journal });
  const evidence = recoveryEvidence({ sourceSha, imageReleaseSha: bindings.imageReleaseSha, imageAuthorizationSha256, state: before, stateBinding: prepared, imageDigest: bindings.backendImage, replacement: { arn: registration.arn, fingerprint: registration.fingerprint, protectedSourceFingerprint: fingerprint } });
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
  if (!exact(strip(before), strip(after))) throw new Error("Recovery changed Terraform state outside the backend candidate resource.");
  const current = stateBackendCandidate(after);
  if (current.arn !== expectedArn) throw new Error("Terraform state backend candidate does not point to the canonical replacement.");
}

export async function reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: targetArn, sourceSha, journal } = {}) {
  if (typeof readState !== "function" || typeof removeState !== "function" || typeof importState !== "function") throw new Error("Canonical backend state reconciliation adapters are required.");
  const recoveryJournal = requireJournal(journal);
  const journalState = recoveryJournal.read();
  const before = await readState();
  const target = replacementArn(targetArn);
  if (STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(target.arn)) throw new Error("Historical backend revisions cannot be adopted.");
  if (journalState.replacementArn !== target.arn) throw new Error("Recovery replacement does not match the persistent recovery journal.");
  if (before.lineage !== journalState.stateLineage) throw new Error("Terraform state lineage changed during backend recovery.");
  const checkpoint = ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED", "COMPLETED"].includes(journalState.phase)
    ? recoveryStateCheckpoint(journalState, before, target.arn)
    : (assertBackendRecoveryPreconditions({ state: before, sourceSha }), "PRE_REMOVE");
  if (checkpoint === "IMPORTED") {
    recoveryJournal.write({ ...journalState, phase: "STATE_RECONCILED" });
    return { stateLineageBefore: journalState.stateLineage, stateLineageAfter: before.lineage, stateSerialBefore: journalState.stateSerial, stateSerialAfter: before.serial, stateBackendCandidate: target.arn, liveBackendCandidate: target.arn, stateLivePredecessorMatch: true, removeCalls: 0, importCalls: 0 };
  }
  if (checkpoint === "POST_REMOVE") {
    assertJournalState({ ...journalState, phase: "STATE_RECONCILING_POST_REMOVE" }, before, target.arn);
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
  assertJournalState({ ...journalState, phase: "STATE_RECONCILING_POST_REMOVE" }, removed, target.arn);
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

export function recoveryEvidence({ sourceSha, imageReleaseSha, imageAuthorizationSha256, state, stateBinding, replacement, imageDigest, registrationEvent = null } = {}) {
  if (stateBinding) {
    if (stateBinding.stateLineage !== STAGE_B_BACKEND_RECOVERY.lineage || stateBinding.stateSerial !== STAGE_B_BACKEND_RECOVERY.serial
      || stateBinding.predecessorArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn) throw new Error("Recovery evidence state binding is not the reviewed predecessor.");
  } else assertBackendRecoveryPreconditions({ state, sourceSha });
  const verifiedReplacement = replacement && replacementArn(replacement.arn);
  if (!verifiedReplacement || STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(verifiedReplacement.arn) || replacement.fingerprint !== replacement.protectedSourceFingerprint) throw new Error("Recovery evidence does not bind the replacement to the protected fingerprint.");
  if (!DIGEST.test(imageDigest || "")) throw new Error("Recovery evidence image binding is invalid.");
  if (!SHA.test(imageReleaseSha || "") || !/^[a-f0-9]{64}$/.test(imageAuthorizationSha256 || "")) throw new Error("Recovery evidence image-release authorization binding is invalid.");
  const evidence = { schemaVersion: 2, kind: "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY", sourceSha, toolingSha: sourceSha, imageReleaseSha, imageAuthorizationSha256, address: STAGE_B_BACKEND_RECOVERY.address, family: STAGE_B_BACKEND_RECOVERY.family, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, historicalRevisionArns: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns, replacementArn: replacement.arn, protectedSourceFingerprint: replacement.protectedSourceFingerprint, replacementFingerprint: replacement.fingerprint, imageDigest, stateLineage: stateBinding?.stateLineage || state.lineage, stateSerial: stateBinding?.stateSerial || state.serial, registrationEvent };
  return { ...evidence, evidenceSha256: canonicalSha256(evidence) };
}
