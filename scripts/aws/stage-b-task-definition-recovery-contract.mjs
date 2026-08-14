import crypto from "node:crypto";
import { renderStageBTaskDefinition, assertFixedTaskDefinition } from "./production-green-stage-b-task-definitions.mjs";

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
const exact = (a, b) => canonicalJson(a) === canonicalJson(b);

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function canonicalSha256(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
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
  definition.containerDefinitions = sortBy(definition.containerDefinitions, "name")?.map((container) => ({
    ...container,
    environment: sortBy(container.environment, "name"),
    secrets: sortBy(container.secrets, "name"),
    portMappings: sortBy(container.portMappings, "name"),
    mountPoints: sortBy(container.mountPoints, "containerPath"),
    ulimits: sortBy(container.ulimits, "name"),
    systemControls: sortBy(container.systemControls, "namespace"),
    dependsOn: sortBy(container.dependsOn, "containerName"),
  }));
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

export async function registerCanonicalBackendRecovery({ bindings, state, sourceSha, expectedFingerprint, register, describe, newest = null } = {}) {
  assertBackendRecoveryPreconditions({ state, sourceSha });
  if (typeof register !== "function" || typeof describe !== "function") throw new Error("Canonical backend recovery requires registration and readback adapters.");
  const newestBefore = typeof newest === "function" ? await newest() : STAGE_B_BACKEND_RECOVERY.newestHistoricalArn;
  if (newestBefore !== STAGE_B_BACKEND_RECOVERY.newestHistoricalArn) throw new Error("Canonical recovery requires the exact reviewed :7 newest-live predecessor.");
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const response = await register(payload);
  const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
  const readback = await describe(arn);
  const newestAfter = typeof newest === "function" ? await newest() : arn;
  if (newestAfter !== arn) throw new Error("Canonical recovery replacement is not the newest retained backend revision.");
  const verified = assertCanonicalBackendRecoveryReadback({ readback, expectedArn: arn, expectedFingerprint, expectedNewestArn: newestBefore });
  return { ...verified, payload, registrationCalls: 1 };
}

export async function runCanonicalBackendRecovery({ bindings, sourceSha, readState, register, describe, newest, removeState, importState } = {}) {
  if (typeof readState !== "function") throw new Error("Canonical backend recovery requires a Terraform state reader.");
  const before = await readState();
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const fingerprint = taskDefinitionFingerprint(payload.taskDefinition, payload.tags);
  const registration = await registerCanonicalBackendRecovery({ bindings, state: before, sourceSha, expectedFingerprint: fingerprint, register, describe, newest });
  const evidence = recoveryEvidence({ sourceSha, state: before, imageDigest: bindings.backendImage, replacement: { arn: registration.arn, fingerprint: registration.fingerprint, protectedSourceFingerprint: fingerprint } });
  const reconciliation = await reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: registration.arn, sourceSha });
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

export async function reconcileCanonicalBackendState({ readState, removeState, importState, replacementArn: targetArn, sourceSha } = {}) {
  if (typeof readState !== "function" || typeof removeState !== "function" || typeof importState !== "function") throw new Error("Canonical backend state reconciliation adapters are required.");
  const before = await readState();
  assertBackendRecoveryPreconditions({ state: before, sourceSha });
  const target = replacementArn(targetArn);
  if (STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(target.arn)) throw new Error("Historical backend revisions cannot be adopted.");
  await removeState({ address: STAGE_B_BACKEND_RECOVERY.address, expectedArn: STAGE_B_BACKEND_RECOVERY.predecessorArn });
  const removed = await readState();
  if (removed.lineage !== before.lineage || removed.serial !== before.serial + 1 || stateBackendCandidateFromOptional(removed) !== null) throw new Error("Terraform state changed unexpectedly during backend recovery removal.");
  await importState({ address: STAGE_B_BACKEND_RECOVERY.address, arn: target.arn });
  const after = await readState();
  if (after.lineage !== before.lineage || after.serial !== before.serial + 2) throw new Error("Terraform state serial/lineage did not advance exactly during backend recovery.");
  assertOnlyBackendStateChange(before, after, target.arn);
  return { stateLineageBefore: before.lineage, stateLineageAfter: after.lineage, stateSerialBefore: before.serial, stateSerialAfter: after.serial, stateBackendCandidate: target.arn, liveBackendCandidate: target.arn, stateLivePredecessorMatch: true, removeCalls: 1, importCalls: 1 };
}

function stateBackendCandidateFromOptional(state) {
  try { return stateBackendCandidate(state).arn; } catch { return null; }
}

export function recoveryEvidence({ sourceSha, state, replacement, imageDigest, registrationEvent = null } = {}) {
  assertBackendRecoveryPreconditions({ state, sourceSha });
  const verifiedReplacement = replacement && replacementArn(replacement.arn);
  if (!verifiedReplacement || STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.includes(verifiedReplacement.arn) || replacement.fingerprint !== replacement.protectedSourceFingerprint) throw new Error("Recovery evidence does not bind the replacement to the protected fingerprint.");
  if (!DIGEST.test(imageDigest || "")) throw new Error("Recovery evidence image binding is invalid.");
  const evidence = { schemaVersion: 1, kind: "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY", sourceSha, address: STAGE_B_BACKEND_RECOVERY.address, family: STAGE_B_BACKEND_RECOVERY.family, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, historicalRevisionArns: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns, replacementArn: replacement.arn, protectedSourceFingerprint: replacement.protectedSourceFingerprint, replacementFingerprint: replacement.fingerprint, imageDigest, stateLineage: state.lineage, stateSerial: state.serial, registrationEvent };
  return { ...evidence, evidenceSha256: canonicalSha256(evidence) };
}
