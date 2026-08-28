#!/usr/bin/env node
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createInitialDualSlotSecretsManagerClient } from "./production-initial-dual-slot-bootstrap.mjs";
import { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOTS, assertRebaselinePreconditions, buildAbandonmentEvidence,
  buildRebaselineIdentity, buildRebaselinePreparation, buildRebaselineWritePlan, buildRebaselinePayloads,
  canonicalSha256, historicalSlotIdentity, loadOrCreateRebaselineMaterialJournal, readRebaselineMaterialJournal, executeProductionDualSlotRebaseline, resolveProductionDualSlotRebaselineAuthorizationArtifact, assertAbandonmentEvidence,
  REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256,
} from "./production-dual-slot-rebaseline-contract.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const requireBackend = createRequire(path.join(REPOSITORY_ROOT, "backend/package.json"));
const { GetSecretValueCommand, DescribeSecretCommand, PutSecretValueCommand } = requireBackend("@aws-sdk/client-secrets-manager");
const ACCOUNT = PRODUCTION_DUAL_SLOT_REBASELINE.accountId;
const REGION = PRODUCTION_DUAL_SLOT_REBASELINE.region;
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const HISTORICAL_ROTATION_ID = "rotation-20260826060632-b15b3f51";
const HISTORICAL_SOURCES = ["5506cbe3972a27a77c211f2891756c3b97de7197", "9f39d1c4f646467146c12c0587fd7ad585f3fe10"];
const required = (args, name) => { const value = args.get(name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const parseArgs = (argv) => { const values = new Map(); for (let i = 0; i < argv.length; i += 1) { const key = argv[i]?.replace(/^--/, ""); if (["prepare", "execute"].includes(key)) { if (values.has(key)) throw new Error(`Duplicate argument: ${argv[i]}`); values.set(key, true); continue; } if (!key || !argv[i + 1] || argv[i + 1].startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${argv[i]}`); values.set(key, argv[++i]); } return values; };
const json = (bytes) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
const parseSecret = (response, label, expectedVersionId) => { if (expectedVersionId !== undefined && response?.VersionId !== expectedVersionId) throw new Error(`${label} returned a substituted secret version.`); if (typeof response?.SecretString !== "string") throw new Error(`${label} is not a reviewed JSON secret.`); const value = JSON.parse(response.SecretString); if (!value || typeof value !== "object" || typeof value.value !== "string") throw new Error(`${label} has an invalid rotation payload.`); return { value, payloadSha256: canonicalSha256(value) }; };

export async function readDualSlotTopology({ client, names = REBASELINE_SLOTS, historicalRotationId = HISTORICAL_ROTATION_ID, preparedState, preparedWritePlan } = {}) {
  if ((preparedState && !preparedWritePlan) || (!preparedState && preparedWritePlan)) throw new Error("Prepared rebaseline topology requires both authenticated preparation and write plan.");
  if (preparedState) assertAbandonmentEvidence(preparedState.abandonmentEvidence, { sourceSha: preparedState.sourceSha, resources: preparedState.resources, historicalTopologySha256: preparedState.historicalTopologySha256 });
  const preparedBySlot = preparedWritePlan ? Object.fromEntries(preparedWritePlan.map((entry) => [entry.slot, entry])) : null;
  const resources = {};
  const currentVersionIds = {};
  const snapshots = {};
  for (const [slot, name] of Object.entries(names)) {
    const described = await client.send(new DescribeSecretCommand({ SecretId: name }));
    if (described.Name !== name || typeof described.ARN !== "string" || (preparedState && described.ARN !== preparedState.resources[slot])) throw new Error(`Secret resource ${slot} is outside the exact rebaseline allowlist.`);
    const current = Object.entries(described.VersionIdsToStages || {}).filter(([, stages]) => stages.includes("AWSCURRENT"));
    if (current.length !== 1) throw new Error(`Secret resource ${slot} does not have exactly one authenticated AWSCURRENT version.`);
    const response = await client.send(new GetSecretValueCommand({ SecretId: described.ARN, VersionId: current[0][0] }));
    const parsed = parseSecret(response, slot, current[0][0]);
    resources[slot] = described.ARN;
    currentVersionIds[slot] = current[0][0];
    snapshots[slot] = { slot, arn: described.ARN, versions: Object.entries(described.VersionIdsToStages).map(([versionId, stages]) => ({ versionId, stages, ...(versionId === current[0][0] ? { payloadSha256: parsed.payloadSha256 } : {}) })) };
    if (!preparedState) {
      snapshots[slot].historicalIdentity = historicalSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value });
      continue;
    }
    const historicalIdentity = preparedState.abandonmentEvidence.observedSlotIdentities[slot];
    const historicalVersionId = preparedState.abandonmentEvidence.currentVersionIds[slot];
    const expectedWrite = preparedBySlot[slot];
    if (!expectedWrite) throw new Error(`Prepared rebaseline write identity for ${slot} is missing.`);
    if (current[0][0] === historicalVersionId) {
      const observed = historicalSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value });
      if (canonicalSha256(observed) !== canonicalSha256(historicalIdentity)) throw new Error(`Historical ${slot} identity changed during rebaseline resume.`);
      snapshots[slot].classification = "HISTORICAL_NOT_YET_WRITTEN";
    } else if (current[0][0] === expectedWrite.clientRequestToken) {
      if (parsed.payloadSha256 !== expectedWrite.payloadSha256 || canonicalSha256(parsed.value) !== expectedWrite.payloadSha256 || current[0][1].length !== 1 || current[0][1][0] !== "AWSCURRENT") throw new Error(`Prepared ${slot} write identity does not authenticate.`);
      snapshots[slot].classification = "REBASELINE_WRITE_ALREADY_COMPLETE";
    } else throw new Error(`Current ${slot} version is neither authenticated historical state nor the exact prepared rebaseline write.`);
  }
  const observedSlotIdentities = preparedState
    ? preparedState.abandonmentEvidence.observedSlotIdentities
    : Object.freeze(Object.fromEntries(Object.entries(snapshots).map(([slot, snapshot]) => [slot, snapshot.historicalIdentity])));
  return Object.freeze({ resources, currentVersionIds, snapshots, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities), ...(preparedState ? { classifications: Object.freeze(Object.fromEntries(Object.entries(snapshots).map(([slot, snapshot]) => [slot, snapshot.classification]))) } : {}) });
}

export async function readPreparedDualSlotTopology({ client, preparation, writePlan } = {}) {
  return readDualSlotTopology({ client, preparedState: preparation, preparedWritePlan: writePlan });
}

async function readSlotSnapshot(client, slot, secretArn, expectedVersionId, expectedIdentity = {}) {
  const described = await client.send(new DescribeSecretCommand({ SecretId: secretArn }));
  const ids = new Set(Object.keys(described.VersionIdsToStages || {}));
  const currentVersionIds = [...ids].filter((versionId) => described.VersionIdsToStages[versionId]?.includes("AWSCURRENT"));
  if (currentVersionIds.length !== 1) throw new Error(`Secret ${slot} does not have exactly one authenticated AWSCURRENT version.`);
  const [currentVersionId] = currentVersionIds;
  const versions = [];
  let unexpectedRebaselineIdentity = false;
  let currentPayloadSha256;
  for (const versionId of ids) {
    const parsed = parseSecret(await client.send(new GetSecretValueCommand({ SecretId: secretArn, VersionId: versionId })), slot, versionId);
    versions.push({ versionId, stages: described.VersionIdsToStages[versionId] || [], payloadSha256: parsed.payloadSha256 });
    if (versionId === currentVersionId) currentPayloadSha256 = parsed.payloadSha256;
    const payload = parsed.value;
    if ((payload.materialType === "fresh-generated" || payload.baselineMarker) && (payload.sourceSha !== expectedIdentity.sourceSha || payload.rotationId !== expectedIdentity.rotationId)) unexpectedRebaselineIdentity = true;
  }
  return { slot, arn: secretArn, versions, currentVersionId, currentStages: described.VersionIdsToStages[currentVersionId], currentPayloadSha256, unexpectedRebaselineIdentity };
}

function awsJson(run, args) { return JSON.parse(run(["ecs", ...args])); }
function chunks(values, size = 100) { return Array.from({ length: Math.ceil(values.length / size) }, (_, index) => values.slice(index * size, index * size + size)); }

export function auditLiveProductionDualSlotReferences({ run, resources, databaseDependencies = 0, externalConsumers = 0 } = {}) {
  const service = awsJson(run, ["describe-services", "--cluster", CLUSTER, "--services", SERVICE]).services?.[0];
  if (!service?.taskDefinition || !service.serviceArn) throw new Error("Current production ECS service topology is unavailable.");
  const deploymentController = service.deploymentController?.type || "ECS";
  if (!["ECS", "CODE_DEPLOY", "EXTERNAL"].includes(deploymentController)) throw new Error("ECS deployment controller topology is unsupported.");
  const serviceTaskArns = new Set();
  const clusterTaskArns = new Set();
  for (const status of ["RUNNING", "PENDING"]) {
    const serviceListed = awsJson(run, ["list-tasks", "--cluster", CLUSTER, "--service-name", SERVICE, "--desired-status", status]).taskArns || [];
    const clusterListed = awsJson(run, ["list-tasks", "--cluster", CLUSTER, "--desired-status", status]).taskArns || [];
    if (!Array.isArray(serviceListed) || !Array.isArray(clusterListed)) throw new Error(`ECS ${status} task inventory is malformed.`);
    serviceListed.forEach((arn) => { serviceTaskArns.add(arn); clusterTaskArns.add(arn); });
    clusterListed.forEach((arn) => clusterTaskArns.add(arn));
  }
  const tasks = [];
  for (const batch of chunks([...clusterTaskArns].sort())) {
    if (batch.length === 0) continue;
    const described = awsJson(run, ["describe-tasks", "--cluster", CLUSTER, "--tasks", ...batch]).tasks;
    if (!Array.isArray(described) || described.length !== batch.length || new Set(described.map(({ taskArn }) => taskArn)).size !== batch.length || described.some(({ taskArn, taskDefinitionArn }) => !batch.includes(taskArn) || !taskDefinitionArn)) throw new Error("ECS task description inventory is incomplete.");
    tasks.push(...described);
  }
  const deployments = (service.deployments || []).filter((deployment) => deployment?.status === "PRIMARY" || deployment?.status === "ACTIVE").map(({ id, status, taskDefinition }) => ({ id, status, taskDefinition })).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  if (deployments.some(({ id, taskDefinition }) => !id || !taskDefinition)) throw new Error("ECS active deployment topology is incomplete.");
  const serviceTaskDefinitionArns = new Set([service.taskDefinition, ...deployments.map(({ taskDefinition }) => taskDefinition), ...tasks.filter(({ taskArn }) => serviceTaskArns.has(taskArn)).map(({ taskDefinitionArn }) => taskDefinitionArn)].filter(Boolean));
  const taskDefinitionArns = new Set([...serviceTaskDefinitionArns, ...tasks.map(({ taskDefinitionArn }) => taskDefinitionArn)].filter(Boolean));
  if (deploymentController !== "ECS") {
    const taskSets = awsJson(run, ["describe-task-sets", "--cluster", CLUSTER, "--service", SERVICE]).taskSets;
    if (!Array.isArray(taskSets)) throw new Error("ECS task-set topology is unavailable.");
    taskSets.filter((set) => set?.status === "PRIMARY" || set?.status === "ACTIVE").forEach(({ taskDefinition }) => { if (!taskDefinition) throw new Error("ECS task-set task definition is unavailable."); serviceTaskDefinitionArns.add(taskDefinition); taskDefinitionArns.add(taskDefinition); });
  }
  const taskDefinitions = [...taskDefinitionArns].sort().map((taskDefinitionArn) => ({ requestedArn: taskDefinitionArn, definition: awsJson(run, ["describe-task-definition", "--task-definition", taskDefinitionArn, "--include", "TAGS"]) }));
  const perTaskDefinition = taskDefinitions.map(({ requestedArn, definition }) => {
    const taskDefinitionArn = definition.taskDefinition?.taskDefinitionArn || definition.taskDefinitionArn;
    if (taskDefinitionArn !== requestedArn) throw new Error("ECS task definition identity is incomplete or substituted.");
    return { taskDefinitionArn, dualSlotReferences: Object.values(resources).filter((arn) => JSON.stringify(definition).includes(arn)).sort() };
  }).sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn));
  const dualSlotReferences = perTaskDefinition.reduce((count, item) => count + item.dualSlotReferences.length, 0);
  const active = taskDefinitions.find(({ requestedArn }) => requestedArn === service.taskDefinition)?.definition;
  if (!active) throw new Error("Current service task definition was not fully audited.");
  const legacy = deriveLegacyRotationBaseline(active);
  const evidence = { service: { arn: service.serviceArn, desiredCount: service.desiredCount, runningCount: service.runningCount, pendingCount: service.pendingCount, taskDefinition: service.taskDefinition, deploymentController }, deployments, tasks: tasks.map(({ taskArn, taskDefinitionArn, lastStatus, desiredStatus }) => ({ taskArn, taskDefinitionArn, lastStatus, desiredStatus, serviceTask: serviceTaskArns.has(taskArn) })).sort((a, b) => a.taskArn.localeCompare(b.taskArn)), taskDefinitionArns: [...taskDefinitionArns].sort(), serviceTaskDefinitionArns: [...serviceTaskDefinitionArns].sort(), perTaskDefinition, databaseDependencies, externalConsumers };
  const stableEvidence = { cluster: CLUSTER, service: { arn: service.serviceArn, deploymentController, taskDefinition: service.taskDefinition }, serviceTaskDefinitionArns: [...serviceTaskDefinitionArns].sort(), serviceTaskDefinitionReferences: perTaskDefinition.filter(({ taskDefinitionArn }) => serviceTaskDefinitionArns.has(taskDefinitionArn)), legacy, databaseDependencies, externalConsumers, externalDualSlotReferences: perTaskDefinition.filter(({ taskDefinitionArn }) => !serviceTaskDefinitionArns.has(taskDefinitionArn)).flatMap(({ dualSlotReferences }) => dualSlotReferences).sort() };
  const auditSha256 = canonicalSha256(evidence);
  const stableAuditSha256 = canonicalSha256(stableEvidence);
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, databaseDependencies, externalConsumers, runningTasks: service.runningCount, pendingTasks: service.pendingCount, activeTaskDefinition: service.taskDefinition, legacy, evidence, auditSha256, stableEvidence, stableAuditSha256 });
}

export function createProductionRebaselineAdapters({ client, run, resources, preparation } = {}) {
  return {
    readReferenceAudit: async () => auditLiveProductionDualSlotReferences({ run, resources, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers }),
    readSlot: (slot, secretArn, expectedVersionId, expectedIdentity) => readSlotSnapshot(client, slot, secretArn, expectedVersionId, expectedIdentity),
    writeSlot: ({ secretArn, clientRequestToken, payload }) => client.send(new PutSecretValueCommand({ SecretId: secretArn, ClientRequestToken: clientRequestToken, SecretString: JSON.stringify(payload) })).then((response) => ({ arn: secretArn, versionId: response.VersionId })),
  };
}

export function auditLegacyTaskDefinition(taskDefinition, resources, { runningTasks = 0, pendingTasks = 0, databaseDependencies = 0, externalConsumers = 0 } = {}) {
  const serialized = JSON.stringify(taskDefinition);
  const dualSlotReferences = Object.values(resources).filter((arn) => serialized.includes(arn)).length;
  const legacy = deriveLegacyRotationBaseline(taskDefinition);
  const taskDefinitionArn = taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown";
  const perTaskDefinition = [{ taskDefinitionArn, dualSlotReferences: Object.values(resources).filter((arn) => serialized.includes(arn)).sort() }];
  const evidence = { service: { arn: "fixture", desiredCount: runningTasks, runningCount: runningTasks, pendingCount: pendingTasks, taskDefinition: taskDefinitionArn, deploymentController: "ECS" }, deployments: [], tasks: [], taskDefinitionArns: [taskDefinitionArn], serviceTaskDefinitionArns: [taskDefinitionArn], perTaskDefinition, databaseDependencies, externalConsumers };
  const stableEvidence = { cluster: "fixture", service: { arn: "fixture", deploymentController: "ECS", taskDefinition: taskDefinitionArn }, serviceTaskDefinitionArns: [taskDefinitionArn], serviceTaskDefinitionReferences: perTaskDefinition, legacy, databaseDependencies, externalConsumers, externalDualSlotReferences: [] };
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, databaseDependencies, externalConsumers, runningTasks, pendingTasks, activeTaskDefinition: taskDefinitionArn, legacy, evidence, auditSha256: canonicalSha256(evidence), stableEvidence, stableAuditSha256: canonicalSha256(stableEvidence) });
}

export function readAuthenticatedRebaselineCheckout({ sourceSha, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), repositoryRoot = REPOSITORY_ROOT } = {}) {
  const checkout = readStageBProtectedMainCheckout({ cwd: repositoryRoot, fetchOriginMain: true, run: gitRun });
  if (checkout.toolingSha !== sourceSha) throw new Error("Protected rebaseline checkout does not match the requested source SHA.");
  return checkout;
}

export async function prepareProductionDualSlotRebaseline({ sourceSha, rotationId, outputDirectory, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, topology: suppliedTopology, taskDefinition, liveReferenceAudit = {}, repositoryRoot = REPOSITORY_ROOT } = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Dual-slot rebaseline preparation directory" });
  const checkout = readAuthenticatedRebaselineCheckout({ sourceSha, gitRun, repositoryRoot });
  const topology = suppliedTopology || await readDualSlotTopology({ client });
  const audit = liveReferenceAudit?.stableAuditSha256 ? liveReferenceAudit : auditLegacyTaskDefinition(taskDefinition, topology.resources, liveReferenceAudit);
  const abandonmentEvidence = buildAbandonmentEvidence({ sourceSha: checkout.toolingSha, historicalRotationId: HISTORICAL_ROTATION_ID, historicalSourceShas: HISTORICAL_SOURCES, resources: topology.resources, currentVersionIds: topology.currentVersionIds, observedSlotIdentities: topology.observedSlotIdentities, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative });
  const preconditions = assertRebaselinePreconditions({ environment: "production", accountId: ACCOUNT, region: REGION, sourceSha: checkout.toolingSha, sourceCas: checkout.toolingSha === sourceSha, cleanWorktree: checkout.porcelainStatus === "", existingSecretResources: true, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, databaseDependencies: audit.databaseDependencies, externalConsumers: audit.externalConsumers, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, resources: topology.resources, abandonmentEvidence });
  const rotation = buildRebaselineIdentity({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, legacyBaseline: audit.legacy });
  const material = loadOrCreateRebaselineMaterialJournal({ filePath: path.join(directory, "rebaseline-material.json"), repositoryRoot, sourceSha: checkout.toolingSha, rotationId, baselineIdentitySha256: rotation.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha: checkout.toolingSha, rotationId, generatedMaterial: material.material, legacyBaseline: audit.legacy });
  const writePlan = buildRebaselineWritePlan({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, baselineIdentitySha256: rotation.identitySha256, payloads });
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha: checkout.toolingSha, rotationId, baselineIdentity: rotation, writePlan });
  const abandonmentFile = path.join(directory, "abandonment-evidence.json");
  writeStageBPrivateFileExclusive({ filePath: abandonmentFile, bytes: Buffer.from(`${JSON.stringify(abandonmentEvidence, null, 2)}\n`), repositoryRoot, label: "Dual-slot abandonment evidence" });
  const preparationFile = path.join(directory, "rebaseline-preparation.json");
  writeStageBPrivateFileAtomic({ filePath: preparationFile, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot, label: "Dual-slot rebaseline preparation" });
  return Object.freeze({ sourceSha: checkout.toolingSha, rotationId, abandonmentFile, preparationFile, preparationSha256: preparation.preparationSha256, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), writeCount: 7, liveReferenceAuditSha256: audit.stableAuditSha256, liveReferenceObservationSha256: audit.auditSha256, observedSlotIdentitiesSha256: topology.observedSlotIdentitiesSha256 });
}

export async function executePreparedProductionDualSlotRebaseline({ preparationFile, authorization, materialJournalFile, completionFile, bindingsFile, repositoryRoot = REPOSITORY_ROOT, sourceSha, currentPreconditions, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, adapters, afterCompletionPersist, afterBindingsPersist } = {}) {
  const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes);
  const { assertRebaselinePreparation, assertProductionDualSlotRebaselineAuthorization } = await import("./production-dual-slot-rebaseline-contract.mjs");
  assertRebaselinePreparation(preparation, { sourceSha, rotationId: preparation.rotationId });
  if (preparation.historicalTopologySha256 !== REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256) throw new Error("Rebaseline preparation historical topology is not the protected-source abandoned identity.");
  const checkout = readAuthenticatedRebaselineCheckout({ sourceSha, gitRun, repositoryRoot });
  const current = assertRebaselinePreconditions({ ...currentPreconditions, sourceSha: checkout.toolingSha, sourceCas: true, cleanWorktree: checkout.porcelainStatus === "" });
  if (current.sourceSha !== preparation.sourceSha || current.historicalRotationId !== preparation.historicalRotationId || current.dualSlotReferences !== 0 || current.liveReferenceAuditSha256 !== preparation.liveReferenceAuditSha256 || canonicalSha256(current.resources) !== canonicalSha256(preparation.resources) || canonicalSha256(current.legacyBaseline) !== canonicalSha256(preparation.legacyBaseline) || current.abandonmentEvidence.evidenceSha256 !== preparation.abandonmentEvidenceSha256 || canonicalSha256(current.abandonmentEvidence) !== canonicalSha256(preparation.abandonmentEvidence)) throw new Error("Rebaseline preconditions changed after authorization.");
  if (!authorization || typeof authorization !== "object") throw new Error("Authenticated dual-slot rebaseline authorization artifact is required.");
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId: preparation.rotationId, resources: preparation.resources });
  if (authorization.historicalRotationId !== preparation.historicalRotationId || authorization.abandonmentEvidenceSha256 !== preparation.abandonmentEvidenceSha256 || authorization.baselineIdentitySha256 !== preparation.baselineIdentity.identitySha256 || authorization.liveReferenceAuditSha256 !== preparation.liveReferenceAuditSha256 || authorization.observedSlotIdentitiesSha256 !== preparation.abandonmentEvidence.observedSlotIdentitiesSha256) throw new Error("Rebaseline authorization is not bound to the authenticated preparation.");
  const journal = readRebaselineMaterialJournal({ filePath: materialJournalFile, repositoryRoot, sourceSha, rotationId: preparation.rotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha, rotationId: preparation.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
  const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId: preparation.rotationId, resources: preparation.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
  const preparedBySlot = Object.fromEntries(preparation.writePlan.map((entry) => [entry.slot, entry]));
  for (const entry of writePlan) if (entry.payloadSha256 !== preparedBySlot[entry.slot]?.payloadSha256 || entry.secretArn !== preparedBySlot[entry.slot]?.secretArn || entry.clientRequestToken !== preparedBySlot[entry.slot]?.clientRequestToken) throw new Error(`Rebaseline material for ${entry.slot} does not match the authenticated preparation.`);
  const descriptors = Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]));
  if (JSON.stringify(descriptors) !== JSON.stringify(authorization.writeIdentities)) throw new Error("Authorization write identities do not match the authenticated preparation.");
  return executeProductionDualSlotRebaseline({ preconditions: current, sourceSha, rotationId: preparation.rotationId, baselineIdentity: preparation.baselineIdentity, writePlan, authorization, completionFile, bindingsFile, repositoryRoot, afterCompletionPersist, afterBindingsPersist, ...adapters });
}

export function createProductionRebaselineClient({ profile = "mscqr-production-release-deployer" } = {}) { return createInitialDualSlotSecretsManagerClient({ region: REGION, profile }); }

export async function runProductionDualSlotRebaselineCli({ argv = process.argv.slice(2), repositoryRoot = REPOSITORY_ROOT, readCheckout = readAuthenticatedRebaselineCheckout, createRun = () => createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: REGION }), createClient = createProductionRebaselineClient, resolveAuthorization = resolveProductionDualSlotRebaselineAuthorizationArtifact, readTopology = readDualSlotTopology, readPreparedTopology = readPreparedDualSlotTopology, auditReferences = auditLiveProductionDualSlotReferences, executePrepared = executePreparedProductionDualSlotRebaseline, output = (value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) } = {}) {
  const args = parseArgs(argv);
  const sourceSha = required(args, "source-sha");
  if (args.has("prepare")) {
    const checkout = readCheckout({ sourceSha, repositoryRoot });
    const run = createRun();
    const client = createClient(); await client.assertCredentialIdentity();
    const outputDirectory = path.resolve(required(args, "output-directory")); mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
    const topology = await readTopology({ client });
    const audit = auditReferences({ run, resources: topology.resources, databaseDependencies: Number(required(args, "database-dependencies")), externalConsumers: Number(required(args, "external-consumers")) });
    const result = await prepareProductionDualSlotRebaseline({ sourceSha: checkout.toolingSha, rotationId: required(args, "rotation-id"), outputDirectory, client, topology, liveReferenceAudit: audit, repositoryRoot });
    output(result);
    return result;
  } else if (args.has("execute")) {
    const checkout = readCheckout({ sourceSha, repositoryRoot });
    const requestedRotationId = required(args, "rotation-id");
    const preparationFile = path.resolve(required(args, "preparation")); const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes);
    const { assertRebaselinePreparation } = await import("./production-dual-slot-rebaseline-contract.mjs");
    assertRebaselinePreparation(preparation, { sourceSha: checkout.toolingSha, rotationId: requestedRotationId });
    const run = createRun();
    const client = createClient(); await client.assertCredentialIdentity();
    const authorization = resolveAuthorization({ workflowRunId: required(args, "workflow-run-id"), workflowRunAttempt: required(args, "workflow-run-attempt"), sourceSha: checkout.toolingSha, rotationId: requestedRotationId, resources: preparation.resources }).authorization;
    const journal = readRebaselineMaterialJournal({ filePath: path.resolve(required(args, "material-journal")), repositoryRoot, sourceSha: checkout.toolingSha, rotationId: requestedRotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
    const payloads = buildRebaselinePayloads({ sourceSha: checkout.toolingSha, rotationId: preparation.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
    const writePlan = buildRebaselineWritePlan({ sourceSha: checkout.toolingSha, rotationId: preparation.rotationId, resources: preparation.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
    const topology = await readPreparedTopology({ client, preparation, writePlan }); const audit = auditReferences({ run, resources: topology.resources, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers });
    const currentPreconditions = { ...preparation, resources: topology.resources, abandonmentEvidence: preparation.abandonmentEvidence, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, legacyBaseline: audit.legacy };
    const result = await executePrepared({ preparationFile, authorization, materialJournalFile: path.resolve(required(args, "material-journal")), completionFile: path.resolve(required(args, "completion-output")), bindingsFile: path.resolve(required(args, "rotation-bindings-output")), repositoryRoot, sourceSha: checkout.toolingSha, currentPreconditions, client, adapters: createProductionRebaselineAdapters({ client, run, resources: topology.resources, preparation }) });
    const summary = { baselineComplete: result.baselineComplete, writes: result.writes, baselineBindingSha256: result.completion.baselineBindingSha256, completionPath: result.completionPath, completionSha256: result.completionSha256, rotationBindingsPath: result.bindingsPath, rotationBindingsSha256: result.bindingsSha256 };
    output(summary);
    return summary;
  } else throw new Error("Use --prepare or --execute.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) await runProductionDualSlotRebaselineCli();
