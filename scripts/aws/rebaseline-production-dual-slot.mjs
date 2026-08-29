#!/usr/bin/env node
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { createInitialDualSlotSecretsManagerClient } from "./production-initial-dual-slot-bootstrap.mjs";
import { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOTS, assertRebaselinePreconditions, buildAbandonmentEvidence,
  buildRebaselineIdentity, buildRebaselinePreparation, buildRebaselineWritePlan, buildRebaselinePayloads,
  canonicalSha256, historicalSlotIdentity, loadOrCreateRebaselineMaterialJournal, readRebaselineMaterialJournal, executeProductionDualSlotRebaseline, executeAuthenticatedPartialRebaselineRecovery as executePartialRecoveryContract, resolveProductionDualSlotRebaselineAuthorizationArtifact, resolvePartialRebaselineRecoveryAuthorizationArtifact, assertAuthenticatedPartialRebaselineRecovery, assertAbandonmentEvidence,
  REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, assertProductionDualSlotRebaselineAuthorization, assertRebaselinePreparation, assertRebaselineRotationBindings, rebaselineWritePayloadIdentities, safeWriteDescriptors, coordinatorTransitionSlotIdentity, assertAuthenticatedPreCutoverCoordinatorTransition,
} from "./production-dual-slot-rebaseline-contract.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const requireBackend = createRequire(path.join(REPOSITORY_ROOT, "backend/package.json"));
const { GetSecretValueCommand, DescribeSecretCommand, PutSecretValueCommand } = requireBackend("@aws-sdk/client-secrets-manager");
const ACCOUNT = PRODUCTION_DUAL_SLOT_REBASELINE.accountId;
const REGION = PRODUCTION_DUAL_SLOT_REBASELINE.region;
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const HISTORICAL_ROTATION_ID = REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID;
const HISTORICAL_SOURCES = ["5506cbe3972a27a77c211f2891756c3b97de7197", "9f39d1c4f646467146c12c0587fd7ad585f3fe10"];
const required = (args, name) => { const value = args.get(name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const parseArgs = (argv) => { const values = new Map(); for (let i = 0; i < argv.length; i += 1) { const key = argv[i]?.replace(/^--/, ""); if (["prepare", "execute", "recover-execute"].includes(key)) { if (values.has(key)) throw new Error(`Duplicate argument: ${argv[i]}`); values.set(key, true); continue; } if (!key || !argv[i + 1] || argv[i + 1].startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${argv[i]}`); values.set(key, argv[++i]); } return values; };
const json = (bytes) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
const parseSecret = (response, label, expectedVersionId) => { if (expectedVersionId !== undefined && response?.VersionId !== expectedVersionId) throw new Error(`${label} returned a substituted secret version.`); if (typeof response?.SecretString !== "string") throw new Error(`${label} is not a reviewed JSON secret.`); const value = JSON.parse(response.SecretString); if (!value || typeof value !== "object" || typeof value.value !== "string") throw new Error(`${label} has an invalid rotation payload.`); return { value, payloadSha256: canonicalSha256(value) }; };

export async function verifyLiveProductionDualSlotRebaseline({ client, bindings, authorization } = {}) {
  assertRebaselineRotationBindings(bindings, { authorization });
  const resources = {
    jwtPending: bindings.jwt.pendingSecretId,
    qrPrivatePending: bindings.qr.privatePendingSecretId,
    qrPublicPending: bindings.qr.publicPendingSecretId,
    jwtPrevious: bindings.jwt.previousSecretId,
    qrPublicPrevious: bindings.qr.publicPreviousSecretId,
    qrCurrentVersion: bindings.qr.currentKeyVersionSecretId,
    qrPreviousVersion: bindings.qr.previousKeyVersionSecretId,
  };
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources });
  const versionIds = {};
  const payloadIdentities = {};
  for (const [slot, secretArn] of Object.entries(resources)) {
    const described = await client.send(new DescribeSecretCommand({ SecretId: secretArn }));
    if (described.ARN !== secretArn) throw new Error(`Live ${slot} secret ARN is substituted.`);
    const current = Object.entries(described.VersionIdsToStages || {}).filter(([, stages]) => Array.isArray(stages) && stages.includes("AWSCURRENT"));
    const expectedVersionId = authorization.writeIdentities[slot];
    if (current.length !== 1 || current[0][0] !== expectedVersionId || current[0][1].length !== 1 || current[0][1][0] !== "AWSCURRENT") throw new Error(`Live ${slot} secret is not the exact completed rebaseline version.`);
    const parsed = parseSecret(await client.send(new GetSecretValueCommand({ SecretId: secretArn, VersionId: expectedVersionId })), `Live ${slot}`, expectedVersionId);
    const expected = authorization.writePayloadIdentities[slot];
    if (parsed.payloadSha256 !== expected.payloadSha256 || parsed.value.sourceSha !== bindings.sourceSha || parsed.value.rotationId !== bindings.rotationId || (parsed.value.materialType !== undefined ? parsed.value.materialType : parsed.value.baselineMarker) !== expected.materialType || (parsed.value.keyVersion || null) !== expected.keyVersion) throw new Error(`Live ${slot} secret payload does not match the protected rebaseline authorization.`);
    versionIds[slot] = expectedVersionId;
    payloadIdentities[slot] = expected;
  }
  const body = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, authorizationSha256: authorization.authorizationSha256, resources, versionIds, payloadIdentities };
  return Object.freeze({ ...body, livePostWriteSha256: canonicalSha256(body) });
}


export async function readDualSlotTopology({ client, names = REBASELINE_SLOTS, historicalRotationId = HISTORICAL_ROTATION_ID, preparedState, preparedWritePlan, historicalTransitionEvidence } = {}) {
  if ((preparedState && !preparedWritePlan) || (!preparedState && preparedWritePlan)) throw new Error("Prepared rebaseline topology requires both authenticated preparation and write plan.");
  if (preparedState) assertAbandonmentEvidence(preparedState.abandonmentEvidence, { sourceSha: preparedState.sourceSha, resources: preparedState.resources, historicalTopologySha256: preparedState.historicalTopologySha256 });
  const transitionEvidence = historicalTransitionEvidence || preparedState?.abandonmentEvidence?.historicalTransitionEvidence;
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
      snapshots[slot].historicalIdentity = transitionEvidence && ["jwtPrevious", "qrCurrentVersion"].includes(slot)
        ? coordinatorTransitionSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value })
        : historicalSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value });
      continue;
    }
    const historicalIdentity = preparedState.abandonmentEvidence.observedSlotIdentities[slot];
    const historicalVersionId = preparedState.abandonmentEvidence.currentVersionIds[slot];
    const expectedWrite = preparedBySlot[slot];
    if (!expectedWrite) throw new Error(`Prepared rebaseline write identity for ${slot} is missing.`);
    if (current[0][0] === historicalVersionId) {
      const observed = transitionEvidence && ["jwtPrevious", "qrCurrentVersion"].includes(slot)
        ? coordinatorTransitionSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value })
        : historicalSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0][0], stages: current[0][1], payload: parsed.value });
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
  if (transitionEvidence && !preparedState) assertAuthenticatedPreCutoverCoordinatorTransition(transitionEvidence, { resources, observedVersionIds: currentVersionIds, observedSlotIdentities });
  return Object.freeze({ resources, currentVersionIds, snapshots, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities), ...(transitionEvidence ? { historicalTransitionEvidence: transitionEvidence } : {}), ...(preparedState ? { classifications: Object.freeze(Object.fromEntries(Object.entries(snapshots).map(([slot, snapshot]) => [slot, snapshot.classification]))) } : {}) });
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
function listAllTaskArns(run, args) {
  const taskArns = new Set(); const tokens = new Set(); let nextToken;
  for (let page = 0; page < 10; page += 1) {
    const pageArgs = [...args, "--page-size", "100", "--max-items", "100"];
    if (nextToken) pageArgs.push("--starting-token", nextToken);
    const response = awsJson(run, pageArgs);
    if (!response || !Array.isArray(response.taskArns)) throw new Error("ECS task census page is malformed.");
    for (const taskArn of response.taskArns) {
      if (typeof taskArn !== "string" || !taskArn.startsWith("arn:aws:ecs:eu-west-2:368992683803:task/")) throw new Error("ECS task census returned an invalid task ARN.");
      taskArns.add(taskArn);
      if (taskArns.size > 1000) throw new Error("ECS task census exceeds the bounded task limit.");
    }
    const token = response.nextToken ?? response.NextToken;
    if (token === undefined || token === null || token === "") return [...taskArns].sort();
    if (typeof token !== "string" || tokens.has(token)) throw new Error("ECS task census pagination token is malformed or cyclic.");
    tokens.add(token); nextToken = token;
  }
  throw new Error("ECS task census exceeds the bounded page limit.");
}

export function auditLiveProductionDualSlotReferences({ run, resources, databaseDependencies = 0, externalConsumers = 0 } = {}) {
  const service = awsJson(run, ["describe-services", "--cluster", CLUSTER, "--services", SERVICE]).services?.[0];
  if (!service?.taskDefinition || !service.serviceArn) throw new Error("Current production ECS service topology is unavailable.");
  const deploymentController = service.deploymentController?.type || "ECS";
  if (!["ECS", "CODE_DEPLOY", "EXTERNAL"].includes(deploymentController)) throw new Error("ECS deployment controller topology is unsupported.");
  const serviceTaskArns = new Set();
  const clusterTaskArns = new Set();
  for (const desiredStatus of ["RUNNING", "STOPPED"]) {
    const serviceListed = listAllTaskArns(run, ["list-tasks", "--cluster", CLUSTER, "--service-name", SERVICE, "--desired-status", desiredStatus]);
    const clusterListed = listAllTaskArns(run, ["list-tasks", "--cluster", CLUSTER, "--desired-status", desiredStatus]);
    serviceListed.forEach((arn) => { serviceTaskArns.add(arn); clusterTaskArns.add(arn); });
    clusterListed.forEach((arn) => clusterTaskArns.add(arn));
  }
  const tasks = [];
  for (const batch of chunks([...clusterTaskArns].sort())) {
    if (batch.length === 0) continue;
    const response = awsJson(run, ["describe-tasks", "--cluster", CLUSTER, "--tasks", ...batch]);
    const described = response.tasks;
    if (Array.isArray(response.failures) && response.failures.length > 0) throw new Error("ECS task description inventory contains failures.");
    if (!Array.isArray(described) || described.length !== batch.length || new Set(described.map(({ taskArn }) => taskArn)).size !== batch.length || described.some(({ taskArn, taskDefinitionArn, lastStatus, desiredStatus }) => !batch.includes(taskArn) || !taskDefinitionArn || typeof lastStatus !== "string" || typeof desiredStatus !== "string")) throw new Error("ECS task description inventory is incomplete.");
    tasks.push(...described);
  }
  const deployments = (service.deployments || []).filter((deployment) => deployment?.status === "PRIMARY" || deployment?.status === "ACTIVE").map(({ id, status, taskDefinition }) => ({ id, status, taskDefinition })).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  if (deployments.some(({ id, taskDefinition }) => !id || !taskDefinition)) throw new Error("ECS active deployment topology is incomplete.");
  const liveTasks = tasks.filter(({ lastStatus }) => lastStatus !== "STOPPED");
  const serviceTaskDefinitionArns = new Set([service.taskDefinition, ...deployments.map(({ taskDefinition }) => taskDefinition), ...liveTasks.filter(({ taskArn }) => serviceTaskArns.has(taskArn)).map(({ taskDefinitionArn }) => taskDefinitionArn)].filter(Boolean));
  const taskDefinitionArns = new Set([...serviceTaskDefinitionArns, ...liveTasks.map(({ taskDefinitionArn }) => taskDefinitionArn)].filter(Boolean));
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
  const definitionsByArn = new Map(taskDefinitions.map(({ requestedArn, definition }) => [requestedArn, definition]));
  const liveServiceTaskDefinitionArns = [...new Set(liveTasks.filter(({ taskArn }) => serviceTaskArns.has(taskArn)).map(({ taskDefinitionArn }) => taskDefinitionArn))].sort();
  const deploymentTaskDefinitionCoverage = deployments.map(({ id, status, taskDefinition }) => ({ id, status, taskDefinitionArn: taskDefinition, representedByLiveServiceTask: liveServiceTaskDefinitionArns.includes(taskDefinition) }));
  const liveLegacyBaselines = liveServiceTaskDefinitionArns.map((taskDefinitionArn) => ({ taskDefinitionArn, legacy: deriveLegacyRotationBaseline(definitionsByArn.get(taskDefinitionArn)) }));
  const uniqueLegacyBaselines = [...new Map(liveLegacyBaselines.map(({ legacy }) => [canonicalSha256(legacy), legacy])).entries()].sort(([left], [right]) => left.localeCompare(right)).map(([identitySha256, legacy]) => ({ identitySha256, legacy }));
  const liveLegacyBaselineCount = uniqueLegacyBaselines.length;
  const legacy = liveLegacyBaselineCount === 1 ? uniqueLegacyBaselines[0].legacy : undefined;
  const legacyRuntimeAuthoritative = dualSlotReferences === 0 && liveLegacyBaselineCount === 1;
  const evidence = { service: { arn: service.serviceArn, desiredCount: service.desiredCount, runningCount: service.runningCount, pendingCount: service.pendingCount, taskDefinition: service.taskDefinition, deploymentController }, deployments, deploymentTaskDefinitionCoverage, tasks: tasks.map(({ taskArn, taskDefinitionArn, lastStatus, desiredStatus }) => ({ taskArn, taskDefinitionArn, lastStatus, desiredStatus, live: lastStatus !== "STOPPED", serviceTask: serviceTaskArns.has(taskArn) })).sort((a, b) => a.taskArn.localeCompare(b.taskArn)), taskDefinitionArns: [...taskDefinitionArns].sort(), serviceTaskDefinitionArns: [...serviceTaskDefinitionArns].sort(), liveServiceTaskDefinitionArns, perTaskDefinition, databaseDependencies, externalConsumers };
  const stableEvidence = { cluster: CLUSTER, service: { arn: service.serviceArn, deploymentController, taskDefinition: service.taskDefinition }, serviceTaskDefinitionArns: [...serviceTaskDefinitionArns].sort(), serviceTaskDefinitionReferences: perTaskDefinition.filter(({ taskDefinitionArn }) => serviceTaskDefinitionArns.has(taskDefinitionArn)), liveServiceTaskDefinitionArns, deploymentTaskDefinitionCoverage, liveLegacyBaselines, liveLegacyBaselineCount, legacy, databaseDependencies, externalConsumers, externalDualSlotReferences: perTaskDefinition.filter(({ taskDefinitionArn }) => !serviceTaskDefinitionArns.has(taskDefinitionArn)).flatMap(({ dualSlotReferences }) => dualSlotReferences).sort() };
  const auditSha256 = canonicalSha256(evidence);
  const stableAuditSha256 = canonicalSha256(stableEvidence);
  return Object.freeze({ status: legacyRuntimeAuthoritative ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative, liveLegacyBaselineCount, liveLegacyBaselineIdentitySha256: legacyRuntimeAuthoritative ? canonicalSha256(legacy) : undefined, databaseDependencies, externalConsumers, runningTasks: service.runningCount, pendingTasks: service.pendingCount, activeTaskDefinition: service.taskDefinition, legacy, evidence, auditSha256, stableEvidence, stableAuditSha256 });
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
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, liveLegacyBaselineCount: 1, liveLegacyBaselineIdentitySha256: dualSlotReferences === 0 ? canonicalSha256(legacy) : undefined, databaseDependencies, externalConsumers, runningTasks, pendingTasks, activeTaskDefinition: taskDefinitionArn, legacy, evidence, auditSha256: canonicalSha256(evidence), stableEvidence, stableAuditSha256: canonicalSha256(stableEvidence) });
}

export function readAuthenticatedRebaselineCheckout({ sourceSha, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), repositoryRoot = REPOSITORY_ROOT } = {}) {
  const checkout = readStageBProtectedMainCheckout({ cwd: repositoryRoot, fetchOriginMain: true, run: gitRun });
  if (checkout.toolingSha !== sourceSha) throw new Error("Protected rebaseline checkout does not match the requested source SHA.");
  return checkout;
}

export async function prepareProductionDualSlotRebaseline({ sourceSha, rotationId, outputDirectory, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, topology: suppliedTopology, historicalTransitionEvidence, taskDefinition, liveReferenceAudit = {}, repositoryRoot = REPOSITORY_ROOT, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, afterAbandonmentPersist, afterPreparationPersist } = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Dual-slot rebaseline preparation directory" });
  const checkout = readAuthenticatedRebaselineCheckout({ sourceSha, gitRun, repositoryRoot });
  const topology = suppliedTopology || await readDualSlotTopology({ client, historicalTransitionEvidence });
  const audit = liveReferenceAudit?.stableAuditSha256 ? liveReferenceAudit : auditLegacyTaskDefinition(taskDefinition, topology.resources, liveReferenceAudit);
  const abandonmentFile = path.join(directory, "abandonment-evidence.json");
  let abandonmentEvidence;
  const existingAbandonment = lstatSync(abandonmentFile, { throwIfNoEntry: false });
  if (existingAbandonment) {
    if (!existingAbandonment.isFile() || existingAbandonment.isSymbolicLink()) throw new Error("Existing dual-slot abandonment evidence must be a regular private file.");
    const captured = readStageBPrivateFileBytes({ filePath: abandonmentFile, repositoryRoot, label: "Dual-slot abandonment evidence" });
    abandonmentEvidence = assertAbandonmentEvidence(json(captured.bytes), { sourceSha: checkout.toolingSha, resources: topology.resources, historicalTopologySha256 });
    if (abandonmentEvidence.historicalRotationId !== HISTORICAL_ROTATION_ID || canonicalSha256(abandonmentEvidence.currentVersionIds) !== canonicalSha256(topology.currentVersionIds) || canonicalSha256(abandonmentEvidence.observedSlotIdentities) !== canonicalSha256(topology.observedSlotIdentities) || abandonmentEvidence.liveReferenceAuditSha256 !== audit.stableAuditSha256 || abandonmentEvidence.legacyRuntimeAuthoritative !== audit.legacyRuntimeAuthoritative) throw new Error("Existing dual-slot abandonment evidence does not match the authenticated preparation baseline.");
  } else {
    abandonmentEvidence = buildAbandonmentEvidence({ sourceSha: checkout.toolingSha, historicalRotationId: HISTORICAL_ROTATION_ID, historicalSourceShas: HISTORICAL_SOURCES, resources: topology.resources, currentVersionIds: topology.currentVersionIds, historicalTopologySha256, observedSlotIdentities: topology.observedSlotIdentities, historicalTransitionEvidence: topology.historicalTransitionEvidence || historicalTransitionEvidence, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, liveLegacyBaselineIdentitySha256: (topology.historicalTransitionEvidence || historicalTransitionEvidence) ? audit.liveLegacyBaselineIdentitySha256 : undefined, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative });
    writeStageBPrivateFileAtomicExclusive({ filePath: abandonmentFile, bytes: Buffer.from(`${JSON.stringify(abandonmentEvidence, null, 2)}\n`), repositoryRoot, label: "Dual-slot abandonment evidence" });
    if (typeof afterAbandonmentPersist === "function") await afterAbandonmentPersist();
  }
  const preconditions = assertRebaselinePreconditions({ environment: "production", accountId: ACCOUNT, region: REGION, sourceSha: checkout.toolingSha, sourceCas: checkout.toolingSha === sourceSha, cleanWorktree: checkout.porcelainStatus === "", existingSecretResources: true, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, liveLegacyBaselineCount: audit.liveLegacyBaselineCount, liveLegacyBaselineIdentitySha256: audit.liveLegacyBaselineIdentitySha256, legacyBaseline: audit.legacy, databaseDependencies: audit.databaseDependencies, externalConsumers: audit.externalConsumers, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, resources: topology.resources, historicalTopologySha256, abandonmentEvidence });
  const rotation = buildRebaselineIdentity({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, legacyBaseline: audit.legacy });
  const material = loadOrCreateRebaselineMaterialJournal({ filePath: path.join(directory, "rebaseline-material.json"), repositoryRoot, sourceSha: checkout.toolingSha, rotationId, baselineIdentitySha256: rotation.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha: checkout.toolingSha, rotationId, generatedMaterial: material.material, legacyBaseline: audit.legacy });
  const writePlan = buildRebaselineWritePlan({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, baselineIdentitySha256: rotation.identitySha256, payloads });
  const preparationFile = path.join(directory, "rebaseline-preparation.json");
  const proposedPreparation = buildRebaselinePreparation({ preconditions, sourceSha: checkout.toolingSha, rotationId, baselineIdentity: rotation, writePlan });
  const existingPreparation = lstatSync(preparationFile, { throwIfNoEntry: false });
  const preparation = existingPreparation
    ? (() => {
      if (!existingPreparation.isFile() || existingPreparation.isSymbolicLink()) throw new Error("Existing dual-slot rebaseline preparation must be a regular private file.");
      const recovered = assertRebaselinePreparation(json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes), { sourceSha: checkout.toolingSha, rotationId });
      if (recovered.abandonmentEvidence.evidenceSha256 !== abandonmentEvidence.evidenceSha256) throw new Error("Existing dual-slot rebaseline preparation abandonment evidence does not match the authenticated resume contract.");
      if (recovered.baselineIdentity.identitySha256 !== rotation.identitySha256) throw new Error("Existing dual-slot rebaseline preparation baseline identity does not match the authenticated resume contract.");
      if (canonicalSha256(recovered.writePlan) !== canonicalSha256(safeWriteDescriptors(writePlan))) throw new Error("Existing dual-slot rebaseline preparation write plan does not match the authenticated resume contract.");
      return recovered;
    })()
    : (() => {
      writeStageBPrivateFileAtomicExclusive({ filePath: preparationFile, bytes: Buffer.from(`${JSON.stringify(proposedPreparation, null, 2)}\n`), repositoryRoot, label: "Dual-slot rebaseline preparation" });
      return proposedPreparation;
    })();
  if (!existingPreparation && typeof afterPreparationPersist === "function") await afterPreparationPersist();
  return Object.freeze({ sourceSha: checkout.toolingSha, rotationId, abandonmentFile, preparationFile, preparationSha256: preparation.preparationSha256, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), writePayloadIdentities: rebaselineWritePayloadIdentities(writePlan), writeCount: 7, liveReferenceAuditSha256: audit.stableAuditSha256, liveReferenceObservationSha256: audit.auditSha256, liveLegacyBaselineCount: audit.liveLegacyBaselineCount, observedSlotIdentitiesSha256: topology.observedSlotIdentitiesSha256 });
}

export async function executePreparedProductionDualSlotRebaseline({ preparationFile, authorization, materialJournalFile, completionFile, bindingsFile, repositoryRoot = REPOSITORY_ROOT, sourceSha, currentPreconditions, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, adapters, afterCompletionPersist, afterBindingsPersist } = {}) {
  const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes);
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
  if (JSON.stringify(descriptors) !== JSON.stringify(authorization.writeIdentities) || canonicalSha256(rebaselineWritePayloadIdentities(writePlan)) !== canonicalSha256(authorization.writePayloadIdentities)) throw new Error("Authorization write identities do not match the authenticated preparation.");
  return executeProductionDualSlotRebaseline({ preconditions: current, sourceSha, rotationId: preparation.rotationId, baselineIdentity: preparation.baselineIdentity, writePlan, authorization, completionFile, bindingsFile, repositoryRoot, afterCompletionPersist, afterBindingsPersist, ...adapters });
}

export async function executeAuthenticatedPartialRebaselineRecovery({ recoveryEnvelopeFile, originalPreparationFile, materialJournalFile, authorization, imageAuthorization, imageAuthorizationValidation, sourceSha, currentPreconditions, completionFile, bindingsFile, repositoryRoot = REPOSITORY_ROOT, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, adapters, proveDescendant = (({ ancestorSha, descendantSha }) => { try { gitRun(["merge-base", "--is-ancestor", ancestorSha, descendantSha]); return true; } catch { return false; } }) } = {}) {
  const envelope = assertAuthenticatedPartialRebaselineRecovery(json(readStageBPrivateFileBytes({ filePath: recoveryEnvelopeFile, repositoryRoot, label: "Partial rebaseline recovery envelope" }).bytes));
  const preparation = json(readStageBPrivateFileBytes({ filePath: originalPreparationFile, repositoryRoot, label: "Original dual-slot rebaseline preparation" }).bytes);
  assertRebaselinePreparation(preparation, { sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId });
  const checkout = readAuthenticatedRebaselineCheckout({ sourceSha, gitRun, repositoryRoot });
  const current = currentPreconditions;
  if (!current || current.sourceSha !== checkout.toolingSha || current.sourceCas !== true || current.cleanWorktree !== true || current.liveReferenceAudit !== "PASS" || current.dualSlotReferences !== 0 || current.liveLegacyBaselineCount !== 1 || !/^[a-f0-9]{64}$/.test(current.liveReferenceAuditSha256 || "") || !/^[a-f0-9]{64}$/.test(current.liveLegacyBaselineIdentitySha256 || "") || canonicalSha256(current.resources) !== canonicalSha256(envelope.resources)) throw new Error("Partial rebaseline recovery preconditions changed.");
  const journal = readRebaselineMaterialJournal({ filePath: materialJournalFile, repositoryRoot, sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
  const writePlan = buildRebaselineWritePlan({ sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, resources: envelope.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
  const topology = await readPreparedDualSlotTopology({ client, preparation, writePlan });
  const liveCas = { liveReferenceAuditSha256: current.liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256: current.liveLegacyBaselineIdentitySha256, observedSlotIdentitiesSha256: canonicalSha256(topology.snapshots) };
  return executePartialRecoveryContract({ recoveryEnvelope: envelope, recoveryAuthorization: authorization, sourceSha: checkout.toolingSha, imageAuthorization, imageAuthorizationValidation, liveCas, originalPreparation: preparation, originalWritePlan: writePlan, materialJournalSha256: journal.journalSha256, readReferenceAudit: adapters?.readReferenceAudit, readSlot: adapters?.readSlot, writeSlot: adapters?.writeSlot, completionFile, bindingsFile, repositoryRoot, sleep: adapters?.sleep, proveDescendant });
}

export function createProductionRebaselineClient({ profile = "mscqr-production-release-deployer" } = {}) { return createInitialDualSlotSecretsManagerClient({ region: REGION, profile }); }

export async function runProductionDualSlotRebaselineCli({ argv = process.argv.slice(2), repositoryRoot = REPOSITORY_ROOT, readCheckout = readAuthenticatedRebaselineCheckout, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), createRun = () => createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: REGION }), createClient = createProductionRebaselineClient, resolveAuthorization = resolveProductionDualSlotRebaselineAuthorizationArtifact, resolveRecoveryAuthorization = resolvePartialRebaselineRecoveryAuthorizationArtifact, readTopology = readDualSlotTopology, readPreparedTopology = readPreparedDualSlotTopology, auditReferences = auditLiveProductionDualSlotReferences, executePrepared = executePreparedProductionDualSlotRebaseline, executeRecovery = executeAuthenticatedPartialRebaselineRecovery, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, afterAbandonmentPersist, afterPreparationPersist, output = (value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) } = {}) {
  const args = parseArgs(argv);
  const sourceSha = required(args, "source-sha");
  if (args.has("prepare")) {
    const checkout = readCheckout({ sourceSha, repositoryRoot });
    const run = createRun();
    const client = createClient(); await client.assertCredentialIdentity();
    const outputDirectory = path.resolve(required(args, "output-directory")); mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
    const historicalTransitionEvidence = args.has("historical-transition-evidence")
      ? json(readStageBPrivateFileBytes({ filePath: path.resolve(required(args, "historical-transition-evidence")), repositoryRoot, label: "Historical coordinator transition evidence" }).bytes)
      : undefined;
    const topology = await readTopology({ client, historicalTransitionEvidence });
    const audit = auditReferences({ run, resources: topology.resources, databaseDependencies: Number(required(args, "database-dependencies")), externalConsumers: Number(required(args, "external-consumers")) });
    const result = await prepareProductionDualSlotRebaseline({ sourceSha: checkout.toolingSha, rotationId: required(args, "rotation-id"), outputDirectory, client, topology, historicalTransitionEvidence, liveReferenceAudit: audit, repositoryRoot, gitRun, historicalTopologySha256, afterAbandonmentPersist, afterPreparationPersist });
    output(result);
    return result;
  } else if (args.has("execute")) {
    const checkout = readCheckout({ sourceSha, repositoryRoot });
    const requestedRotationId = required(args, "rotation-id");
    const preparationFile = path.resolve(required(args, "preparation")); const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes);
    assertRebaselinePreparation(preparation, { sourceSha: checkout.toolingSha, rotationId: requestedRotationId });
    const run = createRun();
    const client = createClient(); await client.assertCredentialIdentity();
    const authorization = resolveAuthorization({ workflowRunId: required(args, "workflow-run-id"), workflowRunAttempt: required(args, "workflow-run-attempt"), sourceSha: checkout.toolingSha, rotationId: requestedRotationId, resources: preparation.resources, run: createProductionGithubCommandRunner() }).authorization;
    const journal = readRebaselineMaterialJournal({ filePath: path.resolve(required(args, "material-journal")), repositoryRoot, sourceSha: checkout.toolingSha, rotationId: requestedRotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
    const payloads = buildRebaselinePayloads({ sourceSha: checkout.toolingSha, rotationId: preparation.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
    const writePlan = buildRebaselineWritePlan({ sourceSha: checkout.toolingSha, rotationId: preparation.rotationId, resources: preparation.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
    const topology = await readPreparedTopology({ client, preparation, writePlan }); const audit = auditReferences({ run, resources: topology.resources, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers });
    const currentPreconditions = { ...preparation, resources: topology.resources, abandonmentEvidence: preparation.abandonmentEvidence, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, liveLegacyBaselineCount: audit.liveLegacyBaselineCount, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, legacyBaseline: audit.legacy };
    const result = await executePrepared({ preparationFile, authorization, materialJournalFile: path.resolve(required(args, "material-journal")), completionFile: path.resolve(required(args, "completion-output")), bindingsFile: path.resolve(required(args, "rotation-bindings-output")), repositoryRoot, sourceSha: checkout.toolingSha, currentPreconditions, client, adapters: createProductionRebaselineAdapters({ client, run, resources: topology.resources, preparation }) });
    const summary = { baselineComplete: result.baselineComplete, writes: result.writes, baselineBindingSha256: result.completion.baselineBindingSha256, completionPath: result.completionPath, completionSha256: result.completionSha256, rotationBindingsPath: result.bindingsPath, rotationBindingsSha256: result.bindingsSha256 };
    output(summary);
    return summary;
  } else if (args.has("recover-execute")) {
    const checkout = readCheckout({ sourceSha, repositoryRoot });
    const run = createRun();
    const client = createClient(); await client.assertCredentialIdentity();
    const envelope = assertAuthenticatedPartialRebaselineRecovery(json(readStageBPrivateFileBytes({ filePath: path.resolve(required(args, "recovery-envelope")), repositoryRoot, label: "Partial rebaseline recovery envelope" }).bytes));
    const preparationFile = path.resolve(required(args, "original-preparation"));
    const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Original dual-slot rebaseline preparation" }).bytes);
    assertRebaselinePreparation(preparation, { sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId });
    const journalFile = path.resolve(required(args, "material-journal"));
    const journal = readRebaselineMaterialJournal({ filePath: journalFile, repositoryRoot, sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
    const payloads = buildRebaselinePayloads({ sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
    const writePlan = buildRebaselineWritePlan({ sourceSha: envelope.originalSourceSha, rotationId: envelope.rotationId, resources: envelope.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
    const topology = await readPreparedTopology({ client, preparation, writePlan });
    const audit = auditReferences({ run, resources: topology.resources, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers });
    const currentPreconditions = { sourceSha: checkout.toolingSha, sourceCas: true, cleanWorktree: checkout.porcelainStatus === "", resources: topology.resources, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.stableAuditSha256, liveLegacyBaselineIdentitySha256: audit.liveLegacyBaselineIdentitySha256, liveLegacyBaselineCount: audit.liveLegacyBaselineCount, dualSlotReferences: audit.dualSlotReferences };
    const imageAuthorization = json(readStageBPrivateFileBytes({ filePath: path.resolve(required(args, "image-authorization")), repositoryRoot, label: "Current image authorization" }).bytes);
    const imageAuthorizationValidation = { verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run }) };
    const liveCas = { liveReferenceAuditSha256: currentPreconditions.liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256: currentPreconditions.liveLegacyBaselineIdentitySha256, observedSlotIdentitiesSha256: canonicalSha256(topology.snapshots) };
    const authorization = resolveRecoveryAuthorization({ workflowRunId: required(args, "workflow-run-id"), workflowRunAttempt: required(args, "workflow-run-attempt"), sourceSha: checkout.toolingSha, recoveryEnvelope: envelope, imageAuthorization, imageAuthorizationValidation, liveCas, proveDescendant: ({ ancestorSha, descendantSha }) => { try { gitRun(["merge-base", "--is-ancestor", ancestorSha, descendantSha]); return true; } catch { return false; } }, run: createProductionGithubCommandRunner() }).authorization;
    const result = await executeRecovery({ recoveryEnvelopeFile: path.resolve(required(args, "recovery-envelope")), originalPreparationFile: preparationFile, materialJournalFile: journalFile, authorization, imageAuthorization, imageAuthorizationValidation, sourceSha: checkout.toolingSha, currentPreconditions, completionFile: path.resolve(required(args, "completion-output")), bindingsFile: path.resolve(required(args, "rotation-bindings-output")), repositoryRoot, gitRun, client, adapters: createProductionRebaselineAdapters({ client, run, resources: topology.resources, preparation }) });
    const summary = { baselineComplete: result.baselineComplete, writes: result.writes, completedSlots: result.completedSlots, remainingWrites: 0, completionPath: result.completionPath, bindingsPath: result.bindingsPath };
    output(summary);
    return summary;
  } else throw new Error("Use --prepare, --execute, or --recover-execute.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) await runProductionDualSlotRebaselineCli();
