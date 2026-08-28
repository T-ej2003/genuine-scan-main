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
  canonicalSha256, historicalSlotIdentity, loadOrCreateRebaselineMaterialJournal, executeProductionDualSlotRebaseline, resolveProductionDualSlotRebaselineAuthorizationArtifact,
  REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256,
} from "./production-dual-slot-rebaseline-contract.mjs";

const requireBackend = createRequire(path.resolve("backend/package.json"));
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
const parseSecret = (response, label) => { if (typeof response?.SecretString !== "string") throw new Error(`${label} is not a reviewed JSON secret.`); const value = JSON.parse(response.SecretString); if (!value || typeof value !== "object" || typeof value.value !== "string") throw new Error(`${label} has an invalid rotation payload.`); return { value, payloadSha256: canonicalSha256(value) }; };

export async function readDualSlotTopology({ client, names = REBASELINE_SLOTS, historicalRotationId = HISTORICAL_ROTATION_ID } = {}) {
  const resources = {};
  const currentVersionIds = {};
  const snapshots = {};
  for (const [slot, name] of Object.entries(names)) {
    const described = await client.send(new DescribeSecretCommand({ SecretId: name }));
    if (described.Name !== name || typeof described.ARN !== "string") throw new Error(`Secret resource ${slot} is outside the exact rebaseline allowlist.`);
    const current = Object.entries(described.VersionIdsToStages || {}).find(([, stages]) => stages.includes("AWSCURRENT"));
    if (!current) throw new Error(`Secret resource ${slot} has no authenticated AWSCURRENT version.`);
    const response = await client.send(new GetSecretValueCommand({ SecretId: described.ARN, VersionId: current[0] }));
    const parsed = parseSecret(response, slot);
    resources[slot] = described.ARN;
    currentVersionIds[slot] = current[0];
    snapshots[slot] = { slot, arn: described.ARN, versions: Object.entries(described.VersionIdsToStages).map(([versionId, stages]) => ({ versionId, stages, ...(versionId === current[0] ? { payloadSha256: parsed.payloadSha256 } : {}) })) };
    snapshots[slot].historicalIdentity = historicalSlotIdentity({ slot, secretArn: described.ARN, versionId: current[0], stages: current[1], payload: parsed.value });
  }
  const observedSlotIdentities = Object.freeze(Object.fromEntries(Object.entries(snapshots).map(([slot, snapshot]) => [slot, snapshot.historicalIdentity])));
  return Object.freeze({ resources, currentVersionIds, snapshots, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) });
}

async function readSlotSnapshot(client, slot, secretArn, expectedVersionId, expectedIdentity = {}) {
  const described = await client.send(new DescribeSecretCommand({ SecretId: secretArn }));
  const ids = new Set(Object.keys(described.VersionIdsToStages || {}));
  const versions = [];
  let unexpectedRebaselineIdentity = false;
  for (const versionId of ids) {
    const parsed = parseSecret(await client.send(new GetSecretValueCommand({ SecretId: secretArn, VersionId: versionId })), slot);
    versions.push({ versionId, stages: described.VersionIdsToStages[versionId] || [], payloadSha256: parsed.payloadSha256 });
    const payload = parsed.value;
    if ((payload.materialType === "fresh-generated" || payload.baselineMarker) && (payload.sourceSha !== expectedIdentity.sourceSha || payload.rotationId !== expectedIdentity.rotationId)) unexpectedRebaselineIdentity = true;
  }
  return { slot, arn: secretArn, versions, unexpectedRebaselineIdentity };
}

function awsJson(run, args) { return JSON.parse(run(["ecs", ...args])); }
function chunks(values, size = 100) { return Array.from({ length: Math.ceil(values.length / size) }, (_, index) => values.slice(index * size, index * size + size)); }

export function auditLiveProductionDualSlotReferences({ run, resources, databaseDependencies = 0, externalConsumers = 0 } = {}) {
  const service = awsJson(run, ["describe-services", "--cluster", CLUSTER, "--services", SERVICE]).services?.[0];
  if (!service?.taskDefinition || !service.serviceArn) throw new Error("Current production ECS service topology is unavailable.");
  const taskArns = new Set();
  for (const status of ["RUNNING", "PENDING"]) {
    const listed = awsJson(run, ["list-tasks", "--cluster", CLUSTER, "--service-name", SERVICE, "--desired-status", status]).taskArns || [];
    if (!Array.isArray(listed)) throw new Error(`ECS ${status} task inventory is malformed.`);
    listed.forEach((arn) => taskArns.add(arn));
  }
  const tasks = [];
  for (const batch of chunks([...taskArns].sort())) {
    if (batch.length === 0) continue;
    const described = awsJson(run, ["describe-tasks", "--cluster", CLUSTER, "--tasks", ...batch]).tasks;
    if (!Array.isArray(described) || described.length !== batch.length) throw new Error("ECS task description inventory is incomplete.");
    tasks.push(...described);
  }
  const deployments = (service.deployments || []).filter((deployment) => deployment?.status === "PRIMARY" || deployment?.status === "ACTIVE").map(({ id, status, taskDefinition }) => ({ id, status, taskDefinition })).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const taskDefinitionArns = new Set([service.taskDefinition, ...deployments.map(({ taskDefinition }) => taskDefinition), ...tasks.map(({ taskDefinitionArn }) => taskDefinitionArn)].filter(Boolean));
  if (service.deploymentController?.type && !["ECS", "CODE_DEPLOY", "EXTERNAL"].includes(service.deploymentController.type)) throw new Error("ECS deployment controller topology is unsupported.");
  if (service.deploymentController?.type && service.deploymentController.type !== "ECS") {
    const taskSets = awsJson(run, ["describe-task-sets", "--cluster", CLUSTER, "--service", SERVICE]).taskSets;
    if (!Array.isArray(taskSets)) throw new Error("ECS task-set topology is unavailable.");
    taskSets.filter((set) => set?.status === "PRIMARY" || set?.status === "ACTIVE").forEach(({ taskDefinition }) => taskDefinitionArns.add(taskDefinition));
  }
  const taskDefinitions = [...taskDefinitionArns].sort().map((taskDefinitionArn) => awsJson(run, ["describe-task-definition", "--task-definition", taskDefinitionArn, "--include", "TAGS"]));
  const perTaskDefinition = taskDefinitions.map((definition) => ({ taskDefinitionArn: definition.taskDefinition?.taskDefinitionArn || definition.taskDefinitionArn, dualSlotReferences: Object.values(resources).filter((arn) => JSON.stringify(definition).includes(arn)).sort() })).sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn));
  const dualSlotReferences = perTaskDefinition.reduce((count, item) => count + item.dualSlotReferences.length, 0);
  const active = taskDefinitions.find((definition) => (definition.taskDefinition?.taskDefinitionArn || definition.taskDefinitionArn) === service.taskDefinition) || taskDefinitions[0];
  const legacy = deriveLegacyRotationBaseline(active);
  const evidence = { service: { arn: service.serviceArn, desiredCount: service.desiredCount, runningCount: service.runningCount, pendingCount: service.pendingCount, taskDefinition: service.taskDefinition }, deployments, tasks: tasks.map(({ taskArn, taskDefinitionArn, lastStatus, desiredStatus }) => ({ taskArn, taskDefinitionArn, lastStatus, desiredStatus })).sort((a, b) => a.taskArn.localeCompare(b.taskArn)), taskDefinitionArns: [...taskDefinitionArns].sort(), perTaskDefinition, databaseDependencies, externalConsumers };
  const auditSha256 = canonicalSha256(evidence);
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, databaseDependencies, externalConsumers, runningTasks: service.runningCount, pendingTasks: service.pendingCount, activeTaskDefinition: service.taskDefinition, legacy, evidence, auditSha256 });
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
  const evidence = { service: { arn: "fixture", desiredCount: runningTasks, runningCount: runningTasks, pendingCount: pendingTasks, taskDefinition: taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown" }, deployments: [], tasks: [], taskDefinitionArns: [taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown"], perTaskDefinition: [{ taskDefinitionArn: taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown", dualSlotReferences: Object.values(resources).filter((arn) => serialized.includes(arn)).sort() }], databaseDependencies, externalConsumers };
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, databaseDependencies, externalConsumers, runningTasks, pendingTasks, activeTaskDefinition: taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown", legacy, evidence, auditSha256: canonicalSha256(evidence) });
}

export function readAuthenticatedRebaselineCheckout({ sourceSha, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), repositoryRoot = process.cwd() } = {}) {
  const checkout = readStageBProtectedMainCheckout({ cwd: repositoryRoot, fetchOriginMain: true, run: gitRun });
  if (checkout.toolingSha !== sourceSha) throw new Error("Protected rebaseline checkout does not match the requested source SHA.");
  return checkout;
}

export async function prepareProductionDualSlotRebaseline({ sourceSha, rotationId, outputDirectory, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, topology: suppliedTopology, taskDefinition, liveReferenceAudit = {}, repositoryRoot = process.cwd() } = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Dual-slot rebaseline preparation directory" });
  const checkout = readAuthenticatedRebaselineCheckout({ sourceSha, gitRun, repositoryRoot });
  const topology = suppliedTopology || await readDualSlotTopology({ client });
  const audit = liveReferenceAudit?.auditSha256 ? liveReferenceAudit : auditLegacyTaskDefinition(taskDefinition, topology.resources, liveReferenceAudit);
  const abandonmentEvidence = buildAbandonmentEvidence({ sourceSha: checkout.toolingSha, historicalRotationId: HISTORICAL_ROTATION_ID, historicalSourceShas: HISTORICAL_SOURCES, resources: topology.resources, currentVersionIds: topology.currentVersionIds, observedSlotIdentities: topology.observedSlotIdentities, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative });
  const preconditions = assertRebaselinePreconditions({ environment: "production", accountId: ACCOUNT, region: REGION, sourceSha: checkout.toolingSha, sourceCas: checkout.toolingSha === sourceSha, cleanWorktree: checkout.porcelainStatus === "", existingSecretResources: true, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, databaseDependencies: audit.databaseDependencies, externalConsumers: audit.externalConsumers, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, resources: topology.resources, abandonmentEvidence });
  const rotation = buildRebaselineIdentity({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, legacyBaseline: audit.legacy });
  const material = loadOrCreateRebaselineMaterialJournal({ filePath: path.join(directory, "rebaseline-material.json"), repositoryRoot, sourceSha: checkout.toolingSha, rotationId, baselineIdentitySha256: rotation.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha: checkout.toolingSha, rotationId, generatedMaterial: material.material, legacyBaseline: audit.legacy });
  const writePlan = buildRebaselineWritePlan({ sourceSha: checkout.toolingSha, rotationId, resources: topology.resources, baselineIdentitySha256: rotation.identitySha256, payloads });
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha: checkout.toolingSha, rotationId, baselineIdentity: rotation, writePlan });
  const abandonmentFile = path.join(directory, "abandonment-evidence.json");
  writeStageBPrivateFileExclusive({ filePath: abandonmentFile, bytes: Buffer.from(`${JSON.stringify(abandonmentEvidence, null, 2)}\n`), repositoryRoot, label: "Dual-slot abandonment evidence" });
  const preparationFile = path.join(directory, "rebaseline-preparation.json");
  writeStageBPrivateFileAtomic({ filePath: preparationFile, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot, label: "Dual-slot rebaseline preparation" });
  return Object.freeze({ sourceSha: checkout.toolingSha, rotationId, abandonmentFile, preparationFile, preparationSha256: preparation.preparationSha256, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), writeCount: 7, liveReferenceAuditSha256: audit.auditSha256, observedSlotIdentitiesSha256: topology.observedSlotIdentitiesSha256 });
}

export async function executePreparedProductionDualSlotRebaseline({ preparationFile, authorization, materialJournalFile, completionFile, bindingsFile, repositoryRoot = process.cwd(), sourceSha, currentPreconditions, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, adapters, afterCompletionPersist, afterBindingsPersist } = {}) {
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
  const journal = loadOrCreateRebaselineMaterialJournal({ filePath: materialJournalFile, repositoryRoot, sourceSha, rotationId: preparation.rotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha, rotationId: preparation.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
  const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId: preparation.rotationId, resources: preparation.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
  const preparedBySlot = Object.fromEntries(preparation.writePlan.map((entry) => [entry.slot, entry]));
  for (const entry of writePlan) if (entry.payloadSha256 !== preparedBySlot[entry.slot]?.payloadSha256 || entry.secretArn !== preparedBySlot[entry.slot]?.secretArn || entry.clientRequestToken !== preparedBySlot[entry.slot]?.clientRequestToken) throw new Error(`Rebaseline material for ${entry.slot} does not match the authenticated preparation.`);
  const descriptors = Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]));
  if (JSON.stringify(descriptors) !== JSON.stringify(authorization.writeIdentities)) throw new Error("Authorization write identities do not match the authenticated preparation.");
  return executeProductionDualSlotRebaseline({ preconditions: current, sourceSha, rotationId: preparation.rotationId, baselineIdentity: preparation.baselineIdentity, writePlan, authorization, completionFile, bindingsFile, repositoryRoot, afterCompletionPersist, afterBindingsPersist, ...adapters });
}

export function createProductionRebaselineClient({ profile = "mscqr-production-release-deployer" } = {}) { return createInitialDualSlotSecretsManagerClient({ region: REGION, profile }); }

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const args = parseArgs(process.argv.slice(2));
  const sourceSha = required(args, "source-sha");
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: REGION });
  const client = createProductionRebaselineClient(); await client.assertCredentialIdentity();
  if (args.has("prepare")) {
    const outputDirectory = path.resolve(required(args, "output-directory")); mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
    const topology = await readDualSlotTopology({ client });
    const audit = auditLiveProductionDualSlotReferences({ run, resources: topology.resources, databaseDependencies: Number(required(args, "database-dependencies")), externalConsumers: Number(required(args, "external-consumers")) });
    const result = await prepareProductionDualSlotRebaseline({ sourceSha, rotationId: required(args, "rotation-id"), outputDirectory, client, topology, liveReferenceAudit: audit });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (args.has("execute")) {
    const preparationFile = path.resolve(required(args, "preparation")); const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot: process.cwd(), label: "Dual-slot rebaseline preparation" }).bytes);
    const topology = await readDualSlotTopology({ client }); const audit = auditLiveProductionDualSlotReferences({ run, resources: topology.resources, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers });
    const currentPreconditions = { ...preparation, resources: topology.resources, abandonmentEvidence: { ...preparation.abandonmentEvidence, currentVersionIds: topology.currentVersionIds, observedSlotIdentities: topology.observedSlotIdentities, observedSlotIdentitiesSha256: topology.observedSlotIdentitiesSha256, liveReferenceAuditSha256: audit.auditSha256 }, liveReferenceAudit: audit.status, liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition };
    const authorization = resolveProductionDualSlotRebaselineAuthorizationArtifact({ workflowRunId: required(args, "workflow-run-id"), workflowRunAttempt: required(args, "workflow-run-attempt"), sourceSha, rotationId: preparation.rotationId, resources: preparation.resources }).authorization;
    const result = await executePreparedProductionDualSlotRebaseline({ preparationFile, authorization, materialJournalFile: path.resolve(required(args, "material-journal")), completionFile: path.resolve(required(args, "completion-output")), bindingsFile: path.resolve(required(args, "rotation-bindings-output")), repositoryRoot: process.cwd(), sourceSha, currentPreconditions, client, adapters: createProductionRebaselineAdapters({ client, run, resources: topology.resources, preparation }) });
    process.stdout.write(`${JSON.stringify({ baselineComplete: result.baselineComplete, writes: result.writes, baselineBindingSha256: result.completion.baselineBindingSha256, completionPath: result.completionPath, completionSha256: result.completionSha256, rotationBindingsPath: result.bindingsPath, rotationBindingsSha256: result.bindingsSha256 }, null, 2)}\n`);
  } else throw new Error("Use --prepare or --execute.");
}
