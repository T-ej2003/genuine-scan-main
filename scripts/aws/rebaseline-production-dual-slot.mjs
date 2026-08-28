#!/usr/bin/env node
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createInitialDualSlotSecretsManagerClient } from "./production-initial-dual-slot-bootstrap.mjs";
import { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOTS, assertRebaselinePreconditions, buildAbandonmentEvidence,
  buildRebaselineIdentity, buildRebaselinePreparation, buildRebaselineWritePlan, buildRebaselinePayloads,
  canonicalSha256, loadOrCreateRebaselineMaterialJournal, executeProductionDualSlotRebaseline,
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

export async function readDualSlotTopology({ client, names = REBASELINE_SLOTS } = {}) {
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
    snapshots[slot] = { slot, arn: described.ARN, versions: Object.entries(described.VersionIdsToStages).map(([versionId, stages]) => ({ versionId, stages, ...(versionId === current[0] ? parsed : {}) })) };
  }
  return Object.freeze({ resources, currentVersionIds, snapshots });
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

export function createProductionRebaselineAdapters({ client, run, resources, preparation } = {}) {
  const currentTaskDefinition = () => {
    const service = JSON.parse(run(["ecs", "describe-services", "--cluster", CLUSTER, "--services", SERVICE])).services?.[0];
    if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
    return { service, taskDefinition: JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS"])) };
  };
  return {
    readReferenceAudit: async () => { const { service, taskDefinition } = currentTaskDefinition(); return auditLegacyTaskDefinition(taskDefinition, resources, { runningTasks: service.runningCount, pendingTasks: service.pendingCount, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers }); },
    readSlot: (slot, secretArn, expectedVersionId, expectedIdentity) => readSlotSnapshot(client, slot, secretArn, expectedVersionId, expectedIdentity),
    writeSlot: ({ secretArn, clientRequestToken, payload }) => client.send(new PutSecretValueCommand({ SecretId: secretArn, ClientRequestToken: clientRequestToken, SecretString: JSON.stringify(payload) })).then((response) => ({ arn: secretArn, versionId: response.VersionId })),
  };
}

export function auditLegacyTaskDefinition(taskDefinition, resources, { runningTasks = 0, pendingTasks = 0, databaseDependencies = 0, externalConsumers = 0 } = {}) {
  const serialized = JSON.stringify(taskDefinition);
  const dualSlotReferences = Object.values(resources).filter((arn) => serialized.includes(arn)).length;
  const legacy = deriveLegacyRotationBaseline(taskDefinition);
  return Object.freeze({ status: dualSlotReferences === 0 ? "PASS" : "FAIL", dualSlotReferences, legacyRuntimeAuthoritative: dualSlotReferences === 0, databaseDependencies, externalConsumers, runningTasks, pendingTasks, activeTaskDefinition: taskDefinition.taskDefinitionArn || taskDefinition.family || "unknown", legacy });
}

export async function prepareProductionDualSlotRebaseline({ sourceSha, rotationId, outputDirectory, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, taskDefinition, liveReferenceAudit = {}, repositoryRoot = process.cwd() } = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Dual-slot rebaseline preparation directory" });
  const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: sourceSha });
  const topology = await readDualSlotTopology({ client });
  const audit = auditLegacyTaskDefinition(taskDefinition, topology.resources, liveReferenceAudit);
  const abandonmentEvidence = buildAbandonmentEvidence({ sourceSha: fresh.headSha, historicalRotationId: HISTORICAL_ROTATION_ID, historicalSourceShas: HISTORICAL_SOURCES, resources: topology.resources, currentVersionIds: topology.currentVersionIds, liveReferenceAudit: audit.status, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative });
  const preconditions = assertRebaselinePreconditions({ environment: "production", accountId: ACCOUNT, region: REGION, sourceSha: fresh.headSha, sourceCas: fresh.headSha === sourceSha, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: audit.status, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, databaseDependencies: audit.databaseDependencies, externalConsumers: audit.externalConsumers, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition, resources: topology.resources, abandonmentEvidence });
  const rotation = buildRebaselineIdentity({ sourceSha: fresh.headSha, rotationId, resources: topology.resources, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, legacyBaseline: audit.legacy });
  const material = loadOrCreateRebaselineMaterialJournal({ filePath: path.join(directory, "rebaseline-material.json"), repositoryRoot, sourceSha: fresh.headSha, rotationId, baselineIdentitySha256: rotation.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha: fresh.headSha, rotationId, generatedMaterial: material.material, legacyBaseline: audit.legacy });
  const writePlan = buildRebaselineWritePlan({ sourceSha: fresh.headSha, rotationId, resources: topology.resources, baselineIdentitySha256: rotation.identitySha256, payloads });
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha: fresh.headSha, rotationId, baselineIdentity: rotation, writePlan });
  const abandonmentFile = path.join(directory, "abandonment-evidence.json");
  writeStageBPrivateFileExclusive({ filePath: abandonmentFile, bytes: Buffer.from(`${JSON.stringify(abandonmentEvidence, null, 2)}\n`), repositoryRoot, label: "Dual-slot abandonment evidence" });
  const preparationFile = path.join(directory, "rebaseline-preparation.json");
  writeStageBPrivateFileAtomic({ filePath: preparationFile, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot, label: "Dual-slot rebaseline preparation" });
  return Object.freeze({ sourceSha: fresh.headSha, rotationId, abandonmentFile, preparationFile, preparationSha256: preparation.preparationSha256, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), writeCount: 7 });
}

export async function executePreparedProductionDualSlotRebaseline({ preparationFile, authorizationFile, materialJournalFile, repositoryRoot = process.cwd(), sourceSha, currentPreconditions, gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), client, adapters } = {}) {
  const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot, label: "Dual-slot rebaseline preparation" }).bytes);
  const { assertRebaselinePreparation, assertProductionDualSlotRebaselineAuthorization } = await import("./production-dual-slot-rebaseline-contract.mjs");
  assertRebaselinePreparation(preparation, { sourceSha, rotationId: preparation.rotationId });
  const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: sourceSha });
  if (fresh.headSha !== sourceSha || fresh.headSha !== fresh.freshRemoteMainSha) throw new Error("Protected source changed before rebaseline execution.");
  const current = assertRebaselinePreconditions(currentPreconditions);
  if (current.sourceSha !== preparation.sourceSha || current.historicalRotationId !== preparation.historicalRotationId || current.dualSlotReferences !== 0 || canonicalSha256(current.resources) !== canonicalSha256(preparation.resources) || canonicalSha256(current.legacyBaseline) !== canonicalSha256(preparation.legacyBaseline) || current.abandonmentEvidence.evidenceSha256 !== preparation.abandonmentEvidenceSha256 || canonicalSha256(current.abandonmentEvidence) !== canonicalSha256(preparation.abandonmentEvidence)) throw new Error("Rebaseline preconditions changed after authorization.");
  const authorization = json(readStageBPrivateFileBytes({ filePath: authorizationFile, repositoryRoot, label: "Dual-slot rebaseline authorization" }).bytes);
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId: preparation.rotationId, resources: preparation.resources });
  if (authorization.historicalRotationId !== preparation.historicalRotationId || authorization.abandonmentEvidenceSha256 !== preparation.abandonmentEvidenceSha256 || authorization.baselineIdentitySha256 !== preparation.baselineIdentity.identitySha256) throw new Error("Rebaseline authorization is not bound to the authenticated preparation.");
  const journal = loadOrCreateRebaselineMaterialJournal({ filePath: materialJournalFile, repositoryRoot, sourceSha, rotationId: preparation.rotationId, baselineIdentitySha256: preparation.baselineIdentity.identitySha256 });
  const payloads = buildRebaselinePayloads({ sourceSha, rotationId: preparation.rotationId, generatedMaterial: journal.material, legacyBaseline: preparation.legacyBaseline });
  const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId: preparation.rotationId, resources: preparation.resources, baselineIdentitySha256: preparation.baselineIdentity.identitySha256, payloads });
  const preparedBySlot = Object.fromEntries(preparation.writePlan.map((entry) => [entry.slot, entry]));
  for (const entry of writePlan) if (entry.payloadSha256 !== preparedBySlot[entry.slot]?.payloadSha256 || entry.secretArn !== preparedBySlot[entry.slot]?.secretArn || entry.clientRequestToken !== preparedBySlot[entry.slot]?.clientRequestToken) throw new Error(`Rebaseline material for ${entry.slot} does not match the authenticated preparation.`);
  const descriptors = Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]));
  if (JSON.stringify(descriptors) !== JSON.stringify(authorization.writeIdentities)) throw new Error("Authorization write identities do not match the authenticated preparation.");
  return executeProductionDualSlotRebaseline({ preconditions: current, sourceSha, rotationId: preparation.rotationId, baselineIdentity: preparation.baselineIdentity, writePlan, authorizationBinding: authorization.authorizationSha256, ...adapters });
}

export function createProductionRebaselineClient({ profile = "mscqr-production-release-deployer" } = {}) { return createInitialDualSlotSecretsManagerClient({ region: REGION, profile }); }

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const args = parseArgs(process.argv.slice(2));
  const sourceSha = required(args, "source-sha");
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: REGION });
  const client = createProductionRebaselineClient(); await client.assertCredentialIdentity();
  const service = JSON.parse(run(["ecs", "describe-services", "--cluster", CLUSTER, "--services", SERVICE])).services?.[0];
  if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
  const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS"]));
  if (args.has("prepare")) {
    const outputDirectory = path.resolve(required(args, "output-directory")); mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
    const result = await prepareProductionDualSlotRebaseline({ sourceSha, rotationId: required(args, "rotation-id"), outputDirectory, client, taskDefinition, liveReferenceAudit: { runningTasks: service.runningCount, pendingTasks: service.pendingCount, databaseDependencies: Number(required(args, "database-dependencies")), externalConsumers: Number(required(args, "external-consumers")) } });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (args.has("execute")) {
    const preparationFile = path.resolve(required(args, "preparation")); const preparation = json(readStageBPrivateFileBytes({ filePath: preparationFile, repositoryRoot: process.cwd(), label: "Dual-slot rebaseline preparation" }).bytes);
    const topology = await readDualSlotTopology({ client }); const audit = auditLegacyTaskDefinition(taskDefinition, topology.resources, { runningTasks: service.runningCount, pendingTasks: service.pendingCount, databaseDependencies: preparation.databaseDependencies, externalConsumers: preparation.externalConsumers });
    const currentPreconditions = { ...preparation, resources: topology.resources, abandonmentEvidence: preparation.abandonmentEvidence, liveReferenceAudit: audit.status, legacyRuntimeAuthoritative: audit.legacyRuntimeAuthoritative, dualSlotReferences: audit.dualSlotReferences, runningTasks: audit.runningTasks, pendingTasks: audit.pendingTasks, activeTaskDefinition: audit.activeTaskDefinition };
    const result = await executePreparedProductionDualSlotRebaseline({ preparationFile, authorizationFile: path.resolve(required(args, "authorization")), materialJournalFile: path.resolve(required(args, "material-journal")), repositoryRoot: process.cwd(), sourceSha, currentPreconditions, client, adapters: createProductionRebaselineAdapters({ client, run, resources: topology.resources, preparation }) });
    process.stdout.write(`${JSON.stringify({ baselineComplete: result.baselineComplete, writes: result.writes, baselineBindingSha256: result.completion.baselineBindingSha256 }, null, 2)}\n`);
  } else throw new Error("Use --prepare or --execute.");
}
