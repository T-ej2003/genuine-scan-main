#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { linkSync, lstatSync, mkdirSync, unlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { supersedeStalePendingRotation, bootstrapInitialDualSlotRotation, finalizeStaleRotationSupersessionMaterialJournal } from "./production-initial-dual-slot-bootstrap.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import { assertApprovedStaleRotationSupersessionAuthorization, assertStaleRotationSupersessionAuthorizationProvenance, assertStaleRotationSupersessionConsumption, assertStaleRotationSupersessionExecutionStart, assertStaleRotationSupersessionExecutionStartForPreparation, assertStaleRotationSupersessionPreparation, assertStaleRotationSupersessionReplacementReservation, createStaleRotationSupersessionConsumption, createStaleRotationSupersessionExecutionStart, createStaleRotationSupersessionPreparation, createStaleRotationSupersessionReplacementReservation, deriveStaleRotationReplacementId, resolveStaleRotationSupersessionAuthorizationArtifact, staleRotationSupersessionSha256 } from "./production-stale-rotation-supersession-contract.mjs";
import { readStageBTerraformStateIdentity } from "./stage-b-terraform-backend-contract.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const accepted = new Set(["mode", "stale-source-sha", "stale-rotation-id", "source-sha", "publication", "live-backend", "stage-b-state", "authorization-workflow-run-id", "authorization-workflow-run-attempt", "preparation-sha256"]);
const parse = (argv) => {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]?.replace(/^--/, "");
    if (!accepted.has(key) || !argv[index + 1] || argv[index + 1].startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${argv[index] || "<missing>"}`);
    values.set(key, argv[index + 1]);
  }
  if (!values.has("mode") || !["prepare", "execute"].includes(values.get("mode"))) throw new Error("--mode prepare or --mode execute is required; there is no mutating default.");
  return values;
};
const required = (values, name) => {
  const value = values.get(name);
  if (!value) throw new Error(`--${name} is required.`);
  return value;
};
const readJson = (filePath, label) => {
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: ROOT, label });
  return { ...captured, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) };
};
const transactionDirectory = ({ sourceSha, staleRotationId, homeDirectory = os.homedir() }) => path.join(homeDirectory, ".mscqr", "production-cutover", "stale-rotation-supersession", sourceSha, staleRotationId);
const imageDigest = (taskDefinition) => String(taskDefinition?.taskDefinition?.containerDefinitions?.find(({ name }) => name === "backend")?.image || "").split("@").at(-1);
const now = (value) => value instanceof Date ? value : new Date(value || Date.now());
const privateJsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const archivePrivateFile = ({ filePath, capture, repositoryRoot, label, suffix }) => {
  const archiveFile = `${filePath}.${capture.sha256}.${suffix}.json`;
  const existing = lstatSync(archiveFile, { throwIfNoEntry: false });
  if (existing) {
    const archived = readJson(archiveFile, `${label} archive`);
    if (!archived.bytes.equals(capture.bytes)) throw new Error(`${label} archive differs from the authenticated transaction.`);
  } else {
    linkSync(filePath, archiveFile);
    const archived = readJson(archiveFile, `${label} archive`);
    if (!archived.bytes.equals(capture.bytes)) throw new Error(`${label} archive differs from the authenticated transaction.`);
  }
  if (readJson(filePath, label).sha256 !== capture.sha256) throw new Error(`${label} changed before archival.`);
  unlinkSync(filePath);
  return archiveFile;
};
export const createStaleRotationSecretsManagerSender = (run) => async (command) => {
  const input = command?.input || {};
  const common = ["secretsmanager"];
  if (command.constructor.name === "DescribeSecretCommand") return JSON.parse(run([...common, "describe-secret", "--secret-id", input.SecretId, "--output", "json", "--no-cli-pager"]));
  if (command.constructor.name === "GetSecretValueCommand") return JSON.parse(run([...common, "get-secret-value", "--secret-id", input.SecretId, "--version-id", input.VersionId, "--output", "json", "--no-cli-pager"]));
  if (command.constructor.name === "PutSecretValueCommand") return JSON.parse(run([...common, "put-secret-value", "--secret-id", input.SecretId, "--client-request-token", input.ClientRequestToken, "--secret-string", "file:///dev/stdin", "--output", "json", "--no-cli-pager"], { input: input.SecretString }));
  throw new Error("Unsupported stale-supersession Secrets Manager operation.");
};

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const values = parse(argv);
  const gitRun = deps.gitRun || ((args) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const sourceSha = required(values, "source-sha");
  // Authenticate the exact bytes being executed before any credential source
  // can be constructed or resolved.  The canonical helper rejects staged,
  // unstaged, and untracked repository substitutions.
  (deps.readProtectedMain || readStageBProtectedMainCheckout)({ run: gitRun, cwd: ROOT, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  const proveDescendant = deps.proveDescendant || (({ ancestorSha, descendantSha }) => { try { gitRun(["cat-file", "-e", `${ancestorSha}^{commit}`]); gitRun(["merge-base", "--is-ancestor", ancestorSha, descendantSha]); return true; } catch { return false; } });
  const createRunner = deps.createProductionCommandRunner || createProductionCommandRunner;
  const run = deps.run || createRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
  const client = deps.client;
  const send = client ? (command) => client.send(command) : createStaleRotationSecretsManagerSender(run);
  if (client) await client.assertCredentialIdentity();
  else {
    const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
    if (caller.Account !== "368992683803" || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(caller.Arn || "")) throw new Error("Secrets Manager mutation client caller identity is outside the reviewed account/principal contract.");
  }
  const readLiveBackend = () => {
    const service = JSON.parse(run(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2", "--output", "json", "--no-cli-pager"])).services?.[0];
    if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
    const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
    return { service, taskDefinition };
  };
  const { service, taskDefinition } = readLiveBackend();
  const staleSourceSha = required(values, "stale-source-sha");
  const staleRotationId = required(values, "stale-rotation-id");
  const directory = transactionDirectory({ sourceSha, staleRotationId, homeDirectory: deps.homeDirectory });
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const preparationFile = path.join(directory, "preparation.json");
  const evidenceFile = path.join(directory, "supersession.json");
  const consumptionFile = path.join(directory, "consumption.json");
  const replacementReservationFile = path.join(directory, "replacement-id-reservation.json");
  const executionStartFile = path.join(directory, "execution-start.json");
  const mode = values.get("mode");
  if (mode === "prepare") {
    const prepareNow = now(typeof deps.now === "function" ? deps.now() : deps.now);
    const publication = readJson(required(values, "publication"), "Stale supersession publication identity").value;
    const liveBackend = readJson(required(values, "live-backend"), "Stale supersession live backend identity").value;
    const stageBState = readJson(required(values, "stage-b-state"), "Stale supersession Stage-B state identity").value;
    if (liveBackend.taskDefinitionArn !== service.taskDefinition || liveBackend.imageDigest !== imageDigest(taskDefinition)) throw new Error("Live backend changed before stale supersession preparation.");
    const preparationCapture = lstatSync(preparationFile, { throwIfNoEntry: false }) ? readJson(preparationFile, "Stale rotation supersession preparation") : null;
    if (!preparationCapture && lstatSync(executionStartFile, { throwIfNoEntry: false })) throw new Error("Stale rotation supersession execution start exists without its preparation.");
    const existingPreparation = preparationCapture ? assertStaleRotationSupersessionPreparation(preparationCapture.value, { sourceSha, now: prepareNow, validationMode: "continuation" }) : null;
    if (lstatSync(consumptionFile, { throwIfNoEntry: false })) throw new Error("Stale rotation supersession is already terminal and cannot be prepared again.");
    const existingReservation = lstatSync(replacementReservationFile, { throwIfNoEntry: false })
      ? assertStaleRotationSupersessionReplacementReservation(readJson(replacementReservationFile, "Stale rotation supersession replacement reservation").value, { sourceSha, staleSourceSha, staleRotationId, publicationIdentitySha256: publication.identitySha256, transactionDirectory: directory })
      : null;
    const reservation = existingReservation || createStaleRotationSupersessionReplacementReservation({ sourceSha, staleSourceSha, staleRotationId, publicationIdentitySha256: publication.identitySha256, replacementRotationId: deriveStaleRotationReplacementId({ sourceSha, staleRotationId, publicationIdentitySha256: publication.identitySha256, now: now(typeof deps.now === "function" ? deps.now() : deps.now) }), transactionDirectory: directory });
    if (!existingReservation) writeStageBPrivateFileAtomicExclusive({ filePath: replacementReservationFile, bytes: Buffer.from(`${JSON.stringify(reservation, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession replacement reservation" });
    const rotationId = reservation.replacementRotationId;
    const result = await supersedeStalePendingRotation({ send, taskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, proveDescendant, outputFile: evidenceFile, repositoryRoot: ROOT, mode: "prepare" });
    deps.afterPrepareDiscovery?.({ reservation, result });
    const preparationFor = (preparedAt) => createStaleRotationSupersessionPreparation({ discovery: result.preparationInput, publication, liveBackend, stageBState, preparedAt });
    if (existingPreparation) {
      if (prepareNow <= new Date(existingPreparation.expiresAt)) {
        const rebound = preparationFor(existingPreparation.preparedAt);
        if (rebound.preparationSha256 !== existingPreparation.preparationSha256 || !preparationCapture.bytes.equals(privateJsonBytes(existingPreparation))) throw new Error("Existing stale rotation supersession preparation differs from current authenticated topology.");
        return { mode, sourceSha, staleRotationId, rotationId, preparationFile, preparationSha256: existingPreparation.preparationSha256, writes: 0, authorizationStatus: "NOT_CREATED", preparationReused: true };
      }
      if (result.completedWriteCount !== 0) throw new Error("Expired stale rotation supersession preparation cannot refresh after mutation has started.");
      const executionStartCapture = lstatSync(executionStartFile, { throwIfNoEntry: false }) ? readJson(executionStartFile, "Stale rotation supersession execution start") : null;
      if (executionStartCapture) {
        assertStaleRotationSupersessionExecutionStartForPreparation(executionStartCapture.value, { preparation: existingPreparation });
        archivePrivateFile({ filePath: executionStartFile, capture: executionStartCapture, repositoryRoot: ROOT, label: "Stale rotation supersession execution start", suffix: "abandoned" });
      }
      archivePrivateFile({ filePath: preparationFile, capture: preparationCapture, repositoryRoot: ROOT, label: "Stale rotation supersession preparation", suffix: "expired" });
    }
    const preparation = preparationFor(prepareNow.toISOString());
    writeStageBPrivateFileAtomicExclusive({ filePath: preparationFile, bytes: privateJsonBytes(preparation), repositoryRoot: ROOT, label: "Stale rotation supersession preparation" });
    return { mode, sourceSha, staleRotationId, rotationId, preparationFile, preparationSha256: preparation.preparationSha256, writes: 0, authorizationStatus: "NOT_CREATED", preparationRefreshed: Boolean(existingPreparation) };
  }
  const executionNow = now(typeof deps.now === "function" ? deps.now() : deps.now);
  const preparationCapture = readJson(preparationFile, "Stale rotation supersession preparation");
  if (preparationCapture.sha256 !== required(values, "preparation-sha256")) throw new Error("Stale rotation supersession preparation file changed after authorization.");
  // Freshness selects the mode. A start record alone never grants an expired
  // transaction permission to begin its first write.
  const structurallyCheckedPreparation = assertStaleRotationSupersessionPreparation(preparationCapture.value, { sourceSha, now: executionNow, validationMode: "continuation" });
  const validationMode = executionNow <= new Date(structurallyCheckedPreparation.expiresAt) ? "start" : "continuation";
  const preparation = assertStaleRotationSupersessionPreparation(structurallyCheckedPreparation, { sourceSha, now: executionNow, validationMode });
  const executionStartCapture = lstatSync(executionStartFile, { throwIfNoEntry: false }) ? readJson(executionStartFile, "Stale rotation supersession execution start") : null;
  if (preparation.staleSourceSha !== staleSourceSha || preparation.staleRotationId !== staleRotationId || preparation.liveBackend.taskDefinitionArn !== service.taskDefinition || preparation.liveBackend.imageDigest !== imageDigest(taskDefinition)) throw new Error("Live/source supersession topology changed after authorization.");
  const authenticated = await (deps.resolveAuthorization || resolveStaleRotationSupersessionAuthorizationArtifact)({ workflowRunId: required(values, "authorization-workflow-run-id"), workflowRunAttempt: required(values, "authorization-workflow-run-attempt"), sourceSha, preparation, run: deps.githubRun, now: executionNow, validationMode });
  const { authorization, provenance: authorizationProvenance } = authenticated;
  assertStaleRotationSupersessionAuthorizationProvenance(authorizationProvenance, { authorization, sourceSha });
  const postAuthorizationLiveBackend = readLiveBackend();
  if (preparation.liveBackend.taskDefinitionArn !== postAuthorizationLiveBackend.service.taskDefinition || preparation.liveBackend.imageDigest !== imageDigest(postAuthorizationLiveBackend.taskDefinition)) throw new Error("Live backend changed after stale rotation supersession authorization.");
  const executionStart = executionStartCapture ? assertStaleRotationSupersessionExecutionStart(executionStartCapture.value, { authorization, authorizationProvenance, preparation }) : null;
  const finalizeJournal = deps.finalizeJournal || finalizeStaleRotationSupersessionMaterialJournal;
  if (lstatSync(consumptionFile, { throwIfNoEntry: false })) {
    const consumption = assertStaleRotationSupersessionConsumption(readJson(consumptionFile, "Stale rotation supersession consumption").value, { authorization, authorizationProvenance, preparation });
    const supersessionEvidence = readJson(evidenceFile, "Stale rotation supersession evidence");
    const rotationBinding = readJson(path.join(directory, "rotation-bindings.json"), "Stale rotation supersession bindings");
    if (supersessionEvidence.sha256 !== consumption.supersessionEvidenceSha256 || rotationBinding.sha256 !== consumption.rotationBindingSha256) throw new Error("Supersession terminal receipt does not match its exact execution evidence.");
    if (lstatSync(`${evidenceFile}.material`, { throwIfNoEntry: false })) {
      finalizeJournal({ outputFile: evidenceFile, expectedFileSha256: preparation.materialJournalFileSha256, repositoryRoot: ROOT });
      return { mode, sourceSha, staleRotationId, rotationId: preparation.replacementRotationId, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationConsumed: true, consumptionFile, consumptionSha256: consumption.consumptionSha256, terminalCleanupRecovered: true, writes: 0 };
    }
    throw new Error("Stale rotation supersession authorization is already durably consumed.");
  }
  const readCurrentStageBState = deps.readStageBState || (() => readStageBTerraformStateIdentity(run));
  const result = await supersedeStalePendingRotation({
    send, taskDefinition, sourceSha, staleSourceSha, rotationId: preparation.replacementRotationId, staleRotationId, proveDescendant, outputFile: evidenceFile, repositoryRoot: ROOT, mode: "execute",
    authorizeWritePlan: async (discovery, { completedWriteCount } = {}) => {
      const recomputed = createStaleRotationSupersessionPreparation({ discovery, publication: preparation.publication, liveBackend: preparation.liveBackend, stageBState: preparation.stageBState, preparedAt: preparation.preparedAt });
      if (recomputed.preparationSha256 !== preparation.preparationSha256 || staleRotationSupersessionSha256(discovery.writePlan) !== preparation.writePlanSha256) throw new Error("Final supersession topology differs from the approved preparation.");
      assertApprovedStaleRotationSupersessionAuthorization(authorization, preparation, { sourceSha, materialJournalFileSha256: discovery.materialJournalFileSha256, now: executionNow, validationMode });
      const currentStageBState = await readCurrentStageBState({ sourceSha, preparation });
      if (currentStageBState?.lineage !== preparation.stageBState.lineage || currentStageBState?.serial !== preparation.stageBState.serial || currentStageBState?.stateSha256 !== preparation.stageBState.stateSha256) throw new Error("Stage-B state changed after stale rotation supersession preparation.");
      if (!Number.isSafeInteger(completedWriteCount) || completedWriteCount < 0 || completedWriteCount > 7) throw new Error("Stale rotation supersession completed-write count is invalid.");
      if (!executionStart && completedWriteCount !== 0) throw new Error("expired stale rotation supersession prefix is missing its authenticated execution start.");
      if (validationMode === "continuation" && (!executionStart || completedWriteCount < 1)) throw new Error("expired stale rotation supersession has no authenticated write prefix to continue.");
      if (!executionStart) {
        const start = createStaleRotationSupersessionExecutionStart({ authorization, authorizationProvenance, preparation, startedAt: executionNow.toISOString() });
        writeStageBPrivateFileAtomicExclusive({ filePath: executionStartFile, bytes: Buffer.from(`${JSON.stringify(start, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession execution start" });
        deps.afterExecutionStart?.({ start });
      }
      return true;
    },
  });
  const binding = await bootstrapInitialDualSlotRotation({ send, taskDefinition, sourceSha, rotationId: preparation.replacementRotationId, supersessionEvidence: result.evidence, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, "rotation-bindings.json"), repositoryRoot: ROOT });
  deps.afterBootstrap?.({ result, binding });
  const consumption = createStaleRotationSupersessionConsumption({ authorization, authorizationProvenance, preparation, supersessionEvidenceSha256: result.evidenceSha256, rotationBindingSha256: binding.evidenceSha256 });
  writeStageBPrivateFileAtomicExclusive({ filePath: consumptionFile, bytes: Buffer.from(`${JSON.stringify(consumption, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession consumption" });
  deps.afterConsumptionPersist?.({ consumptionFile, consumption });
  finalizeJournal({ outputFile: evidenceFile, expectedFileSha256: preparation.materialJournalFileSha256, repositoryRoot: ROOT });
  return { mode, sourceSha, staleRotationId, rotationId: preparation.replacementRotationId, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationProvenanceSha256: authorizationProvenance.provenanceSha256, authorizationConsumed: true, consumptionFile, consumptionSha256: consumption.consumptionSha256, supersessionEvidenceFile: result.evidenceFile, bindingFile: binding.bindingFile, writes: result.writes };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
