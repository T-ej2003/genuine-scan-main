#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { supersedeStalePendingRotation, bootstrapInitialDualSlotRotation, finalizeStaleRotationSupersessionMaterialJournal } from "./production-initial-dual-slot-bootstrap.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import { assertApprovedStaleRotationSupersessionAuthorization, assertStaleRotationSupersessionConsumption, assertStaleRotationSupersessionPreparation, createStaleRotationSupersessionConsumption, createStaleRotationSupersessionPreparation, deriveStaleRotationReplacementId, staleRotationSupersessionSha256 } from "./production-stale-rotation-supersession-contract.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const accepted = new Set(["mode", "stale-source-sha", "stale-rotation-id", "source-sha", "publication", "live-backend", "stage-b-state", "authorization", "preparation-sha256"]);
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
const transactionDirectory = ({ sourceSha, staleRotationId }) => path.join(os.homedir(), ".mscqr", "production-cutover", "stale-rotation-supersession", sourceSha, staleRotationId);
const imageDigest = (taskDefinition) => String(taskDefinition?.taskDefinition?.containerDefinitions?.find(({ name }) => name === "backend")?.image || "").split("@").at(-1);
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
  (deps.readProtectedMain || readFreshProtectedMainIdentity)({ run: gitRun, cwd: ROOT, expectedSourceSha: sourceSha });
  const proveDescendant = deps.proveDescendant || (({ ancestorSha, descendantSha }) => { try { gitRun(["cat-file", "-e", `${ancestorSha}^{commit}`]); gitRun(["merge-base", "--is-ancestor", ancestorSha, descendantSha]); return true; } catch { return false; } });
  const run = deps.run || createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
  const client = deps.client;
  const send = client ? (command) => client.send(command) : createStaleRotationSecretsManagerSender(run);
  if (client) await client.assertCredentialIdentity();
  else {
    const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
    if (caller.Account !== "368992683803" || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(caller.Arn || "")) throw new Error("Secrets Manager mutation client caller identity is outside the reviewed account/principal contract.");
  }
  const service = JSON.parse(run(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2", "--output", "json", "--no-cli-pager"])).services?.[0];
  if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
  const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
  const staleSourceSha = required(values, "stale-source-sha");
  const staleRotationId = required(values, "stale-rotation-id");
  const directory = transactionDirectory({ sourceSha, staleRotationId });
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const preparationFile = path.join(directory, "preparation.json");
  const evidenceFile = path.join(directory, "supersession.json");
  const consumptionFile = path.join(directory, "consumption.json");
  const mode = values.get("mode");
  if (mode === "prepare") {
    const publication = readJson(required(values, "publication"), "Stale supersession publication identity").value;
    const liveBackend = readJson(required(values, "live-backend"), "Stale supersession live backend identity").value;
    const stageBState = readJson(required(values, "stage-b-state"), "Stale supersession Stage-B state identity").value;
    if (liveBackend.taskDefinitionArn !== service.taskDefinition || liveBackend.imageDigest !== imageDigest(taskDefinition)) throw new Error("Live backend changed before stale supersession preparation.");
    const rotationId = deriveStaleRotationReplacementId({ sourceSha, staleRotationId, publicationIdentitySha256: publication.identitySha256 });
    const result = await supersedeStalePendingRotation({ send, taskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, proveDescendant, outputFile: evidenceFile, repositoryRoot: ROOT, mode: "prepare" });
    const preparation = createStaleRotationSupersessionPreparation({ discovery: result.preparationInput, publication, liveBackend, stageBState });
    writeStageBPrivateFileAtomicExclusive({ filePath: preparationFile, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession preparation" });
    return { mode, sourceSha, staleRotationId, rotationId, preparationFile, preparationSha256: preparation.preparationSha256, writes: 0, authorizationStatus: "NOT_CREATED" };
  }
  const preparationCapture = readJson(preparationFile, "Stale rotation supersession preparation");
  if (preparationCapture.sha256 !== required(values, "preparation-sha256")) throw new Error("Stale rotation supersession preparation file changed after authorization.");
  const preparation = assertStaleRotationSupersessionPreparation(preparationCapture.value, { sourceSha });
  if (preparation.staleSourceSha !== staleSourceSha || preparation.staleRotationId !== staleRotationId || preparation.liveBackend.taskDefinitionArn !== service.taskDefinition || preparation.liveBackend.imageDigest !== imageDigest(taskDefinition)) throw new Error("Live/source supersession topology changed after authorization.");
  const authorization = readJson(required(values, "authorization"), "Stale rotation supersession authorization").value;
  if (lstatSync(consumptionFile, { throwIfNoEntry: false })) {
    assertStaleRotationSupersessionConsumption(readJson(consumptionFile, "Stale rotation supersession consumption").value, { authorization, preparation });
    throw new Error("Stale rotation supersession authorization is already durably consumed.");
  }
  const result = await supersedeStalePendingRotation({
    send, taskDefinition, sourceSha, staleSourceSha, rotationId: preparation.replacementRotationId, staleRotationId, proveDescendant, outputFile: evidenceFile, repositoryRoot: ROOT, mode: "execute",
    authorizeWritePlan: (discovery) => {
      const recomputed = createStaleRotationSupersessionPreparation({ discovery, publication: preparation.publication, liveBackend: preparation.liveBackend, stageBState: preparation.stageBState, preparedAt: preparation.preparedAt });
      if (recomputed.preparationSha256 !== preparation.preparationSha256 || staleRotationSupersessionSha256(discovery.writePlan) !== preparation.writePlanSha256) throw new Error("Final supersession topology differs from the approved preparation.");
      assertApprovedStaleRotationSupersessionAuthorization(authorization, preparation, { sourceSha, materialJournalFileSha256: discovery.materialJournalFileSha256 });
      return true;
    },
  });
  const binding = await bootstrapInitialDualSlotRotation({ send, taskDefinition, sourceSha, rotationId: preparation.replacementRotationId, supersessionEvidence: result.evidence, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, "rotation-bindings.json"), repositoryRoot: ROOT });
  const consumption = createStaleRotationSupersessionConsumption({ authorization, preparation, supersessionEvidenceSha256: result.evidenceSha256, rotationBindingSha256: binding.evidenceSha256 });
  writeStageBPrivateFileAtomicExclusive({ filePath: consumptionFile, bytes: Buffer.from(`${JSON.stringify(consumption, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession consumption" });
  finalizeStaleRotationSupersessionMaterialJournal({ outputFile: evidenceFile, repositoryRoot: ROOT });
  return { mode, sourceSha, staleRotationId, rotationId: preparation.replacementRotationId, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationConsumed: true, consumptionFile, consumptionSha256: consumption.consumptionSha256, supersessionEvidenceFile: result.evidenceFile, bindingFile: binding.bindingFile, writes: result.writes };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
