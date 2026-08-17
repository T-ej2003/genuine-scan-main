#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { bootstrapInitialDualSlotRotation, createInitialDualSlotSecretsManagerClient } from "./production-initial-dual-slot-bootstrap.mjs";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!["--output-directory", "--rotation-id", "--source-sha"].includes(arg) || !argv[index + 1] || argv[index + 1].startsWith("--") || values.has(arg)) throw new Error(`Invalid or duplicate argument: ${arg}`);
    values.set(arg, argv[++index]);
  }
  return values;
}

const values = parseArgs(process.argv.slice(2));
const outputDirectory = path.resolve(values.get("--output-directory") || path.join(os.homedir(), ".mscqr", "production-cutover", "initial-dual-slot"));
mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
const gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: values.get("--source-sha") });
const sourceSha = fresh.headSha;
const rotationId = values.get("--rotation-id") || `rotation-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer", region: REGION });
const client = createInitialDualSlotSecretsManagerClient({ region: REGION, profile: "mscqr-production-release-deployer" });
await client.assertCredentialIdentity();
const service = JSON.parse(run(["ecs", "describe-services", "--cluster", CLUSTER, "--services", SERVICE])).services?.[0];
if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS"]));
const result = await bootstrapInitialDualSlotRotation({
  send: (command) => client.send(command),
  taskDefinition,
  sourceSha,
  rotationId,
  outputFile: path.join(outputDirectory, "rotation-bindings.json"),
  repositoryRoot: process.cwd(),
});
const manifest = {
  status: "valid",
  sourceSha,
  rotationId,
  bindingFile: result.bindingFile,
  bindingEvidenceSha256: result.evidenceSha256,
  createdSecretSlots: result.created,
  secretResourceCount: result.secretResourceCount,
  secretValueWrites: result.secretValueWrites,
  pendingMaterialGenerated: result.pendingMaterialGenerated,
  next: `npm run stage-b:prepare-cutover-runtime -- --rotation-bindings ${result.bindingFile}`,
};
const manifestPath = path.join(outputDirectory, "initial-dual-slot-bootstrap-manifest.json");
writeStageBPrivateFileAtomic({ filePath: manifestPath, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Initial dual-slot bootstrap manifest" });
process.stdout.write(`${JSON.stringify({ ...manifest, manifestPath, AWS_WRITES: result.created.length + result.secretValueWrites }, null, 2)}\n`);
