#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { createInitialDualSlotSecretsManagerClient, supersedeStalePendingRotation, bootstrapInitialDualSlotRotation } from "./production-initial-dual-slot-bootstrap.mjs";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const parse = (argv) => {
  const accepted = new Set(["output-directory", "stale-source-sha", "stale-rotation-id", "source-sha", "rotation-id"]);
  const values = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!accepted.has(key) || !argv[i + 1] || values.has(key)) throw new Error(`Invalid or duplicate argument: ${argv[i]}`);
    values.set(key, argv[i + 1]);
  }
  return values;
};
const args = parse(process.argv.slice(2));
const outputDirectory = path.resolve(args.get("output-directory") || path.join(os.homedir(), ".mscqr", "production-cutover", "rotation-supersession"));
mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
const gitRun = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: args.get("source-sha") });
const sourceSha = fresh.headSha;
const rotationId = args.get("rotation-id");
const staleRotationId = args.get("stale-rotation-id");
if (!rotationId || !staleRotationId || !args.get("stale-source-sha")) throw new Error("Replacement and stale rotation identities are required.");
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
const service = JSON.parse(run(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"])).services?.[0];
if (!service?.taskDefinition) throw new Error("Current production task definition is unavailable.");
const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS"]));
const client = createInitialDualSlotSecretsManagerClient();
const result = await supersedeStalePendingRotation({
  send: (command) => client.send(command), sourceSha, staleSourceSha: args.get("stale-source-sha"), rotationId, staleRotationId,
  outputFile: path.join(outputDirectory, "rotation-supersession.json"), repositoryRoot: process.cwd(),
});
const binding = await bootstrapInitialDualSlotRotation({ send: (command) => client.send(command), taskDefinition, sourceSha, rotationId, outputFile: path.join(outputDirectory, "rotation-bindings.json"), repositoryRoot: process.cwd() });
const manifest = { status: "valid", transition: result.transition, sourceSha, staleSourceSha: result.staleSourceSha, rotationId, staleRotationId, supersessionEvidenceFile: result.evidenceFile, supersessionEvidenceSha256: result.evidenceSha256, bindingFile: binding.bindingFile, bindingEvidenceSha256: binding.evidenceSha256, writes: result.writes };
writeStageBPrivateFileAtomic({ filePath: path.join(outputDirectory, "rotation-supersession-manifest.json"), bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Rotation supersession manifest" });
process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
