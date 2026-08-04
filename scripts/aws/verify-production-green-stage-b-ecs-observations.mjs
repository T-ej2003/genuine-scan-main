#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { createAwsReader, observeStageBEcs } from "./production-green-stage-b-ecs-observations.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function requireOption(argv, option) {
  const index = argv.indexOf(option);
  const value = index === -1 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--") || !path.isAbsolute(value)) throw new Error(`${option} must be an absolute path.`);
  return value;
}

export function runCli(argv = process.argv.slice(2)) {
  const outputPath = assertStageBArtifactPath({ artifactPath: requireOption(argv, "--output"), repositoryRoot, label: "Stage B ECS observations", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot, create: true });
  const reader = createAwsReader({ region: STAGE_B.region, clusterArn: STAGE_B.clusterArn });
  const callerArn = reader.getCallerIdentity()?.Arn;
  if (typeof callerArn !== "string" || !callerArn) throw new Error("Stage B ECS observation caller identity is missing.");
  const observations = observeStageBEcs({ reader, region: STAGE_B.region, clusterArn: STAGE_B.clusterArn });
  const result = {
    schemaVersion: 1,
    callerArn,
    region: STAGE_B.region,
    clusterArn: STAGE_B.clusterArn,
    ...observations,
  };
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot, label: "Stage B ECS observations" });
  return { outputPath, serviceCount: result.services.length, runningCount: result.runningTasks.length, pendingCount: result.pendingTasks.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify({ status: "verified", ...runCli() })}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
