#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { createStageBStateReconciliationAuthorization } from "./production-green-stage-b-state-reconciliation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function runAuthorization(argv = process.argv.slice(2)) {
  const expected = new Set(["--source-sha", "--preparation", "--preparation-file-sha256", "--environment-approval", "--environment-approval-file-sha256", "--output"]);
  for (let index = 0; index < argv.length; index += 2) if (!expected.has(argv[index]) || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error("Stage B state reconciliation authorization CLI arguments are not exact.");
  const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Stage B state reconciliation preparation" }).value;
  const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "Stage B state reconciliation environment approval" }).value;
  const authorization = createStageBStateReconciliationAuthorization({ preparation, approval });
  if (authorization.sourceSha !== required(argv, "--source-sha")) throw new Error("Stage B state reconciliation authorization source SHA is wrong.");
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Stage B state reconciliation authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage B state reconciliation authorization output" });
  writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation authorization" });
  return authorization;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runAuthorization(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }
