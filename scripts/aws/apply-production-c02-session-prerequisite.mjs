#!/usr/bin/env node
import { buildC02CombinedPackage } from "./production-c02-combined-package.mjs";
import { authenticateCanonicalProductionRequirementsArtifact } from "./probe-production-rls-catalogue.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { PRINTING_ROUTINE_DELTA, authenticatePrintingRoutineExecutorPredecessor } from "./apply-production-printing-routine-delta.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { buildC02SessionPrerequisitePackage } from "./production-c02-session-package.mjs";
import { writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const family = "mscqr-production-c02-session-prerequisite";
const containerName = "production-c02-session-prerequisite";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (value) => JSON.parse(value);

export function buildC02SessionTask({ sourceSha, hostname, combinedRequirements, repositoryRoot = root } = {}) {
  assert.match(hostname || "", /^[a-z0-9.-]+$/);
  const pkg = combinedRequirements ? buildC02CombinedPackage({ sourceSha, ...combinedRequirements, repositoryRoot }) : buildC02SessionPrerequisitePackage({ sourceSha, repositoryRoot });
  let executor = fs.readFileSync(path.join(repositoryRoot, "scripts/aws/production-c02-session-executor.cjs"), "utf8");
  let runtimeArgument;
  if (combinedRequirements) {
    const sources=Object.fromEntries(["production-c02-session-executor.cjs","production-printing-routine-delta-executor.cjs","production-c02-combined-executor.cjs"].map(name=>["./"+name,fs.readFileSync(path.join(repositoryRoot,"scripts/aws",name),"utf8")]));
    const runtime=`const sources=${JSON.stringify(sources)};const cache=Object.create(null);function load(n){if(cache[n])return cache[n].exports;if(!Object.hasOwn(sources,n))return require(n);const module={exports:{}};cache[n]=module;new Function('module','require',sources[n])(module,load);return module.exports;}load('./production-c02-combined-executor.cjs').main();`;
    assert.ok(Buffer.byteLength(runtime)<96*1024);
    runtimeArgument=gzipSync(Buffer.from(runtime),{level:9,mtime:0}).toString("base64");
    executor="const z=require('node:zlib');const src=z.gunzipSync(Buffer.from(process.argv.splice(1,1)[0],'base64'),{maxOutputLength:98304}).toString('utf8');require('node:vm').runInThisContext(src);";
  }
  assert.ok(Buffer.byteLength(executor) < 64 * 1024);
  const bytes = Buffer.from(canonicalJson(pkg));
  assert.ok(bytes.length < (combinedRequirements ? 192 : 64) * 1024);
  const encoded = gzipSync(bytes, { level: 9, mtime: 0 }).toString("base64");
  assert.ok(encoded.length <= 32768, "C02 task payload exceeds the reviewed bounded transport");
  const definition = { family, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
    executionRoleArn: PRINTING_ROUTINE_DELTA.executionRoleArn, runtimePlatform: STAGE_B.taskRuntimePlatform,
    volumes: [{ name: "executor-tmp" }], containerDefinitions: [{ name: containerName,
      image: PRINTING_ROUTINE_DELTA.executorImage, essential: true, entryPoint: ["node"],
      command: ["-e", executor, ...(runtimeArgument ? [runtimeArgument] : []), encoded, sha256(bytes), hostname], readonlyRootFilesystem: true,
      mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }, { name: "RELEASE_GIT_SHA", value: sourceSha }],
      secrets: [{ name: "MSCQR_C02_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region,
        "awslogs-group": PRINTING_ROUTINE_DELTA.logGroup, "awslogs-stream-prefix": "c02-session-prerequisite" } },
    }] };
  const serialized = JSON.stringify(definition);
  assert.ok(Buffer.byteLength(serialized) < 60 * 1024, "C02 task definition exceeds the safe ECS budget");
  return Object.freeze({ pkg, definition, serialized });
}

export function authenticateC02SessionResult(message, { sourceSha, packageSha256, combined = false }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) < 4096);
  const result = JSON.parse(message);
  const { evidenceSha256, ...body } = result;
  assert.equal(evidenceSha256, canonicalSha256(body));
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "kind", "sourceSha", "packageSha256", "database",
    "databaseRole", "status", "writeCount", "evidenceSha256"].sort());
  assert.equal(result.schemaVersion, combined ? 2 : 1);
  assert.equal(result.kind, combined ? "PRODUCTION_C02_COMBINED_INSTALL_RESULT" : "PRODUCTION_C02_SESSION_INSTALL_RESULT");
  assert.equal(result.sourceSha, sourceSha); assert.equal(result.packageSha256, packageSha256);
  assert.equal(result.database, "mscqr_production_rls_green_phase2");
  assert.equal(result.databaseRole, PRINTING_ROUTINE_DELTA.administrator);
  assert.ok(result.status === "APPLIED" && result.writeCount === (combined ? 28 : 15) ||
    result.status === "ALREADY_CONVERGED" && result.writeCount === 0);
  return result;
}

// This command is an explicitly authorized production operation. It never runs
// during CI, normal deployment, or backend startup. The backend independently
// reads the installed C02 contract before opening its listener.
export async function applyProductionC02SessionPrerequisite({ sourceSha, awsProfile,
  receiptOut, predecessorReference, requirementsReference, repositoryRoot = root, run = execFileSync, wait = sleep, env = process.env } = {}) {
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const awsEnv = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: awsProfile, env });
  const aws = (args, timeout = 30000) => json(run(productionAwsExecutable(), [...args, "--output", "json", "--no-cli-pager"],
    { env: awsEnv, encoding: "utf8", timeout, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }));
  const caller = aws(["sts", "get-caller-identity"]);
  assert.equal(caller.Account, APP_ONLY.account);
  assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:root`);
  const service = aws(["ecs", "describe-services", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster,
    "--services", APP_ONLY.service]);
  assert.equal(service.services?.length, 1);
  const predecessor = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region,
    "--task-definition", service.services[0].taskDefinition]).taskDefinition;
  const imageDetails = aws(["ecr", "describe-images", "--region", APP_ONLY.region, "--repository-name", "mscqr-backend",
    "--image-ids", `imageDigest=${PRINTING_ROUTINE_DELTA.executorImage.split("@")[1]}`]).imageDetails;
  authenticatePrintingRoutineExecutorPredecessor({ serviceResponse: service, taskDefinition: predecessor, imageDetails });
  const hostname = aws(["rds", "describe-db-instances", "--region", APP_ONLY.region, "--db-instance-identifier",
    STAGE_B.greenDatabaseIdentifier]).DBInstances?.[0]?.Endpoint?.Address;
  let combinedRequirements;
  if (predecessorReference || requirementsReference) {
    assert.ok(predecessorReference && requirementsReference);
    assert.equal(predecessorReference.sourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
    const predecessor = JSON.parse(downloadAppOnlyArtifact({ kind: "requirements", reference: predecessorReference, repositoryRoot }).bytes);
    assert.equal(predecessor.sourceSha, predecessorReference.sourceSha);
    const { requirements: successor } = authenticateCanonicalProductionRequirementsArtifact({
      sourceSha, candidateSourceSha: sourceSha, requirementsReference, repositoryRoot });
    combinedRequirements = { predecessor, successor };
  }
  const task = buildC02SessionTask({ sourceSha, hostname, combinedRequirements, repositoryRoot });
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const registered = aws(["ecs", "register-task-definition", "--region", APP_ONLY.region,
    "--cli-input-json", task.serialized]).taskDefinition;
  const arn = registered?.taskDefinitionArn;
  assert.match(arn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${family}:[1-9][0-9]*$`));
  const readback = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region,
    "--task-definition", arn, "--include", "TAGS"]);
  assertEcsTaskDefinitionReadback({ definition: { ...readback.taskDefinition, tags: readback.tags || [] },
    taskDefinitionArn: arn, expected: task.definition, label: "C02 session prerequisite" });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: arn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken: canonicalSha256({ sourceSha, packageSha256: task.pkg.packageSha256, arn }),
    networkConfiguration: appOnlyVerifierNetwork() };
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const launched = aws(["ecs", "run-task", "--region", APP_ONLY.region, "--cli-input-json", JSON.stringify(request)]);
  assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1);
  const taskArn = launched.tasks[0].taskArn;
  assert.match(taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  let stopped;
  for (let i = 0; i < 60; i++) {
    const response = aws(["ecs", "describe-tasks", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster, "--tasks", taskArn]);
    assert.deepEqual(response.failures || [], []);
    stopped = response.tasks?.[0];
    if (stopped?.lastStatus === "STOPPED") break;
    await wait(5000);
  }
  assert.equal(stopped?.lastStatus, "STOPPED", "C02 installation outcome uncertain; verify read-only before retry");
  const stream = `c02-session-prerequisite/${containerName}/${taskArn.split("/").at(-1)}`;
  let message;
  for (let i = 0; i < 12 && !message; i++) {
    const logs = aws(["logs", "get-log-events", "--region", APP_ONLY.region, "--log-group-name",
      PRINTING_ROUTINE_DELTA.logGroup, "--log-stream-name", stream, "--start-from-head", "--limit", "10"]);
    if (logs.events?.length) { assert.equal(logs.events.length, 1); message = logs.events[0].message; }
    else await wait(5000);
  }
  const result = authenticateC02SessionResult(message, { sourceSha, packageSha256: task.pkg.packageSha256, combined: Boolean(combinedRequirements) });
  assert.equal(stopped.containers?.[0]?.exitCode, 0);
  const executedAt = new Date();
  const receipt = { schemaVersion: combinedRequirements ? 2 : 1, kind: combinedRequirements ? "PRODUCTION_C02_COMBINED_INSTALL_RECEIPT" : "PRODUCTION_C02_SESSION_INSTALL_RECEIPT", sourceSha,
    taskArn, taskDefinitionArn: arn, packageSha256: task.pkg.packageSha256, execution: result,
    executedAt: executedAt.toISOString(), expiresAt: new Date(executedAt.getTime() + 30 * 60 * 1000).toISOString() };
  const completed = { ...receipt, receiptSha256: canonicalSha256(receipt) };
  if (receiptOut) writeStageBPrivateFileExclusive({ filePath: receiptOut, repositoryRoot,
    bytes: Buffer.from(`${canonicalJson(completed)}\n`), label: "C02 session installation receipt" });
  return completed;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "source-sha": { type: "string" }, "aws-profile": { type: "string" },
      "receipt-out": { type: "string" }, "predecessor-reference": { type: "string" }, "requirements-reference": { type: "string" } }, strict: true });
    assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/);
    assert.ok(values["aws-profile"]); assert.ok(values["receipt-out"]);
    const result = await applyProductionC02SessionPrerequisite({ sourceSha: values["source-sha"],
      awsProfile: values["aws-profile"], receiptOut: values["receipt-out"],
      predecessorReference: values["predecessor-reference"] ? parseAppOnlyArtifactReference(values["predecessor-reference"]) : undefined,
      requirementsReference: values["requirements-reference"] ? parseAppOnlyArtifactReference(values["requirements-reference"]) : undefined });
    process.stdout.write(`${JSON.stringify({ status: result.execution.status, receiptSha256: result.receiptSha256 })}\n`);
  } catch {
    process.stderr.write("C02 prerequisite installation failed closed; reconcile read-only before retry.\n");
    process.exitCode = 1;
  }
}
