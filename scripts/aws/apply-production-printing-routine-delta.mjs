#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { completeGithubCollection, readAppOnlyArtifactArchive } from "./production-app-only-artifacts.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCommandRunner, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { authenticateCanonicalProductionRequirements, authenticateCanonicalProductionRequirementsArtifact, EXPECTED_PRINTING_ROUTINE_PREDECESSORS, EXPECTED_PRINTING_ROUTINES, hashProductionRlsCatalogue, RLS_PROBE_CLASSIFICATIONS } from "./probe-production-rls-catalogue.mjs";
import { encodeWorkflowDispatchGzip } from "./workflow-dispatch-gzip-transport.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const require = createRequire(import.meta.url);
const runtime = require("./production-printing-routine-delta-executor.cjs");
const runtimePath = fileURLToPath(new URL("./production-printing-routine-delta-executor.cjs", import.meta.url));
const repository = "T-ej2003/genuine-scan-main";
const sourceSqlPath = "backend/src/rls-waves/session-c/c02/printingLifecycle.sql";
const family = "mscqr-production-printing-routine-delta";
const containerName = "production-printing-routine-delta";
const executorImageSourceSha = "bcec05a421bff28eb2216f399d0a9e7cd2389d5e";
const executorImageDigest = "sha256:d2a6f641f44e27454a80d502914a9e168c61cdace1201f9d7af9d85a87ea208c";
const executorImage = `${APP_ONLY.backendRepository}@${executorImageDigest}`;
const administrator = "mscqr_prod_admin";
const ownerRole = "mscqr_prd_rls_phase2_auth_owner";
const appRole = "mscqr_prd_rls_phase2_app";
const executionRoleArn = `arn:aws:iam::${APP_ONLY.account}:role/mscqr-production-full-rls-green-executor-execution`;
const administratorSecretArn = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo:password::";
const logGroup = STAGE_B.executorLogGroupName;
const collections = Object.freeze(["routines", "tables", "policies", "schemas", "roles"]);
export const AWS_TASK_DEFINITION_LIMIT_BYTES = 64 * 1024;
export const SAFE_TASK_DEFINITION_CEILING_BYTES = 60 * 1024;
const MAX_DECOMPRESSED_PAYLOAD_BYTES = 64 * 1024;
const MAX_ENCODED_TRANSPORT_BYTES = 32 * 1024;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);

export const PRINTING_ROUTINE_DELTA = Object.freeze({
  family, containerName, executorImage, executorImageSourceSha, administrator, ownerRole, appRole, executionRoleArn,
  administratorSecretArn, logGroup, sourceSqlPath,
  routineNames: EXPECTED_PRINTING_ROUTINES,
});

export function discoverCanonicalRequirementsReference({ sourceSha, repositoryRoot = root, githubRun = createProductionGithubCommandRunner() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const get = (endpoint, { flags = [], ...options } = {}) => parse(githubRun("gh", ["api", endpoint, ...flags], { maxBuffer: 8 * 1024 * 1024, ...options }));
  const endpoint = `repos/${repository}/actions/workflows/produce-production-app-only-requirements.yml/runs?branch=main&event=workflow_dispatch&status=success&per_page=100`;
  const listedRuns = completeGithubCollection(get(endpoint, { flags: ["--paginate", "--slurp"] }), "workflow_runs");
  for (const run of listedRuns) {
    assert.match(String(run.id), /^[1-9][0-9]*$/); assert.match(String(run.run_attempt), /^[1-9][0-9]*$/);
    assert.equal(run.head_branch, "main"); assert.equal(run.path, ".github/workflows/produce-production-app-only-requirements.yml");
    assert.equal(run.event, "workflow_dispatch"); assert.equal(run.status, "completed"); assert.equal(run.conclusion, "success");
    assert.equal(run.repository?.full_name, repository); assert.equal(run.head_repository?.full_name, repository);
    assert.ok(Number.isSafeInteger(run.repository?.id) && run.repository.id > 0); assert.equal(run.repository.id, run.head_repository.id);
  }
  const runs = listedRuns.filter((run) => run.head_sha === sourceSha)
    .sort((left, right) => BigInt(right.id) > BigInt(left.id) ? 1 : BigInt(right.id) < BigInt(left.id) ? -1 : 0);
  assert.ok(runs.length > 0, "No successful canonical requirements producer exists for protected main");
  for (const run of runs) {
    const artifactPages = get(`repos/${repository}/actions/runs/${run.id}/artifacts?per_page=100`, { flags: ["--paginate", "--slurp"] });
    const artifacts = completeGithubCollection(artifactPages, "artifacts");
    const matches = artifacts.filter((artifact) => artifact.name === "production-app-only-requirements" && !artifact.expired);
    if (matches.length === 0) continue;
    assert.equal(matches.length, 1, "Ambiguous canonical requirements artifact");
    const artifact = matches[0];
    assert.match(artifact.digest || "", /^sha256:[a-f0-9]{64}$/);
    const reference = Object.freeze({ sourceSha, runId: String(run.id), runAttempt: String(run.run_attempt), artifactId: String(artifact.id),
      artifactDigest: artifact.digest, fileSha256: null });
    const archive = Buffer.from(githubRun("gh", ["api", `repos/${repository}/actions/artifacts/${artifact.id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
    assert.equal(`sha256:${sha256(archive)}`, artifact.digest);
    const bytes = readAppOnlyArtifactArchive(archive, "requirements");
    const bound = Object.freeze({ ...reference, fileSha256: sha256(bytes) });
    const { requirements } = authenticateCanonicalProductionRequirementsArtifact({ sourceSha, requirementsReference: bound, repositoryRoot, githubRun });
    if (requirements.candidateSourceSha !== sourceSha) continue;
    return bound;
  }
  throw new Error("Canonical requirements artifact is absent or ambiguous");
}

const functionSql = (source, name) => {
  const marker = `CREATE OR REPLACE FUNCTION app_rls.${name}(`;
  assert.equal(source.split(marker).length, 2, `Canonical ${name} definition is absent or ambiguous`);
  const start = source.indexOf(marker), end = source.indexOf("\n$fn$;", start);
  assert.ok(end > start, `Canonical ${name} definition is unterminated`);
  const sql = source.slice(start, end + 6).replaceAll("{{APP_ROLE}}", `'${appRole}'`);
  assert.equal((sql.match(/CREATE OR REPLACE FUNCTION/g) || []).length, 1);
  assert.equal((sql.match(/\{\{[A-Z_]+\}\}/g) || []).length, 0, `Canonical ${name} contains an unresolved source placeholder`);
  assert.match(sql, new RegExp(`^CREATE OR REPLACE FUNCTION app_rls\\.${name}\\(`));
  assert.ok(sql.endsWith("$fn$;"));
  return sql;
};

export function canonicalPrintingRoutineDelta({ repositoryRoot = root } = {}) {
  const source = fs.readFileSync(path.join(repositoryRoot, sourceSqlPath), "utf8");
  const routines = EXPECTED_PRINTING_ROUTINES.map((name) => Object.freeze({ name, sql: functionSql(source, name) }));
  assert.equal(new Set(routines.map(({ name }) => name)).size, 3);
  return Object.freeze(routines);
}

function catalogueDigestContract(catalogue) {
  return Object.fromEntries(collections.map((name) => [name, canonicalSha256(catalogue[name])]));
}

export function classifyPrintingRoutineTransactionCatalogue(catalogue, requirements) {
  const observed = catalogueDigestContract(hashProductionRlsCatalogue(catalogue));
  if (canonicalJson(observed) === canonicalJson(requirements.successor)) return RLS_PROBE_CLASSIFICATIONS.MATCH;
  if (canonicalJson(observed) === canonicalJson(requirements.predecessor)) return RLS_PROBE_CLASSIFICATIONS.EXPECTED;
  return RLS_PROBE_CLASSIFICATIONS.UNEXPECTED;
}

export const executePrintingRoutineDeltaTransaction = runtime.executePrintingRoutineDeltaTransaction;

export function buildPrintingRoutineDeltaCommand({ sourceSha, requirements, databaseHostname, repositoryRoot = root }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  const routines = canonicalPrintingRoutineDelta({ repositoryRoot });
  assert.deepEqual(routines.map(({ name }) => name), EXPECTED_PRINTING_ROUTINES);
  const expectedSuccessors = Object.fromEntries(requirements.objects.routines.filter(({ identity }) =>
    EXPECTED_PRINTING_ROUTINES.some((name) => identity.startsWith(`app_rls.${name}(`))).map(({ identity, sha256: digest }) => [identity, digest]));
  assert.deepEqual(Object.keys(expectedSuccessors).sort(), Object.keys(EXPECTED_PRINTING_ROUTINE_PREDECESSORS).sort());
  const predecessor = structuredClone(requirements);
  for (const row of predecessor.objects.routines) if (Object.hasOwn(EXPECTED_PRINTING_ROUTINE_PREDECESSORS, row.identity)) row.sha256 = EXPECTED_PRINTING_ROUTINE_PREDECESSORS[row.identity];
  const packed = { predecessor: catalogueDigestContract(predecessor.objects), successor: catalogueDigestContract(requirements.objects) };
  const executorSourcePath = path.join(repositoryRoot, path.relative(root, runtimePath));
  assert.ok(fs.lstatSync(executorSourcePath).isFile()); assert.equal(fs.realpathSync(executorSourcePath), executorSourcePath);
  const executorSource = fs.readFileSync(executorSourcePath, "utf8");
  assert.ok(Buffer.byteLength(executorSource) <= 65536, "Bounded printing routine executor exceeds source budget");
  const contract = { sourceSha, requirementsSha256: requirements.requirementsSha256, identities: Object.keys(expectedSuccessors).sort(),
    predecessorSha256: EXPECTED_PRINTING_ROUTINE_PREDECESSORS, successorSha256: expectedSuccessors,
    predecessorContractSha256: canonicalSha256(packed.predecessor), successorContractSha256: canonicalSha256(packed.successor),
    sqlSha256: Object.fromEntries(routines.map(({ name, sql }) => [name, sha256(sql)])), executorSourceSha256: sha256(executorSource) };
  const input = { contract, requirements: packed, databaseHostname, routines };
  const payload = Buffer.from(canonicalJson({ input, contractSha256: canonicalSha256(contract) }));
  assert.ok(payload.length <= MAX_DECOMPRESSED_PAYLOAD_BYTES, "Bounded printing routine payload exceeds data budget");
  const encodedPayload = encodeWorkflowDispatchGzip(payload, { label: "Bounded printing routine payload", maxDecompressedBytes: MAX_DECOMPRESSED_PAYLOAD_BYTES });
  assert.ok(Buffer.byteLength(encodedPayload) <= MAX_ENCODED_TRANSPORT_BYTES, "Bounded printing routine transport exceeds encoded budget");
  return Object.freeze({ command: ["-e", executorSource, encodedPayload, sha256(payload)], contract: Object.freeze(contract), contractSha256: canonicalSha256(contract) });
}

export function buildPrintingRoutineDeltaDefinition({ sourceSha, requirements, databaseHostname, repositoryRoot = root }) {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha, requirements, databaseHostname, repositoryRoot });
  const definition = { family, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
    executionRoleArn, runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }], containerDefinitions: [{
      name: containerName, image: executorImage, essential: true, entryPoint: ["node"], command: built.command,
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }],
      secrets: [{ name: "MSCQR_PRINTING_DELTA_ADMIN_PASSWORD", valueFrom: administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region, "awslogs-group": logGroup, "awslogs-stream-prefix": "printing-routine-delta" } },
    }] };
  const registrationPayload = JSON.stringify(definition);
  const serializedTaskDefinitionBytes = Buffer.byteLength(registrationPayload, "utf8");
  assert.ok(serializedTaskDefinitionBytes <= SAFE_TASK_DEFINITION_CEILING_BYTES, "Bounded printing routine task definition exceeds safe ECS budget");
  assert.ok(serializedTaskDefinitionBytes < AWS_TASK_DEFINITION_LIMIT_BYTES, "Bounded printing routine task definition exceeds AWS ECS limit");
  return Object.freeze({ definition, registrationPayload, serializedTaskDefinitionBytes, ...built });
}

export function authenticatePrintingRoutineDeltaResult(message, { sourceSha, requirementsSha256, contractSha256 }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 4096);
  const result = JSON.parse(message), { evidenceSha256, ...body } = result;
  assert.deepEqual(Object.keys(result).sort(), ["contractSha256", "database", "databaseRole", "evidenceSha256", "kind", "requirementsSha256", "schemaVersion", "sourceSha", "status", "writeCount"].sort());
  assert.equal(evidenceSha256, canonicalSha256(body)); assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_PRINTING_ROUTINE_DELTA_RESULT");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.requirementsSha256, requirementsSha256); assert.equal(body.contractSha256, contractSha256);
  assert.equal(body.database, "mscqr_production_rls_green_phase2"); assert.equal(body.databaseRole, administrator);
  assert.ok(body.status === "APPLIED" && body.writeCount === 3 || body.status === "ALREADY_CONVERGED" && body.writeCount === 0);
  return result;
}

export function authenticatePrintingRoutineExecutorPredecessor({ serviceResponse, taskDefinition, imageDetails }) {
  assert.deepEqual(serviceResponse.failures || [], []); assert.equal(serviceResponse.services?.length, 1);
  const service = serviceResponse.services[0]; assert.equal(service.deployments?.length, 1);
  assert.equal(service.runningCount, service.desiredCount); assert.equal(service.pendingCount, 0);
  assert.equal(taskDefinition?.taskDefinitionArn, service.taskDefinition);
  assert.deepEqual(taskDefinition?.containerDefinitions?.filter(({ name }) => name === APP_ONLY.container).map(({ image }) => image), [executorImage]);
  assert.equal(imageDetails?.length, 1); assert.equal(imageDetails[0].imageDigest, executorImageDigest);
  assert.deepEqual((imageDetails[0].imageTags || []).filter((tag) => /^[a-f0-9]{40}$/.test(tag)), [executorImageSourceSha]);
  return true;
}

export async function applyProductionPrintingRoutineDelta({ sourceSha, awsProfile, run = (command, args, options) => execFileSync(command, args, options),
  githubRun = createProductionGithubCommandRunner(), wait = sleep, repositoryRoot = root, env = process.env } = {}) {
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const reference = discoverCanonicalRequirementsReference({ sourceSha, repositoryRoot, githubRun });
  const { requirements } = authenticateCanonicalProductionRequirements({ sourceSha, requirementsReference: reference, repositoryRoot, githubRun });
  const commandEnvironment = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: awsProfile, env });
  const awsExecutable = productionAwsExecutable();
  const aws = (args, timeout = 30000) => parse(run(awsExecutable, [...args, "--output", "json", "--no-cli-pager"], { env: commandEnvironment, encoding: "utf8", timeout, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }));
  const caller = aws(["sts", "get-caller-identity"]); assert.equal(caller.Account, APP_ONLY.account); assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:root`);
  const serviceResponse = aws(["ecs", "describe-services", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster, "--services", APP_ONLY.service]);
  assert.equal(serviceResponse.services?.length, 1);
  const predecessor = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region, "--task-definition", serviceResponse.services[0].taskDefinition]).taskDefinition;
  const imageDetails = aws(["ecr", "describe-images", "--region", APP_ONLY.region, "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${executorImageDigest}`]).imageDetails;
  authenticatePrintingRoutineExecutorPredecessor({ serviceResponse, taskDefinition: predecessor, imageDetails });
  const databaseHostname = aws(["rds", "describe-db-instances", "--region", APP_ONLY.region, "--db-instance-identifier", STAGE_B.greenDatabaseIdentifier]).DBInstances?.[0]?.Endpoint?.Address;
  assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  const built = buildPrintingRoutineDeltaDefinition({ sourceSha, requirements, databaseHostname, repositoryRoot });
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const registered = aws(["ecs", "register-task-definition", "--region", APP_ONLY.region, "--cli-input-json", built.registrationPayload]).taskDefinition;
  const taskDefinitionArn = registered?.taskDefinitionArn; assert.match(taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${family}:[1-9][0-9]*$`));
  const readback = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region, "--task-definition", taskDefinitionArn, "--include", "TAGS"]);
  assertEcsTaskDefinitionReadback({ definition: { ...readback.taskDefinition, tags: readback.tags || [] }, taskDefinitionArn, expected: built.definition, label: "Bounded printing routine delta" });
  const clientToken = canonicalSha256({ sourceSha, contractSha256: built.contractSha256, taskDefinitionArn });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1, enableExecuteCommand: false, clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  const launched = aws(["ecs", "run-task", "--region", APP_ONLY.region, "--cli-input-json", JSON.stringify(request)]); assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1);
  const taskArn = launched.tasks[0].taskArn; assert.match(taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  let task; for (let attempt = 0; attempt < 60; attempt++) { const response = aws(["ecs", "describe-tasks", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster, "--tasks", taskArn]); assert.deepEqual(response.failures || [], []); task = response.tasks?.[0]; if (task?.lastStatus === "STOPPED") break; await wait(5000); }
  assert.equal(task?.lastStatus, "STOPPED", "Printing routine delta timeout; reconcile with the read-only probe and do not relaunch automatically"); assert.equal(task.enableExecuteCommand, false); assert.equal(task.containers?.length, 1);
  const stream = `printing-routine-delta/${containerName}/${taskArn.split("/").at(-1)}`; let message;
  for (let attempt = 0; attempt < 12 && !message; attempt++) { const logs = aws(["logs", "get-log-events", "--region", APP_ONLY.region, "--log-group-name", logGroup, "--log-stream-name", stream, "--start-from-head", "--limit", "10"]); const events = logs.events || []; if (events.length) { assert.equal(events.length, 1); message = events[0].message; } else await wait(5000); }
  assert.ok(message, "Printing routine delta evidence unavailable; reconcile with the read-only probe and do not relaunch automatically");
  const result = authenticatePrintingRoutineDeltaResult(message, { sourceSha, requirementsSha256: requirements.requirementsSha256, contractSha256: built.contractSha256 });
  assert.equal(task.containers[0].exitCode, 0, "Printing routine delta task failed; reconcile read only before any retry");
  return { status: result.status, sourceSha, taskDefinitionArn, taskArn, requirementsSha256: requirements.requirementsSha256, contractSha256: built.contractSha256, writeCount: result.writeCount };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "source-sha": { type: "string" }, "aws-profile": { type: "string" } }, strict: true });
    assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.ok(values["aws-profile"]);
    const result = await applyProductionPrintingRoutineDelta({ sourceSha: values["source-sha"], awsProfile: values["aws-profile"] });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("Production printing routine delta failed closed; reconcile with the read-only catalogue probe before any retry.\n"); process.exitCode = 1;
  }
}
