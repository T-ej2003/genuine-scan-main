#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { collectAppOnlyDatabaseCatalogueRows } from "./production-app-only-database-verifier.mjs";
import { appOnlyRequirementIdentity } from "./production-app-only-requirements.mjs";
import { readAppOnlyArtifactArchive } from "./production-app-only-artifacts.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCommandRunner, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { authenticateCanonicalProductionRequirements, EXPECTED_PRINTING_ROUTINE_PREDECESSORS, EXPECTED_PRINTING_ROUTINES, hashProductionRlsCatalogue, RLS_PROBE_CLASSIFICATIONS } from "./probe-production-rls-catalogue.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
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
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);

export const PRINTING_ROUTINE_DELTA = Object.freeze({
  family, containerName, executorImage, executorImageSourceSha, administrator, ownerRole, appRole, executionRoleArn,
  administratorSecretArn, logGroup, sourceSqlPath,
  routineNames: EXPECTED_PRINTING_ROUTINES,
});

export function discoverCanonicalRequirementsReference({ sourceSha, githubRun = createProductionGithubCommandRunner() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const get = (endpoint, options = {}) => parse(githubRun("gh", ["api", endpoint], { maxBuffer: 8 * 1024 * 1024, ...options }));
  const listed = get(`repos/${repository}/actions/workflows/produce-production-app-only-requirements.yml/runs?branch=main&event=workflow_dispatch&status=success&per_page=100`);
  const runs = (listed.workflow_runs || []).filter((run) => run.head_sha === sourceSha && run.head_branch === "main"
    && run.path === ".github/workflows/produce-production-app-only-requirements.yml" && run.event === "workflow_dispatch"
    && run.status === "completed" && run.conclusion === "success" && run.repository?.full_name === repository
    && run.head_repository?.full_name === repository && run.repository.id === run.head_repository.id)
    .sort((left, right) => Number(right.id) - Number(left.id));
  assert.ok(runs.length > 0, "No successful canonical requirements producer exists for protected main");
  for (const run of runs) {
    const artifacts = get(`repos/${repository}/actions/runs/${run.id}/artifacts`).artifacts || [];
    const matches = artifacts.filter((artifact) => artifact.name === "production-app-only-requirements" && !artifact.expired
      && artifact.workflow_run?.id === run.id && artifact.workflow_run?.head_sha === sourceSha
      && artifact.workflow_run?.repository_id === run.repository.id && artifact.workflow_run?.head_repository_id === run.head_repository.id);
    if (matches.length !== 1) continue;
    const artifact = matches[0];
    assert.match(artifact.digest || "", /^sha256:[a-f0-9]{64}$/);
    const archive = Buffer.from(githubRun("gh", ["api", `repos/${repository}/actions/artifacts/${artifact.id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
    assert.equal(`sha256:${sha256(archive)}`, artifact.digest);
    const bytes = readAppOnlyArtifactArchive(archive, "requirements");
    return Object.freeze({ sourceSha, runId: String(run.id), runAttempt: String(run.run_attempt), artifactId: String(artifact.id),
      artifactDigest: artifact.digest, fileSha256: sha256(bytes) });
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

export async function executePrintingRoutineDeltaTransaction({ tx, input, collect = collectAppOnlyDatabaseCatalogueRows,
  classify = classifyPrintingRoutineTransactionCatalogue } = {}) {
  assert.deepEqual(input.routines.map(({ name }) => name), EXPECTED_PRINTING_ROUTINES);
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$queryRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-printing-routine-delta',0))");
  const before = await collect(tx), { identity } = before;
  assert.equal(identity.role, administrator); assert.equal(identity.session_role, administrator);
  assert.equal(identity.database, "mscqr_production_rls_green_phase2"); assert.equal(identity.read_only, "off");
  assert.equal(identity.rolsuper, false); assert.equal(identity.rolbypassrls, false);
  assert.equal(identity.rolcreaterole, true); assert.equal(identity.rolcreatedb, true);
  const owners = await tx.$queryRawUnsafe("SELECT n.nspname||'.'||p.proname||'('||pg_catalog.pg_get_function_identity_arguments(p.oid)||')' AS identity,o.rolname AS owner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles o ON o.oid=p.proowner WHERE n.nspname='app_rls' AND p.proname=ANY(ARRAY['printing_readiness','printing_create_job','printing_connector_identity']) ORDER BY 1");
  assert.equal(owners.length, 3); assert.deepEqual(owners.map((value) => value.identity), input.contract.identities);
  assert.ok(owners.every((value) => value.owner === ownerRole));
  const state = classify(before, input.requirements);
  if (state === RLS_PROBE_CLASSIFICATIONS.MATCH) return { status: "ALREADY_CONVERGED", writeCount: 0 };
  assert.equal(state, RLS_PROBE_CLASSIFICATIONS.EXPECTED);
  await tx.$executeRawUnsafe(`SET LOCAL ROLE "${ownerRole}"`);
  let writeCount = 0;
  for (const routine of input.routines) {
    assert.equal(sha256(routine.sql), input.contract.sqlSha256[routine.name]);
    await tx.$executeRawUnsafe(routine.sql); writeCount++;
  }
  assert.equal(writeCount, 3);
  await tx.$executeRawUnsafe("RESET ROLE");
  const after = await collect(tx);
  assert.equal(classify(after, input.requirements), RLS_PROBE_CLASSIFICATIONS.MATCH);
  return { status: "APPLIED", writeCount };
}

export function buildPrintingRoutineDeltaCommand({ sourceSha, requirements, databaseHostname, routines = canonicalPrintingRoutineDelta() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  assert.deepEqual(routines.map(({ name }) => name), EXPECTED_PRINTING_ROUTINES);
  const expectedSuccessors = Object.fromEntries(requirements.objects.routines.filter(({ identity }) =>
    EXPECTED_PRINTING_ROUTINES.some((name) => identity.startsWith(`app_rls.${name}(`))).map(({ identity, sha256: digest }) => [identity, digest]));
  assert.deepEqual(Object.keys(expectedSuccessors).sort(), Object.keys(EXPECTED_PRINTING_ROUTINE_PREDECESSORS).sort());
  const predecessor = structuredClone(requirements);
  for (const row of predecessor.objects.routines) if (Object.hasOwn(EXPECTED_PRINTING_ROUTINE_PREDECESSORS, row.identity)) row.sha256 = EXPECTED_PRINTING_ROUTINE_PREDECESSORS[row.identity];
  const packed = { predecessor: catalogueDigestContract(predecessor.objects), successor: catalogueDigestContract(requirements.objects) };
  const contract = { sourceSha, requirementsSha256: requirements.requirementsSha256, identities: Object.keys(expectedSuccessors).sort(),
    predecessorSha256: EXPECTED_PRINTING_ROUTINE_PREDECESSORS, successorSha256: expectedSuccessors,
    predecessorContractSha256: canonicalSha256(packed.predecessor), successorContractSha256: canonicalSha256(packed.successor),
    sqlSha256: Object.fromEntries(routines.map(({ name, sql }) => [name, sha256(sql)])) };
  const input = { contract, requirements: packed, databaseHostname, routines };
  const functions = [collectAppOnlyDatabaseCatalogueRows, appOnlyRequirementIdentity, hashProductionRlsCatalogue, catalogueDigestContract,
    classifyPrintingRoutineTransactionCatalogue, executePrintingRoutineDeltaTransaction]
    .map((fn) => fn.toString()).join("\n");
  const command = `"use strict";const assert=require("node:assert/strict"),crypto=require("node:crypto");const {PrismaClient}=require("@prisma/client");const canonicalJson=${canonicalJson.toString()};const canonicalSha256=v=>crypto.createHash("sha256").update(canonicalJson(v)).digest("hex");const sha256=v=>crypto.createHash("sha256").update(v).digest("hex");const collections=${JSON.stringify(collections)};const administrator=${JSON.stringify(administrator)},ownerRole=${JSON.stringify(ownerRole)};const EXPECTED_PRINTING_ROUTINES=${JSON.stringify(EXPECTED_PRINTING_ROUTINES)};const EXPECTED_PRINTING_ROUTINE_PREDECESSORS=${JSON.stringify(EXPECTED_PRINTING_ROUTINE_PREDECESSORS)};const RLS_PROBE_CLASSIFICATIONS=${JSON.stringify(RLS_PROBE_CLASSIFICATIONS)};${functions};const input=${JSON.stringify(input)};(async()=>{assert.equal(canonicalSha256(input.contract),${JSON.stringify(canonicalSha256(contract))});assert.equal(canonicalSha256(input.requirements.predecessor),input.contract.predecessorContractSha256);assert.equal(canonicalSha256(input.requirements.successor),input.contract.successorContractSha256);const url=new URL("postgresql://unused/mscqr_production_rls_green_phase2");url.username=administrator;url.password=process.env.MSCQR_PRINTING_DELTA_ADMIN_PASSWORD||"";url.hostname=input.databaseHostname;url.port="5432";url.searchParams.set("sslmode","require");url.searchParams.set("application_name","mscqr-production-printing-routine-delta");assert.ok(url.password);const client=new PrismaClient({datasources:{db:{url:url.toString()}}});try{const result=await client.$transaction(tx=>executePrintingRoutineDeltaTransaction({tx,input}),{maxWait:10000,timeout:120000});const body={schemaVersion:1,kind:"PRODUCTION_PRINTING_ROUTINE_DELTA_RESULT",sourceSha:input.contract.sourceSha,requirementsSha256:input.contract.requirementsSha256,contractSha256:${JSON.stringify(canonicalSha256(contract))},database:"mscqr_production_rls_green_phase2",databaseRole:administrator,status:result.status,writeCount:result.writeCount};console.log(JSON.stringify({...body,evidenceSha256:canonicalSha256(body)}));}finally{await client.$disconnect();}})().catch(()=>{console.error(JSON.stringify({status:"PRODUCTION_PRINTING_ROUTINE_DELTA_FAILED"}));process.exitCode=1;});`;
  assert.ok(Buffer.byteLength(command) <= 98304, "Bounded printing routine command exceeds task-definition budget");
  return Object.freeze({ command: ["-e", command], contract: Object.freeze(contract), contractSha256: canonicalSha256(contract) });
}

export function buildPrintingRoutineDeltaDefinition({ sourceSha, requirements, databaseHostname, routines, repositoryRoot = root }) {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha, requirements, databaseHostname, routines: routines || canonicalPrintingRoutineDelta({ repositoryRoot }) });
  const definition = { family, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
    executionRoleArn, runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }], containerDefinitions: [{
      name: containerName, image: executorImage, essential: true, entryPoint: ["node"], command: built.command,
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }],
      secrets: [{ name: "MSCQR_PRINTING_DELTA_ADMIN_PASSWORD", valueFrom: administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region, "awslogs-group": logGroup, "awslogs-stream-prefix": "printing-routine-delta" } },
    }] };
  return Object.freeze({ definition, ...built });
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
  const reference = discoverCanonicalRequirementsReference({ sourceSha, githubRun });
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
  const registered = aws(["ecs", "register-task-definition", "--region", APP_ONLY.region, "--cli-input-json", JSON.stringify(built.definition)]).taskDefinition;
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
