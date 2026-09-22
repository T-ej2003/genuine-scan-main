import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { collectAppOnlyDatabaseCatalogue } from "./production-app-only-database-verifier.mjs";
import { appOnlyRequirementIdentity, assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const collections = Object.freeze(["routines", "tables", "policies", "schemas", "roles"]);
export const EXPECTED_PRINTING_ROUTINES = Object.freeze(["printing_readiness", "printing_create_job", "printing_connector_identity"]);
// Exact catalogue hashes authenticated by the last compatible production proof:
// source 6d5a48ce7c32b12ce8671731392f92ddfa625a88, requirements 647841407b6bbba43d45ecc880dca713e73cacae4e1d27e74ce3dcdf977a2f88.
export const EXPECTED_PRINTING_ROUTINE_PREDECESSORS = Object.freeze({
  "app_rls.printing_connector_identity(p_kind text, p_agent_id text, p_device_fingerprint text, p_printer_selector text, p_gateway_id text, p_gateway_secret_hash text, p_operation text)": "aec14f16d5bf85cc48809a63d3e1a34c8a35c0eb51ac1f46899cfc05a24673b1",
  "app_rls.printing_create_job(p_capability text, p_purpose text, p_request_id text, p_batch_id text, p_printer_id text, p_quantity integer, p_range_start text, p_range_end text, p_print_mode text, p_payload_type text, p_print_lock_token_hash text, p_items jsonb)": "fafcc5b92873b51b786cf937b834f7991bc2eda8ba00b8d5e5a618edd2b1bd1c",
  "app_rls.printing_readiness(p_capability text, p_purpose text, p_request_id text, p_operation text, p_subject_id text, p_options jsonb)": "780215b4db85c6561e7ce8529838f15d72ce4d78f19507078d2e02f8f7e07f83",
});
export const RLS_PROBE_CLASSIFICATIONS = Object.freeze({ MATCH: "MATCH", EXPECTED: "EXPECTED_THREE_ROUTINE_DELTA_ONLY", UNEXPECTED: "UNEXPECTED_DRIFT" });

export function hashProductionRlsCatalogue(catalogue) {
  return Object.fromEntries(collections.map((name) => [name, catalogue[name].map((row) => ({ identity: appOnlyRequirementIdentity(name, row), sha256: canonicalSha256(row) })).sort((a, b) => a.identity.localeCompare(b.identity))]));
}

export function classifyProductionRlsCatalogue(catalogue, requirements) {
  const differences = [];
  let observedRoutines;
  for (const name of collections) {
    const observed = new Map(catalogue[name].map(({ identity, sha256 }) => [identity, sha256]));
    assert.equal(observed.size, catalogue[name].length, `Duplicate ${name} catalogue identity`);
    if (name === "routines") observedRoutines = observed;
    const expected = new Map(requirements.objects[name].map(({ identity, sha256 }) => [identity, sha256]));
    for (const identity of new Set([...expected.keys(), ...observed.keys()]))
      if (expected.get(identity) !== observed.get(identity)) differences.push({ collection: name, identity });
  }
  if (!differences.length) return { classification: RLS_PROBE_CLASSIFICATIONS.MATCH, deltaObjects: [] };
  const target = requirements.objects.routines.filter(({ identity }) => EXPECTED_PRINTING_ROUTINES.some((name) => identity.startsWith(`app_rls.${name}(`))).map(({ identity }) => identity).sort();
  assert.equal(target.length, EXPECTED_PRINTING_ROUTINES.length, "Canonical printing routine set is incomplete or ambiguous");
  assert.deepEqual(target, Object.keys(EXPECTED_PRINTING_ROUTINE_PREDECESSORS).sort(), "Canonical printing routine signatures changed");
  const actual = differences.filter(({ collection }) => collection === "routines").map(({ identity }) => identity).sort();
  const expectedOnly = differences.length === target.length && canonicalJson(actual) === canonicalJson(target)
    && target.every((identity) => observedRoutines.get(identity) === EXPECTED_PRINTING_ROUTINE_PREDECESSORS[identity]);
  return { classification: expectedOnly ? RLS_PROBE_CLASSIFICATIONS.EXPECTED : RLS_PROBE_CLASSIFICATIONS.UNEXPECTED,
    deltaObjects: differences.map(({ identity }) => identity).sort() };
}

export function buildProductionRlsProbeCommand(requirements, identity) {
  const input = { requirementsSha256: requirements.requirementsSha256, identity };
  const functions = [collectAppOnlyDatabaseCatalogue, appOnlyRequirementIdentity, hashProductionRlsCatalogue].map((fn) => fn.toString()).join("\n");
  const command = `"use strict";const assert=require("node:assert/strict"),crypto=require("node:crypto");const {PrismaClient}=require("@prisma/client");const canonicalJson=${canonicalJson.toString()};const canonicalSha256=v=>crypto.createHash("sha256").update(canonicalJson(v)).digest("hex");const collections=${JSON.stringify(collections)};${functions};const input=${JSON.stringify(input)};(async()=>{const url=new URL(process.env.RLS_CANARY_DATABASE_URL||"");assert.equal(url.username,"mscqr_prod_rls_canary_read");assert.equal(url.hostname,input.identity.databaseHostname);assert.equal(url.pathname,"/mscqr_production_rls_green_phase2");assert.equal(url.searchParams.size,2);assert.equal(url.searchParams.get("sslmode"),"require");assert.equal(url.searchParams.get("application_name"),"mscqr-production-green-read-only-rls-canary");assert.equal(url.hash,"");const client=new PrismaClient({datasources:{db:{url:url.toString()}}});try{const catalogue=await collectAppOnlyDatabaseCatalogue(client);const body={schemaVersion:1,kind:"PRODUCTION_RLS_CATALOGUE_PROBE",sourceSha:input.identity.sourceSha,requirementsSha256:input.requirementsSha256,databaseRole:catalogue.identity.role,catalogue:hashProductionRlsCatalogue(catalogue)};const output=JSON.stringify({...body,evidenceSha256:canonicalSha256(body)});assert.ok(Buffer.byteLength(output)<=196608);console.log(output);}finally{await client.$disconnect();}})().catch(()=>{console.error(JSON.stringify({status:"PRODUCTION_RLS_CATALOGUE_PROBE_FAILED"}));process.exitCode=1;});`;
  assert.ok(Buffer.byteLength(command) <= 48000, "RLS catalogue probe command exceeds task-definition budget");
  return ["-e", command];
}

export function buildProductionRlsProbeDefinition({ baseDefinition, requirements, identity, databaseSecretArn }) {
  assert.equal(baseDefinition.family, APP_ONLY_VERIFIER.family);
  assert.equal(baseDefinition.taskRoleArn, APP_ONLY_VERIFIER.taskRoleArn); assert.equal(baseDefinition.executionRoleArn, APP_ONLY_VERIFIER.executionRoleArn);
  assert.equal(baseDefinition.networkMode, "awsvpc"); assert.deepEqual(baseDefinition.runtimePlatform, STAGE_B.taskRuntimePlatform);
  assert.equal(baseDefinition.containerDefinitions?.length, 1); const base = baseDefinition.containerDefinitions[0];
  assert.equal(base.name, "production-green-read-only-rls-canary"); assert.equal(base.readonlyRootFilesystem, true); assert.equal(base.privileged, false);
  assert.deepEqual(base.entryPoint, ["node"]); assert.deepEqual(base.environment || [], []); assert.deepEqual(base.secrets, [{ name: "RLS_CANARY_DATABASE_URL", valueFrom: databaseSecretArn }]);
  assert.match(base.image || "", new RegExp(`^${APP_ONLY.backendRepository.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}@sha256:[a-f0-9]{64}$`));
  const template = JSON.parse(fs.readFileSync(new URL("../../infra/aws/terraform/production-green-stage-b/task-definitions/green-read-only-rls-canary.json", import.meta.url), "utf8"));
  template.family = APP_ONLY_VERIFIER.family;
  template.taskRoleArn = APP_ONLY_VERIFIER.taskRoleArn; template.executionRoleArn = APP_ONLY_VERIFIER.executionRoleArn; template.runtimePlatform = STAGE_B.taskRuntimePlatform;
  const container = template.containerDefinitions[0]; container.image = base.image; container.entryPoint = ["node"]; container.command = buildProductionRlsProbeCommand(requirements, identity);
  container.secrets[0].valueFrom = databaseSecretArn; container.logConfiguration.options["awslogs-group"] = APP_ONLY_VERIFIER.logGroup; container.logConfiguration.options["awslogs-stream-prefix"] = "prebaseline-rls";
  return template;
}

export function authenticateProductionRlsProbeResult(message, { sourceSha, requirementsSha256 }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 196608, "RLS probe result is oversized");
  const result = JSON.parse(message), { evidenceSha256, ...body } = result;
  assert.equal(evidenceSha256, canonicalSha256(body)); assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_RLS_CATALOGUE_PROBE");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.requirementsSha256, requirementsSha256); assert.equal(body.databaseRole, APP_ONLY_VERIFIER.databaseRole);
  assert.deepEqual(Object.keys(body.catalogue || {}).sort(), [...collections].sort());
  for (const rows of Object.values(body.catalogue)) for (const row of rows) { assert.match(row.identity || "", /^.{1,4096}$/s); assert.match(row.sha256 || "", /^[a-f0-9]{64}$/); }
  return result;
}

const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
export async function runProductionRlsCatalogueProbe({ sourceSha, requirementsPath, awsProfile, run = (command, args) => execFileSync(command, args, { encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024 }), wait = sleep, repositoryRoot = root }) {
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const requirements = assertAppOnlyRequirements(JSON.parse(fs.readFileSync(requirementsPath, "utf8")), { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  const aws = (args) => parse(run("aws", ["--profile", awsProfile, ...args, "--output", "json", "--no-cli-pager"]));
  const caller = aws(["sts", "get-caller-identity"]); assert.equal(caller.Account, APP_ONLY.account); assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:root`);
  const live = aws(["ecs", "describe-services", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster, "--services", APP_ONLY.service]);
  assert.deepEqual(live.failures || [], []); assert.equal(live.services?.length, 1); const service = live.services[0]; assert.equal(service.deployments?.length, 1); assert.equal(service.runningCount, service.desiredCount);
  const backend = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region, "--task-definition", service.taskDefinition]).taskDefinition;
  const backendContainer = backend.containerDefinitions?.find(({ name }) => name === APP_ONLY.container); assert.ok(backendContainer);
  const verifier = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region, "--task-definition", APP_ONLY_VERIFIER.family, "--include", "TAGS"]);
  const verifierContainer = verifier.taskDefinition?.containerDefinitions?.[0]; const databaseSecretArn = verifierContainer?.secrets?.find(({ name }) => name === "RLS_CANARY_DATABASE_URL")?.valueFrom;
  assert.match(databaseSecretArn || "", /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/phase4\/read-only-canary-database-url-[A-Za-z0-9]{6}$/);
  const databaseHostname = aws(["rds", "describe-db-instances", "--region", APP_ONLY.region, "--db-instance-identifier", STAGE_B.greenDatabaseIdentifier]).DBInstances?.[0]?.Endpoint?.Address;
  assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  const digest = verifierContainer.image.split("@")[1]; const predecessorDigest = backendContainer.image.split("@")[1];
  const identity = { sourceSha, candidateSourceSha: sourceSha, account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: service.taskDefinition, predecessorBackendDigest: predecessorDigest, candidateDigest: digest, verifierImageDigest: digest, databaseHostname };
  const definition = buildProductionRlsProbeDefinition({ baseDefinition: verifier.taskDefinition, requirements, identity, databaseSecretArn });
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  const registered = aws(["ecs", "register-task-definition", "--region", APP_ONLY.region, "--cli-input-json", JSON.stringify(definition)]).taskDefinition;
  const taskDefinitionArn = registered?.taskDefinitionArn; assert.match(taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:[1-9][0-9]*$`));
  const readback = aws(["ecs", "describe-task-definition", "--region", APP_ONLY.region, "--task-definition", taskDefinitionArn, "--include", "TAGS"]);
  assertEcsTaskDefinitionReadback({ definition: { ...readback.taskDefinition, tags: readback.tags || [] }, taskDefinitionArn, expected: definition, label: "Pre-baseline read-only RLS probe" });
  const clientToken = canonicalSha256({ sourceSha, requirementsSha256: requirements.requirementsSha256, taskDefinitionArn });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1, enableExecuteCommand: false, clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  const launched = aws(["ecs", "run-task", "--region", APP_ONLY.region, "--cli-input-json", JSON.stringify(request)]); assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1);
  const taskArn = launched.tasks[0].taskArn; let task;
  assert.match(taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  for (let attempt = 0; attempt < 60; attempt++) { const response = aws(["ecs", "describe-tasks", "--region", APP_ONLY.region, "--cluster", APP_ONLY.cluster, "--tasks", taskArn]); assert.deepEqual(response.failures || [], []); task = response.tasks?.[0]; if (task?.lastStatus === "STOPPED") break; await wait(5000); }
  assert.equal(task?.lastStatus, "STOPPED", "RLS probe completion timeout; do not relaunch automatically"); assert.equal(task.enableExecuteCommand, false); assert.equal(task.containers?.length, 1);
  const stream = `prebaseline-rls/production-green-read-only-rls-canary/${taskArn.split("/").at(-1)}`; let message;
  for (let attempt = 0; attempt < 12 && !message; attempt++) { const logs = aws(["logs", "get-log-events", "--region", APP_ONLY.region, "--log-group-name", APP_ONLY_VERIFIER.logGroup, "--log-stream-name", stream, "--start-from-head", "--limit", "10"]); const events = logs.events || []; if (events.length) { assert.equal(events.length, 1); message = events[0].message; } else await wait(5000); }
  assert.ok(message, "RLS probe evidence unavailable; do not relaunch automatically"); const evidence = authenticateProductionRlsProbeResult(message, { sourceSha, requirementsSha256: requirements.requirementsSha256 });
  assert.equal(task.containers[0].exitCode, 0, "RLS probe task failed"); const result = classifyProductionRlsCatalogue(evidence.catalogue, requirements);
  return { status: "PRODUCTION_RLS_CATALOGUE_PROBED", sourceSha, taskDefinitionArn, taskArn, classification: result.classification, deltaObjects: result.deltaObjects, requirementsSha256: requirements.requirementsSha256 };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "source-sha": { type: "string" }, requirements: { type: "string" }, "aws-profile": { type: "string" } }, strict: true });
    assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.ok(path.isAbsolute(values.requirements || "")); assert.ok(values["aws-profile"]);
    const result = await runProductionRlsCatalogueProbe({ sourceSha: values["source-sha"], requirementsPath: values.requirements, awsProfile: values["aws-profile"] });
    process.stdout.write(`${JSON.stringify(result)}\n`); if (result.classification === RLS_PROBE_CLASSIFICATIONS.UNEXPECTED) process.exitCode = 2;
  } catch { process.stderr.write("Production RLS catalogue probe failed closed; no database mutation was attempted.\n"); process.exitCode = 1; }
}
