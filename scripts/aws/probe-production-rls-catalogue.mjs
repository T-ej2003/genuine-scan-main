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
import { assertAppOnlyCandidateAncestor } from "./produce-production-app-only-requirements.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCommandRunner, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertSecurityRebaselineInventory, createLiveSecurityRebaselineInventory, securityRebaselineLogSummary } from "./production-security-rebaseline-inventory.mjs";
import { createSecurityCatalogueTransportKeyPair, decryptSecurityCatalogueTransport } from "./production-security-rebaseline-transport.mjs";
import { createProductionRlsProbeRuntimeConfig, PRODUCTION_RLS_PROBE_ENTRYPOINT } from "./production-rls-catalogue-probe-config.mjs";

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

export function buildProductionRlsProbeCommand(requirements, identity, { securityTransportPublicKey = null } = {}) {
  assert.match(identity?.sourceSha || "", /^[a-f0-9]{40}$/); assert.match(identity?.candidateSourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(identity.candidateSourceSha, requirements?.candidateSourceSha, "Probe candidate differs from authenticated requirements");
  const configuration = createProductionRlsProbeRuntimeConfig(requirements, identity, securityTransportPublicKey);
  return Object.freeze({ entryPoint: ["node", PRODUCTION_RLS_PROBE_ENTRYPOINT], command: [],
    environment: [{ name: "RLS_PROBE_INPUT_JSON", value: configuration }] });
}

export function buildProductionRlsProbeDefinition({ baseDefinition, requirements, identity, databaseSecretArn, securityTransportPublicKey = null }) {
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
  const container = template.containerDefinitions[0], probe = buildProductionRlsProbeCommand(requirements, identity, { securityTransportPublicKey }); container.image = base.image; container.entryPoint = probe.entryPoint; container.command = probe.command; container.environment = probe.environment;
  container.secrets[0].valueFrom = databaseSecretArn; container.logConfiguration.options["awslogs-group"] = APP_ONLY_VERIFIER.logGroup; container.logConfiguration.options["awslogs-stream-prefix"] = "prebaseline-rls";
  return template;
}

export function authenticateProductionRlsProbeResult(message, { sourceSha, candidateSourceSha, requirementsSha256, securityTransportExpected = false }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 196608, "RLS probe result is oversized");
  const result = JSON.parse(message), { evidenceSha256, ...body } = result;
  assert.deepEqual(Object.keys(result).sort(), ["candidateSourceSha", "catalogue", "databaseRole", "evidenceSha256", "kind", "requirementsSha256", "schemaVersion", "sourceSha", ...(securityTransportExpected ? ["securityTransport"] : [])].sort());
  assert.equal(evidenceSha256, canonicalSha256(body)); assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_RLS_CATALOGUE_PROBE");
  assert.equal(body.sourceSha, sourceSha); assert.match(candidateSourceSha || "", /^[a-f0-9]{40}$/, "Expected candidate source SHA is required"); assert.equal(body.candidateSourceSha, candidateSourceSha); assert.equal(body.requirementsSha256, requirementsSha256); assert.equal(body.databaseRole, APP_ONLY_VERIFIER.databaseRole);
  assert.deepEqual(Object.keys(body.catalogue || {}).sort(), [...collections].sort());
  for (const rows of Object.values(body.catalogue)) {
    assert.ok(Array.isArray(rows) && rows.length <= 2000);
    for (const row of rows) { assert.deepEqual(Object.keys(row).sort(), ["identity", "sha256"]); assert.match(row.identity || "", /^.{1,4096}$/s); assert.match(row.sha256 || "", /^[a-f0-9]{64}$/); }
  }
  if (securityTransportExpected) { assert.deepEqual(Object.keys(body.securityTransport || {}).sort(), ["count","transportSha256"]); assert.ok(Number.isInteger(body.securityTransport.count) && body.securityTransport.count > 0 && body.securityTransport.count <= 64); assert.match(body.securityTransport.transportSha256 || "", /^[a-f0-9]{64}$/); }
  return result;
}

const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
export function authenticateCanonicalProductionRequirementsArtifact({ sourceSha, candidateSourceSha, requirementsReference, repositoryRoot = root, githubRun = createProductionGithubCommandRunner() }) {
  assert.equal(requirementsReference.sourceSha, sourceSha, "Canonical requirements source does not match protected source");
  const branch = parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
  assert.equal(branch.commit?.sha, sourceSha, "Canonical requirements source is not current protected main");
  const artifact = downloadAppOnlyArtifact({ kind: "requirements", reference: requirementsReference, repositoryRoot, githubRun });
  const parsed = JSON.parse(artifact.bytes);
  assert.match(parsed.candidateSourceSha || "", /^[a-f0-9]{40}$/, "Canonical requirements candidate source is invalid");
  assertAppOnlyCandidateAncestor({ sourceSha, candidateSourceSha: parsed.candidateSourceSha, repositoryRoot });
  if (candidateSourceSha !== undefined) assert.equal(parsed.candidateSourceSha, candidateSourceSha, "Canonical requirements candidate does not match the requested candidate");
  const requirements = assertAppOnlyRequirements(parsed, { sourceSha, candidateSourceSha: parsed.candidateSourceSha, repositoryRoot });
  assert.equal(artifact.sha256, requirementsReference.fileSha256);
  return Object.freeze({ requirements, provenance: Object.freeze({ runId: String(artifact.run.id), runAttempt: String(artifact.run.run_attempt), artifactId: String(artifact.artifact.id), artifactDigest: artifact.artifact.digest, fileSha256: artifact.sha256 }) });
}

export function authenticateCanonicalProductionRequirements(options) {
  const authenticated = authenticateCanonicalProductionRequirementsArtifact(options);
  assert.equal(authenticated.requirements.candidateSourceSha, options.sourceSha, "Canonical requirements candidate does not match protected source");
  return authenticated;
}

export function authenticateCanonicalSecurityRebaselineArtifact({ sourceSha, candidateSourceSha, reference, requirementsSha256, repositoryRoot = root, githubRun = createProductionGithubCommandRunner() }) {
  assert.equal(reference.sourceSha, sourceSha); const branch = parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"])); assert.equal(branch.commit?.sha, sourceSha);
  const artifact = downloadAppOnlyArtifact({ kind: "securityRebaselineCanonical", reference, repositoryRoot, githubRun });
  const inventory = assertSecurityRebaselineInventory(JSON.parse(artifact.bytes), { protectedMainSha: sourceSha, candidateSourceSha });
  assert.equal(inventory.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY"); assert.equal(inventory.appOnlyRequirementsSha256, requirementsSha256); assert.equal(artifact.sha256, reference.fileSha256);
  return Object.freeze({ inventory, bytes: artifact.bytes, provenance: Object.freeze({ runId: String(artifact.run.id), runAttempt: String(artifact.run.run_attempt), artifactId: String(artifact.artifact.id), artifactDigest: artifact.artifact.digest, fileSha256: artifact.sha256 }) });
}

export function assertSemanticallyEmptyRlsProbeOverrides(overrides, expectedContainerName) {
  assert.deepEqual(Object.keys(overrides || {}).sort(), ["containerOverrides", "inferenceAcceleratorOverrides"].sort());
  assert.deepEqual(overrides.inferenceAcceleratorOverrides, []); assert.deepEqual(overrides.containerOverrides, [{ name: expectedContainerName }]); return true;
}

export function collectCompleteRlsProbeLogEvents(pages, { maxPages = 100 } = {}) {
  assert.ok(Array.isArray(pages) && pages.length > 0 && pages.length <= maxPages, "Incomplete RLS probe log pagination"); const events = []; let expectedToken;
  for (let index = 0; index < pages.length; index++) { const page = pages[index]; assert.ok(page && Array.isArray(page.events) && page.events.length <= 10000); if (index > 0) assert.equal(page.requestToken, expectedToken); events.push(...page.events); expectedToken = page.nextForwardToken; assert.ok(expectedToken === undefined || typeof expectedToken === "string"); }
  assert.equal(pages.at(-1).nextForwardToken, pages.at(-1).requestToken, "Incomplete RLS probe log pagination"); assert.ok(events.length <= 66, "Unbounded RLS probe output");
  return events.map(({ message }) => { assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 256 * 1024); return message; });
}

export function authenticateCompleteRlsProbeObservation(messages, { sourceSha, candidateSourceSha, requirementsSha256, securityMode }) {
  assert.ok(Array.isArray(messages)); const parsed = messages.map((message) => { try { return { message, value: JSON.parse(message) }; } catch { return { message, value: null }; } });
  const terminals = parsed.filter(({ value }) => value?.kind === "PRODUCTION_RLS_CATALOGUE_PROBE"); if (terminals.length === 0) return null; assert.equal(terminals.length, 1, "Ambiguous RLS probe terminal evidence");
  const evidence = authenticateProductionRlsProbeResult(terminals[0].message, { sourceSha, candidateSourceSha, requirementsSha256, securityTransportExpected: securityMode });
  if (!securityMode) return Object.freeze({ evidence, chunks: Object.freeze([]) });
  const chunks = parsed.filter(({ value }) => value?.kind === "PRODUCTION_SECURITY_CATALOGUE_CHUNK"); assert.ok(chunks.length <= evidence.securityTransport.count, "Duplicate or excess security catalogue chunks"); const indexes = new Set();
  for (const { value } of chunks) { assert.deepEqual(Object.keys(value).sort(), ["count","data","index","kind","schemaVersion","transportSha256"].sort()); assert.equal(value.schemaVersion, 1); assert.equal(value.count, evidence.securityTransport.count); assert.equal(value.transportSha256, evidence.securityTransport.transportSha256); assert.ok(Number.isInteger(value.index) && value.index >= 0 && value.index < value.count); assert.ok(!indexes.has(value.index), "Duplicate security catalogue chunk"); indexes.add(value.index); }
  if (chunks.length < evidence.securityTransport.count) return null; assert.deepEqual([...indexes].sort((a, b) => a - b), Array.from({ length: evidence.securityTransport.count }, (_, index) => index));
  return Object.freeze({ evidence, chunks: Object.freeze(chunks.map(({ message }) => message)) });
}

export async function waitForCompleteRlsProbeObservation(readMessages, binding, { attempts = 12, wait = sleep } = {}) {
  assert.equal(typeof readMessages, "function"); assert.ok(Number.isInteger(attempts) && attempts > 0 && attempts <= 12);
  for (let attempt = 0; attempt < attempts; attempt++) {
    const observation = authenticateCompleteRlsProbeObservation(await readMessages(), binding);
    if (observation) return observation;
    if (attempt + 1 < attempts) await wait(5000);
  }
  return null;
}

export async function runProductionRlsCatalogueProbe({ sourceSha, requirementsReference, awsProfile, securityRebaselineReference = null,
  candidateSourceSha, securityRebaselineCanonicalOut = null, securityRebaselineLiveOut = null, run = (command, args, options) => execFileSync(command, args, options), githubRun = createProductionGithubCommandRunner(), wait = sleep, repositoryRoot = root, env = process.env }) {
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  assert.match(candidateSourceSha || "", /^[a-f0-9]{40}$/, "Explicit candidate source SHA is required");
  const { requirements } = authenticateCanonicalProductionRequirementsArtifact({ sourceSha, candidateSourceSha, requirementsReference, repositoryRoot, githubRun });
  const securityMode = [securityRebaselineReference, securityRebaselineCanonicalOut, securityRebaselineLiveOut].some(Boolean);
  assert.equal([securityRebaselineReference, securityRebaselineCanonicalOut, securityRebaselineLiveOut].every(Boolean), securityMode, "Security inventory arguments are all-or-none");
  if (securityMode) { assert.notEqual(path.resolve(securityRebaselineCanonicalOut), path.resolve(securityRebaselineLiveOut)); assert.equal(fs.existsSync(securityRebaselineLiveOut), false, "Live security inventory destination already exists"); }
  const canonicalSecurity = securityMode ? authenticateCanonicalSecurityRebaselineArtifact({ sourceSha, candidateSourceSha: requirements.candidateSourceSha, reference: securityRebaselineReference, requirementsSha256: requirements.requirementsSha256, repositoryRoot, githubRun }) : null;
  if (securityMode) writeStageBPrivateFileExclusive({ filePath: securityRebaselineCanonicalOut, bytes: canonicalSecurity.bytes, repositoryRoot });
  const transportKeys = securityMode ? createSecurityCatalogueTransportKeyPair() : null;
  const commandEnvironment = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: awsProfile, env });
  const awsExecutable = productionAwsExecutable();
  const aws = (args) => parse(run(awsExecutable, [...args, "--output", "json", "--no-cli-pager"], { env: commandEnvironment, encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }));
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
  const identity = { sourceSha, candidateSourceSha: requirements.candidateSourceSha, account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: service.taskDefinition, predecessorBackendDigest: predecessorDigest, candidateDigest: digest, verifierImageDigest: digest, databaseHostname };
  const definition = buildProductionRlsProbeDefinition({ baseDefinition: verifier.taskDefinition, requirements, identity, databaseSecretArn, securityTransportPublicKey: transportKeys?.publicKeyPem });
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
  assert.equal(task?.lastStatus, "STOPPED", "RLS probe completion timeout; do not relaunch automatically"); assert.equal(task.taskArn, taskArn); assert.equal(task.clusterArn, APP_ONLY.clusterArn); assert.equal(task.taskDefinitionArn, taskDefinitionArn); assert.equal(task.launchType, "FARGATE"); assert.equal(task.enableExecuteCommand, false); assert.equal(task.containers?.length, 1); assert.equal(task.containers[0].name, "production-green-read-only-rls-canary"); assertSemanticallyEmptyRlsProbeOverrides(task.overrides, "production-green-read-only-rls-canary");
  const stream = `prebaseline-rls/production-green-read-only-rls-canary/${taskArn.split("/").at(-1)}`;
  const observation = await waitForCompleteRlsProbeObservation(() => { const pages = []; let requestToken; for (let page = 0; page < 100; page++) { const args = ["logs", "get-log-events", "--region", APP_ONLY.region, "--log-group-name", APP_ONLY_VERIFIER.logGroup, "--log-stream-name", stream, "--start-from-head", "--limit", "10000"]; if (requestToken) args.push("--next-token", requestToken); const response = aws(args); pages.push({ ...response, requestToken }); if (response.nextForwardToken === requestToken) break; requestToken = response.nextForwardToken; } return collectCompleteRlsProbeLogEvents(pages); }, { sourceSha, candidateSourceSha: requirements.candidateSourceSha, requirementsSha256: requirements.requirementsSha256, securityMode }, { attempts: 12, wait });
  assert.ok(observation, "RLS probe evidence incomplete; do not relaunch automatically"); const { evidence } = observation;
  assert.equal(task.containers[0].exitCode, 0, "RLS probe task failed"); const result = classifyProductionRlsCatalogue(evidence.catalogue, requirements);
  if (securityMode) { const binding = { sourceSha, candidateSourceSha: requirements.candidateSourceSha, requirementsSha256: requirements.requirementsSha256 }; const catalogue = decryptSecurityCatalogueTransport(observation.chunks, transportKeys.privateKeyPem, binding); const liveInventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, candidateSourceSha: requirements.candidateSourceSha, catalogue, canonical: canonicalSecurity.inventory,
      taskEvidence: { taskArn, taskDefinitionArn, containerName: task.containers[0].name, containerExitCode: task.containers[0].exitCode, requestSha256: canonicalSha256(request), verificationContractSha256: canonicalSha256(definition) } });
    writeStageBPrivateFileExclusive({ filePath: securityRebaselineLiveOut, bytes: Buffer.from(`${JSON.stringify(liveInventory)}\n`), repositoryRoot });
    return { status: "PRODUCTION_SECURITY_REBASELINE_INVENTORIED", sourceSha, candidateSourceSha: requirements.candidateSourceSha, taskDefinitionArn, taskArn, classification: result.classification, deltaObjectCount: result.deltaObjects.length, requirementsSha256: requirements.requirementsSha256, inventory: securityRebaselineLogSummary(liveInventory) }; }
  return { status: "PRODUCTION_RLS_CATALOGUE_PROBED", sourceSha, candidateSourceSha: requirements.candidateSourceSha, taskDefinitionArn, taskArn, classification: result.classification, deltaObjects: result.deltaObjects, requirementsSha256: requirements.requirementsSha256 };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "source-sha": { type: "string" }, "candidate-source-sha": { type: "string" }, "requirements-reference": { type: "string" }, "aws-profile": { type: "string" }, "security-rebaseline-reference": { type: "string" }, "security-rebaseline-canonical-out": { type: "string" }, "security-rebaseline-live-out": { type: "string" } }, strict: true });
    assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.match(values["candidate-source-sha"] || "", /^[a-f0-9]{40}$/); assert.ok(values["aws-profile"]);
    const requirementsReference = parseAppOnlyArtifactReference(values["requirements-reference"]);
    const securityRebaselineReference = values["security-rebaseline-reference"] ? parseAppOnlyArtifactReference(values["security-rebaseline-reference"]) : null;
    const result = await runProductionRlsCatalogueProbe({ sourceSha: values["source-sha"], candidateSourceSha: values["candidate-source-sha"], requirementsReference, awsProfile: values["aws-profile"], securityRebaselineReference, securityRebaselineCanonicalOut: values["security-rebaseline-canonical-out"], securityRebaselineLiveOut: values["security-rebaseline-live-out"] });
    process.stdout.write(`${JSON.stringify(result)}\n`); if (result.classification === RLS_PROBE_CLASSIFICATIONS.UNEXPECTED) process.exitCode = 2;
  } catch { process.stderr.write("Production RLS catalogue probe failed closed; no database mutation was attempted.\n"); process.exitCode = 1; }
}
