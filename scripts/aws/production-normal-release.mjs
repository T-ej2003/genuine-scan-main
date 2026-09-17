#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { classifyProductionChanges, classifyProductionComponentRanges, assertNormalApplicationRelease } from "./production-deployment-classification.mjs";
import { APP_ONLY, captureAppOnlyPredecessor, assertRegisteredAppOnlyCandidate } from "./production-app-only-contract.mjs";
import { createAppOnlyEcsReaders, createAppOnlyActivationAdapters } from "./production-app-only-adapters.mjs";
import { executeAppOnlyActivation, rollbackAppOnlyActivation } from "./production-app-only-activation.mjs";
import { createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { buildNormalFrontendCandidate, captureFrontendPredecessor, assertFrontendCandidateReadback, assertFrontendPredecessorCas, buildFrontendUpdate, buildFrontendRollback, rollbackFrontendCandidate, WEB_RELEASE } from "./production-web-release-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProductionBackendReadiness } from "./production-backend-readiness-contract.mjs";
import { CANONICAL_PRODUCTION_ORIGIN, CANONICAL_PRODUCTION_READINESS_URL } from "./production-backend-readiness-contract.mjs";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, stateHash } from "./production-component-deployment-state.mjs";
import { NORMAL_RECEIPT_WORKFLOW, normalReceiptHash, sameNormalIdentity } from "./production-normal-receipt-contract.mjs";
import { replaceNormalDeploymentReceipt, reconcileNormalDeployment } from "./production-normal-reconciliation.mjs";
export { classifyNormalLiveComponentState } from "./production-normal-receipt-contract.mjs";

export const NORMAL_RELEASE = Object.freeze({
  account: "368992683803", region: "eu-west-2", cluster: "mscqr-prod-euw2-main",
  backendService: "mscqr-backend-servi-euw2", frontendService: "mscqr-frontend-servi-euw2",
  role: "mscqr-production-normal-deployer",
});
const SHA = /^[a-f0-9]{40}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/(mscqr-backend|mscqr-web)@sha256:[a-f0-9]{64}$/;
const taskArn = (family) => new RegExp(`^arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:task-definition/${family}:[1-9][0-9]*$`);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function runNormalSmoke(repositoryRoot) {
  const result = spawnSync(process.execPath, [path.join(repositoryRoot, "scripts/smoke-release.mjs")], { stdio: "inherit", env: process.env });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, "Authenticated application smoke failed.");
}

export function buildNormalReleasePlan({ sourceSha, changedFiles, componentFiles, images = {} } = {}) {
  assert.match(sourceSha || "", SHA);
  const classification = assertNormalApplicationRelease(componentFiles
    ? classifyProductionComponentRanges(componentFiles)
    : classifyProductionChanges(changedFiles));
  for (const [name, required] of Object.entries({ backend: classification.backend, frontend: classification.frontend })) {
    if (required) assert.match(images[name] || "", IMAGE, `Missing immutable ${name} image`);
    if (!required && images[name] !== undefined) throw new Error(`Unneeded ${name} image was supplied.`);
  }
  if (classification.worker) throw new Error("Production has no worker service; worker-impacting changes require the reviewed infrastructure lane.");
  return Object.freeze({ schemaVersion: 1, kind: "NORMAL_APPLICATION_RELEASE", sourceSha, classification, images,
    ...(componentFiles ? { componentFiles: structuredClone(componentFiles) } : {}),
    imageReleaseSha: sourceSha, planSha256: sha256(JSON.stringify({ sourceSha, classification, images, ...(componentFiles ? { componentFiles } : {}) })) });
}

export function assertNormalReleasePlan(plan, sourceSha) {
  assert.equal(plan?.schemaVersion, 1); assert.equal(plan.kind, "NORMAL_APPLICATION_RELEASE"); assert.equal(plan.sourceSha, sourceSha, "Normal release plan source identity mismatch");
  assert.equal(plan.imageReleaseSha, sourceSha); assert.equal(plan.planSha256, sha256(JSON.stringify({ sourceSha, classification: plan.classification, images: plan.images, ...(plan.componentFiles ? { componentFiles: plan.componentFiles } : {}) })));
  const derived = plan.componentFiles ? classifyProductionComponentRanges(plan.componentFiles) : classifyProductionChanges(plan.classification?.files);
  assert.deepEqual(derived, plan.classification, "Normal release classification is not derived from its protected source paths.");
  assertNormalApplicationRelease(derived);
  for (const name of ["backend", "frontend"]) if (plan.classification[name]) assert.match(plan.images?.[name] || "", IMAGE);
  return true;
}

export function buildNormalBackendPreparation({ sourceSha, predecessorSourceSha, live, candidateDigest } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(predecessorSourceSha || "", SHA); assert.match(candidateDigest || "", /^sha256:[a-f0-9]{64}$/);
  const predecessor = captureAppOnlyPredecessor(live);
  const body = { schemaVersion: 1, kind: "NORMAL_APPLICATION_BACKEND_PREPARATION", candidateSourceSha: sourceSha,
    predecessorSourceSha, candidateDigest, predecessor };
  return Object.freeze({ ...body, preparationSha256: sha256(JSON.stringify(body)) });
}

export async function executeNormalFrontendActivation({ sourceSha, imageRef, adapters, recordCandidate = async () => {} } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/);
  for (const name of ["readService", "describeTaskDefinition", "registerTaskDefinition", "updateService", "waitStable", "verifyHealth"]) assert.equal(typeof adapters?.[name], "function", `Missing frontend adapter: ${name}`);
  const initialService = await adapters.readService();
  const initialDefinition = await adapters.describeTaskDefinition(initialService.taskDefinition);
  const predecessor = captureFrontendPredecessor(initialService, initialDefinition);
  const candidate = buildNormalFrontendCandidate({ predecessor, imageRef });
  const registered = await adapters.registerTaskDefinition(candidate);
  const candidateArn = registered?.taskDefinition?.taskDefinitionArn || registered?.taskDefinitionArn;
  assert.match(candidateArn || "", taskArn(WEB_RELEASE.family));
  const readback = await adapters.describeTaskDefinition(candidateArn);
  assertFrontendCandidateReadback({ definition: readback, taskDefinitionArn: candidateArn, candidate });
  await recordCandidate(candidateArn);
  const casService = await adapters.readService();
  const casDefinition = await adapters.describeTaskDefinition(casService.taskDefinition);
  assertFrontendPredecessorCas({ predecessor, currentService: casService, currentTaskDefinition: casDefinition });
  let updateAttempted = false;
  try {
    updateAttempted = true; await adapters.updateService(buildFrontendUpdate({ predecessor, candidateTaskDefinitionArn: candidateArn }));
    await adapters.waitStable({ expectedTaskDefinitionArn: candidateArn });
    const health = await adapters.verifyHealth({ expectedTaskDefinitionArn: candidateArn, expectedImageRef: imageRef });
    assert.equal(health?.ready, true, "Frontend health failed"); assert.equal(health?.loginStatus, 200, "Frontend login health failed");
    return Object.freeze({ sourceSha, predecessorTaskDefinitionArn: predecessor.taskDefinitionArn, predecessorDesiredCount: predecessor.desiredCount, candidateTaskDefinitionArn: candidateArn, imageRef, rollbackCount: 0, health });
  } catch (error) {
    let rollback = { attempted: false, verified: false };
    if (updateAttempted) {
      try {
        const current = await adapters.readService();
        if (current.taskDefinition === candidateArn) {
          rollback = { attempted: true, verified: false };
          await rollbackFrontendCandidate({ predecessor, candidateTaskDefinitionArn: candidateArn, ...adapters });
          rollback.verified = true;
        }
      } catch (rollbackError) {
        rollback.error = rollbackError.message.slice(0, 512);
        throw Object.assign(new Error(`Frontend rollback failed after: ${error.message}`, { cause: rollbackError }), { frontendRollback: rollback });
      }
    }
    throw Object.assign(error, { frontendRollback: rollback });
  }
}

const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
export function createNormalFrontendAdapters({ run, fetchImpl = fetch, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  const serviceArn = `arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:service/${NORMAL_RELEASE.cluster}/${NORMAL_RELEASE.frontendService}`;
  const clusterArn = `arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:cluster/${NORMAL_RELEASE.cluster}`;
  const readService = () => {
    const response = json(run, ["ecs", "describe-services", "--cluster", clusterArn, "--services", serviceArn]);
    assert.equal(response.failures?.length, 0); assert.equal(response.services?.length, 1);
    const service = response.services[0]; assert.equal(service.serviceArn, serviceArn); assert.equal(service.clusterArn, clusterArn); return service;
  };
  const describeTaskDefinition = (arn) => {
    assert.match(arn || "", taskArn(WEB_RELEASE.family));
    const response = json(run, ["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
    assert.equal(response.taskDefinition?.taskDefinitionArn, arn); return { ...response.taskDefinition, tags: response.tags || [] };
  };
  const registerTaskDefinition = (definition) => {
    assert.equal(definition.family, WEB_RELEASE.family);
    return json(run, ["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(definition)]);
  };
  const updateService = ({ cluster, service, taskDefinition }) => {
    assert.equal(cluster, NORMAL_RELEASE.cluster); assert.equal(service, NORMAL_RELEASE.frontendService); assert.match(taskDefinition || "", taskArn(WEB_RELEASE.family));
    return json(run, ["ecs", "update-service", "--cluster", clusterArn, "--service", serviceArn, "--task-definition", taskDefinition]).service;
  };
  const waitStable = async ({ expectedTaskDefinitionArn }) => {
    assert.match(expectedTaskDefinitionArn || "", taskArn(WEB_RELEASE.family));
    run(["ecs", "wait", "services-stable", "--cluster", clusterArn, "--services", serviceArn]);
    const service = readService(); assert.equal(service.taskDefinition, expectedTaskDefinitionArn); assert.equal(service.desiredCount, service.runningCount); assert.equal(service.pendingCount, 0); return service;
  };
  const verifyHealth = async () => {
    const login = await fetchImpl(`${CANONICAL_PRODUCTION_ORIGIN}/login`, { redirect: "error" });
    const readyResponse = await fetchImpl(CANONICAL_PRODUCTION_READINESS_URL, { redirect: "error" });
    assert.equal(login.status, 200); const body = await readyResponse.json(); assertProductionBackendReadiness(body);
    return { ready: true, loginStatus: login.status };
  };
  return { readService, describeTaskDefinition, registerTaskDefinition, updateService, waitStable, verifyHealth };
}

function assertCaller(caller, role) {
  assert.equal(String(caller?.Account), NORMAL_RELEASE.account);
  assert.match(caller?.Arn || "", new RegExp(`^arn:aws:sts::${NORMAL_RELEASE.account}:assumed-role/${role}/[^/]+$`));
}

const sameComponentIdentity = sameNormalIdentity;

export const assertNormalBackendExactCandidate = (predecessorDefinition, candidateDefinition, candidateDigest) => assertRegisteredAppOnlyCandidate(predecessorDefinition, candidateDefinition, candidateDigest);

async function executeBackendCli({ sourceSha, imageRef, expectedState, run, repositoryRoot, recordCandidate }) {
  assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/);
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role);
  const readers = createAppOnlyEcsReaders(run), live = readers.readLive();
  const digest = imageRef.split("@")[1];
  const predecessor = captureAppOnlyPredecessor(live);
  const liveIdentity = { sourceSha: readers.readBackendImageSource(predecessor.backendDigest), imageDigest: predecessor.backendDigest, taskDefinitionArn: predecessor.taskDefinitionArn, desiredCount: predecessor.desiredCount };
  if (expectedState && !sameComponentIdentity(liveIdentity, expectedState)) {
    throw new Error("LIVE_IS_UNKNOWN: backend must reconcile its durable receipt before activation.");
  }
  const preparation = buildNormalBackendPreparation({ sourceSha, predecessorSourceSha: readers.readBackendImageSource(predecessor.backendDigest), live, candidateDigest: digest });
  const authenticate = async () => { assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role); };
  const journalDirectory = process.env.MSCQR_APP_ONLY_JOURNAL_DIR ? path.join(process.env.MSCQR_APP_ONLY_JOURNAL_DIR, "backend") : undefined;
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: preparation.preparationSha256, directory: journalDirectory });
  const adapters = createAppOnlyActivationAdapters({ run, preparation, authenticate, writeEvidence: async (entry) => {
    journal.writeEvidence(entry);
    if (entry.status === "CANDIDATE_REGISTERED") await recordCandidate(entry.candidateTaskDefinition);
  } });
  const result = await executeAppOnlyActivation(preparation, adapters);
  return Object.freeze({ result, predecessor: preparation.predecessor, rollback: () => rollbackAppOnlyActivation({ preparation, candidateArn: result.candidateTaskDefinition, candidateDeploymentId: result.candidateDeploymentId, adapters }) });
}

async function executeFrontendCli({ sourceSha, imageRef, expectedState, run, recordCandidate }) {
  assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/);
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role);
  const repo = json(run, ["ecr", "describe-repositories", "--repository-names", WEB_RELEASE.repository]).repositories?.[0];
  assert.equal(repo?.repositoryName, WEB_RELEASE.repository); assert.equal(String(repo.registryId), NORMAL_RELEASE.account); assert.equal(repo.imageTagMutability, "IMMUTABLE");
  const digest = imageRef.split("@")[1]; const image = json(run, ["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageDigest=${digest}`]).imageDetails;
  assert.equal(image?.length, 1); assert.equal(image[0].imageDigest, digest); assert.ok(image[0].imageTags?.includes(sourceSha));
  const adapters = createNormalFrontendAdapters({ run });
  const liveService = await adapters.readService(); const liveDefinition = await adapters.describeTaskDefinition(liveService.taskDefinition); const livePredecessor = captureFrontendPredecessor(liveService, liveDefinition); const liveDigest = livePredecessor.imageRef.split("@")[1];
  const liveImage = json(run, ["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageDigest=${liveDigest}`]).imageDetails;
  assert.equal(liveImage?.length, 1); const liveSources = (liveImage[0].imageTags || []).filter((tag) => SHA.test(tag)); assert.equal(liveSources.length, 1, "Frontend live source identity is ambiguous");
  const liveIdentity = { sourceSha: liveSources[0], imageDigest: liveDigest, taskDefinitionArn: livePredecessor.taskDefinitionArn, desiredCount: livePredecessor.desiredCount };
  if (expectedState && !sameComponentIdentity(liveIdentity, expectedState)) {
    throw new Error("LIVE_IS_UNKNOWN: frontend must reconcile its durable receipt before activation.");
  }
  const result = await executeNormalFrontendActivation({ sourceSha, imageRef, adapters, recordCandidate });
  const predecessor = { taskDefinitionArn: result.predecessorTaskDefinitionArn, desiredCount: result.predecessorDesiredCount };
  return Object.freeze({ result, predecessor, rollback: () => rollbackFrontendCandidate({ predecessor, candidateTaskDefinitionArn: result.candidateTaskDefinitionArn, ...adapters }) });
}

export async function executeNormalRelease({ plan, sourceSha, backend, frontend, database = {}, smoke = async () => true, writeJournal = async () => {} } = {}) {
  assert.match(sourceSha || "", SHA, "Normal release source identity is required");
  assertNormalReleasePlan(plan, sourceSha);
  if (plan.classification.database) await database.applyAndVerify();
  const result = { sourceSha: plan.sourceSha, database: plan.classification.database ? "APPLIED" : "UNCHANGED", backend: "UNCHANGED", frontend: "UNCHANGED" };
  try {
    await writeJournal({ status: "PRE_MUTATION", affectedComponents: Object.keys(plan.images).sort() });
    if (plan.classification.backend) { await writeJournal({ status: "BACKEND_ACTIVATION_INTENT" }); result.backend = await backend.deploy(plan.images.backend); await writeJournal({ status: "BACKEND_HEALTHY", taskDefinitionArn: (result.backend?.result || result.backend).candidateTaskDefinition }); }
    if (plan.classification.frontend) { await writeJournal({ status: "FRONTEND_ACTIVATION_INTENT" }); result.frontend = await frontend.deploy(plan.images.frontend); await writeJournal({ status: "FRONTEND_HEALTHY", taskDefinitionArn: (result.frontend?.result || result.frontend).candidateTaskDefinitionArn }); }
    await smoke({ sourceSha: plan.sourceSha, result });
    await writeJournal({ status: "WHOLE_RELEASE_SMOKE_HEALTHY" });
  }
  catch (error) {
    const rollbackErrors = [];
    const record = async (entry) => {
      try { await writeJournal(entry); }
      catch (journalError) { rollbackErrors.push({ component: "JOURNAL", error: journalError.message.slice(0, 512) }); }
    };
    await record({ status: "FAILURE", error: error.message.slice(0, 512) });
    if (error.frontendRollback?.attempted) await record({ status: error.frontendRollback.verified ? "FRONTEND_ROLLED_BACK" : "FRONTEND_ROLLBACK_UNVERIFIED" });
    const rollback = async (component, value, operation) => {
      await record({ status: `${component}_ROLLBACK_INTENT` });
      try { await operation(value); }
      catch (rollbackError) { rollbackErrors.push({ component, error: rollbackError.message.slice(0, 512) }); await record({ status: `${component}_ROLLBACK_FAILED`, error: rollbackError.message.slice(0, 512) }); return; }
      await record({ status: `${component}_ROLLED_BACK` });
    };
    if (plan.classification.frontend && result.frontend !== "UNCHANGED") await rollback("FRONTEND", result.frontend, frontend.rollback);
    if (plan.classification.backend && result.backend !== "UNCHANGED") await rollback("BACKEND", result.backend, backend.rollback);
    if (rollbackErrors.length) throw Object.assign(new Error(`Normal release rollback failed after: ${error.message}`, { cause: error }), { rollbackErrors });
    throw error;
  }
  return Object.freeze(result);
}

export async function executeNormalComponentTransaction({ plan, sourceSha, state, stateClient, backend, frontend, smoke = async () => true, verifyCandidates, isAncestor, writeJournal = async () => {}, writerContext = {} } = {}) {
  assertNormalReleasePlan(plan, sourceSha); assert.ok(state); assert.equal(typeof stateClient?.advance, "function");
  const names = ["backend", "frontend"].filter((name) => plan.classification[name]);
  let receipt;
  if (names.length) {
    assert.equal(typeof verifyCandidates, "function");
    assert.equal(typeof isAncestor, "function");
    assert.equal(state.normalDeploymentReceipt, undefined, "Reconcile the previous normal release before preparing another");
    receipt = { schemaVersion: 1, kind: "NORMAL_DEPLOYMENT_RECEIPT", workflow: writerContext.updatedByWorkflow,
      githubRunId: String(writerContext.githubRunId), sourceSha, planSha256: plan.planSha256, phase: "PREPARED",
      predecessors: Object.fromEntries(names.map((name) => [name, state.components[name]])), images: plan.images, candidates: {} };
    await verifyCandidates(receipt.predecessors);
    for (const previous of Object.values(receipt.predecessors)) assert.equal(isAncestor(previous.establishedThroughSha, sourceSha), true);
    state = replaceNormalDeploymentReceipt({ client: stateClient, expected: undefined, receipt, writerContext });
  }
  const wrap = (name, adapter) => ({ ...adapter, deploy: (image) => adapter.deploy(image, {
    recordCandidate: async (taskDefinitionArn) => {
      assert.equal(receipt.candidates[name], undefined, "Candidate identity is immutable within a release");
      const next = { ...receipt, candidates: { ...receipt.candidates, [name]: { sourceSha, establishedThroughSha: sourceSha,
        imageDigest: plan.images[name].split("@")[1], taskDefinitionArn, desiredCount: receipt.predecessors[name].desiredCount } } };
      state = replaceNormalDeploymentReceipt({ client: stateClient, expected: receipt, receipt: next, writerContext });
      receipt = next;
    },
  }) });
  const result = await executeNormalRelease({ plan, sourceSha,
    backend: plan.classification.backend ? wrap("backend", backend) : {}, frontend: plan.classification.frontend ? wrap("frontend", frontend) : {},
    smoke: async (value) => { await smoke(value); if (names.length) await verifyCandidates(receipt.candidates); }, writeJournal });
  const changes = {};
  if (plan.classification.backend) {
    const activation = result.backend?.result || result.backend;
    changes.backend = { sourceSha, establishedThroughSha: sourceSha, imageDigest: activation.deployedBackendDigest, taskDefinitionArn: activation.candidateTaskDefinition, desiredCount: state.components.backend.desiredCount };
  }
  if (plan.classification.frontend) {
    const activation = result.frontend?.result || result.frontend;
    changes.frontend = { sourceSha, establishedThroughSha: sourceSha, imageDigest: activation.imageRef?.split("@")[1], taskDefinitionArn: activation.candidateTaskDefinitionArn, desiredCount: state.components.frontend.desiredCount };
  }
  if (Object.keys(changes).length) {
    assert.deepEqual(changes, receipt.candidates, "Activation did not bind all registered candidates before mutation");
    const verified = { ...receipt, phase: "VERIFIED", verification: "STABILITY_READINESS_AUTHENTICATED_SMOKE_PASSED" };
    state = replaceNormalDeploymentReceipt({ client: stateClient, expected: receipt, receipt: verified, writerContext });
    // A persisted verified receipt survives both runner loss and main advancing.
    // Its removal and the complete component transition are one DynamoDB CAS.
    await writeJournal({ status: "STATE_CAS_INTENT", stateGeneration: state.generation, components: Object.keys(changes).sort() });
    const committed = advanceProductionComponentDeploymentStateWithRetry({ client: stateClient, current: state, lane: "NORMAL_APPLICATION", changes, normalReceiptSha256: normalReceiptHash(verified), isAncestor, ...writerContext });
    await writeJournal({ status: "STATE_COMMITTED", stateGeneration: committed.state.generation });
    return Object.freeze({ ...result, componentState: committed.state, stateCommitAttempts: committed.attempts });
  }
  return Object.freeze({ ...result, componentState: state, stateCommitAttempts: 0 });
}

// The CLI is intentionally fixed to the checked-out commit and workflow
// credential source. It accepts only image refs emitted by the preceding
// publisher jobs; resource names, roles, region, and account are constants.
export function parseNormalReleaseArgs(argv) {
  const values = Object.fromEntries(argv.map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  assert.deepEqual(Object.keys(values).sort(), ["backend-image", "changed-files", "frontend-image", "service", "source-sha"].filter((key) => values[key] !== undefined).sort());
  assert.match(values["source-sha"] || "", SHA); assert.equal(values["source-sha"], process.env.GITHUB_SHA); assert.ok(["backend", "frontend", "none"].includes(values.service));
  const files = JSON.parse(values["changed-files"]); assert.ok(Array.isArray(files));
  const plan = buildNormalReleasePlan({ sourceSha: values["source-sha"], changedFiles: files, images: Object.fromEntries(["backend", "frontend"].filter((name) => values[`${name}-image`] !== undefined).map((name) => [name, values[`${name}-image`]])) });
  if (values.service === "backend") assert.equal(plan.classification.backend, true, "Backend was selected for a non-backend release");
  if (values.service === "frontend") assert.equal(plan.classification.frontend, true, "Frontend was selected for a non-frontend release");
  if (values.service === "none") assert.equal(plan.classification.backend || plan.classification.frontend, false, "No-op was selected for an affected release");
  return plan;
}

export function parseNormalComponentReleaseArgs(argv) {
  const values = Object.fromEntries(argv.map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  assert.deepEqual(Object.keys(values).sort(), ["backend-image", "frontend-image", "preparation-file", "source-sha"].filter((key) => values[key] !== undefined).sort());
  assert.match(values["source-sha"] || "", SHA); assert.equal(values["source-sha"], process.env.GITHUB_SHA);
  assert.ok(path.isAbsolute(values["preparation-file"] || ""));
  const bytes = fs.readFileSync(values["preparation-file"], "utf8"); assert.ok(Buffer.byteLength(bytes) <= 1024 * 1024);
  const preparation = JSON.parse(bytes); assert.equal(preparation?.kind, "NORMAL_COMPONENT_DEPLOYMENT_PREPARATION"); assert.equal(preparation.sourceSha, values["source-sha"]);
  const plan = buildNormalReleasePlan({ sourceSha: values["source-sha"], componentFiles: preparation.componentFiles,
    images: Object.fromEntries(["backend", "frontend"].filter((name) => values[`${name}-image`] !== undefined).map((name) => [name, values[`${name}-image`]])) });
  assert.deepEqual(plan.classification, preparation.classification, "Component deployment preparation classification changed.");
  return Object.freeze({ plan, preparation });
}

export function createNormalReconciliationAdapters({ run, repositoryRoot }) {
  const backend = createAppOnlyEcsReaders(run), frontend = createNormalFrontendAdapters({ run });
  const service = (name) => name === "backend" ? backend.readService() : frontend.readService();
  const definition = (name, arn) => name === "backend" ? backend.readDefinition(arn) : frontend.describeTaskDefinition(arn);
  const readLive = async (name) => {
    const observed = await service(name), task = await definition(name, observed.taskDefinition);
    const container = task.containerDefinitions?.find((entry) => entry.name === (name === "backend" ? APP_ONLY.container : WEB_RELEASE.container));
    const repository = name === "backend" ? "mscqr-backend" : WEB_RELEASE.repository;
    assert.match(container?.image || "", new RegExp(`^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/${repository}@sha256:[a-f0-9]{64}$`));
    const imageDigest = container.image.split("@")[1];
    const images = json(run, ["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${imageDigest}`]).imageDetails;
    assert.equal(images?.length, 1); assert.equal(images[0].imageDigest, imageDigest);
    assert.equal(images[0].repositoryName, repository); assert.equal(String(images[0].registryId), NORMAL_RELEASE.account);
    const sources = (images[0].imageTags || []).filter((value) => SHA.test(value)); assert.equal(sources.length, 1);
    return { sourceSha: sources[0], imageDigest, taskDefinitionArn: observed.taskDefinition, desiredCount: observed.desiredCount };
  };
  const authenticateCandidate = async (name, previous, candidate) => {
    const prior = await definition(name, previous.taskDefinitionArn), next = await definition(name, candidate.taskDefinitionArn);
    const imageRef = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${name === "backend" ? "mscqr-backend" : WEB_RELEASE.repository}@${candidate.imageDigest}`;
    if (name === "backend") {
      assert.equal(prior.containerDefinitions?.find((entry) => entry.name === APP_ONLY.container)?.image, `${APP_ONLY.backendRepository}@${previous.imageDigest}`);
      assertNormalBackendExactCandidate(prior, next, candidate.imageDigest);
    }
    else {
      const priorImage = prior.containerDefinitions?.find((entry) => entry.name === WEB_RELEASE.container)?.image;
      assert.equal(priorImage, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}@${previous.imageDigest}`);
      const expected = buildNormalFrontendCandidate({ predecessor: { taskDefinitionArn: previous.taskDefinitionArn, desiredCount: previous.desiredCount, imageRef: priorImage, taskDefinition: prior }, imageRef });
      assertFrontendCandidateReadback({ definition: next, taskDefinitionArn: candidate.taskDefinitionArn, candidate: expected });
    }
  };
  const verify = async (identities) => {
    for (const [name, expected] of Object.entries(identities)) {
      const serviceName = name === "backend" ? NORMAL_RELEASE.backendService : NORMAL_RELEASE.frontendService;
      run(["ecs", "wait", "services-stable", "--cluster", NORMAL_RELEASE.cluster, "--services", serviceName]);
      assert.ok(sameNormalIdentity(await readLive(name), expected), "Normal verification live identity changed");
      if (name === "backend") {
        captureAppOnlyPredecessor(backend.readLive());
        const response = await fetch(CANONICAL_PRODUCTION_READINESS_URL, { redirect: "error" });
        assert.equal(response.status, 200); assertProductionBackendReadiness(await response.json(), { expectedReleaseSha: expected.sourceSha });
      } else {
        const observed = await frontend.readService(); captureFrontendPredecessor(observed, await frontend.describeTaskDefinition(observed.taskDefinition));
        const listing = json(run, ["ecs", "list-tasks", "--cluster", NORMAL_RELEASE.cluster, "--service-name", NORMAL_RELEASE.frontendService, "--desired-status", "RUNNING"]);
        assert.equal(listing.nextToken, undefined); assert.equal(listing.taskArns?.length, expected.desiredCount);
        assert.equal(new Set(listing.taskArns).size, expected.desiredCount);
        for (const arn of listing.taskArns) assert.match(arn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
        const response = json(run, ["ecs", "describe-tasks", "--cluster", NORMAL_RELEASE.cluster, "--tasks", ...listing.taskArns]);
        assert.equal(response.failures?.length, 0); assert.equal(response.tasks?.length, expected.desiredCount);
        assert.deepEqual(response.tasks.map((task) => task.taskArn).sort(), [...listing.taskArns].sort());
        for (const task of response.tasks) {
          assert.equal(task.clusterArn, observed.clusterArn); assert.equal(task.group, `service:${NORMAL_RELEASE.frontendService}`);
          assert.equal(task.startedBy, observed.deployments[0].id);
          assert.equal(task.taskDefinitionArn, expected.taskDefinitionArn); assert.equal(task.lastStatus, "RUNNING");
          assert.notEqual(task.healthStatus, "UNHEALTHY");
          const container = task.containers?.find((entry) => entry.name === WEB_RELEASE.container);
          assert.equal(container?.imageDigest, expected.imageDigest); assert.equal(container.lastStatus, "RUNNING");
        }
        await frontend.verifyHealth();
      }
    }
    runNormalSmoke(repositoryRoot);
    for (const [name, expected] of Object.entries(identities)) assert.ok(sameNormalIdentity(await readLive(name), expected), "Normal live identity changed during smoke");
  };
  const rollback = async (name, previous, candidate) => {
    await authenticateCandidate(name, previous, candidate);
    assert.ok(sameNormalIdentity(await readLive(name), candidate), "Normal rollback lost exact candidate ownership");
    const serviceName = name === "backend" ? NORMAL_RELEASE.backendService : NORMAL_RELEASE.frontendService;
    json(run, ["ecs", "update-service", "--cluster", NORMAL_RELEASE.cluster, "--service", serviceName, "--task-definition", previous.taskDefinitionArn]);
    run(["ecs", "wait", "services-stable", "--cluster", NORMAL_RELEASE.cluster, "--services", serviceName]);
    assert.ok(sameNormalIdentity(await readLive(name), previous), "Normal rollback predecessor mismatch");
  };
  return { readLive, authenticateCandidate, verify, rollback };
}

async function main() {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  assertGithubOidcReleaseDeployerEnvironment();
  assert.equal(process.env.GITHUB_WORKFLOW_REF, NORMAL_RECEIPT_WORKFLOW);
  assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: NORMAL_RELEASE.region });
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role);
  for (const ref of ["HEAD", "refs/remotes/origin/main"]) {
    const result = spawnSync("git", ["rev-parse", ref], { cwd: repositoryRoot, encoding: "utf8" });
    assert.equal(result.status, 0); assert.equal(result.stdout.trim(), process.env.GITHUB_SHA);
  }
  const writerContext = { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID };
  const isAncestor = (ancestor, candidate) => spawnSync("git", ["merge-base", "--is-ancestor", ancestor, candidate], { cwd: repositoryRoot, stdio: "ignore" }).status === 0;
  const reconciliation = createNormalReconciliationAdapters({ run, repositoryRoot });
  if (process.argv.slice(2).length === 1 && process.argv[2] === "--reconcile") {
    const client = createProductionComponentDeploymentStateClient({ run });
    const initial = client.read(); assert.ok(initial, "Production component deployment state is not bootstrapped");
    const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha: process.env.GITHUB_SHA, preparationSha256: stateHash(initial) });
    const state = await reconcileNormalDeployment({ client, sourceSha: process.env.GITHUB_SHA, isAncestor, ...reconciliation, writerContext, writeJournal: journal.writeEvidence });
    journal.writeEvidence({ status: "RECONCILIATION_COMPLETE", stateGeneration: state.generation });
    process.stdout.write(`${JSON.stringify({ reconciledGeneration: state.generation })}\n`); return;
  }
  const { plan, preparation } = parseNormalComponentReleaseArgs(process.argv.slice(2));
  const stateClient = createProductionComponentDeploymentStateClient({ run }); const state = stateClient.read();
  assert.ok(state, "Production component deployment state is not bootstrapped."); assert.equal(state.generation, preparation.stateGeneration, "Component deployment state changed; reprepare release."); assert.equal(stateHash(state), preparation.stateSha256, "Component deployment state changed; reprepare release.");
  const journalDirectory = process.env.MSCQR_APP_ONLY_JOURNAL_DIR ? path.join(process.env.MSCQR_APP_ONLY_JOURNAL_DIR, "release") : undefined;
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha: plan.sourceSha, preparationSha256: sha256(JSON.stringify(preparation)), directory: journalDirectory });
  for (const [name, imageRef] of Object.entries(plan.images)) {
    const repository = name === "backend" ? "mscqr-backend" : WEB_RELEASE.repository, digest = imageRef.split("@")[1];
    const images = json(run, ["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${digest}`]).imageDetails;
    assert.equal(images?.length, 1); assert.equal(images[0].imageDigest, digest);
    assert.equal(images[0].repositoryName, repository); assert.equal(String(images[0].registryId), NORMAL_RELEASE.account);
    assert.deepEqual((images[0].imageTags || []).filter((tag) => SHA.test(tag)), [plan.sourceSha], "Published normal image source mismatch");
  }
  const component = (name, deploy) => ({ deploy: (image, { recordCandidate }) => deploy({ sourceSha: plan.sourceSha, imageRef: image, expectedState: state.components[name], run, repositoryRoot, recordCandidate }), rollback: (value) => value.rollback() });
  let result;
  try {
    result = await executeNormalComponentTransaction({ plan, sourceSha: plan.sourceSha, state, stateClient,
      backend: component("backend", executeBackendCli), frontend: component("frontend", executeFrontendCli), smoke: async () => { runNormalSmoke(repositoryRoot); }, writeJournal: journal.writeEvidence,
      verifyCandidates: reconciliation.verify, isAncestor, writerContext });
  } catch (error) {
    journal.writeEvidence({ status: "FINAL_FAILURE", error: error.message.slice(0, 512) }); throw error;
  }
  journal.writeEvidence({ status: "COMPLETE", stateGeneration: result.componentState.generation });
  process.stdout.write(`${JSON.stringify({ plan, result })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
