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

export async function executeNormalFrontendActivation({ sourceSha, imageRef, adapters } = {}) {
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

const sameComponentIdentity = (actual, expected) => actual?.sourceSha === expected?.sourceSha && actual?.imageDigest === expected?.imageDigest && actual?.taskDefinitionArn === expected?.taskDefinitionArn && actual?.desiredCount === expected?.desiredCount;

export const assertNormalBackendExactCandidate = (predecessorDefinition, candidateDefinition, candidateDigest) => assertRegisteredAppOnlyCandidate(predecessorDefinition, candidateDefinition, candidateDigest);

export function classifyNormalLiveComponentState({ live, predecessor, candidate } = {}) {
  if (sameComponentIdentity(live, predecessor)) return "LIVE_IS_PREDECESSOR";
  if (live?.sourceSha === candidate?.sourceSha && live?.imageDigest === candidate?.imageDigest && live?.desiredCount === predecessor?.desiredCount && live.taskDefinitionArn !== predecessor?.taskDefinitionArn) return "LIVE_IS_EXACT_CANDIDATE";
  return "LIVE_IS_UNKNOWN";
}

async function rollbackBackendToState({ state, sourceSha, run, repositoryRoot }) {
  const readers = createAppOnlyEcsReaders(run); const live = readers.readLive(); const observed = captureAppOnlyPredecessor(live);
  assert.equal(readers.readBackendImageSource(observed.backendDigest), sourceSha, "Backend rollback ownership is lost");
  assert.notEqual(observed.taskDefinitionArn, state.taskDefinitionArn, "Backend is already at its predecessor");
  const definition = readers.readDefinition(state.taskDefinitionArn); const target = captureAppOnlyPredecessor({ service: { ...live.service, taskDefinition: state.taskDefinitionArn, deployments: [{ ...live.service.deployments[0], taskDefinition: state.taskDefinitionArn }] }, definition, tasks: live.tasks.map((task) => ({ ...task, taskDefinitionArn: state.taskDefinitionArn, containers: task.containers.map((container) => container.name === APP_ONLY.container ? { ...container, imageDigest: state.imageDigest } : container) })) });
  assert.equal(target.backendDigest, state.imageDigest);
  json(run, ["ecs", "update-service", "--cluster", APP_ONLY.clusterArn, "--service", APP_ONLY.serviceArn, "--task-definition", state.taskDefinitionArn]);
  run(["ecs", "wait", "services-stable", "--cluster", APP_ONLY.clusterArn, "--services", APP_ONLY.serviceArn]);
  const restored = captureAppOnlyPredecessor(readers.readLive()); assert.equal(restored.taskDefinitionArn, state.taskDefinitionArn); assert.equal(restored.backendDigest, state.imageDigest); assert.equal(restored.desiredCount, state.desiredCount); assert.equal(readers.readBackendImageSource(restored.backendDigest), state.sourceSha);
  runNormalSmoke(repositoryRoot);
}

async function rollbackFrontendToState({ state, sourceSha, run, repositoryRoot }) {
  const adapters = createNormalFrontendAdapters({ run }); const service = await adapters.readService(); const definition = await adapters.describeTaskDefinition(service.taskDefinition); const current = captureFrontendPredecessor(service, definition);
  const currentDigest = current.imageRef.split("@")[1]; const response = json(run, ["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageDigest=${currentDigest}`]);
  assert.equal(response.imageDetails?.length, 1); assert.ok(response.imageDetails[0].imageTags?.includes(sourceSha), "Frontend rollback ownership is lost");
  assert.notEqual(current.taskDefinitionArn, state.taskDefinitionArn, "Frontend is already at its predecessor");
  const target = await adapters.describeTaskDefinition(state.taskDefinitionArn); const targetImage = target.containerDefinitions?.find(({ name }) => name === WEB_RELEASE.container)?.image;
  assert.equal(targetImage, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}@${state.imageDigest}`);
  await rollbackFrontendCandidate({ predecessor: { taskDefinitionArn: state.taskDefinitionArn, desiredCount: state.desiredCount }, candidateTaskDefinitionArn: current.taskDefinitionArn, ...adapters });
  runNormalSmoke(repositoryRoot);
}

async function executeBackendCli({ sourceSha, imageRef, expectedState, run, repositoryRoot }) {
  assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/);
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role);
  const readers = createAppOnlyEcsReaders(run), live = readers.readLive();
  const digest = imageRef.split("@")[1];
  const predecessor = captureAppOnlyPredecessor(live);
  const liveIdentity = { sourceSha: readers.readBackendImageSource(predecessor.backendDigest), imageDigest: predecessor.backendDigest, taskDefinitionArn: predecessor.taskDefinitionArn, desiredCount: predecessor.desiredCount };
  if (expectedState && !sameComponentIdentity(liveIdentity, expectedState)) {
    if (classifyNormalLiveComponentState({ live: liveIdentity, predecessor: expectedState, candidate: { sourceSha, imageDigest: digest } }) === "LIVE_IS_EXACT_CANDIDATE") {
      assertNormalBackendExactCandidate(readers.readDefinition(expectedState.taskDefinitionArn), live.definition, digest);
      return Object.freeze({ result: { candidateTaskDefinition: liveIdentity.taskDefinitionArn, candidateDeploymentId: predecessor.deploymentId, deployedBackendDigest: digest, deployedImageSourceSha: sourceSha, retry: "LIVE_IS_EXACT_CANDIDATE" }, predecessor: expectedState, rollback: () => rollbackBackendToState({ state: expectedState, sourceSha, run, repositoryRoot }) });
    }
    throw new Error("Backend live state is neither the authenticated predecessor nor the exact candidate.");
  }
  const preparation = buildNormalBackendPreparation({ sourceSha, predecessorSourceSha: readers.readBackendImageSource(predecessor.backendDigest), live, candidateDigest: digest });
  const authenticate = async () => { assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role); };
  const journalDirectory = process.env.MSCQR_APP_ONLY_JOURNAL_DIR ? path.join(process.env.MSCQR_APP_ONLY_JOURNAL_DIR, "backend") : undefined;
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: preparation.preparationSha256, directory: journalDirectory });
  const adapters = createAppOnlyActivationAdapters({ run, preparation, authenticate, writeEvidence: journal.writeEvidence });
  const result = await executeAppOnlyActivation(preparation, adapters);
  return Object.freeze({ result, predecessor: preparation.predecessor, rollback: () => rollbackAppOnlyActivation({ preparation, candidateArn: result.candidateTaskDefinition, candidateDeploymentId: result.candidateDeploymentId, adapters }) });
}

async function executeFrontendCli({ sourceSha, imageRef, expectedState, run, repositoryRoot }) {
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
    if (classifyNormalLiveComponentState({ live: liveIdentity, predecessor: expectedState, candidate: { sourceSha, imageDigest: digest } }) === "LIVE_IS_EXACT_CANDIDATE") {
      const predecessorDefinition = await adapters.describeTaskDefinition(expectedState.taskDefinitionArn);
      const predecessorImage = predecessorDefinition.containerDefinitions?.find(({ name }) => name === WEB_RELEASE.container)?.image;
      assert.equal(predecessorImage, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}@${expectedState.imageDigest}`);
      const expectedCandidate = buildNormalFrontendCandidate({ predecessor: { taskDefinitionArn: expectedState.taskDefinitionArn, desiredCount: expectedState.desiredCount, imageRef: predecessorImage, taskDefinition: predecessorDefinition }, imageRef });
      assertFrontendCandidateReadback({ definition: liveDefinition, taskDefinitionArn: liveIdentity.taskDefinitionArn, candidate: expectedCandidate });
      return Object.freeze({ result: { sourceSha, predecessorTaskDefinitionArn: expectedState.taskDefinitionArn, candidateTaskDefinitionArn: liveIdentity.taskDefinitionArn, imageRef, retry: "LIVE_IS_EXACT_CANDIDATE" }, predecessor: expectedState, rollback: () => rollbackFrontendToState({ state: expectedState, sourceSha, run, repositoryRoot }) });
    }
    throw new Error("Frontend live state is neither the authenticated predecessor nor the exact candidate.");
  }
  const result = await executeNormalFrontendActivation({ sourceSha, imageRef, adapters });
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
    await writeJournal({ status: "FAILURE", error: error.message.slice(0, 512) });
    if (error.frontendRollback?.attempted) await writeJournal({ status: error.frontendRollback.verified ? "FRONTEND_ROLLED_BACK" : "FRONTEND_ROLLBACK_UNVERIFIED" });
    const rollbackErrors = [];
    const rollback = async (component, value, operation) => {
      try { await writeJournal({ status: `${component}_ROLLBACK_INTENT` }); await operation(value); await writeJournal({ status: `${component}_ROLLED_BACK` }); }
      catch (rollbackError) { rollbackErrors.push({ component, error: rollbackError.message.slice(0, 512) }); try { await writeJournal({ status: `${component}_ROLLBACK_FAILED`, error: rollbackError.message.slice(0, 512) }); } catch (journalError) { rollbackErrors.push({ component: `${component}_JOURNAL`, error: journalError.message.slice(0, 512) }); } }
    };
    if (plan.classification.frontend && result.frontend !== "UNCHANGED") await rollback("FRONTEND", result.frontend, frontend.rollback);
    if (plan.classification.backend && result.backend !== "UNCHANGED") await rollback("BACKEND", result.backend, backend.rollback);
    if (rollbackErrors.length) throw Object.assign(new Error(`Normal release rollback failed after: ${error.message}`, { cause: error }), { rollbackErrors });
    throw error;
  }
  return Object.freeze(result);
}

export async function executeNormalComponentTransaction({ plan, sourceSha, state, stateClient, backend, frontend, smoke = async () => true, isAncestor, writeJournal = async () => {}, writerContext = {} } = {}) {
  assertNormalReleasePlan(plan, sourceSha); assert.ok(state); assert.equal(typeof stateClient?.advance, "function");
  const result = await executeNormalRelease({ plan, sourceSha,
    backend: plan.classification.backend ? backend : {}, frontend: plan.classification.frontend ? frontend : {}, smoke, writeJournal });
  const changes = {};
  if (plan.classification.backend) {
    const activation = result.backend?.result || result.backend;
    changes.backend = { sourceSha, imageDigest: activation.deployedBackendDigest, taskDefinitionArn: activation.candidateTaskDefinition, desiredCount: state.components.backend.desiredCount };
  }
  if (plan.classification.frontend) {
    const activation = result.frontend?.result || result.frontend;
    changes.frontend = { sourceSha, imageDigest: activation.imageRef?.split("@")[1], taskDefinitionArn: activation.candidateTaskDefinitionArn, desiredCount: state.components.frontend.desiredCount };
  }
  if (Object.keys(changes).length) {
    // If this CAS fails after smoke, retain the exact live candidate. A retry
    // authenticates that candidate and commits; it never lies about success.
    await writeJournal({ status: "STATE_CAS_INTENT", stateGeneration: state.generation, components: Object.keys(changes).sort() });
    const committed = advanceProductionComponentDeploymentStateWithRetry({ client: stateClient, current: state, lane: "NORMAL_APPLICATION", changes, isAncestor, ...writerContext });
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

async function main() {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const { plan, preparation } = parseNormalComponentReleaseArgs(process.argv.slice(2));
  assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/production-deploy\.yml@refs\/heads\/main$/);
  assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: NORMAL_RELEASE.region });
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.role);
  const stateClient = createProductionComponentDeploymentStateClient({ run }); const state = stateClient.read();
  assert.ok(state, "Production component deployment state is not bootstrapped."); assert.equal(state.generation, preparation.stateGeneration, "Component deployment state changed; reprepare release."); assert.equal(stateHash(state), preparation.stateSha256, "Component deployment state changed; reprepare release.");
  const journalDirectory = process.env.MSCQR_APP_ONLY_JOURNAL_DIR ? path.join(process.env.MSCQR_APP_ONLY_JOURNAL_DIR, "release") : undefined;
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha: plan.sourceSha, preparationSha256: sha256(JSON.stringify(preparation)), directory: journalDirectory });
  const component = (name, deploy) => ({ deploy: (image) => deploy({ sourceSha: plan.sourceSha, imageRef: image, expectedState: state.components[name], run, repositoryRoot }), rollback: (value) => value.rollback() });
  let result;
  try {
    result = await executeNormalComponentTransaction({ plan, sourceSha: plan.sourceSha, state, stateClient,
      backend: component("backend", executeBackendCli), frontend: component("frontend", executeFrontendCli), smoke: async () => { runNormalSmoke(repositoryRoot); }, writeJournal: journal.writeEvidence,
      isAncestor: (ancestor, candidate) => spawnSync("git", ["merge-base", "--is-ancestor", ancestor, candidate], { cwd: repositoryRoot, stdio: "ignore" }).status === 0,
      writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID } });
  } catch (error) {
    journal.writeEvidence({ status: "FINAL_FAILURE", error: error.message.slice(0, 512) }); throw error;
  }
  journal.writeEvidence({ status: "COMPLETE", stateGeneration: result.componentState.generation });
  process.stdout.write(`${JSON.stringify({ plan, result })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
